use std::ffi::{CStr, CString};

use anyhow::{bail, ensure, Context};
use aya::{
    maps::{MapData, PerCpuArray, RingBuf},
    programs::{
        tc,
        tc::{NlOptions, TcAttach},
        SchedClassifier, TcAttachType, Xdp, XdpMode,
    },
    Ebpf,
};
use aya_log::EbpfLogger;
use common::REALTIME_EVENT_QUEUE_COUNT;
use log::{debug, error, info};
use tokio::{io::unix::AsyncFd, task::JoinSet};

use super::{
    ebpf_objects::{ebpf_object_path, INGRESS_EXPERIMENT_OBJECT},
    queue_label,
};

const EXPERIMENT_ENV: &str = "RUSTIFLOW_EXPERIMENT_INGRESS";

enum Ingress {
    SplitTc,
    Experiment(ExperimentHook),
}

enum ExperimentHook {
    SingleTc,
    LegacySingleTc,
    Xdp(XdpMode),
}

impl Ingress {
    fn select(ingress_only: bool) -> anyhow::Result<Self> {
        let Some(value) = std::env::var_os(EXPERIMENT_ENV) else {
            if std::env::var_os("RUSTIFLOW_EXPERIMENT_SINGLE_TC").is_some() {
                ensure!(ingress_only, "single TC experiment requires --ingress-only");
                return Ok(Self::Experiment(ExperimentHook::LegacySingleTc));
            }
            return Ok(Self::SplitTc);
        };
        let mode = match value.to_str() {
            Some("single-tc") => ExperimentHook::SingleTc,
            Some("xdp-driver") => ExperimentHook::Xdp(XdpMode::Driver),
            Some("xdp-skb") => ExperimentHook::Xdp(XdpMode::Skb),
            _ => bail!("{EXPERIMENT_ENV} expects single-tc, xdp-driver, or xdp-skb"),
        };
        ensure!(ingress_only, "{EXPERIMENT_ENV} requires --ingress-only");
        Ok(Self::Experiment(mode))
    }
}

type Sources = Vec<(String, RingBuf<MapData>)>;

#[derive(Default)]
pub(super) struct Capture {
    // Owning the loaded objects keeps their attachments alive for this capture.
    programs: Vec<Ebpf>,
    logger_tasks: JoinSet<()>,
    ipv4: Sources,
    ipv6: Sources,
    counters: Vec<RealtimeEbpfCounters>,
}

impl Capture {
    pub(super) fn attach(interface: &str, ingress_only: bool) -> anyhow::Result<Self> {
        let ingress = Ingress::select(ingress_only)?;
        let interface_name = CString::new(interface)
            .with_context(|| format!("interface name {interface:?} contains a NUL byte"))?;
        let mut capture = Self::default();
        match ingress {
            Ingress::SplitTc => {
                capture.add_split_tc(&interface_name, TcAttachType::Ingress)?;
                if !ingress_only {
                    capture.add_split_tc(&interface_name, TcAttachType::Egress)?;
                }
            }
            Ingress::Experiment(hook) => {
                let mut bpf = load_object(if matches!(hook, ExperimentHook::LegacySingleTc) {
                    "rustiflow-ebpf-dual-stack"
                } else {
                    INGRESS_EXPERIMENT_OBJECT
                })?;
                match hook {
                    ExperimentHook::LegacySingleTc | ExperimentHook::SingleTc => attach_tc(
                        &mut bpf,
                        &interface_name,
                        "dual-stack",
                        TcAttachType::Ingress,
                    )?,
                    ExperimentHook::Xdp(mode) => attach_xdp(&mut bpf, &interface_name, mode)?,
                }
                capture.ipv4 = take_sources(&mut bpf, "EVENTS_IPV4", "ingress-ipv4")?;
                capture.ipv6 = take_sources(&mut bpf, "EVENTS_IPV6", "ingress-ipv6")?;
                capture.counters.push(RealtimeEbpfCounters::take(
                    &mut bpf,
                    &["ingress-ipv4", "ingress-ipv6"],
                )?);
                capture.programs.push(bpf);
            }
        }
        for program in &mut capture.programs {
            spawn_ebpf_logger(program, &mut capture.logger_tasks);
        }
        Ok(capture)
    }

    fn add_split_tc(&mut self, interface: &CStr, attach_type: TcAttachType) -> anyhow::Result<()> {
        let (label4, label6) = match attach_type {
            TcAttachType::Ingress => ("ingress-ipv4", "ingress-ipv6"),
            TcAttachType::Egress => ("egress-ipv4", "egress-ipv6"),
        };
        let mut ipv4 = load_object("rustiflow-ebpf-ipv4")?;
        attach_tc(&mut ipv4, interface, "IPv4", attach_type)?;
        let mut ipv6 = load_object("rustiflow-ebpf-ipv6")?;
        attach_tc(&mut ipv6, interface, "IPv6", attach_type)?;
        // Preserve the order in which the original pipeline starts its source tasks.
        self.ipv4
            .splice(0..0, take_sources(&mut ipv4, "EVENTS_IPV4", label4)?);
        self.ipv6
            .splice(0..0, take_sources(&mut ipv6, "EVENTS_IPV6", label6)?);
        self.counters
            .push(RealtimeEbpfCounters::take(&mut ipv4, &[label4])?);
        self.counters
            .push(RealtimeEbpfCounters::take(&mut ipv6, &[label6])?);
        self.programs.extend([ipv4, ipv6]);
        Ok(())
    }

    pub(super) fn take_sources(&mut self) -> (Sources, Sources) {
        (
            std::mem::take(&mut self.ipv4),
            std::mem::take(&mut self.ipv6),
        )
    }

    pub(super) fn log_totals(&self) -> u64 {
        self.counters
            .iter()
            .map(RealtimeEbpfCounters::log_totals)
            .sum()
    }
}

fn load_object(object: &str) -> anyhow::Result<Ebpf> {
    let binary_path = ebpf_object_path(object)?;
    info!("Loading eBPF binary {}", binary_path.display());
    Ebpf::load_file(&binary_path)
        .with_context(|| format!("Failed to load eBPF binary from {}", binary_path.display()))
}

fn attach_xdp(bpf: &mut Ebpf, interface: &CStr, mode: XdpMode) -> anyhow::Result<()> {
    let program: &mut Xdp = bpf
        .program_mut("xdp_flow_track")
        .context("missing xdp_flow_track program")?
        .try_into()?;
    program
        .load()
        .context("Failed to load passive XDP program")?;
    program.attach(interface, mode).with_context(|| {
        format!(
            "Failed to attach passive XDP in {mode:?} mode on {}",
            interface.to_string_lossy()
        )
    })?;
    info!(
        "Attached passive XDP in {mode:?} mode on {}",
        interface.to_string_lossy()
    );
    Ok(())
}

struct RealtimeEbpfCounters {
    labels: Vec<&'static str>,
    dropped_packets: PerCpuArray<MapData, u64>,
    matched_packets: PerCpuArray<MapData, u64>,
    submitted_events: PerCpuArray<MapData, u64>,
}

impl RealtimeEbpfCounters {
    fn take(bpf: &mut Ebpf, labels: &[&'static str]) -> anyhow::Result<Self> {
        let mut take_counter = |name| {
            PerCpuArray::try_from(
                bpf.take_map(name)
                    .with_context(|| format!("missing eBPF counter map {name}"))?,
            )
            .with_context(|| format!("invalid eBPF counter map {name}"))
        };
        Ok(Self {
            labels: labels.to_vec(),
            dropped_packets: take_counter("DROPPED_PACKETS")?,
            matched_packets: take_counter("MATCHED_PACKETS")?,
            submitted_events: take_counter("SUBMITTED_EVENTS")?,
        })
    }

    fn log_totals(&self) -> u64 {
        let mut total_dropped = 0;
        for (index, &label) in (0..).zip(&self.labels) {
            let dropped = read_per_cpu_counter(&self.dropped_packets, index, label, "dropped");
            let matched = read_per_cpu_counter(&self.matched_packets, index, label, "matched");
            let submitted = read_per_cpu_counter(&self.submitted_events, index, label, "submitted");
            total_dropped += dropped;
            info!(
                "eBPF counters {label}: matched_packets={matched}, submitted_events={submitted}, dropped_packets={dropped}"
            );
        }
        total_dropped
    }
}

fn read_per_cpu_counter(
    counter_array: &PerCpuArray<MapData, u64>,
    index: u32,
    label: &str,
    counter_name: &str,
) -> u64 {
    match counter_array.get(&index, 0) {
        Ok(values) => values.iter().sum(),
        Err(e) => {
            error!(
                "Failed to read {} counter for {}: {:?}",
                counter_name, label, e
            );
            0
        }
    }
}

fn take_sources(bpf: &mut Ebpf, base_name: &str, label: &str) -> anyhow::Result<Sources> {
    (0..REALTIME_EVENT_QUEUE_COUNT)
        .map(|index| {
            let map_name = format!("{base_name}_{index}");
            let ring = RingBuf::try_from(
                bpf.take_map(&map_name)
                    .with_context(|| format!("missing ring buffer map {map_name}"))?,
            )?;
            Ok((queue_label(label, index), ring))
        })
        .collect()
}

/// Forwards `aya-log` records from the eBPF program to the userspace logger.
fn spawn_ebpf_logger(bpf: &mut Ebpf, tasks: &mut JoinSet<()>) {
    let logger = match EbpfLogger::init(bpf) {
        Ok(logger) => logger,
        Err(e) => {
            debug!("eBPF logger unavailable: {e}");
            return;
        }
    };
    // SAFETY: the logger owns its ring buffer map file descriptor and reports
    // that same descriptor from `as_raw_fd` until it is dropped with the `AsyncFd`.
    let mut logger = match unsafe { AsyncFd::register(logger) } {
        Ok(logger) => logger,
        Err(e) => {
            error!("Failed to poll the eBPF logger: {e}");
            return;
        }
    };

    tasks.spawn(async move {
        loop {
            let Ok(mut guard) = logger.readable_mut().await else {
                return;
            };
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });
}

fn tc_attach_type_label(tc_attach_type: TcAttachType) -> &'static str {
    match tc_attach_type {
        TcAttachType::Ingress => "ingress",
        TcAttachType::Egress => "egress",
    }
}

fn attach_tc(
    bpf: &mut Ebpf,
    interface_name: &CStr,
    family: &str,
    attach_type: TcAttachType,
) -> anyhow::Result<()> {
    let attach_label = tc_attach_type_label(attach_type);
    let interface = interface_name.to_string_lossy();
    match tc::qdisc_add_clsact(interface_name) {
        Ok(()) => info!("Ensured clsact qdisc on {interface}"),
        Err(e) => debug!("qdisc_add_clsact({interface}): {e:?}"),
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("tc_flow_track")
        .context("missing tc_flow_track classifier")?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("Failed to load {family} tc classifier"))?;
    program
        .attach(
            interface_name,
            TcAttach::Netlink {
                parent: attach_type.into(),
                options: NlOptions::default(),
            },
        )
        .with_context(|| {
            format!("Failed to attach {family} tc classifier to {attach_label} on {interface}")
        })?;
    info!("Attached {family} tc classifier to {attach_label} on {interface}");

    Ok(())
}
