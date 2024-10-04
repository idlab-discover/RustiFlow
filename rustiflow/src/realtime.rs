use std::{hash::{DefaultHasher, Hash, Hasher}, sync::atomic::{AtomicU64, Ordering}};

use crate::{flow_table::FlowTable, flows::flow::Flow, packet_features::PacketFeatures};
use bytes::BytesMut;
use common::{EbpfEventIpv4, EbpfEventIpv6};
use log::{error, info};
use tokio::{signal, sync::mpsc::{self, Sender}, task::JoinSet};
use crate::debug;
use aya::{include_bytes_aligned, maps::{AsyncPerfEventArray, MapData}, programs::{tc, SchedClassifier, TcAttachType}, Bpf};

static TOTAL_LOST_EVENTS: AtomicU64 = AtomicU64::new(0);

pub async fn handle_realtime<T>(
    interface: &str,
    output_channel: Sender<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<u64>,
    expiration_check_interval: u64,
    ingress_only: bool,
) -> Result<(), anyhow::Error>
where
    T: Flow,
{
    // Needed for older kernels
    bump_memlock_rlimit();

    // Load the eBPF programs and attach to the event arrays
    let mut bpf_ingress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Ingress)?;
    let mut bpf_ingress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Ingress)?;
    let events_ingress_ipv4 = AsyncPerfEventArray::try_from(bpf_ingress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
    let events_ingress_ipv6 = AsyncPerfEventArray::try_from(bpf_ingress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
    let event_sources_v4: Vec<AsyncPerfEventArray<MapData>>;
    let event_sources_v6: Vec<AsyncPerfEventArray<MapData>>;

    if !ingress_only {
        let mut bpf_egress_ipv4 = load_ebpf_ipv4(interface, TcAttachType::Egress)?;
        let mut bpf_egress_ipv6 = load_ebpf_ipv6(interface, TcAttachType::Egress)?;
        let events_egress_ipv4 = AsyncPerfEventArray::try_from(bpf_egress_ipv4.take_map("EVENTS_IPV4").unwrap())?;
        let events_egress_ipv6 = AsyncPerfEventArray::try_from(bpf_egress_ipv6.take_map("EVENTS_IPV6").unwrap())?;
        event_sources_v4 = vec![events_egress_ipv4, events_ingress_ipv4];
        event_sources_v6 = vec![events_egress_ipv6, events_ingress_ipv6];
    } else {
        event_sources_v4 = vec![events_ingress_ipv4];
        event_sources_v6 = vec![events_ingress_ipv6];
    }

    let buffer_num_packets = 10_000;
    let mut shard_senders = Vec::with_capacity(num_threads as usize);
    
    debug!("Creating {} sharded FlowTables...", num_threads);
    for _ in 0..num_threads {
        let (tx, mut rx) = mpsc::channel::<PacketFeatures>(buffer_num_packets);
        let mut flow_table = FlowTable::new(active_timeout, idle_timeout, early_export, output_channel.clone(), expiration_check_interval);
        
        // Spawn a task per shard
        tokio::spawn(async move {
            while let Some(packet_features) = rx.recv().await {
                flow_table.process_packet(&packet_features).await;
            }
            debug!("Shard finished processing packets");
            // Handle flow exporting when the receiver is closed
            flow_table.export_all_flows().await;
        });
        shard_senders.push(tx);
    }
    debug!("Sharded FlowTables created");

    // Spawn a task per event source
    let mut handle_set = JoinSet::new();

    for mut ebpf_event_source in event_sources_v4 {
        let shard_senders_clone = shard_senders.clone();
        let mut event_buffer = ebpf_event_source.open(0, None)?;
        
        handle_set.spawn(async move {
            // 10 buffers with 98_304 bytes each, meaning a capacity of 4096 packets per buffer (24 bytes per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(24 * 4096))
                .collect::<Vec<_>>();

            loop {
                match event_buffer.read_events(&mut buffers).await {
                    Ok(events) => {
                        TOTAL_LOST_EVENTS.fetch_add(events.lost as u64, Ordering::SeqCst);
                        debug!("Processed {} events", events.read);

                        for buf in buffers.iter_mut().take(events.read) {
                            let ptr = buf.as_ptr() as *const EbpfEventIpv4;
                            let ebpf_event_ipv4 = unsafe { ptr.read_unaligned() };
                            let packet_features = PacketFeatures::from_ebpf_event_ipv4(&ebpf_event_ipv4);
                            let flow_key = packet_features.biflow_key();
                            debug!("Received packet for flow: {}", flow_key);
                            let shard_index = compute_shard_index(&flow_key, num_threads);

                            if let Err(e) = shard_senders_clone[shard_index].send(packet_features).await {
                                error!("Failed to send packet_features to shard {}: {}", shard_index, e);
                            }
                        }
                    }
                    Err(_) => {
                        error!("Failed to read events from event_buffer");
                    }
                }
            }
        });
    }

    for mut ebpf_event_source in event_sources_v6 {
        let shard_senders_clone = shard_senders.clone();
        let mut event_buffer = ebpf_event_source.open(0, None)?;
        
        handle_set.spawn(async move {
            // 10 buffers with 98_304 bytes each, meaning a capacity of 4096 packets per buffer (24 bytes per packet)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(24 * 4096))
                .collect::<Vec<_>>();

            loop {
                match event_buffer.read_events(&mut buffers).await {
                    Ok(events) => {
                        TOTAL_LOST_EVENTS.fetch_add(events.lost as u64, Ordering::SeqCst);
                        debug!("Processed {} events", events.read);

                        for buf in buffers.iter_mut().take(events.read) {
                            let ptr = buf.as_ptr() as *const EbpfEventIpv6;
                            let ebpf_event_ipv6 = unsafe { ptr.read_unaligned() };
                            let packet_features = PacketFeatures::from_ebpf_event_ipv6(&ebpf_event_ipv6);
                            let flow_key = packet_features.biflow_key();
                            debug!("Received packet for flow: {}", flow_key);
                            let shard_index = compute_shard_index(&flow_key, num_threads);

                            if let Err(e) = shard_senders_clone[shard_index].send(packet_features).await {
                                error!("Failed to send packet_features to shard {}: {}", shard_index, e);
                            }
                        }
                    }
                    Err(_) => {
                        error!("Failed to read events from event_buffer");
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");

    signal::ctrl_c().await?;

    // Cancel the tasks reading ebpf events
    handle_set.abort_all();
    
    // Wait for all tasks to finish
    while let Some(res) = handle_set.join_next().await {
        match res {
            Ok(_) => {
                // Task should never finish by itself
                error!("Event source task finished unexpectedly");
            }
            Err(e) if e.is_cancelled() => {
                // Task was successfully cancelled
                debug!("Task was cancelled as part of graceful shutdown");
            }
            Err(e) => {
                // Log other types of errors
                error!("Task failed: {:?}", e);
            }
        }
    }

    debug!(
        "{} events were lost",
        TOTAL_LOST_EVENTS.load(Ordering::SeqCst)
    );

    Ok(())
}

fn compute_shard_index(flow_key: &str, num_shards: u8) -> usize {
    assert!(num_shards > 0, "num_shards must be greater than 0");
    let mut hasher = DefaultHasher::new();
    flow_key.hash(&mut hasher);
    let hash = hasher.finish();
    (hash % num_shards as u64) as usize
}

fn bump_memlock_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

fn load_ebpf_ipv4(interface: &str, tc_attach_type: TcAttachType) -> Result<Bpf, anyhow::Error> {
    // Loading the eBPF program, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ipv4 = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv4"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ipv4 = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv4"
    ))?;

    // Attach the eBPF program function
    let _ = tc::qdisc_add_clsact(interface);
    let program_egress_ipv4: &mut SchedClassifier = bpf_ipv4
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_egress_ipv4.load()?;
    program_egress_ipv4.attach(&interface, tc_attach_type)?;
    
    Ok(bpf_ipv4)
}

fn load_ebpf_ipv6(interface: &str, tc_attach_type: TcAttachType) -> Result<Bpf, anyhow::Error> {
    // Loading the eBPF program, the macros make sure the correct file is loaded
    #[cfg(debug_assertions)]
    let mut bpf_ipv6 = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/rustiflow-ebpf-ipv6"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf_ipv6 = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/rustiflow-ebpf-ipv6"
    ))?;

    // Attach the eBPF program function
    let _ = tc::qdisc_add_clsact(interface);
    let program_egress_ipv6: &mut SchedClassifier = bpf_ipv6
        .program_mut("tc_flow_track")
        .unwrap()
        .try_into()?;
    program_egress_ipv6.load()?;
    program_egress_ipv6.attach(&interface, tc_attach_type)?;
    
    Ok(bpf_ipv6)
}
