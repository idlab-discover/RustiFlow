use std::{
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Duration,
};

use log::info;

struct ExportProfile {
    clone_count: AtomicU64,
    clone_time_ns: AtomicU64,
    serialized_flow_count: AtomicU64,
    serialized_bytes: AtomicU64,
    dump_time_ns: AtomicU64,
    write_time_ns: AtomicU64,
}

impl ExportProfile {
    const fn new() -> Self {
        Self {
            clone_count: AtomicU64::new(0),
            clone_time_ns: AtomicU64::new(0),
            serialized_flow_count: AtomicU64::new(0),
            serialized_bytes: AtomicU64::new(0),
            dump_time_ns: AtomicU64::new(0),
            write_time_ns: AtomicU64::new(0),
        }
    }

    fn record_clone(&self, duration: Duration) {
        self.clone_count.fetch_add(1, Ordering::Relaxed);
        self.clone_time_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn record_dump(&self, duration: Duration, bytes: usize) {
        self.serialized_flow_count.fetch_add(1, Ordering::Relaxed);
        self.serialized_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.dump_time_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn record_write(&self, duration: Duration) {
        self.write_time_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn log_summary(&self, mode: &str) {
        let clone_count = self.clone_count.load(Ordering::Relaxed);
        let serialized_flow_count = self.serialized_flow_count.load(Ordering::Relaxed);
        let serialized_bytes = self.serialized_bytes.load(Ordering::Relaxed);
        let clone_time_ns = self.clone_time_ns.load(Ordering::Relaxed);
        let dump_time_ns = self.dump_time_ns.load(Ordering::Relaxed);
        let write_time_ns = self.write_time_ns.load(Ordering::Relaxed);

        info!(
            "Export breakdown for {}: clone_count={} clone_ms={:.3} serialized_flows={} serialized_bytes={} dump_ms={:.3} write_ms={:.3}",
            mode,
            clone_count,
            clone_time_ns as f64 / 1_000_000.0,
            serialized_flow_count,
            serialized_bytes,
            dump_time_ns as f64 / 1_000_000.0,
            write_time_ns as f64 / 1_000_000.0,
        );
    }
}

fn export_profile() -> Option<&'static ExportProfile> {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    static PROFILE: ExportProfile = ExportProfile::new();

    if *ENABLED.get_or_init(|| env_flag("RUSTIFLOW_PROFILE_EXPORT_BREAKDOWN")) {
        Some(&PROFILE)
    } else {
        None
    }
}

pub fn record_clone(duration: Duration) {
    if let Some(profile) = export_profile() {
        profile.record_clone(duration);
    }
}

pub fn record_dump(duration: Duration, bytes: usize) {
    if let Some(profile) = export_profile() {
        profile.record_dump(duration, bytes);
    }
}

pub fn record_write(duration: Duration) {
    if let Some(profile) = export_profile() {
        profile.record_write(duration);
    }
}

pub fn log_summary(mode: &str) {
    if let Some(profile) = export_profile() {
        profile.log_summary(mode);
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}
