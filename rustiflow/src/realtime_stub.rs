use std::num::NonZeroU64;

use crate::flows::flow::Flow;
use crate::output::FlowSink;
use crate::realtime_mode::PacketGraphMode;

/// Realtime capture depends on Aya/eBPF and is only available on Linux.
pub async fn handle_realtime<T>(
    interface: &str,
    _exporter: impl FlowSink<T>,
    _num_threads: u8,
    _active_timeout: u64,
    _idle_timeout: u64,
    _early_export: Option<NonZeroU64>,
    _expiration_check_interval: u64,
    _ingress_only: bool,
    _packet_graph_mode: PacketGraphMode,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    Err(anyhow::anyhow!(
        "Realtime capture on interface {interface:?} is only supported on Linux"
    ))
}
