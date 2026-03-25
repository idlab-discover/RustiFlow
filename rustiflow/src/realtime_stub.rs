use crate::flows::flow::Flow;
use tokio::sync::mpsc::Sender;

/// Realtime capture depends on Aya/eBPF and is only available on Linux.
pub async fn handle_realtime<T>(
    interface: &str,
    _output_channel: Sender<T>,
    _num_threads: u8,
    _active_timeout: u64,
    _idle_timeout: u64,
    _early_export: Option<u64>,
    _expiration_check_interval: u64,
    _ingress_only: bool,
    _performance_mode_disabled: bool,
) -> Result<u64, anyhow::Error>
where
    T: Flow,
{
    Err(anyhow::anyhow!(
        "Realtime capture on interface {interface:?} is only supported on Linux"
    ))
}
