//! Load-time overrides for the existing event maps. Map names are ELF symbols,
//! so the classifier and userspace event ABIs do not depend on ring capacity.
use anyhow::{ensure, Context};
use common::REALTIME_EVENT_QUEUE_COUNT;
use log::info;

const SETTING: &str = "RUSTIFLOW_EXPERIMENT_RING_BYTES";

pub(super) fn map_overrides(ingress_only: bool) -> anyhow::Result<Vec<(String, u32)>> {
    let Some(value) = std::env::var_os(SETTING) else {
        return Ok(Vec::new());
    };
    // SAFETY: sysconf with this constant takes no pointers and has no side effects.
    let page = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .context("reading host page size for event rings")?;
    ensure!(page.is_power_of_two(), "invalid host page size {page}");
    let directions = if ingress_only { 1 } else { 2 };
    let (v4, v6, total) = parse_bytes(
        value
            .to_str()
            .with_context(|| format!("non-UTF-8 {SETTING}"))?,
        page,
        directions,
    )
    .with_context(|| format!("invalid {SETTING}"))?;
    info!("Event ring bytes per map: IPv4={v4}, IPv6={v6}, total data capacity={total}");
    Ok([("EVENTS_IPV4", v4), ("EVENTS_IPV6", v6)]
        .into_iter()
        .flat_map(|(prefix, bytes)| {
            (0..REALTIME_EVENT_QUEUE_COUNT).map(move |index| (format!("{prefix}_{index}"), bytes))
        })
        .collect())
}

fn parse_bytes(value: &str, page: u32, directions: u64) -> anyhow::Result<(u32, u32, u64)> {
    let syntax = "expected IPv4_BYTES,IPv6_BYTES,TOTAL_CAP_BYTES";
    let (v4, rest) = value.split_once(',').context(syntax)?;
    let (v6, cap) = rest.split_once(',').context(syntax)?;
    let cap = cap
        .parse::<u64>()
        .context("expected a decimal total ring data cap")?;
    let parse = |s: &str| -> anyhow::Result<u32> {
        let bytes = s
            .parse::<u32>()
            .context("expected a decimal u32 byte count")?;
        ensure!(
            bytes >= page && bytes.is_power_of_two(),
            "ring size {bytes} must be a power of two of at least {page} bytes"
        );
        Ok(bytes)
    };
    let (v4, v6) = (parse(v4)?, parse(v6)?);
    let total = (u64::from(v4) + u64::from(v6)) * REALTIME_EVENT_QUEUE_COUNT as u64 * directions;
    ensure!(
        total <= cap,
        "{directions} capture direction(s) need {total} ring data bytes, cap is {cap}"
    );
    Ok((v4, v6, total))
}

#[cfg(test)]
mod tests {
    use super::parse_bytes;

    #[test]
    fn budget_includes_every_family_queue_and_capture_direction() {
        let ingress = "8388608,131072,68157440";
        assert_eq!(
            parse_bytes(ingress, 65536, 1).unwrap(),
            (8388608, 131072, 68157440)
        );
        assert!(parse_bytes(ingress, 65536, 2).is_err());
        assert_eq!(
            parse_bytes("8388608,131072,136314880", 65536, 2).unwrap(),
            (8388608, 131072, 136314880)
        );
    }

    #[test]
    fn invalid_settings_reject_rounding_and_overspend() {
        for bad in [
            "",
            "4096",
            "4096,4096",
            "4096,4096,65535",
            "4096,0,65536",
            "12288,4096,999999",
            "4294967296,4096,999999",
            "4096,4096,65536,1",
        ] {
            assert!(parse_bytes(bad, 4096, 1).is_err(), "{bad}");
        }
        assert!(parse_bytes("65536,4096,999999", 65536, 1).is_err());
    }
}
