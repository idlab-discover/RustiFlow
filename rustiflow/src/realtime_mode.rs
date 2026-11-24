use crate::args::{ExportMethodType, OutputConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketGraphMode {
    Disabled,
    Enabled,
}

/// Whether realtime capture holds the interface in promiscuous mode, so a
/// physical NIC passes up frames addressed to other MAC addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromiscuousMode {
    Disabled,
    Enabled,
}

impl PromiscuousMode {
    pub fn from_flag(promiscuous: bool) -> Self {
        if promiscuous {
            PromiscuousMode::Enabled
        } else {
            PromiscuousMode::Disabled
        }
    }
}

pub fn packet_graph_mode(output: &OutputConfig) -> PacketGraphMode {
    packet_graph_mode_with_debug(output, debug_logging_enabled())
}

fn packet_graph_mode_with_debug(
    output: &OutputConfig,
    debug_logging_enabled: bool,
) -> PacketGraphMode {
    match (
        &output.output,
        output.export_path.is_some(),
        output.packet_graph,
        debug_logging_enabled,
    ) {
        (ExportMethodType::Csv, true, true, false)
        | (ExportMethodType::Parquet, _, true, false) => PacketGraphMode::Enabled,
        _ => PacketGraphMode::Disabled,
    }
}

fn debug_logging_enabled() -> bool {
    matches!(std::env::var("RUST_LOG"), Ok(ref value) if value.contains("debug"))
}

#[cfg(test)]
mod tests {
    use super::{packet_graph_mode_with_debug, PacketGraphMode};
    use crate::args::{ExportMethodType, OutputConfig};

    fn output_config(
        output: ExportMethodType,
        export_path: Option<&str>,
        packet_graph: bool,
    ) -> OutputConfig {
        OutputConfig {
            output,
            export_path: export_path.map(str::to_string),
            header: false,
            drop_contaminant_features: false,
            packet_graph,
        }
    }

    #[test]
    fn packet_graph_mode_requires_a_file_export_an_explicit_flag_and_no_debug_logging() {
        use ExportMethodType::{Csv, Parquet, Print};
        use PacketGraphMode::{Disabled, Enabled};
        let cases = [
            (Csv, Some("/tmp/out.csv"), true, false, Enabled),
            (Parquet, Some("/tmp/out.parquet"), true, false, Enabled),
            (Parquet, None, true, false, Enabled),
            (Csv, Some("/tmp/out.csv"), false, false, Disabled),
            (Csv, Some("/tmp/out.csv"), true, true, Disabled),
            (Csv, None, true, false, Disabled),
            (Print, None, true, false, Disabled),
        ];
        let actual: Vec<_> = cases
            .iter()
            .map(|(output, path, graph, debug, _)| {
                let config = output_config(output.clone(), *path, *graph);
                packet_graph_mode_with_debug(&config, *debug)
            })
            .collect();
        let expected: Vec<_> = cases.iter().map(|case| case.4).collect();
        assert_eq!(actual, expected);
    }
}
