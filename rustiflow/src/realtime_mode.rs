use crate::args::{ExportMethodType, OutputConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketGraphMode {
    Disabled,
    Enabled,
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
        (ExportMethodType::Csv, true, true, false) => PacketGraphMode::Enabled,
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
    fn packet_graph_mode_only_enables_for_explicit_csv_packet_graph() {
        let output = output_config(ExportMethodType::Csv, Some("/tmp/out.csv"), true);

        assert_eq!(
            packet_graph_mode_with_debug(&output, false),
            PacketGraphMode::Enabled
        );
    }

    #[test]
    fn packet_graph_mode_stays_disabled_without_packet_graph() {
        let output = output_config(ExportMethodType::Csv, Some("/tmp/out.csv"), false);

        assert_eq!(
            packet_graph_mode_with_debug(&output, false),
            PacketGraphMode::Disabled
        );
    }

    #[test]
    fn packet_graph_mode_stays_disabled_for_debug_logging() {
        let output = output_config(ExportMethodType::Csv, Some("/tmp/out.csv"), false);

        assert_eq!(
            packet_graph_mode_with_debug(&output, true),
            PacketGraphMode::Disabled
        );
    }

    #[test]
    fn packet_graph_mode_stays_disabled_without_csv_export_path() {
        let csv_without_path = output_config(ExportMethodType::Csv, None, false);
        let print_output = output_config(ExportMethodType::Print, None, false);

        assert_eq!(
            packet_graph_mode_with_debug(&csv_without_path, false),
            PacketGraphMode::Disabled
        );
        assert_eq!(
            packet_graph_mode_with_debug(&print_output, false),
            PacketGraphMode::Disabled
        );
    }
}
