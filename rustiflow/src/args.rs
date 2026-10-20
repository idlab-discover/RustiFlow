use clap::{ArgGroup, Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    num::{NonZeroU64, NonZeroUsize},
};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(group(ArgGroup::new("config_group").args(&["config_file"])), group(ArgGroup::new("cli_group").args(&["features", "output", "active_timeout", "idle_timeout", "export_path"]).multiple(true)))]
pub struct Cli {
    /// Configuration file path
    #[clap(long, short = 'c', group = "config_group")]
    pub config_file: Option<String>,

    /// The feature set to use (required if no config file is provided)
    #[clap(long, short, group = "cli_group")]
    pub features: Option<FlowType>,

    /// The maximum time a flow is allowed to last in seconds (optional)
    #[clap(long, default_value_t = 3600, group = "cli_group")]
    pub active_timeout: u64,

    /// The maximum time with no packets for a flow in seconds (optional)
    #[clap(long, default_value_t = 120, group = "cli_group")]
    pub idle_timeout: u64,

    /// Export a cumulative snapshot of each open flow every N seconds after its
    /// first packet (optional; must be at least 1 and smaller than the active timeout).
    /// Snapshots are triggered by packets and have flow_expire_cause None
    #[clap(long, group = "cli_group")]
    pub early_export: Option<NonZeroU64>,

    /// Interval (in seconds) for checking and expiring flows in the flowtable.
    /// This represents how often the flowtable should be scanned to remove inactive flows.
    #[clap(long, default_value_t = 60, group = "cli_group")]
    pub expiration_check_interval: u64,

    /// The numbers of threads to use for processing packets (optional)
    /// (default: realtime uses 12, capped at the number of logical CPUs; pcap uses 5; maximum: number of logical CPUs)
    #[clap(long, group = "cli_group")]
    pub threads: Option<u8>,

    /// Output method (required if no config file is provided)
    #[clap(long, short, group = "cli_group")]
    pub output: Option<ExportMethodType>,

    /// File path for output (used if method is Csv)
    #[clap(long, group = "cli_group", required_if_eq("output", "Csv"))]
    pub export_path: Option<String>,

    /// Enable the realtime packet graph when exporting to CSV
    #[clap(long = "packet-graph", alias = "performance-mode", group = "cli_group", action = clap::ArgAction::SetTrue, required_if_eq("output", "Csv"))]
    pub packet_graph: bool,

    /// Whether to export the feature header
    #[clap(long, action = clap::ArgAction::SetTrue, group = "cli_group")]
    pub header: bool,

    /// Whether to drop contaminant features
    #[clap(long, action = clap::ArgAction::SetTrue, group = "cli_group")]
    pub drop_contaminant_features: bool,

    /// Subcommands (Real-time, Pcap or the replay benchmark)
    #[clap(subcommand)]
    pub command: CliCommand,
}

#[derive(Serialize, Deserialize, Debug, Subcommand, Clone)]
pub enum Commands {
    /// Real-time feature extraction
    Realtime {
        /// The network interface to capture packets from
        interface: String,
        /// Whether to capture only ingress packets
        #[clap(long, action = clap::ArgAction::SetTrue)]
        ingress_only: bool,
    },

    /// Feature extraction from a pcap file
    Pcap {
        /// The relative path to the pcap file
        path: String,
    },
}

// Command-line subcommands: the capture modes plus developer benchmarks that
// the TUI and configuration files do not offer. A plain comment, because clap
// would use a doc comment as the program description.
#[derive(Debug, Subcommand)]
pub enum CliCommand {
    #[clap(flatten)]
    Capture(Commands),

    /// Benchmark the realtime userspace pipeline with synthetic eBPF events
    /// (no capture, no root needed). Prints throughput and CPU time per packet
    ReplayBench(ReplayBenchArgs),
}

#[derive(Args, Debug)]
pub struct ReplayBenchArgs {
    /// Number of events to replay
    #[clap(long, default_value = "10000000")]
    pub packets: NonZeroU64,

    /// Number of concurrent flows; each event picks one uniformly at random
    #[clap(long, default_value_t = 100_000, value_parser = clap::value_parser!(u32).range(1..=MAX_REPLAY_FLOWS))]
    pub flows: u32,

    /// Number of event sources drained in parallel, like the per-family rings
    #[clap(long, default_value = "8")]
    pub sources: NonZeroUsize,

    /// Events drained per source before its partial batches are flushed, like
    /// one ring wakeup
    #[clap(long, default_value = "4096")]
    pub drain_burst: NonZeroUsize,

    /// Transport payload bytes per packet
    #[clap(long, default_value_t = 1400, value_parser = clap::value_parser!(u16).range(0..=9000))]
    pub payload_bytes: u16,

    /// Packet rate used to space event timestamps; sets the virtual time seen by
    /// timeouts, expiration checks and early export
    #[clap(long, default_value = "1000000")]
    pub virtual_pps: NonZeroU64,

    /// Generate IPv6 events instead of IPv4
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub ipv6: bool,
}

/// Each replay flow gets its own client address inside 10.0.0.0/8.
pub const MAX_REPLAY_FLOWS: i64 = 1 << 24;

impl fmt::Display for Commands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Commands::Realtime {
                interface,
                ingress_only,
            } => write!(
                f,
                "Realtime/Interface: {}/Ingress only: {}",
                interface, ingress_only
            ),
            Commands::Pcap { path } => write!(f, "Pcap/Path: {}", path),
        }
    }
}

#[derive(Serialize, Deserialize, Args, Debug, Clone)]
pub struct ExportConfig {
    /// The feature set to use
    #[clap(short, long, value_enum)]
    pub features: FlowType,

    /// The maximum time a flow is allowed to last in seconds
    #[clap(long, default_value_t = 3600)]
    pub active_timeout: u64,

    /// The maximum time with no packets for a flow in seconds
    #[clap(long, default_value_t = 120)]
    pub idle_timeout: u64,

    /// Export a cumulative snapshot of each open flow every N seconds after its
    /// first packet (optional; must be at least 1 and smaller than the active timeout).
    /// Snapshots are triggered by packets and have flow_expire_cause None
    #[clap(long)]
    pub early_export: Option<NonZeroU64>,

    /// Interval (in seconds) for checking and expiring flows in the flowtable.
    /// This represents how often the flowtable should be scanned to remove inactive flows.
    #[clap(long, default_value_t = 60, group = "cli_group")]
    pub expiration_check_interval: u64,

    /// The numbers of threads to use for processing packets (optional)
    /// (default: realtime uses 12, capped at the number of logical CPUs; pcap uses 5; maximum: number of logical CPUs)
    #[clap(short, long)]
    pub threads: Option<u8>,
}

#[derive(Serialize, Deserialize, Args, Debug, Clone)]
pub struct OutputConfig {
    /// Output method
    #[clap(short, long, value_enum)]
    pub output: ExportMethodType,

    /// File path for output (used if method is Csv)
    #[clap(required_if_eq("output", "csv"))]
    pub export_path: Option<String>,

    /// Enable the realtime packet graph when exporting to CSV
    #[clap(long = "packet-graph", alias = "performance-mode", action = clap::ArgAction::SetTrue, required_if_eq("output", "Csv"))]
    #[serde(default, alias = "performance_mode")]
    pub packet_graph: bool,

    /// Whether to export the feature header
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub header: bool,

    /// Whether to drop contaminant features
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub drop_contaminant_features: bool,
}

#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Debug)]
pub enum ExportMethodType {
    /// The output will be printed to the console
    Print,

    /// The output will be written to a CSV file
    Csv,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowType {
    /// A basic flow that stores the basic features of a flow.
    Basic,

    /// Represents the CIC Flow, giving 83 features.
    CIC,

    /// Represents the CIDDS Flow, giving 10 features.
    CIDDS,

    /// Represents a nfstream inspired flow, giving 71 features.
    Nfstream,

    /// Represents the Rusti Flow, giving 203 features.
    Rustiflow,

    /// Represents a flow that you can implement yourself.
    Custom,
}

impl FlowType {
    /// Every flow type, in the order the config TUI lists them.
    pub const ALL: [FlowType; 6] = [
        FlowType::Basic,
        FlowType::CIC,
        FlowType::CIDDS,
        FlowType::Nfstream,
        FlowType::Rustiflow,
        FlowType::Custom,
    ];

    /// The name accepted by `--features`, as clap's `ValueEnum` derives it.
    pub const fn name(self) -> &'static str {
        match self {
            FlowType::Basic => "basic",
            FlowType::CIC => "cic",
            FlowType::CIDDS => "cidds",
            FlowType::Nfstream => "nfstream",
            FlowType::Rustiflow => "rustiflow",
            FlowType::Custom => "custom",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigFile {
    pub config: ExportConfig,
    pub output: OutputConfig,
}

impl Default for ConfigFile {
    fn default() -> Self {
        ConfigFile {
            config: ExportConfig {
                features: FlowType::Basic,
                active_timeout: 3600,
                idle_timeout: 120,
                expiration_check_interval: 60,
                early_export: None,
                threads: None,
            },
            output: OutputConfig {
                output: ExportMethodType::Print,
                export_path: None,
                header: false,
                drop_contaminant_features: false,
                packet_graph: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FlowType;
    use clap::ValueEnum;

    #[test]
    fn flow_type_names_match_the_cli() {
        let cli_names: Vec<String> = FlowType::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|value| value.get_name().to_owned())
            .collect();
        let tui_names: Vec<String> = FlowType::ALL
            .into_iter()
            .map(|flow_type| flow_type.name().to_owned())
            .collect();

        assert_eq!(tui_names, cli_names);
    }
}
