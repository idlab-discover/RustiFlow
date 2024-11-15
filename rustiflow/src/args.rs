use clap::{ArgGroup, Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumString, VariantNames};

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

    /// The print interval for open flows in seconds (optional)
    #[clap(long, group = "cli_group")]
    pub early_export: Option<u64>,

    /// Interval (in seconds) for checking and expiring flows in the flowtable.
    /// This represents how often the flowtable should be scanned to remove inactive flows.
    #[clap(long, default_value_t = 60, group = "cli_group")]
    pub expiration_check_interval: u64,

    /// The numbers of threads to use for processing packets (optional)
    /// (default: number of logical CPUs)
    #[clap(long, group = "cli_group")]
    pub threads: Option<u8>,

    /// Output method (required if no config file is provided)
    #[clap(long, short, group = "cli_group")]
    pub output: Option<ExportMethodType>,

    /// File path for output (used if method is Csv)
    #[clap(long, group = "cli_group", required_if_eq("output", "Csv"))]
    pub export_path: Option<String>,

    /// Disable the graph in TUI when exporting in CSV mode
    #[clap(long, group = "cli_group", action = clap::ArgAction::SetTrue, required_if_eq("output", "Csv"))]
    pub performance_mode: bool,

    /// Whether to export the feature header
    #[clap(long, action = clap::ArgAction::SetTrue, group = "cli_group")]
    pub header: bool,

    /// Whether to drop contaminant features
    #[clap(long, action = clap::ArgAction::SetTrue, group = "cli_group")]
    pub drop_contaminant_features: bool,

    /// Subcommands (Real-time or Pcap)
    #[clap(subcommand)]
    pub command: Commands,
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

impl ToString for Commands {
    fn to_string(&self) -> String {
        match self {
            Commands::Realtime {
                interface,
                ingress_only,
            } => format!(
                "Realtime/Interface: {}/Ingress only: {}",
                interface, ingress_only
            ),
            Commands::Pcap { path } => format!("Pcap/Path: {}", path),
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

    /// The print interval for open flows in seconds, needs to be smaller than the flow maximum lifespan
    #[clap(long)]
    pub early_export: Option<u64>,

    /// Interval (in seconds) for checking and expiring flows in the flowtable.
    /// This represents how often the flowtable should be scanned to remove inactive flows.
    #[clap(long, default_value_t = 60, group = "cli_group")]
    pub expiration_check_interval: u64,

    /// The numbers of threads to use for processing packets
    /// (default: number of logical CPUs)
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

    /// Disable the graph in TUI when exporting in CSV mode
    #[clap(long, action = clap::ArgAction::SetTrue, required_if_eq("output", "Csv"))]
    pub performance_mode: bool,

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

#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Debug, EnumString, VariantNames)]
#[strum(serialize_all = "kebab_case")]
pub enum FlowType {
    /// A basic flow that stores the basic features of a flow.
    Basic,

    /// Represents the CIC Flow, giving 83 features.
    CIC,

    /// Represents the CIDDS Flow, giving 10 features.
    CIDDS,

    /// Represents a nfstream inspired flow, giving 69 features.
    Nfstream,

    /// Represents the NTL Flow, giving 120 features.
    NTL,

    /// Represents a flow that you can implement yourself.
    Custom,
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
                performance_mode: false,
            },
        }
    }
}
