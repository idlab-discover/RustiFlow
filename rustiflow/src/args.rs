use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    /// Configuration options common to both real-time and pcap modes
    #[clap(flatten)]
    pub config: ExportConfig,

    /// Output method
    #[clap(flatten)]
    pub output: OutputConfig,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Real-time feature extraction
    Realtime {
        /// The network interface to capture packets from
        interface: String,
    },

    /// Feature extraction from a pcap file
    Pcap {
        /// The relative path to the pcap file
        path: String,
    },
}

#[derive(Args, Debug, Clone)]
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

    /// The numbers of threads to use for processing packets
    /// (default: number of logical CPUs)
    #[clap(short, long)]
    pub threads: Option<u8>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputConfig {
    /// Output method
    #[clap(short, long, value_enum)]
    pub output: ExportMethodType,

    /// File path for output (used if method is Csv)
    #[clap(required_if_eq("output", "csv"))]
    pub export_path: Option<String>,

    /// Whether to export the feature header
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub header: bool,

    /// Whether to drop contaminant features
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub drop_contaminant_features: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ExportMethodType {
    /// The output will be printed to the console
    Print,

    /// The output will be written to a CSV file
    Csv,
}

#[derive(clap::ValueEnum, Clone, Debug)]
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
