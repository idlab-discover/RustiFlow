use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Real-time feature extraction
    Realtime {
        /// The network interface to capture packets from
        interface: String,

        #[clap(value_enum)]
        flow_type: FlowType,

        /// The maximum lifespan of a flow in seconds
        lifespan: u64,

        /// Whether not to include contaminant features
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        no_contaminant_features: bool,

        /// Output method
        #[clap(flatten)]
        export_method: Output,

        /// The print interval for open flows in seconds, needs to be smaller than the flow maximum lifespan
        interval: Option<u64>,
    },

    /// Feature extraction from a dataset
    Dataset {
        #[clap(value_enum)]
        dataset: Dataset,

        /// The relative path to the dataset
        path: String,
    },

    /// Feature extraction from a pcap file
    Pcap {
        #[clap(value_enum)]
        machine_type: GeneratedMachineType,

        #[clap(value_enum)]
        flow_type: FlowType,

        /// The relative path to the pcap file
        path: String,

        /// Whether not to include contaminant features
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        no_contaminant_features: bool,

        /// Output method
        #[clap(flatten)]
        export_method: Output,
    },
}

#[derive(Args, Debug, Clone)]
pub struct Output {
    /// Output method
    #[clap(value_enum)]
    pub method: ExportMethodType,

    /// File path for output (used if method is File)
    #[clap(required_if_eq("method", "Csv"))]
    pub export_path: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ExportMethodType {
    /// The output will be printed to the console
    Print,

    /// The output will be written to a CSV file
    Csv,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum GeneratedMachineType {
    /// The pcap file was generated on a Windows machine
    Windows,

    /// The pcap file was generated on a Linux machine
    Linux,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum FlowType {
    /// A basic flow that stores the basic features of a flow.
    BasicFlow,

    /// Represents the CIC Flow, giving 83 features.
    CicFlow,

    /// Represents the CIDDS Flow, giving 10 features.
    CiddsFlow,

    /// Represents a nfstream inspired flow, giving 69 features.
    NfFlow,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Dataset {
    /// CIC-IDS2017 from the Canadian Institute for Cybersecurity
    CicIds2017,

    /// CSE-CIC-IDS2018 from the Canadian Institute for Cybersecurity
    CseCicIds2018,

    /// CIC-DDoS2019 from the Canadian Institute for Cybersecurity
    CicDdos2019,

    /// CIC-IDS-Collection from Laurens D'Hooge
    CicIdsCollection,

    /// CTU-13 from CTU university of the Czech Republic
    Ctu13,

    /// CTU-13 without contaminant features from Laurens D'Hooge
    Ctu13Ld,

    /// UNSW-NB15 from UNSW Sydney
    UnswNb15,

    /// UNSW-NB15 without contaminant features from Laurens D'Hooge
    UnswNb15Ld,
}
