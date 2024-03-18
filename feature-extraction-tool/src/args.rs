use clap::{Parser, Subcommand};

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
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum FlowType {
    /// A basic flow that stores the basic features of a flow.
    BasicFlow,
    /// Represents the CIC Flow, giving 83 features.
    CicFlow,
    /// Represents the CIDDS Flow, giving 10 features.
    CiddsFlow,
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
