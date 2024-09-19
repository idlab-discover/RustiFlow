mod args;
mod flow_table;
mod flows;
mod output;
mod pcap;
mod realtime;
mod packet_features;

use crate::pcap::read_pcap_file;
use crate::realtime::handle_realtime;
use crate::flows::{cic_flow::CicFlow, ntl_flow::NTLFlow};

use args::{Cli, Commands, FlowType};
use clap::Parser;
use core::panic;
use flows::{
    basic_flow::BasicFlow, cidds_flow::CiddsFlow, custom_flow::CustomFlow, flow::Flow,
    nf_flow::NfFlow,
};
use log::{debug, error};
use output::OutputWriter;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    // Argument validation
    if let Some(early_export) = cli.config.early_export {
        if early_export >= cli.config.active_timeout {
            panic!("The early export timeout needs to be smaller than the active timeout!");
        }
    }

    // Start the selected command
    match cli.command {
        Commands::Realtime { interface } => {
            macro_rules! execute_realtime {
                ($flow_ty:ty) => {{
                    // Create output writer and channel for exporting flows
                    let (sender, receiver) = mpsc::channel::<$flow_ty>(1000);
                    let output_writer = OutputWriter::new(
                        cli.output.output,
                        cli.output.header,
                        cli.output.drop_contaminant_features,
                        receiver,
                        cli.output.export_path,
                    );

                    // Start the output writer in separate task
                    let _output_writer_task = tokio::spawn(output_writer.run());
                    if let Err(err) = handle_realtime::<$flow_ty>(
                        &interface,
                        sender, 
                        cli.config.threads.unwrap_or(num_cpus::get() as u8), 
                        cli.config.active_timeout,
                        cli.config.idle_timeout,
                        cli.config.early_export
                    ).await {
                        error!("Error: {:?}", err);
                    }
                }};
            }

            match cli.config.features {
                FlowType::Basic => execute_realtime!(BasicFlow),
                FlowType::CIC => execute_realtime!(CicFlow),
                FlowType::CIDDS => execute_realtime!(CiddsFlow),
                FlowType::Nfstream => execute_realtime!(NfFlow),
                FlowType::NTL => execute_realtime!(NTLFlow),
                FlowType::Custom => execute_realtime!(CustomFlow),
            }
        }
        Commands::Pcap { path } => {
            macro_rules! execute_offline {
                ($flow_ty:ty) => {{
                    // Create output writer and channel for exporting flows
                    let (sender, receiver) = mpsc::channel::<$flow_ty>(1000);
                    let output_writer = OutputWriter::new(
                        cli.output.output,
                        cli.output.header,
                        cli.output.drop_contaminant_features,
                        receiver,
                        cli.output.export_path,
                    );

                    // Start the output writer in separate task
                    let _output_writer_task = tokio::spawn(output_writer.run());
                    if let Err(err) = read_pcap_file::<$flow_ty>(
                        &path, 
                        sender,
                        cli.config.threads.unwrap_or(num_cpus::get() as u8), 
                        cli.config.active_timeout,
                        cli.config.idle_timeout,
                        cli.config.early_export
                     ).await {
                        error!("Error: {:?}", err);
                    }
                }};
            }

            match cli.config.features {
                FlowType::Basic => execute_offline!(BasicFlow),
                FlowType::CIC => execute_offline!(CicFlow),
                FlowType::CIDDS => execute_offline!(CiddsFlow),
                FlowType::Nfstream => execute_offline!(NfFlow),
                FlowType::NTL => execute_offline!(NTLFlow),
                FlowType::Custom => execute_offline!(CustomFlow),
            }
        }
    }
}
