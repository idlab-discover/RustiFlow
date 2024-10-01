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
use std::time::Instant;

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
                    // Create output writer and initialize it
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        cli.output.output,
                        cli.output.header,
                        cli.output.drop_contaminant_features,
                        cli.output.export_path,
                    );

                    // Synchronous initialization to ensure headers are written
                    output_writer.init(); 

                    // Create channel for exporting flows
                    let (sender, mut receiver) = mpsc::channel::<$flow_ty>(1000);

                    // Start the output writer in a separate task
                    let output_task = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow: {:?}", e);
                            }
                        }

                        // Ensure that all remaining flows are flushed properly before ending
                        output_writer.flush_and_close().unwrap_or_else(|e| {
                            error!("Error flushing and closing the writer: {:?}", e);
                        });
                        debug!("OutputWriter task finished");
                    });
                    
                    
                    let start = Instant::now();
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

                    // Wait for the output task to finish
                    output_task.await.unwrap_or_else(|e| {
                        error!("Error waiting for output task: {:?}", e);
                    });

                    let end = Instant::now();
                    debug!(
                        "Duration: {:?} milliseconds",
                        end.duration_since(start).as_millis()
                    );
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
                    // Create output writer and initialize it
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        cli.output.output,
                        cli.output.header,
                        cli.output.drop_contaminant_features,
                        cli.output.export_path,
                    );

                    // Synchronous initialization to ensure headers are written
                    output_writer.init();

                    // Create channel for exporting flows
                    let (sender, mut receiver) = mpsc::channel::<$flow_ty>(1000);

                    // Start the output writer in a separate task
                    let output_task = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow: {:?}", e);
                            }
                        }

                        // Ensure that all remaining flows are flushed properly before ending
                        output_writer.flush_and_close().unwrap_or_else(|e| {
                            error!("Error flushing and closing the writer: {:?}", e);
                        });
                        debug!("OutputWriter task finished");
                    });

                    let start = Instant::now();

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

                    // Wait for the output task to finish
                    output_task.await.unwrap_or_else(|e| {
                        error!("Error waiting for output task: {:?}", e);
                    });

                    let end = Instant::now();
                    debug!(
                        "Duration: {:?} milliseconds",
                        end.duration_since(start).as_millis()
                    );
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
