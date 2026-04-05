mod args;
mod export_profile;
mod flow_key;
mod flow_table;
#[cfg(target_os = "linux")]
mod flow_tui;
mod flows;
mod output;
#[cfg(target_os = "linux")]
mod packet_counts;
mod packet_features;
mod pcap;
#[cfg(target_os = "linux")]
mod profiling;
#[cfg(not(target_os = "linux"))]
#[path = "profiling_stub.rs"]
mod profiling;
#[cfg(target_os = "linux")]
mod realtime;
#[cfg(not(target_os = "linux"))]
#[path = "realtime_stub.rs"]
mod realtime;
mod realtime_mode;
mod tests;
mod tui;

use crate::flows::{cic_flow::CicFlow, rusti_flow::RustiFlow};
use crate::pcap::read_pcap_file;
use crate::realtime::handle_realtime;
use args::{Cli, Commands, ConfigFile, ExportConfig, FlowType, OutputConfig};
use clap::Parser;
use flows::{
    basic_flow::BasicFlow, cidds_flow::CiddsFlow, custom_flow::CustomFlow, flow::Flow,
    nf_flow::NfFlow,
};
use log::{debug, error, info};
use output::OutputWriter;
use profiling::ProfilingSession;
use realtime_mode::packet_graph_mode;
use std::time::Instant;
use tokio::sync::mpsc;
use tui::{launch_tui, Config};

const DEFAULT_OFFLINE_THREADS: u8 = 5;
const DEFAULT_REALTIME_THREADS: u8 = 12;

#[tokio::main]
async fn main() {
    env_logger::init();

    if std::env::args().len() == 1 {
        // No arguments provided, launch TUI
        let config = launch_tui().await.unwrap_or_else(|e| {
            error!("Error: {:?}", e);
            std::process::exit(1);
        });

        if let Some(config) = config {
            run_with_config(config).await;
        } else {
            error!("No configuration provided.");
            std::process::exit(1);
        }
    } else {
        let cli = Cli::parse();

        // If a config file is provided, load it
        let config: Config = if let Some(config_path) = cli.config_file {
            // Try to load config from file
            match confy::load_path::<ConfigFile>(config_path) {
                Ok(cfg_file) => Config {
                    config: cfg_file.config,
                    output: cfg_file.output,
                    command: cli.command,
                },
                Err(e) => {
                    error!("Error loading configuration file: {:?}", e);
                    return;
                }
            }
        } else {
            // No config file: build config from CLI arguments
            Config {
                config: ExportConfig {
                    features: cli.features.unwrap(),
                    active_timeout: cli.active_timeout,
                    idle_timeout: cli.idle_timeout,
                    early_export: cli.early_export,
                    threads: cli.threads,
                    expiration_check_interval: cli.expiration_check_interval,
                },
                output: OutputConfig {
                    output: cli.output.unwrap(),
                    export_path: cli.export_path,
                    header: cli.header,
                    drop_contaminant_features: cli.drop_contaminant_features,
                    packet_graph: cli.packet_graph,
                },
                command: cli.command,
            }
        };

        run_with_config(config).await;
    }
}

async fn run_with_config(config: Config) {
    // Start the selected command
    match config.command {
        Commands::Realtime {
            interface,
            ingress_only,
        } => {
            macro_rules! execute_realtime {
                ($flow_ty:ty) => {{
                    // Create output writer and initialize it
                    let packet_graph_mode = packet_graph_mode(&config.output);

                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output,
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path,
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

                    debug!("Starting realtime processing...");
                    let start = Instant::now();
                    let profiling_session = match ProfilingSession::start_from_env("realtime") {
                        Ok(session) => session,
                        Err(err) => {
                            error!("Error starting profiler: {:?}", err);
                            None
                        }
                    };
                    let result = handle_realtime::<$flow_ty>(
                        &interface,
                        sender,
                        resolve_realtime_threads(config.config.threads),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                        ingress_only,
                        packet_graph_mode,
                    )
                    .await;

                    // Wait for the output task to finish (flush and close the writer)
                    if let Err(e) = output_task.await {
                        error!("Error waiting for output task: {:?}", e);
                    }

                    if let Some(profiling_session) = profiling_session {
                        if let Err(err) = profiling_session.finish() {
                            error!("Error finishing profiler: {:?}", err);
                        }
                    }

                    export_profile::log_summary("realtime");

                    let end = Instant::now();
                    info!(
                        "Duration: {:.4} seconds",
                        end.duration_since(start).as_secs_f64()
                    );

                    // Now process the result and print the dropped packets
                    match result {
                        Ok(dropped_packets) => {
                            // If successful, log dropped packets count after writer is flushed
                            info!("Total dropped packets: {}", dropped_packets);
                        }
                        Err(err) => {
                            // Handle errors and log them
                            error!("Error during realtime processing: {:?}", err);
                        }
                    }
                }};
            }

            match config.config.features {
                FlowType::Basic => execute_realtime!(BasicFlow),
                FlowType::CIC => execute_realtime!(CicFlow),
                FlowType::CIDDS => execute_realtime!(CiddsFlow),
                FlowType::Nfstream => execute_realtime!(NfFlow),
                FlowType::Rustiflow => execute_realtime!(RustiFlow),
                FlowType::Custom => execute_realtime!(CustomFlow),
            }
        }
        Commands::Pcap { path } => {
            macro_rules! execute_offline {
                ($flow_ty:ty) => {{
                    // Create output writer and initialize it
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output,
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path,
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
                    let profiling_session = match ProfilingSession::start_from_env("offline") {
                        Ok(session) => session,
                        Err(err) => {
                            error!("Error starting profiler: {:?}", err);
                            None
                        }
                    };

                    if let Err(err) = read_pcap_file::<$flow_ty>(
                        &path,
                        sender,
                        resolve_offline_threads(config.config.threads),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }

                    // Wait for the output task to finish
                    output_task.await.unwrap_or_else(|e| {
                        error!("Error waiting for output task: {:?}", e);
                    });

                    export_profile::log_summary("offline");

                    if let Some(profiling_session) = profiling_session {
                        if let Err(err) = profiling_session.finish() {
                            error!("Error finishing profiler: {:?}", err);
                        }
                    }

                    let end = Instant::now();
                    debug!(
                        "Duration: {:?} milliseconds",
                        end.duration_since(start).as_millis()
                    );
                }};
            }

            match config.config.features {
                FlowType::Basic => execute_offline!(BasicFlow),
                FlowType::CIC => execute_offline!(CicFlow),
                FlowType::CIDDS => execute_offline!(CiddsFlow),
                FlowType::Nfstream => execute_offline!(NfFlow),
                FlowType::Rustiflow => execute_offline!(RustiFlow),
                FlowType::Custom => execute_offline!(CustomFlow),
            }
        }
    }
}

fn resolve_realtime_threads(config_threads: Option<u8>) -> u8 {
    let logical_cpus = num_cpus::get() as u8;
    std::cmp::min(
        config_threads.unwrap_or(DEFAULT_REALTIME_THREADS),
        logical_cpus,
    )
}

fn resolve_offline_threads(config_threads: Option<u8>) -> u8 {
    let logical_cpus = num_cpus::get() as u8;
    std::cmp::min(
        config_threads.unwrap_or(DEFAULT_OFFLINE_THREADS),
        logical_cpus,
    )
}
