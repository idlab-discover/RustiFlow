mod args;
mod flow_table;
mod flow_tui;
mod flows;
mod output;
mod packet_counts;
mod packet_features;
mod pcap;
mod realtime;
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
use std::time::Instant;
use tokio::sync::mpsc;
use tui::{launch_tui, Config};
use crate::tui::{launch_tui, Config as TuiConfig, AppTransition, BatchProcessingState, BatchProgress}; // Import new TUI types
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command as TokioCommand; // For async command execution
use tokio::sync::Mutex; // For shared progress
use std::sync::Arc; // For shared progress
use rayon::prelude::*; // For parallel iteration
use std::time::Duration;


// Function to find pcap files, similar to the one in rustiflow_batch.rs
// but adapted for library use.
fn find_pcap_files_for_batch(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, String> {
    let mut pcap_files = Vec::new();
    let mut dirs_to_visit = vec![dir.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match fs::read_dir(current_dir) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => {
                            let path = e.path();
                            if path.is_file() {
                                if let Some(extension) = path.extension() {
                                    let ext = extension.to_string_lossy().to_lowercase();
                                    if ext == "pcap" || ext == "pcapng" {
                                        pcap_files.push(path);
                                    }
                                }
                            } else if path.is_dir() && recursive {
                                dirs_to_visit.push(path);
                            }
                        }
                        Err(e) => return Err(format!("Failed to read directory entry: {}", e)),
                    }
                }
            }
            Err(e) => return Err(format!("Failed to read directory {}: {}", dir.display(), e)),
        }
    }
    pcap_files.sort();
    Ok(pcap_files)
}


// The core processing logic for a single PCAP file, adapted for async execution
async fn process_single_pcap_for_batch(
    pcap_file: PathBuf,
    output_dir: PathBuf,
    feature_set: FlowType,
    active_timeout: u64,
    idle_timeout: u64,
    // TODO: Add threads for rustiflow call if configurable
) -> Result<String, String> {
    let filename_stem = pcap_file.file_stem()
        .ok_or_else(|| format!("Invalid filename: {}", pcap_file.display()))?
        .to_string_lossy();

    let output_file = output_dir.join(format!("{}.csv", filename_stem));

    let rustiflow_executable = env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {}", e))?
        .parent()
        .map(|p| p.join("rustiflow")) // Assumes rustiflow is sibling to the TUI app
        .unwrap_or_else(|| PathBuf::from("rustiflow")); // Fallback to PATH

    log::debug!("Executing: {} pcap {} --features {} --output csv --export-path {} --header --active-timeout {} --idle-timeout {}",
        rustiflow_executable.display(),
        pcap_file.display(),
        feature_set.to_string(), // Assuming FlowType has ToString or use format!
        output_file.display(),
        active_timeout,
        idle_timeout);

    let mut cmd = TokioCommand::new(rustiflow_executable);
    cmd.arg("pcap")
        .arg(pcap_file.clone()) // Pass path for pcap command
        .arg("--features")
        .arg(feature_set.to_string().to_lowercase()) // Ensure lowercase if cli expects that
        .arg("--output")
        .arg("csv")
        .arg("--export-path")
        .arg(&output_file)
        .arg("--header")
        .arg("--active-timeout")
        .arg(active_timeout.to_string())
        .arg("--idle-timeout")
        .arg(idle_timeout.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // If you need to pass thread count to rustiflow process based on batch_state.worker_count:
    // cmd.arg("--threads").arg(batch_state.worker_count.to_string());


    let process_output = cmd.output().await
        .map_err(|e| format!("Failed to execute RustiFlow for {}: {}", pcap_file.display(), e))?;

    if !process_output.status.success() {
        let stderr = String::from_utf8_lossy(&process_output.stderr);
        let stdout = String::from_utf8_lossy(&process_output.stdout);
        Err(format!("RustiFlow failed for {}:\nStderr: {}\nStdout: {}", pcap_file.display(), stderr, stdout))
    } else {
        Ok(pcap_file.file_name().unwrap_or_default().to_string_lossy().into_owned())
    }
}


// Main batch execution function called from TUI
async fn run_batch_processing_from_tui(batch_state: BatchProcessingState, progress_updater: Arc<Mutex<BatchProgress>>) {
    let pcap_files = match find_pcap_files_for_batch(
        Path::new(&batch_state.input_directory),
        batch_state.recursive,
    ) {
        Ok(files) => files,
        Err(e) => {
            error!("Error finding PCAP files: {}", e);
            let mut progress = progress_updater.lock().await;
            progress.current_file = format!("Error: {}", e);
            return;
        }
    };

    if pcap_files.is_empty() {
        info!("No PCAP files found in the specified directory.");
         let mut progress = progress_updater.lock().await;
         progress.current_file = "No PCAP files found.".to_string();
         progress.total_files = 0;
         progress.processed_files = 0;
        return;
    }

    {
        let mut progress = progress_updater.lock().await;
        progress.total_files = pcap_files.len();
        progress.processed_files = 0;
        progress.success_count = 0;
        progress.error_count = 0;
    }

    let output_dir = PathBuf::from(batch_state.output_directory.clone());
    if !output_dir.exists() {
        if let Err(e) = fs::create_dir_all(&output_dir) {
            error!("Failed to create output directory {}: {}", output_dir.display(), e);
             let mut progress = progress_updater.lock().await;
             progress.current_file = format!("Error creating output dir: {}", e);
            return;
        }
    }

    // Create a Rayon thread pool with the specified number of workers
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(batch_state.worker_count)
        .build()
        .unwrap();

    let (tx, mut rx) = mpsc::channel::<(String, Result<String, String>)>(pcap_files.len());

    pool.install(|| {
        pcap_files.into_par_iter().for_each_with(tx, |tx_clone, pcap_file| {
            let file_name_for_progress = pcap_file.file_name().unwrap_or_default().to_string_lossy().into_owned();

            // Update progress: current file being processed (might need a per-thread update mechanism or batch update)
            // For simplicity, we'll update total progress after each file.

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let result = rt.block_on(process_single_pcap_for_batch(
                pcap_file.clone(), // process_single_pcap_for_batch now takes owned PathBuf
                output_dir.clone(),
                batch_state.feature_set.clone(), // Assuming FlowType is Clone
                batch_state.active_timeout,
                batch_state.idle_timeout,
            ));
            if let Err(e) = tx_clone.blocking_send((file_name_for_progress, result)) {
                 error!("Failed to send progress update: {}", e);
            }
        });
    });


    // Collect results and update progress
    for _ in 0..progress_updater.lock().await.total_files {
        if let Some((file_name, result)) = rx.recv().await {
             let mut progress = progress_updater.lock().await;
             progress.processed_files += 1;
             progress.current_file = file_name.clone();

            match result {
                Ok(processed_file_name) => {
                    info!("Successfully processed: {}", processed_file_name);
                    progress.success_count += 1;
                }
                Err(e) => {
                    error!("Failed to process {}: {}", file_name, e);
                    progress.error_count += 1;
                }
            }
            // Add estimated time remaining logic here if desired
             let remaining_files = progress.total_files - progress.processed_files;
             // Dummy estimation
             progress.estimated_remaining = format!("{}s (dummy)", remaining_files * 2);
        }
         tokio::time::sleep(Duration::from_millis(10)).await; // Allow UI to refresh
    }

    let mut progress = progress_updater.lock().await;
    progress.current_file = "Batch processing finished.".to_string();
    info!("Batch processing finished. Success: {}, Errors: {}", progress.success_count, progress.error_count);
}



// run_with_config needs to be aware of the BatchPcap command if it's meant to be
// runnable directly from CLI, though the TUI seems the primary interface for it.
async fn run_with_config(config: crate::args::Config) { // Changed to use crate::args::Config
    match config.command {
        Commands::Realtime { /* ... */ } => { /* ... existing realtime ... */ }
        Commands::Pcap { /* ... */ } => { /* ... existing pcap ... */ }
        Commands::BatchPcap => {
            // This would typically not be run directly from config if TUI handles it.
            // If it *can* be run from CLI (e.g. `rustiflow batch-pcap --input /d --output /o ...` if args were added)
            // then the batch_state would be constructed from CLI args here.
            // For now, this means it was likely a TUI call that didn't transition correctly.
            info!("BatchPcap command reached run_with_config. This is for CLI execution or misfired TUI state.");
            info!("If TUI initiated, batch processing should happen within the TUI's async context.");

             // Example: If CLI could trigger batch (requires adding args to Commands::BatchPcap)
            // let batch_state_from_cli = BatchProcessingState {
            // input_directory: "/default/input".to_string(), // from CLI arg
            // output_directory: "/default/output".to_string(), // from CLI arg
            // feature_set: config.config.features, // from general config
            // worker_count: config.config.threads.unwrap_or_else(num_cpus::get) as usize,
            // recursive: false, // from CLI arg
            // active_timeout: config.config.active_timeout,
            // idle_timeout: config.config.idle_timeout,
            // current_field: Default::default(),
            // processing: true, // Start immediately
            // progress: Some(Default::default()),
            // };
            // let progress_arc = Arc::new(Mutex::new(BatchProgress::default()));
            // run_batch_processing_from_tui(batch_state_from_cli, progress_arc).await;

        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    if std::env::args().len() == 1 {
        // No arguments provided, launch TUI
        // The launch_tui function itself would need to be adapted to handle
        // the AppTransition::StartBatchProcessing by calling run_batch_processing_from_tui.
        // This part requires deeper changes in launch_tui's loop.

        // Simplified: if launch_tui returns a special Config or signal for batch:
        match launch_tui().await {
            Ok(Some(tui_config_val)) => { // Assuming Config from tui.rs
                // Check if it's a batch command initiated from TUI
                if let Commands::BatchPcap = tui_config_val.command {
                     // This path might not be hit if TUI handles batch internally.
                     // Or, BatchPcap could be a marker to re-enter TUI in batch mode.
                     // For now, assume TUI handles batch internally as per AppTransition::StartBatchProcessing.
                    println!("BatchPcap command selected via TUI, but run_with_config handles CLI commands.");
                    println!("Integration point for batch is within launch_tui's event loop via AppTransition.");

                } else {
                     run_with_config(TuiConfig { // Map to the main Config struct if different
                        config: tui_config_val.config,
                        output: tui_config_val.output,
                        command: tui_config_val.command,
                     }).await;
                }
            }
            Ok(None) => { /* TUI exited without selecting a command */ }
            Err(e) => {
                error!("Error launching TUI: {:?}", e);
                std::process::exit(1);
            }
        }

    } else {
        let cli = Cli::parse();
        // ... (existing CLI config loading) ...
        let config_to_run: crate::args::Config = if let Some(config_path) = cli.config_file {
            match confy::load_path::<ConfigFile>(config_path) {
                Ok(cfg_file) => crate::args::Config {
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
             // This part needs to ensure that if `BatchPcap` is somehow passed via CLI without
             // a config file, it's handled (e.g. by erroring or launching TUI in batch mode)
             // However, BatchPcap is primarily for TUI internal navigation.
            if let Commands::BatchPcap = cli.command {
                println!("BatchPcap command is intended for TUI use. Launching TUI for batch setup.");
                if launch_tui().await.is_err() { // Simplified call
                    error!("Failed to launch TUI for batch setup.");
                }
                return;
            }

            crate::args::Config {
                config: ExportConfig {
                    features: cli.features.unwrap_or_else(|| {
                        error!("--features is required when not using a config file.");
                        std::process::exit(1);
                    }),
                    active_timeout: cli.active_timeout,
                    idle_timeout: cli.idle_timeout,
                    early_export: cli.early_export,
                    threads: cli.threads,
                    expiration_check_interval: cli.expiration_check_interval,
                },
                output: OutputConfig {
                    output: cli.output.unwrap_or_else(|| {
                        error!("--output is required when not using a config file.");
                        std::process::exit(1);
                    }),
                    export_path: cli.export_path,
                    header: cli.header,
                    drop_contaminant_features: cli.drop_contaminant_features,
                    performance_mode: cli.performance_mode,
                },
                command: cli.command,
            }
        };
        run_with_config(config_to_run).await;
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
                    let performance_mode_disabled = config.output.export_path.is_some() && !matches!(std::env::var("RUST_LOG"), Ok(ref val) if val.contains("debug")) && !config.output.performance_mode;

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
                    let result = handle_realtime::<$flow_ty>(
                        &interface,
                        sender,
                        std::cmp::min(config.config.threads.unwrap_or(5), num_cpus::get() as u8),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                        ingress_only,
                        performance_mode_disabled,
                    )
                    .await;

                    // Wait for the output task to finish (flush and close the writer)
                    if let Err(e) = output_task.await {
                        error!("Error waiting for output task: {:?}", e);
                    }

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

                    if let Err(err) = read_pcap_file::<$flow_ty>(
                        &path,
                        sender,
                        std::cmp::min(config.config.threads.unwrap_or(5), num_cpus::get() as u8),
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
