// Module declarations
mod args;
mod flow_table;
mod flow_tui; // For the simple packet graph TUI, distinct from the main control TUI
mod flows;
mod output;
mod packet_counts;
mod packet_features;
mod pcap;
mod realtime;
mod tests;
mod tui; // This is our main application TUI module (tui.rs)

// Standard library imports
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::Serialize; // For the GlobalStats struct
use std::fs::File as StdFile; // To avoid conflict with polars::io::File, if any
use std::io::BufWriter as StdBufWriter; // If writing JSON buffered
use std::path::PathBuf as StdPathBuf; // Explicit for path manipulation


// Crate imports
use clap::Parser;
use log::{debug, error, info, warn};
use rayon::prelude::*;
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc as tokio_mpsc; // Aliased to avoid confusion
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// Local crate imports
use crate::args::{Cli, Commands, ConfigFile, ExportConfig, FlowType, OutputConfig};
use crate::flows::{
    basic_flow::BasicFlow, cic_flow::CicFlow, cidds_flow::CiddsFlow, custom_flow::CustomFlow,
    flow::Flow, nf_flow::NfFlow, rusti_flow::RustiFlow,
};
use crate::output::OutputWriter;
use crate::pcap::read_pcap_file;
use crate::realtime::handle_realtime;
// Use the TUI components from our tui.rs module
use crate::tui::{
    launch_tui, BatchProcessingState, BatchProgress, Config as TuiConfig, // TuiConfig is crate::tui::Config
};

/// Finds PCAP files in a given directory, optionally searching recursively.
fn find_pcap_files_for_batch(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, String> {
    let mut pcap_files = Vec::new();
    let mut dirs_to_visit = vec![dir.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match fs::read_dir(&current_dir) {
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
                        Err(e) => {
                            return Err(format!(
                                "Failed to read directory entry in {}: {}",
                                current_dir.display(),
                                e
                            ))
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read directory {}: {}",
                    current_dir.display(),
                    e
                ))
            }
        }
    }
    pcap_files.sort(); // Ensure consistent processing order
    Ok(pcap_files)
}

/// Processes a single PCAP file as part of a batch operation.
/// This involves calling the main `rustiflow` executable as a subprocess.
async fn process_single_pcap_for_batch(
    pcap_file: PathBuf,
    output_dir: PathBuf,
    feature_set: FlowType, // Assuming FlowType is Cloneable
    active_timeout: u64,
    idle_timeout: u64,
    worker_threads_for_rustiflow_subprocess: u8, // Threads for the rustiflow sub-process
) -> Result<String, String> {
    let filename_stem = pcap_file
        .file_stem()
        .ok_or_else(|| format!("Invalid filename: {}", pcap_file.display()))?
        .to_string_lossy();

    let output_file = output_dir.join(format!("{}.csv", filename_stem));

    let rustiflow_executable = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|pd| pd.join("rustiflow")))
        .unwrap_or_else(|| PathBuf::from("rustiflow")); // Fallback to PATH

    log::debug!(
        "Batch Subprocess: {} pcap {} --features {} --output csv --export-path {} --header --active-timeout {} --idle-timeout {} --threads {}",
        rustiflow_executable.display(),
        pcap_file.display(),
        feature_set.to_string().to_lowercase(),
        output_file.display(),
        active_timeout,
        idle_timeout,
        worker_threads_for_rustiflow_subprocess
    );

    let mut cmd = TokioCommand::new(&rustiflow_executable);
    cmd.arg("pcap")
        .arg(&pcap_file) // Path to the pcap file for the 'pcap' subcommand
        .arg("--features")
        .arg(feature_set.to_string().to_lowercase())
        .arg("--output")
        .arg("csv")
        .arg("--export-path")
        .arg(&output_file)
        .arg("--header") // Always include header for batch CSVs
        .arg("--active-timeout")
        .arg(active_timeout.to_string())
        .arg("--idle-timeout")
        .arg(idle_timeout.to_string())
        .arg("--threads") // Pass thread count to the rustiflow subprocess
        .arg(worker_threads_for_rustiflow_subprocess.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let process_output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to execute RustiFlow for {}: {}", pcap_file.display(), e))?;

    if !process_output.status.success() {
        let stderr = String::from_utf8_lossy(&process_output.stderr);
        let stdout = String::from_utf8_lossy(&process_output.stdout);
        Err(format!(
            "RustiFlow subprocess for {} failed with code {:?}:\nStderr: {}\nStdout: {}",
            pcap_file.display(),
            process_output.status.code(),
            stderr,
            stdout
        ))
    } else {
        Ok(pcap_file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned())
    }
}

/// Spawns the main batch processing task.
/// This function matches the signature expected by `launch_tui`.
fn batch_processor_task_spawner(
    batch_state: BatchProcessingState, // Contains all settings from TUI
    progress_sender: tokio_mpsc::Sender<BatchProgress>, // Channel to send progress updates to TUI
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pcap_files = match find_pcap_files_for_batch(
            Path::new(&batch_state.input_directory),
            batch_state.recursive,
        ) {
            Ok(files) => files,
            Err(e) => {
                error!("Error finding PCAP files: {}", e);
                let mut initial_progress = BatchProgress::default();
                initial_progress.last_error_message = Some(format!("Error finding PCAP files: {}", e));
                if progress_sender.send(initial_progress).await.is_err() {
                    error!("TUI progress channel closed. Cannot send find_pcap_files error.");
                }
                return;
            }
        };

        if pcap_files.is_empty() {
            info!("No PCAP files found in the specified directory for batch processing.");
            let final_progress = BatchProgress {
                current_file: "No PCAP files found.".to_string(),
                total_files: 0,
                processed_files: 0,
                ..Default::default()
            };
            if progress_sender.send(final_progress).await.is_err() {
                error!("TUI progress channel closed. Cannot send 'no files found' message.");
            }
            return;
        }

        let initial_progress_update = BatchProgress {
            total_files: pcap_files.len(),
            current_file: format!("Preparing to process {} files...", pcap_files.len()),
            ..Default::default()
        };
        if progress_sender.send(initial_progress_update).await.is_err() {
            error!("TUI progress channel closed at initial update. Aborting batch task.");
            return;
        }

        let output_dir_path = PathBuf::from(batch_state.output_directory.clone());
        if !output_dir_path.exists() {
            if let Err(e) = fs::create_dir_all(&output_dir_path) {
                error!("Failed to create output directory {}: {}", output_dir_path.display(), e);
                let mut err_progress = BatchProgress { total_files: pcap_files.len(), ..Default::default() };
                err_progress.last_error_message = Some(format!("Error creating output dir '{}': {}", output_dir_path.display(), e));
                if progress_sender.send(err_progress).await.is_err() {
                     error!("TUI progress channel closed. Cannot send output directory creation error.");
                }
                return;
            }
        }
        
        // Determine threads for each rustiflow subprocess.
        // If batch_state.worker_count is high, we might want fewer threads per subprocess.
        // For simplicity, let's use a fixed number or make it configurable.
        // Example: if batch_state.worker_count > 4, use 1 thread per subprocess, else use 2.
        let threads_per_subprocess = if batch_state.worker_count >= 4 && num_cpus::get() > 4 {
            (num_cpus::get() / batch_state.worker_count).max(1) as u8
        } else {
            (num_cpus::get() / 2).max(1) as u8
        };


        // Use Rayon for parallel processing of PCAP files. Each Rayon thread will spawn Tokio tasks.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(batch_state.worker_count) // This controls how many PCAP files are processed in parallel by Rayon
            .build()
            .unwrap();

        // Channel to collect results from Rayon-managed Tokio tasks
        let (internal_result_tx, mut internal_result_rx) =
            tokio_mpsc::channel::<(String, Result<String, String>)>(pcap_files.len() + 5); // Buffer slightly larger

        let num_total_files = pcap_files.len();
        let mut current_progress_state = BatchProgress { total_files: num_total_files, ..Default::default() };


        pool.install(move || { // `batch_state` and `output_dir_path` are moved into Rayon's scope
            pcap_files.into_par_iter().for_each_with(
                internal_result_tx, // Each Rayon thread gets a sender to the internal channel
                |tx_clone, pcap_file| {
                    let file_name_for_progress = pcap_file.file_name().unwrap_or_default().to_string_lossy().into_owned();
                    
                    // Each Rayon thread needs its own Tokio runtime to block_on async calls
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    let result = rt.block_on(process_single_pcap_for_batch(
                        pcap_file.clone(), // pcap_file is PathBuf, which is Clone
                        output_dir_path.clone(), // output_dir_path is PathBuf, Clone
                        batch_state.feature_set.clone(), // FlowType needs to be Clone
                        batch_state.active_timeout,
                        batch_state.idle_timeout,
                        threads_per_subprocess,
                    ));

                    if tx_clone.blocking_send((file_name_for_progress, result)).is_err() {
                        error!("Internal result channel closed or full. Dropping result from Rayon thread.");
                    }
                },
            );
        }); // Rayon ThreadPool is dropped here, internal_result_tx senders from Rayon threads are dropped.

        // Loop to collect results from internal_result_rx and send aggregated progress to TUI
        for _ in 0..num_total_files {
            match internal_result_rx.recv().await {
                Some((file_name, result)) => {
                    current_progress_state.processed_files += 1;
                    current_progress_state.current_file = file_name.clone();
                    current_progress_state.last_error_message = None; // Clear previous specific error

                    match result {
                        Ok(processed_file_name) => {
                            info!("Batch: Successfully processed {}", processed_file_name);
                            current_progress_state.success_count += 1;
                        }
                        Err(e) => {
                            error!("Batch: Failed to process {}: {}", file_name, e);
                            current_progress_state.error_count += 1;
                            current_progress_state.last_error_message = Some(format!("Error on {}: {}", file_name, e));
                        }
                    }
                    
                    let remaining_files = current_progress_state.total_files.saturating_sub(current_progress_state.processed_files);
                    current_progress_state.estimated_remaining = format!("~{}s", remaining_files * 2); // Simple estimation

                    if progress_sender.send(current_progress_state.clone()).await.is_err() {
                        warn!("TUI progress channel closed during batch updates. Aborting task.");
                        internal_result_rx.close(); // Stop trying to receive more results
                        break; 
                    }
                }
                None => {
                    // Internal channel closed unexpectedly before all results were received
                    warn!("Internal result channel closed prematurely. Processed {}/{} files.", current_progress_state.processed_files, num_total_files);
                    current_progress_state.last_error_message = Some("Batch task interrupted internally.".to_string());
                    if progress_sender.send(current_progress_state.clone()).await.is_err() {
                         warn!("TUI progress channel closed when reporting internal interruption.");
                    }
                    break;
                }
            }
        }
        
        // Final completion update
        current_progress_state.current_file = if current_progress_state.error_count > 0 {
            format!("Batch finished. {} succeeded, {} failed.", current_progress_state.success_count, current_progress_state.error_count)
        } else {
            format!("Batch processing completed successfully for {} files.", current_progress_state.success_count)
        };
        current_progress_state.estimated_remaining = "Done".to_string();
        if progress_sender.send(current_progress_state).await.is_err() {
            error!("TUI progress channel closed. Cannot send final batch completion status.");
        }

        info!(
            "Batch processor task finished. Total: {}, Success: {}, Errors: {}",
            num_total_files,
            num_success_count, // These local counters are not updated in the loop, use current_progress_state
            num_error_count
        );
    })
}

#[tokio::main]
async fn main() {
    env_logger::init(); // Initialize logger early

    if std::env::args().len() == 1 {
        // No CLI arguments, launch the TUI
        info!("No CLI arguments detected, launching TUI.");
        match launch_tui(batch_processor_task_spawner).await {
            Ok(Some(tui_config)) => {
                // TUI returned a configuration, meaning user wants to run a standard command
                info!("TUI exited with configuration, proceeding to run command.");
                run_with_config(tui_config).await;
            }
            Ok(None) => {
                // TUI exited without returning a configuration (e.g., user quit)
                info!("TUI exited without selecting a command to run.");
            }
            Err(e) => {
                error!("TUI Error: {:?}", e);
                eprintln!("Application failed to start or run the TUI: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // CLI arguments provided
        info!("CLI arguments detected, parsing and running command.");
        let cli = Cli::parse();

        let config_to_run: TuiConfig = if let Some(config_path) = cli.config_file {
            info!("Loading configuration from file: {}", config_path);
            match confy::load_path::<ConfigFile>(&config_path) {
                Ok(cfg_file) => TuiConfig {
                    config: cfg_file.config,
                    output: cfg_file.output,
                    command: cli.command, // Command from CLI overrides file for now
                },
                Err(e) => {
                    error!("Error loading configuration file '{}': {:?}", config_path, e);
                    eprintln!("Error: Could not load config file '{}'. Please check the path and format.", config_path);
                    return;
                }
            }
        } else {
            // No config file, construct from CLI args
            // Handle BatchPcap command if erroneously called via CLI without TUI
            if let Commands::BatchPcap = cli.command {
                info!("BatchPcap command is intended for TUI use. Launching TUI for batch setup.");
                if launch_tui(batch_processor_task_spawner).await.is_err() { // Pass the spawner
                    error!("Failed to launch TUI for batch setup via CLI fallback.");
                }
                return;
            }

            let features = cli.features.unwrap_or_else(|| {
                error!("--features is required when not using a config file for non-batch commands.");
                eprintln!("Usage error: --features <FEATURE_SET> is required.");
                std::process::exit(1);
            });
            let output_method = cli.output.unwrap_or_else(|| {
                error!("--output is required when not using a config file for non-batch commands.");
                eprintln!("Usage error: --output <OUTPUT_METHOD> is required.");
                std::process::exit(1);
            });

            TuiConfig {
                config: ExportConfig {
                    features,
                    active_timeout: cli.active_timeout,
                    idle_timeout: cli.idle_timeout,
                    early_export: cli.early_export,
                    threads: cli.threads,
                    expiration_check_interval: cli.expiration_check_interval,
                },
                output: OutputConfig {
                    output: output_method,
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

/// Executes the main application logic based on the provided configuration.
async fn run_with_config(config: TuiConfig) {
    match config.command {
        Commands::Realtime {
            interface,
            ingress_only,
        } => {
            debug!("Executing Realtime command with interface: {}, ingress_only: {}", interface, ingress_only);
            macro_rules! execute_realtime {
                ($flow_ty:ty) => {{
                    let performance_mode_disabled = config.output.export_path.is_some() &&
                        !matches!(std::env::var("RUST_LOG"), Ok(ref val) if val.to_lowercase().contains("debug")) && // check lowercase
                        !config.output.performance_mode;

                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output.clone(),
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path.clone(),
                    );
                    output_writer.init(); // Ensure header is written if enabled

                    let (sender, mut receiver) = tokio_mpsc::channel::<$flow_ty>(1000); // Increased buffer slightly
                    let output_task_handle = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow during realtime: {:?}", e);
                            }
                        }
                        // output_writer.flush_and_close(); // Optionally flush here, or just return
                        output_writer // Return the writer
                    });

                    info!("Starting realtime processing on interface: {}...", interface);
                    let processing_start_time = Instant::now();
                    let processing_result = handle_realtime::<$flow_ty>(
                        &interface,
                        sender, // This sender is for FlowTable to send exported flows
                        config.config.threads.unwrap_or_else(|| (num_cpus::get() / 2).max(1) as u8), // Default threads
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                        ingress_only,
                        performance_mode_disabled,
                    )
                    .await;

                    info!("Realtime data processing completed in {:.3} seconds.", processing_start_time.elapsed().as_secs_f64());

                    let output_writer_result = output_task_handle.await;
                    if output_writer_result.is_err() {
                        error!("Realtime output task panicked or was cancelled: {:?}", output_writer_result.err().unwrap());
                        // Decide how to proceed if writer task fails
                        return;
                    }
                    let mut output_writer = output_writer_result.unwrap();

                    match processing_result {
                        Ok((dropped_packets, flow_stats)) => {
                            info!("Total eBPF dropped packets (realtime): {}", dropped_packets);
                            let mut inter_flow_deltas_us: Vec<i64> = Vec::new();
                            if flow_stats.len() > 1 {
                                for i in 1..flow_stats.len() {
                                    inter_flow_deltas_us.push(flow_stats[i].0 - flow_stats[i-1].0);
                                }
                            }
                            let all_flow_durations_us: Vec<i64> = flow_stats.iter().map(|&(_, duration)| duration).collect();

                            // OutputWriter's methods for these are now no-ops for Polars/Pandas
                            if let Err(e) = output_writer.write_inter_flow_deltas(&inter_flow_deltas_us) {
                                error!("Error writing inter-flow deltas (CSV/Print): {:?}", e);
                            }
                            if let Err(e) = output_writer.write_all_flow_durations(&all_flow_durations_us) {
                                error!("Error writing all flow durations (CSV/Print): {:?}", e);
                            }

                            // This call now finalizes Parquet for Polars/Pandas, or flushes for CSV/Print
                            if let Err(e) = output_writer.flush_and_close() {
                                error!("Error during final flush/close for output type {:?}: {:?}", config.output.output, e);
                            } else {
                                // If output was Polars or Pandas, write global stats to JSON
                                if config.output.output == ExportMethodType::Polars || config.output.output == ExportMethodType::Pandas {
                                    if let Some(export_path_str) = &config.output.export_path {
                                        let mut json_path = StdPathBuf::from(export_path_str);
                                        let stem = json_path.file_stem().unwrap_or_default().to_os_string();
                                        let mut new_filename = stem;
                                        new_filename.push("_global_stats.json");
                                        json_path.set_file_name(new_filename);

                                        info!("Writing global stats to JSON: {}", json_path.display());

                                        #[derive(Serialize)]
                                        struct GlobalStats<'a> {
                                            inter_flow_deltas_us: &'a [i64],
                                            all_flow_durations_us: &'a [i64],
                                        }
                                        let stats_to_serialize = GlobalStats {
                                            inter_flow_deltas_us: &inter_flow_deltas_us,
                                            all_flow_durations_us: &all_flow_durations_us,
                                        };

                                        match StdFile::create(&json_path) {
                                            Ok(file) => {
                                                let writer = StdBufWriter::new(file);
                                                if let Err(e) = serde_json::to_writer_pretty(writer, &stats_to_serialize) {
                                                    error!("Failed to write global stats JSON to {}: {}", json_path.display(), e);
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to create global stats JSON file {}: {}", json_path.display(), e);
                                            }
                                        }
                                    } else {
                                        warn!("Export path not available for Polars/Pandas global stats JSON output.");
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error during realtime processing: {:?}", err);
                             // Still try to flush/close if output_writer was obtained
                            if let Err(e) = output_writer.flush_and_close() {
                                error!("Error flushing/closing writer for realtime (on error path): {:?}", e);
                            }
                        }
                    }
                    info!("Realtime processing and output finished completely.");
                }};
            }
            // Execute based on selected feature set
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
            debug!("Executing Pcap command for path: {}", path);
            macro_rules! execute_offline {
                ($flow_ty:ty) => {{
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output.clone(),
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path.clone(),
                    );
                    output_writer.init();

                    let (sender, mut receiver) = tokio_mpsc::channel::<$flow_ty>(1000);
                    let output_task_handle = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow during pcap processing: {:?}", e);
                            }
                        }
                        // output_writer.flush_and_close(); // Optionally flush here
                        output_writer // Return the writer
                    });

                    info!("Starting offline PCAP processing for file: {}...", path);
                    let processing_start_time = Instant::now();
                    let pcap_processing_result = read_pcap_file::<$flow_ty>(
                        &path,
                        sender, // Sender for FlowTable to send exported flows
                        config.config.threads.unwrap_or_else(|| (num_cpus::get() / 2).max(1) as u8),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                    )
                    .await;

                    info!("Offline PCAP data processing for '{}' completed in {:.3} seconds.", path, processing_start_time.elapsed().as_secs_f64());

                    let output_writer_result = output_task_handle.await;
                    if output_writer_result.is_err() {
                        error!("PCAP output task panicked or was cancelled: {:?}", output_writer_result.err().unwrap());
                        return;
                    }
                    let mut output_writer = output_writer_result.unwrap();

                    match pcap_processing_result {
                        Ok(flow_stats) => {
                            let mut inter_flow_deltas_us: Vec<i64> = Vec::new();
                            if flow_stats.len() > 1 {
                                for i in 1..flow_stats.len() {
                                    inter_flow_deltas_us.push(flow_stats[i].0 - flow_stats[i-1].0);
                                }
                            }
                            let all_flow_durations_us: Vec<i64> = flow_stats.iter().map(|&(_, duration)| duration).collect();

                            // OutputWriter's methods for these are now no-ops for Polars/Pandas
                            if let Err(e) = output_writer.write_inter_flow_deltas(&inter_flow_deltas_us) {
                                error!("Error writing inter-flow deltas (pcap CSV/Print): {:?}", e);
                            }
                            if let Err(e) = output_writer.write_all_flow_durations(&all_flow_durations_us) {
                                error!("Error writing all flow durations (pcap CSV/Print): {:?}", e);
                            }

                            // This call now finalizes Parquet for Polars/Pandas, or flushes for CSV/Print
                            if let Err(e) = output_writer.flush_and_close() {
                                error!("Error during final flush/close for PCAP output type {:?}: {:?}", config.output.output, e);
                            } else {
                                // If output was Polars or Pandas, write global stats to JSON
                                if config.output.output == ExportMethodType::Polars || config.output.output == ExportMethodType::Pandas {
                                    if let Some(export_path_str) = &config.output.export_path {
                                        let mut json_path = StdPathBuf::from(export_path_str);
                                        let stem = json_path.file_stem().unwrap_or_default().to_os_string();
                                        let mut new_filename = stem;
                                        new_filename.push("_global_stats.json");
                                        json_path.set_file_name(new_filename);

                                        info!("Writing global stats to JSON (pcap): {}", json_path.display());

                                        #[derive(Serialize)]
                                        struct GlobalStats<'a> {
                                            inter_flow_deltas_us: &'a [i64],
                                            all_flow_durations_us: &'a [i64],
                                        }
                                        let stats_to_serialize = GlobalStats {
                                            inter_flow_deltas_us: &inter_flow_deltas_us,
                                            all_flow_durations_us: &all_flow_durations_us,
                                        };

                                        match StdFile::create(&json_path) {
                                            Ok(file) => {
                                                let writer = StdBufWriter::new(file);
                                                if let Err(e) = serde_json::to_writer_pretty(writer, &stats_to_serialize) {
                                                    error!("Failed to write global stats JSON to {} (pcap): {}", json_path.display(), e);
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to create global stats JSON file {} (pcap): {}", json_path.display(), e);
                                            }
                                        }
                                    } else {
                                        warn!("Export path not available for Polars/Pandas global stats JSON output (pcap).");
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error reading pcap file '{}': {:?}", path, err);
                            // Still try to flush/close if output_writer was obtained
                            if let Err(e) = output_writer.flush_and_close() {
                                error!("Error flushing/closing writer for pcap (on error path): {:?}", e);
                            }
                        }
                    }
                    info!("Offline PCAP processing and output for '{}' finished completely.", path);
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
        Commands::BatchPcap => {
            // This arm is reached if BatchPcap is somehow configured via CLI or config file
            // without going through the TUI's StartBatchProcessing transition.
            // The TUI is the primary intended interface for initiating batch processing.
            warn!("BatchPcap command invoked directly via CLI/config. This mode is primarily designed to be launched from the TUI.");
            info!("To run batch processing, please use the TUI (run `rustiflow` without arguments) and navigate to 'Batch PCAP Processing'.");
            info!("If you intend to support direct CLI batch commands, please extend `args.rs` for `Commands::BatchPcap` to include necessary parameters (input/output directories, etc.) and update this logic.");
        }
    }
}
// I hope this will cause a commit changes
