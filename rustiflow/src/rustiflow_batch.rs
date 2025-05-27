use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use rayon::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <pcap_directory> <output_directory>", args[0]);
        std::process::exit(1);
    }

    let pcap_dir = Path::new(&args[1]);
    let output_dir = Path::new(&args[2]);

    // Validate input directory
    if !pcap_dir.exists() || !pcap_dir.is_dir() {
        eprintln!("Error: {} is not a valid directory", pcap_dir.display());
        std::process::exit(1);
    }

    // Create output directory
    fs::create_dir_all(output_dir)?;

    // Find all pcap files (assuming non-recursive for this CLI tool,
    // recursive logic would be handled by the TUI part or an added flag here)
    let pcap_files = find_pcap_files(pcap_dir, false)?; // Added recursive flag, set to false

    if pcap_files.is_empty() {
        println!("No PCAP files found in {}", pcap_dir.display());
        return Ok(());
    }

    println!("Found {} PCAP files to process", pcap_files.len());

    // Process files in parallel
    let results: Vec<_> = pcap_files
        .par_iter()
        .map(|pcap_file| process_pcap(pcap_file, output_dir, "nfstream", 3600, 120)) // Defaulting some params
        .collect();

    // Report results
    let mut success_count = 0;
    let mut error_count = 0;

    for (file, result) in pcap_files.iter().zip(results.iter()) {
        match result {
            Ok(_) => {
                println!("✓ Successfully processed: {}", file.file_name().unwrap().to_string_lossy());
                success_count += 1;
            }
            Err(e) => {
                eprintln!("✗ Failed to process {}: {}", file.file_name().unwrap().to_string_lossy(), e);
                error_count += 1;
            }
        }
    }

    println!("\nBatch processing complete!");
    println!("Success: {}, Errors: {}", success_count, error_count);

    Ok(())
}

fn find_pcap_files(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut pcap_files = Vec::new();
    let mut dirs_to_visit = vec![dir.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();

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
    }
    pcap_files.sort();
    Ok(pcap_files)
}

// Adjusted to accept feature_set, active_timeout, idle_timeout
fn process_pcap(
    pcap_file: &Path,
    output_dir: &Path,
    feature_set: &str, // e.g., "nfstream", "cic", etc.
    active_timeout: u64,
    idle_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = pcap_file.file_stem()
        .ok_or("Invalid filename")?
        .to_string_lossy();

    let output_file = output_dir.join(format!("{}.csv", filename));

    // Construct the path to the main rustiflow executable
    // This assumes rustiflow_batch is in the same directory as rustiflow, or rustiflow is in PATH
    // For development, you might need to adjust this path e.g. to target/debug/rustiflow
    let rustiflow_executable = env::current_exe()?
        .parent()
        .map(|p| p.join("rustiflow"))
        .unwrap_or_else(|| PathBuf::from("rustiflow"));


    let mut command = Command::new(rustiflow_executable);
    command
        .arg("pcap")
        .arg(pcap_file) // pcap command takes path directly after "pcap"
        .arg("--features")
        .arg(feature_set)
        .arg("--output")
        .arg("csv")
        .arg("--export-path")
        .arg(&output_file)
        .arg("--header") // Assumed header is desired for batch processing
        .arg("--active-timeout")
        .arg(active_timeout.to_string())
        .arg("--idle-timeout")
        .arg(idle_timeout.to_string());

    // Pass number of threads if needed, e.g. from an environment variable or another arg
    // For now, it uses rustiflow's default or what's in its config if --config-file is used by rustiflow.


    let output = command.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("RustiFlow failed for {}:\nStderr: {}\nStdout: {}", pcap_file.display(), stderr, stdout).into());
    }

    Ok(())
}
