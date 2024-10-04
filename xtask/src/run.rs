use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(
        BuildOptions {
            target: opts.bpf_target,
            release: opts.release,
        },
        "ebpf-ipv4".to_string(),
    )
    .context("Error while building the eBPF Ipv4 program")?;
    build(&opts).context("Error while building userspace application")?;

    build_ebpf(
        BuildOptions {
            target: opts.bpf_target,
            release: opts.release,
        },
        "ebpf-ipv6".to_string(),
    )
    .context("Error while building the eBPF Ipv6 program")?;
    build(&opts).context("Error while building userspace application")?;

    // profile we are building (release or debug)
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/rustiflow");

    // Determine if 'realtime' is one of the arguments in run_args
    let use_sudo = opts.run_args.iter().any(|arg| arg == "realtime") || opts.run_args.is_empty();

    // configure args
    let runner = if use_sudo {
        opts.runner.trim().split_terminator(' ').collect()
    } else {
        Vec::new()
    };
    let mut args = runner;
    args.push(bin_path.as_str());
    args.extend(opts.run_args.iter().map(String::as_str)); // directly extend with run_args

    // run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
