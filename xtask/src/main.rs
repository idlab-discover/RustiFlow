mod build_ebpf;
mod run;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    #[clap(name = "ingress-ebpf")]
    BuildIngressEbpf(build_ebpf::Options),
    #[clap(name = "egress-ebpf")]
    BuildEgressEbpf(build_ebpf::Options),
    Run(run::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildIngressEbpf(opts) => build_ebpf::build_ebpf(opts, "ingress-ebpf".to_string()),
        BuildEgressEbpf(opts) => build_ebpf::build_ebpf(opts, "egress-ebpf".to_string()),
        Run(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
