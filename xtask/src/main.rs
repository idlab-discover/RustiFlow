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
    #[clap(name = "ingress-ebpf-ipv4")]
    BuildIngressEbpfIpv4(build_ebpf::Options),
    #[clap(name = "ingress-ebpf-ipv6")]
    BuildIngressEbpfIpv6(build_ebpf::Options),
    #[clap(name = "egress-ebpf-ipv4")]
    BuildEgressEbpfIpv4(build_ebpf::Options),
    #[clap(name = "egress-ebpf-ipv6")]
    BuildEgressEbpfIpv6(build_ebpf::Options),
    Run(run::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildIngressEbpfIpv4(opts) => build_ebpf::build_ebpf(opts, "ingress-ebpf-ipv4".to_string()),
        BuildEgressEbpfIpv4(opts) => build_ebpf::build_ebpf(opts, "egress-ebpf-ipv4".to_string()),
        BuildIngressEbpfIpv6(opts) => build_ebpf::build_ebpf(opts, "ingress-ebpf-ipv6".to_string()),
        BuildEgressEbpfIpv6(opts) => build_ebpf::build_ebpf(opts, "egress-ebpf-ipv6".to_string()),
        Run(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
