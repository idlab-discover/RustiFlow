mod build_ebpf;
mod dist;
mod install;
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
    #[clap(name = "ebpf-ipv4")]
    BuildEbpfIpv4(build_ebpf::Options),
    #[clap(name = "ebpf-ipv6")]
    BuildEbpfIpv6(build_ebpf::Options),
    Run(run::Options),
    /// Build and stage the canonical release bundle and its tarball
    Dist(dist::Options),
    /// Install a staged release bundle without rebuilding it
    Install(install::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpfIpv4(opts) => build_ebpf::build_ebpf(opts, "ebpf-ipv4".to_string()),
        BuildEbpfIpv6(opts) => build_ebpf::build_ebpf(opts, "ebpf-ipv6".to_string()),
        Run(opts) => run::run(opts),
        Dist(opts) => dist::dist(opts).map(drop),
        Install(opts) => install::install(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
