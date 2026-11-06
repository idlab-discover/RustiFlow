//! Installs an already staged release bundle; it never builds.

use std::{path::PathBuf, process::Command};

use anyhow::{bail, Context as _};
use clap::Parser;

use crate::dist::{bundle_name, release_version};

#[derive(Debug, Parser)]
pub struct Options {
    /// Staged bundle directory (default: target/dist/<bundle for this version>)
    #[clap(long)]
    pub bundle: Option<PathBuf>,
    /// Installation prefix the files run from
    #[clap(long, default_value = "/usr/local")]
    pub prefix: PathBuf,
    /// Stage below this directory instead of the live filesystem
    #[clap(long)]
    pub destdir: Option<PathBuf>,
    /// Command that wraps the installer, such as `sudo` for a live prefix
    #[clap(long)]
    pub runner: Option<String>,
}

pub fn install(opts: Options) -> Result<(), anyhow::Error> {
    let bundle = match opts.bundle {
        Some(bundle) => bundle,
        None => PathBuf::from("target/dist").join(bundle_name(&release_version()?)),
    };
    let installer = bundle.join("install.sh");
    if !installer.is_file() {
        bail!(
            "{} is not a staged release bundle; run `cargo xtask dist` first",
            bundle.display()
        );
    }

    let mut args: Vec<String> = opts
        .runner
        .as_deref()
        .map(|runner| runner.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    args.extend([
        "sh".to_owned(),
        installer.display().to_string(),
        "--prefix".to_owned(),
        opts.prefix.display().to_string(),
    ]);
    if let Some(destdir) = &opts.destdir {
        args.extend(["--destdir".to_owned(), destdir.display().to_string()]);
    }

    let status = Command::new(&args[0])
        .args(&args[1..])
        .status()
        .with_context(|| format!("failed to run `{}`", args.join(" ")))?;
    if !status.success() {
        bail!("`{}` failed with {status}", args.join(" "));
    }
    Ok(())
}
