//! Produces the canonical release bundle that every production consumer
//! (installer, container images, Debian package, release assets) installs.
//!
//! Layout of `<out-dir>/rustiflow-<version>-x86_64-linux/`:
//!
//! ```text
//! bin/rustiflow
//! lib/rustiflow/rustiflow-ebpf-ipv4
//! lib/rustiflow/rustiflow-ebpf-ipv6
//! share/rustiflow/rustiflow@.service.in
//! share/rustiflow/config.toml.example
//! share/rustiflow/environment.example
//! share/doc/rustiflow/{LICENSE,README.md}
//! install.sh
//! MANIFEST
//! SHA256SUMS
//! ```
//!
//! plus a reproducible `<bundle>.tar.gz` and its `.sha256` beside it.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context as _};
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

/// The only host the release bundle supports; see the README platform notes.
const SUPPORTED_OS: &str = "linux";
const SUPPORTED_ARCH: &str = "x86_64";
const PLATFORM: &str = "x86_64-linux";
const USERSPACE_TARGET: &str = "x86_64-unknown-linux-gnu";
const EBPF_TARGET: Architecture = Architecture::BpfEl;
const EBPF_PROGRAMS: [&str; 2] = ["ebpf-ipv4", "ebpf-ipv6"];
/// Haswell (2013) and newer, and every AMD Zen: AVX2, BMI2, FMA, MOVBE.
const DEFAULT_TARGET_CPU: &str = "x86-64-v3";

#[derive(Debug, Parser)]
pub struct Options {
    /// Directory that receives the staged bundle and its tarball
    #[clap(long, default_value = "target/dist")]
    pub out_dir: PathBuf,
    /// CPU the userspace binary is tuned for and requires, as for rustc's
    /// `-C target-cpu`: an x86-64 level (`x86-64`, `x86-64-v2`,
    /// `x86-64-v3`, `x86-64-v4`), a model such as `znver3`, or `native`
    #[clap(long, default_value = DEFAULT_TARGET_CPU)]
    pub target_cpu: String,
}

/// Builds every release artifact and stages the bundle; returns its directory.
pub fn dist(opts: Options) -> Result<PathBuf, anyhow::Error> {
    check_supported_host(std::env::consts::OS, std::env::consts::ARCH)?;
    let version = release_version()?;
    let target_cpu = resolve_target_cpu(&opts.target_cpu)?;
    let provenance = Provenance::detect(&version, target_cpu)?;

    for program in EBPF_PROGRAMS {
        build_ebpf(
            BuildOptions {
                target: EBPF_TARGET,
                release: true,
            },
            program.to_string(),
        )
        .with_context(|| format!("Error while building the {program} program"))?;
    }
    // Replaces any caller RUSTFLAGS so the bundle depends only on its options.
    run(Command::new("cargo")
        .args(["build", "--locked", "--release", "-p", "rustiflow"])
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env(
            "RUSTFLAGS",
            format!("-C target-cpu={}", provenance.target_cpu),
        ))
    .context("Error while building the userspace application")?;

    let name = bundle_name(&version);
    let bundle = opts.out_dir.join(&name);
    if bundle.exists() {
        fs::remove_dir_all(&bundle)
            .with_context(|| format!("failed to remove stale bundle {}", bundle.display()))?;
    }
    stage(&bundle)?;
    fs::write(bundle.join("MANIFEST"), provenance.manifest(&version)?)
        .context("failed to write MANIFEST")?;
    write_checksums(&bundle)?;
    let tarball = write_tarball(&opts.out_dir, &name, provenance.source_date_epoch)?;

    println!("Staged {}", bundle.display());
    println!("Packed {}", tarball.display());
    Ok(bundle)
}

/// Directory and tarball stem for one release of the supported platform.
pub fn bundle_name(version: &str) -> String {
    format!("rustiflow-{version}-{PLATFORM}")
}

/// The userspace crate version, which is also what `rustiflow --version` reports.
pub fn release_version() -> Result<String, anyhow::Error> {
    let manifest = fs::read_to_string("rustiflow/Cargo.toml")
        .context("failed to read rustiflow/Cargo.toml; run xtask from the workspace root")?;
    manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .context("rustiflow/Cargo.toml has no package version")
}

/// Resolves `native` to the host CPU model, so MANIFEST names what the binary
/// actually requires.
fn resolve_target_cpu(target_cpu: &str) -> Result<String, anyhow::Error> {
    if target_cpu != "native" {
        return Ok(target_cpu.to_owned());
    }
    let cpus = capture(Command::new("rustc").args([
        "--print",
        "target-cpus",
        "--target",
        USERSPACE_TARGET,
    ]))?;
    parse_native_cpu(&cpus).context("rustc did not report the native CPU")
}

/// Extracts `znver3` from rustc's `native - ... (currently znver3).` line.
fn parse_native_cpu(target_cpus: &str) -> Option<String> {
    let line = target_cpus
        .lines()
        .find(|line| line.trim_start().starts_with("native "))?;
    let model = line.split("(currently ").nth(1)?.split(')').next()?;
    Some(model.to_owned())
}

fn check_supported_host(os: &str, arch: &str) -> Result<(), anyhow::Error> {
    if os != SUPPORTED_OS || arch != SUPPORTED_ARCH {
        bail!(
            "release bundles are only supported on {SUPPORTED_ARCH} {SUPPORTED_OS} \
             (userspace {USERSPACE_TARGET}, eBPF {EBPF_TARGET}); this host is {arch} {os}"
        );
    }
    Ok(())
}

/// Where a release came from, recorded in MANIFEST so the binary, eBPF
/// objects, and any image or package built from them identify one release.
struct Provenance {
    target_cpu: String,
    commit: String,
    source_tree: &'static str,
    source_date_epoch: u64,
}

impl Provenance {
    /// Reads Git when available; container builds without `.git` pass
    /// `RUSTIFLOW_COMMIT` and `SOURCE_DATE_EPOCH` instead.
    fn detect(version: &str, target_cpu: String) -> Result<Self, anyhow::Error> {
        let git_commit = capture(Command::new("git").args(["rev-parse", "HEAD"])).ok();

        if git_commit.is_some() {
            if let Ok(tag) = capture(Command::new("git").args([
                "describe",
                "--exact-match",
                "--tags",
                "--match",
                "v*",
            ])) {
                if tag != format!("v{version}") {
                    bail!("HEAD is tagged {tag} but rustiflow/Cargo.toml says {version}");
                }
            }
        }

        let commit = std::env::var("RUSTIFLOW_COMMIT")
            .ok()
            .filter(|commit| !commit.is_empty())
            .or_else(|| git_commit.clone())
            .unwrap_or_else(|| "unknown".to_owned());
        let source_tree = match git_commit {
            Some(_) => match capture(Command::new("git").args(["status", "--porcelain"])) {
                Ok(status) if status.is_empty() => "clean",
                Ok(_) => "modified",
                Err(_) => "unknown",
            },
            None => "unknown",
        };
        // An empty value counts as unset, as with an unset Docker build argument.
        let source_date_epoch = match std::env::var("SOURCE_DATE_EPOCH")
            .ok()
            .filter(|epoch| !epoch.is_empty())
        {
            Some(epoch) => epoch
                .parse()
                .with_context(|| format!("SOURCE_DATE_EPOCH is not a number: {epoch}"))?,
            None => capture(Command::new("git").args(["log", "-1", "--format=%ct"]))
                .ok()
                .and_then(|epoch| epoch.parse().ok())
                .unwrap_or(0),
        };

        Ok(Self {
            target_cpu,
            commit,
            source_tree,
            source_date_epoch,
        })
    }

    fn manifest(&self, version: &str) -> Result<String, anyhow::Error> {
        let Self {
            target_cpu,
            commit,
            source_tree,
            source_date_epoch,
        } = self;
        let rustc = capture(Command::new("rustc").arg("-V"))?;
        let ebpf_rustc = capture(
            Command::new("rustc")
                .arg("-V")
                .current_dir(EBPF_PROGRAMS[0])
                .env_remove("RUSTUP_TOOLCHAIN"),
        )?;
        let bpf_linker = capture(Command::new("bpf-linker").arg("--version"))?;

        Ok(format!(
            "name=rustiflow\n\
             version={version}\n\
             platform={PLATFORM}\n\
             target={USERSPACE_TARGET}\n\
             target_cpu={target_cpu}\n\
             ebpf_target={EBPF_TARGET}\n\
             profile=release\n\
             commit={commit}\n\
             source_tree={source_tree}\n\
             source_date_epoch={source_date_epoch}\n\
             rustc={rustc}\n\
             ebpf_rustc={ebpf_rustc}\n\
             bpf_linker={bpf_linker}\n"
        ))
    }
}

/// Copies build outputs and packaging assets into the bundle with fixed modes.
fn stage(bundle: &Path) -> Result<(), anyhow::Error> {
    let ebpf_ipv4 = format!("target/{EBPF_TARGET}/release/rustiflow-ebpf-ipv4");
    let ebpf_ipv6 = format!("target/{EBPF_TARGET}/release/rustiflow-ebpf-ipv6");
    let files = [
        ("target/release/rustiflow", "bin/rustiflow", 0o755),
        (
            ebpf_ipv4.as_str(),
            "lib/rustiflow/rustiflow-ebpf-ipv4",
            0o644,
        ),
        (
            ebpf_ipv6.as_str(),
            "lib/rustiflow/rustiflow-ebpf-ipv6",
            0o644,
        ),
        (
            "packaging/systemd/rustiflow@.service.in",
            "share/rustiflow/rustiflow@.service.in",
            0o644,
        ),
        ("config.toml", "share/rustiflow/config.toml.example", 0o644),
        (
            "packaging/environment.example",
            "share/rustiflow/environment.example",
            0o644,
        ),
        ("LICENSE", "share/doc/rustiflow/LICENSE", 0o644),
        ("README.md", "share/doc/rustiflow/README.md", 0o644),
        ("packaging/install.sh", "install.sh", 0o755),
    ];

    for (source, relative, mode) in files {
        let target = bundle.join(relative);
        let parent = target.parent().expect("bundle paths have a parent");
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        fs::copy(source, &target)
            .with_context(|| format!("failed to copy {source} into the bundle"))?;
        set_mode(&target, mode)?;
    }
    for dir in [
        "",
        "bin",
        "lib",
        "lib/rustiflow",
        "share",
        "share/rustiflow",
        "share/doc",
        "share/doc/rustiflow",
    ] {
        set_mode(&bundle.join(dir), 0o755)?;
    }
    Ok(())
}

/// Writes `SHA256SUMS` over every bundle file, verifiable with `sha256sum -c`.
fn write_checksums(bundle: &Path) -> Result<(), anyhow::Error> {
    let mut files = Vec::new();
    collect_files(bundle, bundle, &mut files)?;
    files.sort();
    let sums = capture(Command::new("sha256sum").args(&files).current_dir(bundle))?;
    let path = bundle.join("SHA256SUMS");
    fs::write(&path, format!("{sums}\n")).context("failed to write SHA256SUMS")?;
    set_mode(&path, 0o644)?;
    set_mode(&bundle.join("MANIFEST"), 0o644)
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<(), anyhow::Error> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("walk stays inside the bundle");
            files.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// Packs the bundle with normalized order, owners, and timestamps so the same
/// inputs always give the same tarball bytes.
fn write_tarball(out_dir: &Path, name: &str, epoch: u64) -> Result<PathBuf, anyhow::Error> {
    let file_name = format!("{name}.tar.gz");
    let tarball = out_dir.join(&file_name);
    let output = fs::File::create(&tarball)
        .with_context(|| format!("failed to create {}", tarball.display()))?;

    let mut tar = Command::new("tar")
        .args([
            "--sort=name",
            &format!("--mtime=@{epoch}"),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--format=gnu",
            "-cf",
            "-",
            name,
        ])
        .current_dir(out_dir)
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to run GNU tar")?;
    let tar_stdout = tar.stdout.take().expect("tar stdout is piped");
    let gzip = Command::new("gzip")
        .args(["-9", "-n"])
        .stdin(tar_stdout)
        .stdout(output)
        .status()
        .context("failed to run gzip")?;
    let tar = tar.wait().context("failed to wait for tar")?;
    if !tar.success() || !gzip.success() {
        bail!("packing {} failed", tarball.display());
    }

    let sum = capture(
        Command::new("sha256sum")
            .arg(&file_name)
            .current_dir(out_dir),
    )?;
    fs::write(
        out_dir.join(format!("{file_name}.sha256")),
        format!("{sum}\n"),
    )
    .context("failed to write the tarball checksum")?;
    Ok(tarball)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set mode {mode:o} on {}", path.display()))
}

fn run(command: &mut Command) -> Result<(), anyhow::Error> {
    let status = command
        .status()
        .with_context(|| format!("failed to run {command:?}"))?;
    if !status.success() {
        bail!("{command:?} failed with {status}");
    }
    Ok(())
}

/// Runs a command and returns its trimmed stdout, failing on a nonzero exit.
fn capture(command: &mut Command) -> Result<String, anyhow::Error> {
    let output = command
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {command:?}"))?;
    if !output.status.success() {
        bail!("{command:?} failed with {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_x86_64_linux_hosts_are_supported() {
        assert!(check_supported_host("linux", "x86_64").is_ok());
        assert!(check_supported_host("linux", "aarch64").is_err());
        assert!(check_supported_host("macos", "x86_64").is_err());
    }

    #[test]
    fn native_cpu_is_read_from_rustc_target_cpus() {
        let listing = "Available CPUs for this target:\n    \
            native                  - Select the CPU of the current host (currently znver3).\n    \
            alderlake\n";
        assert_eq!(parse_native_cpu(listing).as_deref(), Some("znver3"));
        assert_eq!(parse_native_cpu("Available CPUs for this target:\n"), None);
    }

    #[test]
    fn bundle_name_includes_version_and_platform() {
        assert_eq!(bundle_name("1.2.3"), "rustiflow-1.2.3-x86_64-linux");
    }
}
