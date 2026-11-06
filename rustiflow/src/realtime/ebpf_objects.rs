//! Locates the eBPF object files that realtime capture loads at runtime.
//!
//! A release install keeps the objects beside the executable's prefix in
//! `<prefix>/lib/rustiflow/`, while development builds leave them in Cargo's
//! target directory. Both layouts must work without rebuilding the binary.

use std::path::{Path, PathBuf};

use anyhow::bail;

/// Overrides every other location. When set, only this directory is searched,
/// so a typo fails loudly instead of silently loading a different build.
pub const EBPF_DIR_ENV: &str = "RUSTIFLOW_EBPF_DIR";

/// Where the release bundle installs the objects, relative to the prefix.
const INSTALLED_SUBDIR: &str = "lib/rustiflow";

/// eBPF target the userspace loader expects; the only supported one today.
const EBPF_TARGET: &str = "bpfel-unknown-none";

/// Resolves `program_name` to an existing object file from the current
/// process environment, or reports every directory that was searched.
pub fn ebpf_object_path(program_name: &str) -> Result<PathBuf, anyhow::Error> {
    let search_dirs = ebpf_search_dirs(
        std::env::var_os(EBPF_DIR_ENV).map(PathBuf::from),
        std::env::current_exe().ok().as_deref(),
        &development_target_dir(),
    );

    if let Some(path) = search_dirs
        .iter()
        .map(|dir| dir.join(program_name))
        .find(|path| path.is_file())
    {
        return Ok(path);
    }

    let searched = search_dirs
        .iter()
        .map(|dir| format!("  {}", dir.display()))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "eBPF object {program_name} not found. Searched:\n{searched}\n\
         Install a release bundle, set {EBPF_DIR_ENV}, or build it with `cargo xtask {}`.",
        program_name.trim_start_matches("rustiflow-")
    )
}

/// Directories to search, in priority order: the explicit override alone, or
/// else the installed layout followed by the development target directory.
fn ebpf_search_dirs(
    override_dir: Option<PathBuf>,
    executable: Option<&Path>,
    development_target_dir: &Path,
) -> Vec<PathBuf> {
    if let Some(dir) = override_dir {
        return vec![dir];
    }

    let installed = executable
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|prefix| prefix.join(INSTALLED_SUBDIR));
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let development = development_target_dir.join(EBPF_TARGET).join(profile);

    installed.into_iter().chain([development]).collect()
}

/// Cargo's target directory for `cargo xtask run` and other source-tree runs.
fn development_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> &'static str {
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    }

    #[test]
    fn override_dir_is_the_only_candidate() {
        let dirs = ebpf_search_dirs(
            Some(PathBuf::from("/opt/ebpf")),
            Some(Path::new("/usr/bin/rustiflow")),
            Path::new("/src/target"),
        );

        assert_eq!(dirs, vec![PathBuf::from("/opt/ebpf")]);
    }

    #[test]
    fn installed_layout_precedes_development_target() {
        let dirs = ebpf_search_dirs(
            None,
            Some(Path::new("/usr/local/bin/rustiflow")),
            Path::new("/src/target"),
        );

        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/usr/local/lib/rustiflow"),
                PathBuf::from(format!("/src/target/bpfel-unknown-none/{}", profile())),
            ]
        );
    }

    #[test]
    fn unknown_executable_falls_back_to_development_target() {
        let dirs = ebpf_search_dirs(None, None, Path::new("/src/target"));

        assert_eq!(
            dirs,
            vec![PathBuf::from(format!(
                "/src/target/bpfel-unknown-none/{}",
                profile()
            ))]
        );
    }

    #[test]
    fn missing_objects_report_every_searched_dir() {
        let error = ebpf_object_path("rustiflow-ebpf-does-not-exist")
            .expect_err("object must not exist")
            .to_string();

        assert!(error.contains("rustiflow-ebpf-does-not-exist not found"));
        assert!(error.contains("cargo xtask ebpf-does-not-exist"));
    }
}
