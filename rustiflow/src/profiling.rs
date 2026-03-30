use anyhow::{Context, Result};
use log::info;
use pprof::{ProfilerGuard, ProfilerGuardBuilder};
use std::{env, fs::File, path::PathBuf};

const DEFAULT_PROFILE_FREQUENCY_HZ: i32 = 99;

pub struct ProfilingSession {
    mode: &'static str,
    flamegraph_path: Option<PathBuf>,
    guard: Option<ProfilerGuard<'static>>,
    usage_start: ResourceUsage,
}

impl ProfilingSession {
    pub fn start_from_env(mode: &'static str) -> Result<Option<Self>> {
        let flamegraph_path = env::var_os("RUSTIFLOW_PROFILE_FLAMEGRAPH").map(PathBuf::from);
        let sampling_frequency_hz = env::var("RUSTIFLOW_PROFILE_FREQUENCY_HZ")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_PROFILE_FREQUENCY_HZ);

        let enabled = flamegraph_path.is_some() || env_flag("RUSTIFLOW_PROFILE_RESOURCE_SUMMARY");
        if !enabled {
            return Ok(None);
        }

        let guard = if flamegraph_path.is_some() {
            Some(
                ProfilerGuardBuilder::default()
                    .frequency(sampling_frequency_hz)
                    .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                    .build()
                    .context("failed to start userspace profiler")?,
            )
        } else {
            None
        };

        info!(
            "Profiling enabled for {}: flamegraph={}, resource_summary={}, frequency_hz={}",
            mode,
            flamegraph_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "disabled".to_string()),
            env_flag("RUSTIFLOW_PROFILE_RESOURCE_SUMMARY"),
            sampling_frequency_hz
        );

        Ok(Some(Self {
            mode,
            flamegraph_path,
            guard,
            usage_start: ResourceUsage::read()?,
        }))
    }

    pub fn finish(self) -> Result<()> {
        let usage_end = ResourceUsage::read()?;
        let usage_delta = usage_end.delta_from(&self.usage_start);
        info!(
            "Profile summary for {}: user_cpu_ms={:.3} sys_cpu_ms={:.3} max_rss_kb={} voluntary_ctx_switches={} involuntary_ctx_switches={}",
            self.mode,
            usage_delta.user_cpu_us as f64 / 1_000.0,
            usage_delta.system_cpu_us as f64 / 1_000.0,
            usage_end.max_rss_kb,
            usage_delta.voluntary_context_switches,
            usage_delta.involuntary_context_switches
        );

        if let (Some(guard), Some(flamegraph_path)) = (self.guard, self.flamegraph_path) {
            let report = guard
                .report()
                .build()
                .context("failed to build flamegraph report")?;
            let file = File::create(&flamegraph_path)
                .with_context(|| format!("failed to create {}", flamegraph_path.display()))?;
            report
                .flamegraph(file)
                .with_context(|| format!("failed to write {}", flamegraph_path.display()))?;
            info!(
                "Wrote userspace flamegraph for {} to {}",
                self.mode,
                flamegraph_path.display()
            );
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ResourceUsage {
    user_cpu_us: i64,
    system_cpu_us: i64,
    max_rss_kb: i64,
    voluntary_context_switches: i64,
    involuntary_context_switches: i64,
}

impl ResourceUsage {
    fn read() -> Result<Self> {
        let mut usage = libc::rusage {
            ru_utime: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ru_stime: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ru_maxrss: 0,
            ru_ixrss: 0,
            ru_idrss: 0,
            ru_isrss: 0,
            ru_minflt: 0,
            ru_majflt: 0,
            ru_nswap: 0,
            ru_inblock: 0,
            ru_oublock: 0,
            ru_msgsnd: 0,
            ru_msgrcv: 0,
            ru_nsignals: 0,
            ru_nvcsw: 0,
            ru_nivcsw: 0,
        };

        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("getrusage failed");
        }

        Ok(Self {
            user_cpu_us: timeval_to_us(usage.ru_utime),
            system_cpu_us: timeval_to_us(usage.ru_stime),
            max_rss_kb: usage.ru_maxrss,
            voluntary_context_switches: usage.ru_nvcsw,
            involuntary_context_switches: usage.ru_nivcsw,
        })
    }

    fn delta_from(&self, start: &Self) -> Self {
        Self {
            user_cpu_us: self.user_cpu_us - start.user_cpu_us,
            system_cpu_us: self.system_cpu_us - start.system_cpu_us,
            max_rss_kb: self.max_rss_kb,
            voluntary_context_switches: self.voluntary_context_switches
                - start.voluntary_context_switches,
            involuntary_context_switches: self.involuntary_context_switches
                - start.involuntary_context_switches,
        }
    }
}

fn timeval_to_us(value: libc::timeval) -> i64 {
    value.tv_sec * 1_000_000 + value.tv_usec
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}
