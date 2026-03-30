use anyhow::Result;

pub struct ProfilingSession;

impl ProfilingSession {
    pub fn start_from_env(_mode: &'static str) -> Result<Option<Self>> {
        Ok(None)
    }

    pub fn finish(self) -> Result<()> {
        Ok(())
    }
}
