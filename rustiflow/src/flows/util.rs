/// Use ports as IANA port categories ['well-known', 'registered', 'dynamic']
pub fn iana_port_mapping(port: u16) -> &'static str {
    match port {
        0..=1023 => "well-known",
        1024..=49151 => "registered",
        49152..=65535 => "dynamic",
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FlowExpireCause {
    TcpTermination,
    TcpReset,
    ActiveTimeout,
    IdleTimeout,
    ExporterShutdown,
    None,
}

impl FlowExpireCause {
    /// Returns a human-readable string describing the flow expiration cause.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::ActiveTimeout => "Active Timeout",
            Self::IdleTimeout => "Idle Timeout",
            Self::TcpTermination => "TCP Normal Termination",
            Self::TcpReset => "TCP Reset",
            Self::ExporterShutdown => "Exporter Shutdown",
        }
    }
}
