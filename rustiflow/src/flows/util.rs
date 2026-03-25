use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Use ports as IANA port categories ['well-known', 'registered', 'dynamic']
pub fn iana_port_mapping(port: u16) -> &'static str {
    match port {
        0..=1023 => "well-known",
        1024..=49151 => "registered",
        49152..=65535 => "dynamic",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpScope {
    Loopback,
    LinkLocal,
    Private,
    Shared,
    Multicast,
    Broadcast,
    Unspecified,
    Global,
}

impl IpScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::Private => "private",
            Self::Shared => "shared",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Unspecified => "unspecified",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathLocality {
    Loopback,
    LinkLocal,
    Private,
    Mixed,
    Multicast,
    Public,
    Other,
}

impl PathLocality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::Private => "private",
            Self::Mixed => "mixed",
            Self::Multicast => "multicast",
            Self::Public => "public",
            Self::Other => "other",
        }
    }
}

pub fn classify_ip_scope(address: IpAddr) -> IpScope {
    match address {
        IpAddr::V4(address) => classify_ipv4_scope(address),
        IpAddr::V6(address) => classify_ipv6_scope(address),
    }
}

pub fn classify_path_locality(source: IpAddr, destination: IpAddr) -> PathLocality {
    let source_scope = classify_ip_scope(source);
    let destination_scope = classify_ip_scope(destination);

    if matches!(source_scope, IpScope::Multicast) || matches!(destination_scope, IpScope::Multicast)
    {
        PathLocality::Multicast
    } else if matches!(source_scope, IpScope::Loopback)
        && matches!(destination_scope, IpScope::Loopback)
    {
        PathLocality::Loopback
    } else if matches!(source_scope, IpScope::LinkLocal)
        && matches!(destination_scope, IpScope::LinkLocal)
    {
        PathLocality::LinkLocal
    } else if is_localish_scope(source_scope) && is_localish_scope(destination_scope) {
        PathLocality::Private
    } else if is_localish_scope(source_scope) != is_localish_scope(destination_scope) {
        PathLocality::Mixed
    } else if matches!(source_scope, IpScope::Global)
        && matches!(destination_scope, IpScope::Global)
    {
        PathLocality::Public
    } else {
        PathLocality::Other
    }
}

fn classify_ipv4_scope(address: Ipv4Addr) -> IpScope {
    if address == Ipv4Addr::BROADCAST {
        IpScope::Broadcast
    } else if address.is_unspecified() {
        IpScope::Unspecified
    } else if address.is_loopback() {
        IpScope::Loopback
    } else if address.is_link_local() {
        IpScope::LinkLocal
    } else if address.is_private() {
        IpScope::Private
    } else if is_shared_ipv4(address) {
        IpScope::Shared
    } else if address.is_multicast() {
        IpScope::Multicast
    } else {
        IpScope::Global
    }
}

fn classify_ipv6_scope(address: Ipv6Addr) -> IpScope {
    if address.is_unspecified() {
        IpScope::Unspecified
    } else if address.is_loopback() {
        IpScope::Loopback
    } else if address.is_unicast_link_local() {
        IpScope::LinkLocal
    } else if address.is_unique_local() {
        IpScope::Private
    } else if address.is_multicast() {
        IpScope::Multicast
    } else {
        IpScope::Global
    }
}

fn is_shared_ipv4(address: Ipv4Addr) -> bool {
    let [first_octet, second_octet, ..] = address.octets();
    first_octet == 100 && (second_octet & 0b1100_0000) == 0b0100_0000
}

fn is_localish_scope(scope: IpScope) -> bool {
    matches!(
        scope,
        IpScope::Loopback | IpScope::LinkLocal | IpScope::Private | IpScope::Shared
    )
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
