use std::{fmt, net::IpAddr};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointKey {
    pub ip: IpAddr,
    pub port: u16,
}

impl EndpointKey {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: EndpointKey,
    pub destination: EndpointKey,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            source: EndpointKey::new(source_ip, source_port),
            destination: EndpointKey::new(destination_ip, destination_port),
            protocol,
        }
    }

    pub fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            protocol: self.protocol,
        }
    }

    pub fn canonical(self) -> Self {
        if self.source <= self.destination {
            self
        } else {
            self.reverse()
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}-{}:{}-{}",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.protocol
        )
    }
}
