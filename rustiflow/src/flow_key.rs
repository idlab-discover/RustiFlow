use std::{fmt, hash::BuildHasher, net::IpAddr, num::NonZeroUsize};

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
        self.canonicalize().0
    }

    /// Returns the canonical biflow key together with the orientation `self`
    /// had relative to it. A key whose endpoints are equal is canonical.
    pub fn canonicalize(self) -> (Self, KeyOrientation) {
        if self.source <= self.destination {
            (self, KeyOrientation::Canonical)
        } else {
            (self.reverse(), KeyOrientation::Reversed)
        }
    }
}

/// Direction of a packet's 5-tuple relative to its canonical biflow key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyOrientation {
    Canonical,
    Reversed,
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

/// Hash builder for flow-keyed state.
///
/// Every instance draws its own seed on top of a random per-process seed, so
/// remote traffic cannot precompute colliding keys, and independently built
/// instances (for example a shard selector and a shard's flow map) do not
/// correlate their bucket choices.
pub type FlowKeyHashBuilder = foldhash::quality::RandomState;

/// Assigns biflow keys to a fixed set of shards.
#[derive(Clone)]
pub struct ShardSelector {
    hash_builder: FlowKeyHashBuilder,
    shard_count: NonZeroUsize,
}

impl ShardSelector {
    pub fn new(shard_count: NonZeroUsize) -> Self {
        Self {
            hash_builder: FlowKeyHashBuilder::default(),
            shard_count,
        }
    }

    /// Returns the shard for `biflow_key`, in `0..shard_count`. Callers must pass
    /// the canonical key so both directions of a flow land on the same shard.
    pub fn shard_index(&self, biflow_key: &FlowKey) -> usize {
        (self.hash_builder.hash_one(biflow_key) % self.shard_count.get() as u64) as usize
    }
}
