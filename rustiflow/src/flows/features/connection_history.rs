use std::collections::VecDeque;

use crate::flow_key::FlowKey;

pub(crate) const WINDOW_SIZE: usize = 100;

#[derive(Clone, Copy)]
pub(crate) struct Connection {
    pub key: FlowKey,
    pub service: &'static str,
    pub last_timestamp_us: i64,
    pub first_timestamp_us: i64,
    pub completed: bool,
}

#[derive(Clone, Default)]
pub(crate) struct ConnectionCounts {
    pub service_source: u8,
    pub service_destination: u8,
    pub destination: u8,
    pub source: u8,
    pub source_destination_port: u8,
    pub destination_source_port: u8,
    pub source_destination: u8,
}

#[derive(Default)]
pub(crate) struct ConnectionHistory {
    previous: VecDeque<Connection>,
}

impl ConnectionHistory {
    /// Count this record and the preceding 99 completed connections.
    /// A snapshot gets a count without entering the window itself.
    pub(crate) fn observe(&mut self, current: Connection) -> ConnectionCounts {
        let counts = ConnectionCounts::within(current, self.previous.iter().copied());
        if current.completed {
            if self.previous.len() == WINDOW_SIZE - 1 {
                self.previous.pop_back();
            }
            self.previous.push_front(current);
        }
        counts
    }
}

impl ConnectionCounts {
    pub(crate) fn within(current: Connection, neighbors: impl Iterator<Item = Connection>) -> Self {
        let mut counts = Self::default();
        for connection in std::iter::once(current).chain(neighbors).take(WINDOW_SIZE) {
            let source = connection.key.source.ip == current.key.source.ip;
            let destination = connection.key.destination.ip == current.key.destination.ip;
            let service = connection.service == current.service;

            counts.service_source += u8::from(service && source);
            counts.service_destination += u8::from(service && destination);
            counts.destination += u8::from(destination);
            counts.source += u8::from(source);
            counts.source_destination_port +=
                u8::from(source && connection.key.destination.port == current.key.destination.port);
            counts.destination_source_port +=
                u8::from(destination && connection.key.source.port == current.key.source.port);
            counts.source_destination += u8::from(source && destination);
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_do_not_displace_completed_connections() {
        let mut history = ConnectionHistory::default();
        let current = Connection {
            key: FlowKey::new(
                "192.0.2.1".parse().unwrap(),
                50000,
                "192.0.2.2".parse().unwrap(),
                53,
                17,
            ),
            service: "dns",
            first_timestamp_us: 0,
            last_timestamp_us: 0,
            completed: true,
        };
        assert_eq!(history.observe(current).source, 1);
        let mut other = current;
        other.key.source.port = 50001;
        for _ in 0..110 {
            let counts = history.observe(Connection {
                completed: false,
                ..other
            });
            assert_eq!((counts.source, counts.destination_source_port), (2, 1));
        }
        for _ in 0..99 {
            history.observe(other);
        }
        let counts = history.observe(current);
        assert_eq!((counts.source, counts.destination_source_port), (100, 1));
    }
}
