use crate::packet_features::PacketFeatures;

#[derive(Clone, Default)]
pub(crate) enum TcpSetup {
    #[default]
    Unseen,
    Syn {
        timestamp_us: i64,
        expected_ack: u32,
    },
    SynAck {
        timestamp_us: i64,
        synack_us: i64,
        expected_ack: u32,
    },
    Complete {
        synack_us: i64,
        ackdat_us: i64,
    },
}

impl TcpSetup {
    /// Measure a sequence-validated three-way handshake using the first
    /// observed SYN and SYN-ACK. Call only for TCP packets.
    pub(crate) fn observe(&mut self, packet: &PacketFeatures, forward: bool) {
        let timestamp_us = packet.timestamp_us;
        let expected_ack = || {
            packet
                .sequence_number
                .wrapping_add(1 + u32::from(packet.data_length))
        };

        match *self {
            Self::Unseen if forward && packet.syn_flag != 0 && packet.ack_flag == 0 => {
                *self = Self::Syn {
                    timestamp_us,
                    expected_ack: expected_ack(),
                };
            }
            Self::Syn {
                timestamp_us: syn,
                expected_ack: ack,
            } if !forward
                && packet.syn_flag != 0
                && packet.ack_flag != 0
                && packet.sequence_number_ack == ack
                && timestamp_us >= syn =>
            {
                *self = Self::SynAck {
                    timestamp_us,
                    synack_us: timestamp_us.saturating_sub(syn),
                    expected_ack: expected_ack(),
                };
            }
            Self::SynAck {
                timestamp_us: synack,
                synack_us,
                expected_ack,
            } if forward
                && packet.syn_flag == 0
                && packet.ack_flag != 0
                && packet.rst_flag == 0
                && packet.sequence_number_ack == expected_ack
                && timestamp_us >= synack =>
            {
                *self = Self::Complete {
                    synack_us,
                    ackdat_us: timestamp_us.saturating_sub(synack),
                };
            }
            Self::Unseen | Self::Syn { .. } | Self::SynAck { .. } | Self::Complete { .. } => {}
        }
    }

    pub(crate) fn intervals_seconds(&self) -> (f64, f64) {
        let (synack, ackdat) = match *self {
            Self::Unseen | Self::Syn { .. } => (0, 0),
            Self::SynAck { synack_us, .. } => (synack_us, 0),
            Self::Complete {
                synack_us,
                ackdat_us,
            } => (synack_us, ackdat_us),
        };
        (synack as f64 / 1_000_000.0, ackdat as f64 / 1_000_000.0)
    }
}
