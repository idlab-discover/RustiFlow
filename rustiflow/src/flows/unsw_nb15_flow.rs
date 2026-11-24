use std::net::IpAddr;

use crate::{flow_key::FlowKey, packet_features::PacketFeatures};

use super::{
    basic_flow::{BasicFlow, TcpCloseStyle},
    features::{
        application::{ApplicationProtocol, ApplicationStats},
        connection_history::{Connection, ConnectionCounts},
        iat_stats::IATStats,
        retransmission_stats::RetransmissionStats,
        tcp_setup::TcpSetup,
        util::{safe_div, FlowFeature},
    },
    flow::Flow,
    row::{fields, Record},
    util::FlowExpireCause,
};

const ENDPOINTS: &str = "srcip,sport,dstip,dsport";
const BASIC: &str =
    "proto,state,dur,sbytes,dbytes,sttl,dttl,sloss,dloss,service,Sload,Dload,Spkts,Dpkts,swin,dwin";
const CONTENT: &str = "smeansz,dmeansz,trans_depth,res_bdy_len,Sjit,Djit";
const TIMING: &str = "Sintpkt,Dintpkt,tcprtt,synack,ackdat";
const GENERAL: &str = "is_sm_ips_ports,ct_state_ttl,ct_flw_http_mthd,is_ftp_login,ct_ftp_cmd";
const CONNECTION: &str =
    "ct_srv_src,ct_srv_dst,ct_dst_ltm,ct_src_ltm,ct_src_dport_ltm,ct_dst_sport_ltm,ct_dst_src_ltm";

#[derive(Clone, Default)]
struct Direction {
    bytes: i64,
    packets: i64,
    first_ttl: u8,
    first_window: u16,
    first_sequence: u32,
}

impl Direction {
    fn observe(&mut self, packet: &PacketFeatures) {
        if self.packets == 0 {
            self.first_ttl = packet.ttl;
            self.first_window = packet.window_size;
            self.first_sequence = packet.sequence_number;
        }
        self.bytes += i64::from(packet.length);
        self.packets += 1;
    }

    fn mean_size(&self) -> i64 {
        self.bytes.checked_div(self.packets).unwrap_or(0)
    }

    fn load(&self, duration: f64) -> f64 {
        safe_div((self.bytes - self.mean_size()) as f64 * 8.0, duration)
    }
}

#[derive(Clone)]
pub(crate) struct UnswNb15Flow {
    basic: BasicFlow,
    source: Direction,
    destination: Direction,
    iat: IATStats,
    retransmissions: RetransmissionStats,
    setup: TcpSetup,
    application: Option<Box<ApplicationStats>>,
    service: &'static str,
    forward_from_client: bool,
    first_icmp_type: Option<u8>,
    counts: ConnectionCounts,
}

impl UnswNb15Flow {
    fn protocol_name(&self) -> &'static str {
        match self.basic.protocol {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            58 => "ipv6-icmp",
            _ => "-",
        }
    }

    fn state(&self) -> &'static str {
        let bidirectional = self.source.packets > 0 && self.destination.packets > 0;
        match self.basic.protocol {
            6 => match self.basic.tcp_close_style {
                TcpCloseStyle::Reset => "RST",
                TcpCloseStyle::FourWayFin | TcpCloseStyle::SimultaneousFin => "FIN",
                TcpCloseStyle::BidirectionalFin | TcpCloseStyle::HalfClose => "CLO",
                TcpCloseStyle::None | TcpCloseStyle::NotApplicable => {
                    if self.basic.tcp_handshake_completed {
                        "CON"
                    } else if matches!(self.setup, TcpSetup::SynAck { .. }) {
                        "ACC"
                    } else if matches!(self.setup, TcpSetup::Syn { .. }) {
                        "REQ"
                    } else if bidirectional {
                        "CON"
                    } else {
                        "INT"
                    }
                }
            },
            1 | 58 => match (self.basic.protocol, self.first_icmp_type) {
                (1, Some(8)) | (58, Some(128)) => "ECO",
                (1, Some(0)) | (58, Some(129)) => "ECR",
                (1, Some(3)) | (58, Some(1)) => "URN",
                (1, Some(11)) | (58, Some(3)) => "TXD",
                _ => "-",
            },
            17 if bidirectional => "CON",
            17 => "INT",
            _ => "-",
        }
    }

    fn write(&self, row: &mut impl Record, clean: bool) {
        let basic = &self.basic;
        let src = &self.source;
        let dst = &self.destination;
        let duration = basic.get_flow_duration_usec() as f64 / 1_000_000.0;
        let state = self.state();
        if !clean {
            fields!(
                row,
                basic.ip_source,
                basic.port_source,
                basic.ip_destination,
                basic.port_destination
            );
        }
        fields!(
            row,
            self.protocol_name(),
            state,
            duration,
            src.bytes,
            dst.bytes,
            src.first_ttl,
            dst.first_ttl,
            self.retransmissions.fwd_retransmission_count,
            self.retransmissions.bwd_retransmission_count,
            self.service,
            src.load(duration),
            dst.load(duration),
            src.packets,
            dst.packets,
            src.first_window,
            dst.first_window,
        );
        if !clean {
            fields!(row, src.first_sequence, dst.first_sequence);
        }
        let app = self
            .application
            .as_deref()
            .map_or_else(Default::default, ApplicationStats::fields);
        fields!(
            row,
            src.mean_size(),
            dst.mean_size(),
            app.transaction_depth,
            app.response_body_length,
            self.iat.fwd_iat.get_std(),
            self.iat.bwd_iat.get_std(),
        );
        if !clean {
            fields!(
                row,
                basic.first_timestamp_us.div_euclid(1_000_000),
                basic.last_timestamp_us.div_euclid(1_000_000),
            );
        }
        let (synack, ackdat) = self.setup.intervals_seconds();
        let same_endpoint =
            basic.ip_source == basic.ip_destination && basic.port_source == basic.port_destination;
        fields!(
            row,
            self.iat.fwd_iat.get_mean(),
            self.iat.bwd_iat.get_mean(),
            synack + ackdat,
            synack,
            ackdat,
            u8::from(same_endpoint),
            state_ttl(state, src.first_ttl, dst.first_ttl),
            app.http_methods,
            app.ftp_login,
            app.ftp_commands,
        );
        let counts = &self.counts;
        fields!(
            row,
            counts.service_source,
            counts.service_destination,
            counts.destination,
            counts.source,
            counts.source_destination_port,
            counts.destination_source_port,
            counts.source_destination,
        );
    }
}

fn service_for_port(protocol: u8, port: u16) -> &'static str {
    match (protocol, port) {
        (6, 20) => "ftp-data",
        (6, 21) => "ftp",
        (6, 22) => "ssh",
        (6, 25 | 587) => "smtp",
        (6 | 17, 53) => "dns",
        (6, 80 | 8000 | 8080) => "http",
        (6, 110) => "pop3",
        (6, 143) => "imap",
        (17, 161 | 162) => "snmp",
        (6, 443) => "ssl",
        (17, 67 | 68) => "dhcp",
        (6, 6667) => "irc",
        (6, 1812 | 1813) | (17, 1812 | 1813) => "radius",
        _ => "-",
    }
}

fn state_ttl(state: &str, source: u8, destination: u8) -> u8 {
    match (state, source, destination) {
        ("FIN", 62 | 63 | 254 | 255, 252 | 253) => 1,
        ("INT", 0 | 62 | 254, 0) => 2,
        ("CON", 62 | 254, 60 | 252 | 253) => 3,
        ("ACC", 254, 252) => 4,
        ("CLO", 254, 252) => 5,
        ("REQ", 254, 0) => 6,
        _ => 0,
    }
}

impl Flow for UnswNb15Flow {
    const CAPTURE_TCP_PAYLOAD: bool = true;
    const USES_CONNECTION_HISTORY: bool = true;

    fn new(
        key: String,
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self {
        let destination_service = service_for_port(protocol, destination_port);
        let forward_from_client = destination_service != "-";
        let service = if forward_from_client {
            destination_service
        } else {
            service_for_port(protocol, source_port)
        };
        let application = match service {
            "http" => Some(ApplicationProtocol::Http),
            "ftp" => Some(ApplicationProtocol::Ftp),
            _ => None,
        }
        .map(|protocol| Box::new(ApplicationStats::new(protocol)));
        Self {
            basic: BasicFlow::new(
                key,
                source,
                source_port,
                destination,
                destination_port,
                protocol,
                timestamp_us,
            ),
            source: Direction::default(),
            destination: Direction::default(),
            iat: IATStats::new(),
            retransmissions: RetransmissionStats::new(),
            setup: TcpSetup::default(),
            application,
            service,
            forward_from_client,
            first_icmp_type: None,
            counts: ConnectionCounts::default(),
        }
    }

    fn connection(&self) -> Option<Connection> {
        let basic = &self.basic;
        Some(Connection {
            key: FlowKey::new(
                basic.ip_source,
                basic.port_source,
                basic.ip_destination,
                basic.port_destination,
                basic.protocol,
            ),
            service: self.service,
            first_timestamp_us: basic.first_timestamp_us,
            last_timestamp_us: basic.last_timestamp_us,
            completed: basic.flow_expire_cause != FlowExpireCause::None,
        })
    }

    fn set_connection_counts(&mut self, counts: ConnectionCounts) {
        self.counts = counts;
    }

    fn update_flow(&mut self, packet: &PacketFeatures, forward: bool) -> bool {
        if forward {
            self.source.observe(packet);
        } else {
            self.destination.observe(packet);
        }
        self.first_icmp_type = self.first_icmp_type.or(packet.icmp_type);
        let previous_timestamp = self.basic.last_timestamp_us;
        self.iat.update(packet, forward, previous_timestamp);
        self.retransmissions
            .update(packet, forward, previous_timestamp);
        if packet.protocol == 6 {
            self.setup.observe(packet, forward);
        }
        if let Some(application) = self.application.as_deref_mut() {
            application.observe(packet, forward == self.forward_from_client);
        }
        self.basic.update_flow(packet, forward)
    }

    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause) {
        self.basic.close_flow(timestamp_us, cause);
    }

    fn write_fields(&self, output: &mut impl Record) {
        self.write(output, false);
    }

    fn write_clean_fields(&self, output: &mut impl Record) {
        self.write(output, true);
    }

    fn get_first_timestamp_us(&self) -> i64 {
        self.basic.first_timestamp_us
    }

    fn get_features() -> String {
        [
            ENDPOINTS,
            BASIC,
            "stcpb,dtcpb",
            CONTENT,
            "Stime,Ltime",
            TIMING,
            GENERAL,
            CONNECTION,
        ]
        .join(",")
    }

    fn get_features_without_contamination() -> String {
        [BASIC, CONTENT, TIMING, GENERAL, CONNECTION].join(",")
    }

    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause) {
        self.basic
            .is_expired(timestamp_us, active_timeout, idle_timeout)
    }

    #[cfg(feature = "experiment-deadline-index")]
    fn expiration_deadline_us(&self, active_timeout: u64, idle_timeout: u64) -> Option<i64> {
        self.basic
            .expiration_deadline_us(active_timeout, idle_timeout)
    }
}
