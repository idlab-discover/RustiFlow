mod http;

use crate::packet_features::PacketFeatures;

use self::http::HttpStats;

/// Maximum buffered HTTP header block or FTP line.
const MAX_HEADER_BYTES: usize = 8 * 1024;
const UNAVAILABLE: i64 = -1;

#[derive(Clone, Copy)]
pub(crate) enum ApplicationProtocol {
    Http,
    Ftp,
}

impl ApplicationProtocol {
    pub(crate) fn from_ports(source: u16, destination: u16) -> Option<Self> {
        [destination, source]
            .into_iter()
            .find_map(|port| match port {
                80 | 8000 | 8080 => Some(Self::Http),
                21 => Some(Self::Ftp),
                _ => None,
            })
    }
}

#[derive(Clone)]
pub(crate) enum ApplicationStats {
    Http(HttpStats),
    Ftp(FtpStats),
}

#[derive(Default)]
pub(crate) struct ApplicationFields {
    pub transaction_depth: i64,
    pub response_body_length: i64,
    pub http_methods: i64,
    pub ftp_login: i64,
    pub ftp_commands: i64,
}

impl ApplicationStats {
    pub(crate) fn new(protocol: ApplicationProtocol) -> Self {
        match protocol {
            ApplicationProtocol::Http => Self::Http(HttpStats::default()),
            ApplicationProtocol::Ftp => Self::Ftp(FtpStats::default()),
        }
    }

    pub(crate) fn observe(&mut self, packet: &PacketFeatures, from_client: bool) {
        match self {
            Self::Http(stats) => stats.observe(packet, from_client),
            Self::Ftp(stats) if from_client => stats.observe(packet),
            Self::Ftp(_) => {}
        }
    }

    pub(crate) fn fields(&self) -> ApplicationFields {
        match self {
            Self::Http(stats) => stats.fields(),
            Self::Ftp(stats) => ApplicationFields {
                ftp_login: stats.stream.count(i64::from(stats.user && stats.pass)),
                ftp_commands: stats.stream.count(stats.commands),
                ..ApplicationFields::default()
            },
        }
    }
}

#[derive(Clone, Default)]
struct TcpStream {
    next_sequence: Option<u32>,
    incomplete: bool,
}

impl TcpStream {
    fn observe<'a>(&mut self, packet: &'a PacketFeatures) -> Option<&'a [u8]> {
        if self.incomplete {
            return None;
        }
        let Some(payload) = packet.tcp_payload.as_deref() else {
            self.incomplete = true;
            return None;
        };

        let sequence = packet
            .sequence_number
            .wrapping_add(u32::from(packet.syn_flag != 0));
        if payload.is_empty() {
            if packet.syn_flag != 0 {
                self.next_sequence.get_or_insert(sequence);
            }
            return Some(payload);
        }
        let next = self.next_sequence.get_or_insert(sequence);
        let overlap = next.wrapping_sub(sequence) as i32;
        if overlap < 0 {
            self.incomplete = true;
            return None;
        }
        let new_bytes = &payload[(overlap as usize).min(payload.len())..];
        *next = next.wrapping_add(new_bytes.len() as u32);
        Some(new_bytes)
    }

    fn count(&self, value: i64) -> i64 {
        // A direction absent from the capture has no transactions to count.
        if self.incomplete {
            UNAVAILABLE
        } else {
            value
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct FtpStats {
    stream: TcpStream,
    line: Vec<u8>,
    user: bool,
    pass: bool,
    commands: i64,
}

impl FtpStats {
    fn observe(&mut self, packet: &PacketFeatures) {
        let Some(payload) = self.stream.observe(packet) else {
            self.line.clear();
            return;
        };

        for part in payload.split_inclusive(|&byte| byte == b'\n') {
            if self.line.len() + part.len() > MAX_HEADER_BYTES {
                self.stream.incomplete = true;
                self.line.clear();
                return;
            }
            self.line.extend_from_slice(part);
            if let Some(line) = self.line.strip_suffix(b"\r\n") {
                let command_end = line
                    .iter()
                    .position(|&byte| byte == b' ')
                    .unwrap_or(line.len());
                let (command, argument) = line.split_at(command_end);
                if (3..=5).contains(&command.len()) && command.iter().all(u8::is_ascii_alphabetic) {
                    self.commands += 1;
                    let has_argument = argument.iter().any(|byte| !byte.is_ascii_whitespace());
                    self.user |= has_argument && command.eq_ignore_ascii_case(b"USER");
                    self.pass |= has_argument && command.eq_ignore_ascii_case(b"PASS");
                    if command.eq_ignore_ascii_case(b"AUTH") {
                        // Further control traffic may be encrypted.
                        self.stream.incomplete = true;
                    }
                }
                self.line.clear();
                if self.stream.incomplete {
                    return;
                }
            }
        }
    }
}
