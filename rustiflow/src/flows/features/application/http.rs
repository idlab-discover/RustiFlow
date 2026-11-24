use std::collections::VecDeque;

use crate::packet_features::PacketFeatures;

use super::{ApplicationFields, TcpStream, MAX_HEADER_BYTES, UNAVAILABLE};

const MAX_PENDING_REQUESTS: usize = 128;

#[derive(Clone, Default)]
pub(crate) struct HttpStats {
    requests: HttpDirection,
    responses: HttpDirection,
    pending: VecDeque<RequestKind>,
    request_count: i64,
    response_bytes: i64,
    body_size_unknown: bool,
    tunneled: bool,
}

#[derive(Clone, Default)]
struct HttpDirection {
    stream: TcpStream,
    header: Vec<u8>,
    body: Body,
}

#[derive(Clone, Default, PartialEq)]
enum Body {
    #[default]
    None,
    Fixed(u64),
    UntilClose,
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailers,
}

impl Body {
    fn consume(&mut self, payload: &mut &[u8], line: &mut Vec<u8>) -> Option<usize> {
        match *self {
            Self::Fixed(remaining) | Self::ChunkData(remaining) => {
                let fixed = matches!(self, Self::Fixed(_));
                let count = remaining.min(payload.len() as u64);
                *payload = &payload[count as usize..];
                let remaining = remaining - count;
                *self = match (fixed, remaining) {
                    (true, 0) => Self::None,
                    (true, _) => Self::Fixed(remaining),
                    (false, 0) => Self::ChunkEnd,
                    (false, _) => Self::ChunkData(remaining),
                };
                Some(count as usize)
            }
            Self::UntilClose => Some(std::mem::take(payload).len()),
            Self::ChunkSize | Self::ChunkEnd | Self::Trailers => {
                while let Some((&byte, rest)) = payload.split_first() {
                    *payload = rest;
                    line.push(byte);
                    if line.ends_with(b"\r\n") {
                        *self = match *self {
                            Self::ChunkSize => {
                                let httparse::Status::Complete((_, length)) =
                                    httparse::parse_chunk_size(line).ok()?
                                else {
                                    return None;
                                };
                                if length == 0 {
                                    Self::Trailers
                                } else {
                                    Self::ChunkData(length)
                                }
                            }
                            Self::ChunkEnd if line == b"\r\n" => Self::ChunkSize,
                            Self::Trailers if line == b"\r\n" => Self::None,
                            Self::Trailers => Self::Trailers,
                            _ => return None,
                        };
                        line.clear();
                        return Some(0);
                    }
                    if line.len() >= MAX_HEADER_BYTES {
                        return None;
                    }
                }
                Some(0)
            }
            Self::None => unreachable!("only active bodies consume bytes"),
        }
    }

    fn complete(&self) -> bool {
        matches!(self, Self::None | Self::UntilClose)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Head,
    Connect,
    Other,
}

impl HttpStats {
    pub(super) fn observe(&mut self, packet: &PacketFeatures, from_client: bool) {
        if self.tunneled {
            return;
        }
        let direction = if from_client {
            &mut self.requests
        } else {
            &mut self.responses
        };
        let Some(mut payload) = direction.stream.observe(packet) else {
            direction.header.clear();
            return;
        };

        while !payload.is_empty() {
            if direction.body != Body::None {
                let Some(consumed) = direction.body.consume(&mut payload, &mut direction.header)
                else {
                    direction.stream.incomplete = true;
                    direction.header.clear();
                    return;
                };
                if !from_client {
                    self.response_bytes = self.response_bytes.saturating_add(consumed as i64);
                }
                continue;
            }

            let header = &mut direction.header;
            // Stop at the first complete header, even if the packet also
            // contains a body or the next pipelined message.
            while let Some((&byte, rest)) = payload.split_first() {
                payload = rest;
                header.push(byte);
                if header.ends_with(b"\r\n\r\n") || header.len() == MAX_HEADER_BYTES {
                    break;
                }
            }
            if !header.ends_with(b"\r\n\r\n") && header.len() < MAX_HEADER_BYTES {
                return;
            }

            let parsed = if from_client {
                parse_request(header).and_then(|(kind, framing)| {
                    if self.pending.len() == MAX_PENDING_REQUESTS {
                        return None;
                    }
                    self.pending.push_back(kind);
                    self.request_count += 1;
                    Some(framing)
                })
            } else {
                parse_response(header).map(|(status, framing)| {
                    let request = if status < 200 && status != 101 {
                        self.pending.front().copied()
                    } else {
                        self.pending.pop_front()
                    };
                    if status == 101
                        || (request == Some(RequestKind::Connect) && (200..300).contains(&status))
                    {
                        self.tunneled = true;
                    }
                    if self.tunneled
                        || status < 200
                        || matches!(status, 204 | 304)
                        || request == Some(RequestKind::Head)
                    {
                        MessageFraming::default()
                    } else {
                        self.body_size_unknown |= framing.encoded;
                        framing
                    }
                })
            };
            header.clear();
            let Some(framing) = parsed else {
                direction.stream.incomplete = true;
                return;
            };
            if self.tunneled {
                return;
            }
            direction.body = match (framing.chunked, framing.length) {
                (true, _) => Body::ChunkSize,
                (false, Some(0)) => Body::None,
                (false, Some(length)) => Body::Fixed(length),
                (false, None) => Body::UntilClose,
            };
        }
    }

    pub(super) fn fields(&self) -> ApplicationFields {
        let methods = if self.requests.header.is_empty() && self.requests.body.complete() {
            self.requests.stream.count(self.request_count)
        } else {
            UNAVAILABLE
        };
        ApplicationFields {
            transaction_depth: methods,
            http_methods: methods,
            response_body_length: if self.body_size_unknown
                || !self.responses.body.complete()
                || !self.responses.header.is_empty()
            {
                UNAVAILABLE
            } else {
                self.responses.stream.count(self.response_bytes)
            },
            ..ApplicationFields::default()
        }
    }
}

struct MessageFraming {
    length: Option<u64>,
    chunked: bool,
    encoded: bool,
}

impl Default for MessageFraming {
    fn default() -> Self {
        Self {
            length: Some(0),
            chunked: false,
            encoded: false,
        }
    }
}

fn parse_request(bytes: &[u8]) -> Option<(RequestKind, MessageFraming)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if !request.parse(bytes).ok()?.is_complete() {
        return None;
    }
    let kind = match request.method? {
        "HEAD" => RequestKind::Head,
        "CONNECT" => RequestKind::Connect,
        _ => RequestKind::Other,
    };
    let mut framing = parse_framing(request.headers)?;
    framing.length = framing.length.or(Some(0));
    Some((kind, framing))
}

fn parse_response(bytes: &[u8]) -> Option<(u16, MessageFraming)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if !response.parse(bytes).ok()?.is_complete() {
        return None;
    }
    Some((response.code?, parse_framing(response.headers)?))
}

fn parse_framing(headers: &[httparse::Header<'_>]) -> Option<MessageFraming> {
    let mut framing = MessageFraming {
        length: None,
        ..MessageFraming::default()
    };
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let length = std::str::from_utf8(header.value)
                .ok()?
                .trim()
                .parse()
                .ok()?;
            if framing
                .length
                .replace(length)
                .is_some_and(|previous| previous != length)
            {
                return None;
            }
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if framing.chunked || !header.value.trim_ascii().eq_ignore_ascii_case(b"chunked") {
                return None;
            }
            framing.chunked = true;
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            framing.encoded |= !header.value.trim_ascii().eq_ignore_ascii_case(b"identity");
        }
    }
    Some(framing)
}
