use std::fs::File;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::flow_key::ShardSelector;
use crate::output::FlowSink;
use crate::Flow;
use crate::{flow_table::FlowTable, packet_features::PacketFeatures};
use anyhow::{anyhow, bail, Context};
use chrono::DateTime;
use log::{debug, error, warn};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{create_reader, Block, OptionCode, PcapBlockOwned, PcapError, PcapNGOption};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet,
};
use tokio::sync::mpsc;

// Define constants for Linux cooked capture EtherTypes
const SLL_IPV4: u16 = 0x0800;
const SLL_IPV6: u16 = 0x86DD;
// Define constant for 802.1Q VLAN EtherType
const ETHERTYPE_VLAN: u16 = 0x8100;

pub async fn read_pcap_file<T>(
    path: &str,
    exporter: impl FlowSink<T>,
    num_threads: u8,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<NonZeroU64>,
    expiration_check_interval: u64,
) -> Result<(), anyhow::Error>
where
    T: Flow,
{
    let shard_count =
        NonZeroUsize::new(usize::from(num_threads)).context("thread count must be at least 1")?;

    debug!("Opening the pcap file: {:?} ...", path);

    let mut pcap_capture = match CaptureReader::open(path) {
        Ok(c) => c,
        Err(e) => {
            error!("Error opening file: {:?}", e);
            return Err(e);
        }
    };

    // Create sharded FlowTables each in their own task and route packets to them in batches
    let mut dispatcher = ShardDispatcher::new(
        shard_count,
        create_shard_senders::<T>(
            num_threads,
            exporter,
            active_timeout,
            idle_timeout,
            early_export,
            expiration_check_interval,
        ),
    );

    debug!("Reading the pcap file: {:?} ...", path);
    // A corrupt record ends the read like end of file, but is reported once
    // the packets before it have been dispatched.
    let mut read_error = None;
    loop {
        let packet = match pcap_capture.next_packet() {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(e) => {
                read_error = Some(e);
                break;
            }
        };
        // Convert TimeVal from packet capture to DateTime<Utc>
        let timestamp_us = DateTime::from_timestamp(packet.ts_sec, (packet.ts_usec * 1000) as u32)
            .unwrap()
            .timestamp_micros();

        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv4Packet>(
                            &packet,
                            timestamp_us,
                            &mut dispatcher,
                            PacketFeatures::from_ipv4_packet,
                        )
                        .await;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(packet) = Ipv6Packet::new(ethernet.payload()) {
                        process_packet::<T, Ipv6Packet>(
                            &packet,
                            timestamp_us,
                            &mut dispatcher,
                            PacketFeatures::from_ipv6_packet,
                        )
                        .await;
                    }
                }
                EtherTypes::Vlan => {
                    // Handle 802.1Q VLAN tagged packets
                    // VLAN header is 4 bytes: 2 bytes for VLAN tag and 2 bytes for inner EtherType
                    if ethernet.payload().len() >= 4 {
                        let inner_ethertype =
                            u16::from_be_bytes([ethernet.payload()[2], ethernet.payload()[3]]);

                        match inner_ethertype {
                            SLL_IPV4 => {
                                if let Some(packet) = Ipv4Packet::new(&ethernet.payload()[4..]) {
                                    process_packet::<T, Ipv4Packet>(
                                        &packet,
                                        timestamp_us,
                                        &mut dispatcher,
                                        PacketFeatures::from_ipv4_packet,
                                    )
                                    .await;
                                }
                            }
                            SLL_IPV6 => {
                                if let Some(packet) = Ipv6Packet::new(&ethernet.payload()[4..]) {
                                    process_packet::<T, Ipv6Packet>(
                                        &packet,
                                        timestamp_us,
                                        &mut dispatcher,
                                        PacketFeatures::from_ipv6_packet,
                                    )
                                    .await;
                                }
                            }
                            _ => debug!(
                                "Unsupported inner EtherType in VLAN packet: 0x{:04x}",
                                inner_ethertype
                            ),
                        }
                    } else {
                        debug!("VLAN packet too short to contain inner EtherType");
                    }
                }
                _ => {
                    // Check if it is a Linux cooked capture
                    if packet.data.len() < 16 {
                        debug!("Packet too short for Linux cooked capture header");
                        continue;
                    }

                    let ethertype = u16::from_be_bytes([packet.data[14], packet.data[15]]);
                    match ethertype {
                        SLL_IPV4 => {
                            if let Some(packet) = Ipv4Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv4Packet>(
                                    &packet,
                                    timestamp_us,
                                    &mut dispatcher,
                                    PacketFeatures::from_ipv4_packet,
                                )
                                .await;
                            }
                        }
                        SLL_IPV6 => {
                            if let Some(packet) = Ipv6Packet::new(&packet.data[16..]) {
                                process_packet::<T, Ipv6Packet>(
                                    &packet,
                                    timestamp_us,
                                    &mut dispatcher,
                                    PacketFeatures::from_ipv6_packet,
                                )
                                .await;
                            }
                        }
                        ETHERTYPE_VLAN => {
                            // Handle VLAN in Linux cooked capture
                            if packet.data.len() >= 20 {
                                // 16 bytes SLL header + 4 bytes VLAN header
                                let inner_ethertype =
                                    u16::from_be_bytes([packet.data[18], packet.data[19]]);

                                match inner_ethertype {
                                    SLL_IPV4 => {
                                        if let Some(packet) = Ipv4Packet::new(&packet.data[20..]) {
                                            process_packet::<T, Ipv4Packet>(
                                                &packet,
                                                timestamp_us,
                                                &mut dispatcher,
                                                PacketFeatures::from_ipv4_packet,
                                            )
                                            .await;
                                        }
                                    }
                                    SLL_IPV6 => {
                                        if let Some(packet) = Ipv6Packet::new(&packet.data[20..]) {
                                            process_packet::<T, Ipv6Packet>(
                                                &packet,
                                                timestamp_us,
                                                &mut dispatcher,
                                                PacketFeatures::from_ipv6_packet,
                                            )
                                            .await;
                                        }
                                    }
                                    _ => debug!(
                                        "Unsupported inner EtherType in VLAN packet: 0x{:04x}",
                                        inner_ethertype
                                    ),
                                }
                            } else {
                                debug!("VLAN packet in Linux cooked capture too short");
                            }
                        }
                        _ => debug!("Failed to parse packet as IPv4 or IPv6..."),
                    }
                }
            }
        } else {
            error!("Error parsing packet...");
        }
    }
    dispatcher.flush().await;
    if let Some(e) = read_error {
        return Err(e.context(format!("stopped reading {path}")));
    }
    debug!("Finished reading the pcap file: {:?}", path);
    Ok(())
}

/// libpcap's `MAXIMUM_SNAPLEN`: no Ethernet or Linux cooked capture record
/// may be longer, and files that declare no snapshot length get this one.
const MAXIMUM_SNAPLEN: u32 = 262_144;
/// pcapng block type of the Packet Block that Enhanced Packet Blocks replaced.
const OBSOLETE_PACKET_BLOCK: u32 = 2;
/// Streaming read buffer. Each record must fit in it whole, so it is
/// comfortably larger than `MAXIMUM_SNAPLEN` plus a record header.
const READ_BUFFER_BYTES: usize = 1 << 20;

/// One captured frame, with the timestamp libpcap would have reported at its
/// default microsecond precision.
struct CapturedPacket<'a> {
    ts_sec: i64,
    ts_usec: i64,
    data: &'a [u8],
}

/// Streams the packets of a classic pcap or pcapng file through a fixed-size
/// buffer, with the semantics of libpcap's `pcap_next_ex`: timestamps are
/// truncated to microseconds and frames are cut to the snapshot length.
///
/// End of file and a truncated final record both end the stream; the latter
/// with a warning. A record that cannot be framed is an error.
struct CaptureReader {
    blocks: Box<dyn PcapReaderIterator + Send>,
    /// Length of the block that held the packet returned last. It is consumed
    /// at the next call, because the returned packet borrows the read buffer.
    returned_len: usize,
    format: CaptureFormat,
}

enum CaptureFormat {
    Pcap {
        nanosecond: bool,
        big_endian: bool,
        snaplen: u32,
    },
    PcapNg {
        /// Byte order of the current section.
        big_endian: bool,
        /// Interfaces of the current section, indexed by interface ID.
        interfaces: Vec<PcapNgInterface>,
        /// Snapshot length of the first interface in the file, which is what
        /// libpcap applies to every packet.
        snaplen: Option<u32>,
    },
}

struct PcapNgInterface {
    /// Timestamp units per second, from `if_tsresol`.
    units_per_second: u64,
    /// Seconds added to every timestamp, from `if_tsoffset`.
    offset_seconds: i64,
}

impl CaptureReader {
    fn open(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {path}"))?;
        let mut blocks = create_reader(READ_BUFFER_BYTES, file)
            .map_err(|e| anyhow!("{path} is not a pcap or pcapng file: {e}"))?;
        // The legacy reader yields its file header as the first block, and a
        // pcapng file must start with a Section Header Block.
        let (len, format) = match blocks.next() {
            Ok((len, PcapBlockOwned::LegacyHeader(header))) => (
                len,
                CaptureFormat::Pcap {
                    nanosecond: header.is_nanosecond_precision(),
                    big_endian: header.is_bigendian(),
                    snaplen: effective_snaplen(header.snaplen),
                },
            ),
            Ok((len, PcapBlockOwned::NG(Block::SectionHeader(shb)))) => (
                len,
                CaptureFormat::PcapNg {
                    big_endian: shb.big_endian(),
                    interfaces: Vec::new(),
                    snaplen: None,
                },
            ),
            Ok((_, PcapBlockOwned::Legacy(_) | PcapBlockOwned::NG(_))) => {
                bail!("{path} does not start with a capture file header")
            }
            Err(e) => bail!("cannot read the header of {path}: {e}"),
        };
        blocks.consume(len);
        Ok(Self {
            blocks,
            returned_len: 0,
            format,
        })
    }

    fn next_packet(&mut self) -> anyhow::Result<Option<CapturedPacket<'_>>> {
        loop {
            self.blocks.consume(std::mem::take(&mut self.returned_len));
            let offset = self.blocks.consumed();
            let buffer_start = self.blocks.data().as_ptr() as usize;
            // The borrow `next` returns cannot leave the loop iteration, so a
            // packet's frame is recorded as a range of the read buffer and
            // borrowed again below. `next` parses the buffer without moving it.
            let (ts_sec, ts_usec, frame) = match self.blocks.next() {
                Ok((len, block)) => {
                    self.returned_len = len;
                    let Some(packet) = self.format.packet(block, offset)? else {
                        continue;
                    };
                    let start = (packet.data.as_ptr() as usize)
                        .checked_sub(buffer_start)
                        .expect("packet data lies in the read buffer");
                    let frame = start..start + packet.data.len();
                    (packet.ts_sec, packet.ts_usec, frame)
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = self.blocks.refill() {
                        bail!("read failed at offset {offset}: {e}");
                    }
                    continue;
                }
                Err(PcapError::UnexpectedEof) => {
                    self.format
                        .check_truncated_record(self.blocks.data(), offset)?;
                    warn!(
                        "Capture file ends inside the record at offset {offset}; ignoring that record"
                    );
                    return Ok(None);
                }
                Err(PcapError::BufferTooSmall) => {
                    bail!(
                        "corrupt record at offset {offset}: longer than {READ_BUFFER_BYTES} bytes"
                    )
                }
                Err(e) => bail!("corrupt record at offset {offset}: {e}"),
            };
            let buffer = self.blocks.data();
            assert_eq!(buffer.as_ptr() as usize, buffer_start);
            return Ok(Some(CapturedPacket {
                ts_sec,
                ts_usec,
                data: &buffer[frame],
            }));
        }
    }
}

impl CaptureFormat {
    /// Returns the packet a block carries, or updates the reader state for a
    /// block that carries none.
    fn packet<'a>(
        &mut self,
        block: PcapBlockOwned<'a>,
        offset: usize,
    ) -> anyhow::Result<Option<CapturedPacket<'a>>> {
        match (self, block) {
            (
                CaptureFormat::Pcap {
                    nanosecond,
                    snaplen,
                    ..
                },
                PcapBlockOwned::Legacy(record),
            ) => {
                check_legacy_caplen(record.caplen, offset)?;
                let ts_usec = if *nanosecond {
                    record.ts_usec / 1000
                } else {
                    record.ts_usec
                };
                Ok(Some(CapturedPacket {
                    ts_sec: i64::from(record.ts_sec),
                    ts_usec: i64::from(ts_usec),
                    data: truncate_to_snaplen(record.data, *snaplen),
                }))
            }
            (
                CaptureFormat::PcapNg {
                    big_endian,
                    interfaces,
                    snaplen,
                },
                PcapBlockOwned::NG(block),
            ) => match block {
                Block::SectionHeader(shb) => {
                    *big_endian = shb.big_endian();
                    interfaces.clear();
                    Ok(None)
                }
                Block::InterfaceDescription(idb) => {
                    let units_per_second = units_per_second(idb.if_tsresol).with_context(|| {
                        format!(
                            "corrupt interface at offset {offset}: invalid if_tsresol {}",
                            idb.if_tsresol
                        )
                    })?;
                    snaplen.get_or_insert(effective_snaplen(idb.snaplen));
                    interfaces.push(PcapNgInterface {
                        units_per_second,
                        offset_seconds: if_tsoffset(&idb.options, *big_endian),
                    });
                    Ok(None)
                }
                Block::EnhancedPacket(epb) => {
                    let interface = pcapng_interface(interfaces, epb.if_id, offset)?;
                    let units = (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                    let (ts_sec, ts_usec) = interface.timestamp(units, offset)?;
                    Ok(Some(CapturedPacket {
                        ts_sec,
                        ts_usec,
                        data: truncate_to_snaplen(
                            &epb.data[..epb.data.len().min(epb.caplen as usize)],
                            snaplen.unwrap_or(MAXIMUM_SNAPLEN),
                        ),
                    }))
                }
                // A Simple Packet Block belongs to interface 0 and carries no
                // timestamp; libpcap reports it at the interface offset.
                Block::SimplePacket(spb) => {
                    let interface = pcapng_interface(interfaces, 0, offset)?;
                    let (ts_sec, ts_usec) = interface.timestamp(0, offset)?;
                    Ok(Some(CapturedPacket {
                        ts_sec,
                        ts_usec,
                        data: truncate_to_snaplen(
                            &spb.data[..spb.data.len().min(spb.origlen as usize)],
                            snaplen.unwrap_or(MAXIMUM_SNAPLEN),
                        ),
                    }))
                }
                Block::NameResolution(_)
                | Block::InterfaceStatistics(_)
                | Block::SystemdJournalExport(_)
                | Block::DecryptionSecrets(_)
                | Block::ProcessInformation(_)
                | Block::Custom(_) => Ok(None),
                Block::Unknown(unknown) => {
                    // pcap-parser reads the type as little-endian.
                    let block_type = if *big_endian {
                        unknown.block_type.swap_bytes()
                    } else {
                        unknown.block_type
                    };
                    // libpcap still reads the obsolete Packet Block. Skipping
                    // it would drop packets silently.
                    if block_type == OBSOLETE_PACKET_BLOCK {
                        bail!("unsupported obsolete pcapng Packet Block at offset {offset}");
                    }
                    Ok(None)
                }
            },
            (_, PcapBlockOwned::LegacyHeader(_)) => {
                bail!("corrupt file: second pcap file header at offset {offset}")
            }
            (CaptureFormat::Pcap { .. }, PcapBlockOwned::NG(_))
            | (CaptureFormat::PcapNg { .. }, PcapBlockOwned::Legacy(_)) => {
                bail!("corrupt file: mixed pcap and pcapng records at offset {offset}")
            }
        }
    }

    /// Fails if the record that runs past the end of the file was never a
    /// plausible record, so that corruption is not mistaken for a capture that
    /// was cut short while being written.
    fn check_truncated_record(&self, remaining: &[u8], offset: usize) -> anyhow::Result<()> {
        match self {
            CaptureFormat::Pcap { big_endian, .. } => {
                let Some(caplen) = remaining.get(8..12) else {
                    return Ok(());
                };
                let caplen = [caplen[0], caplen[1], caplen[2], caplen[3]];
                let caplen = if *big_endian {
                    u32::from_be_bytes(caplen)
                } else {
                    u32::from_le_bytes(caplen)
                };
                check_legacy_caplen(caplen, offset)
            }
            // pcapng blocks carry their own length, which the parser has
            // already checked against the block structure.
            CaptureFormat::PcapNg { .. } => Ok(()),
        }
    }
}

impl PcapNgInterface {
    /// Splits a timestamp in interface units into seconds and microseconds,
    /// truncating like libpcap does when it scales to microseconds.
    fn timestamp(&self, units: u64, offset: usize) -> anyhow::Result<(i64, i64)> {
        let seconds = i64::try_from(units / self.units_per_second)
            .ok()
            .and_then(|seconds| seconds.checked_add(self.offset_seconds))
            .with_context(|| {
                format!("corrupt packet at offset {offset}: timestamp out of range")
            })?;
        let fraction = u128::from(units % self.units_per_second);
        let micros = fraction * 1_000_000 / u128::from(self.units_per_second);
        // `fraction` is below `units_per_second`, so `micros` is below 10^6.
        Ok((seconds, micros as i64))
    }
}

/// Decodes `if_tsoffset` in the section's byte order. pcap-parser's own
/// decoder always reads it as little-endian.
fn if_tsoffset(options: &[PcapNGOption], big_endian: bool) -> i64 {
    options
        .iter()
        .find(|option| option.code == OptionCode::IfTsoffset)
        .and_then(|option| option.value.get(..8))
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(0, |bytes| {
            if big_endian {
                i64::from_be_bytes(bytes)
            } else {
                i64::from_le_bytes(bytes)
            }
        })
}

/// Decodes `if_tsresol`: 10^n units per second, or 2^n when the top bit is
/// set. pcap-parser's own decoder rejects every binary resolution.
fn units_per_second(if_tsresol: u8) -> Option<u64> {
    let exponent = u32::from(if_tsresol & 0x7f);
    if if_tsresol & 0x80 == 0 {
        10_u64.checked_pow(exponent)
    } else {
        1_u64.checked_shl(exponent)
    }
}

fn pcapng_interface(
    interfaces: &[PcapNgInterface],
    interface_id: u32,
    offset: usize,
) -> anyhow::Result<&PcapNgInterface> {
    usize::try_from(interface_id)
        .ok()
        .and_then(|index| interfaces.get(index))
        .with_context(|| {
            format!("corrupt packet at offset {offset}: no interface with ID {interface_id}")
        })
}

/// libpcap rejects a classic pcap record longer than `MAXIMUM_SNAPLEN` as
/// corrupt instead of reading it.
fn check_legacy_caplen(caplen: u32, offset: usize) -> anyhow::Result<()> {
    if caplen > MAXIMUM_SNAPLEN {
        bail!(
            "corrupt record at offset {offset}: capture length {caplen} exceeds {MAXIMUM_SNAPLEN}"
        );
    }
    Ok(())
}

/// libpcap treats a snapshot length of 0, or one above `MAXIMUM_SNAPLEN`, as
/// `MAXIMUM_SNAPLEN`.
fn effective_snaplen(snaplen: u32) -> u32 {
    if snaplen == 0 || snaplen > MAXIMUM_SNAPLEN {
        MAXIMUM_SNAPLEN
    } else {
        snaplen
    }
}

/// libpcap never returns more of a frame than the file's snapshot length.
fn truncate_to_snaplen(data: &[u8], snaplen: u32) -> &[u8] {
    &data[..data.len().min(snaplen as usize)]
}

/// Packets routed to a shard per channel send.
const SHARD_BATCH_SIZE: usize = 128;
/// Batches that may wait for a shard (about 10k packets).
const SHARD_QUEUE_CAPACITY: usize = 10_000 / SHARD_BATCH_SIZE;

/// Routes packets to shard tasks in per-shard batches, preserving each shard's
/// packet order while amortizing channel sends and wakeups.
struct ShardDispatcher {
    selector: ShardSelector,
    senders: Vec<mpsc::Sender<Vec<PacketFeatures>>>,
    pending: Vec<Vec<PacketFeatures>>,
}

impl ShardDispatcher {
    fn new(shard_count: NonZeroUsize, senders: Vec<mpsc::Sender<Vec<PacketFeatures>>>) -> Self {
        Self {
            selector: ShardSelector::new(shard_count),
            pending: senders
                .iter()
                .map(|_| Vec::with_capacity(SHARD_BATCH_SIZE))
                .collect(),
            senders,
        }
    }

    async fn dispatch(&mut self, packet_features: PacketFeatures) {
        let shard_index = self
            .selector
            .shard_index(&packet_features.biflow_key_value());
        self.pending[shard_index].push(packet_features);
        if self.pending[shard_index].len() >= SHARD_BATCH_SIZE {
            self.send_pending(shard_index).await;
        }
    }

    /// Sends every partially filled batch.
    async fn flush(&mut self) {
        for shard_index in 0..self.pending.len() {
            if !self.pending[shard_index].is_empty() {
                self.send_pending(shard_index).await;
            }
        }
    }

    async fn send_pending(&mut self, shard_index: usize) {
        let batch = std::mem::replace(
            &mut self.pending[shard_index],
            Vec::with_capacity(SHARD_BATCH_SIZE),
        );
        if let Err(e) = self.senders[shard_index].send(batch).await {
            error!(
                "Failed to send packet batch to shard {}: {}",
                shard_index, e
            );
        }
    }
}

/// Extracts packet features and routes them to the appropriate shard.
async fn process_packet<T, P>(
    packet: &P,
    timestamp_us: i64,
    dispatcher: &mut ShardDispatcher,
    extractor: fn(&P, i64) -> Option<PacketFeatures>,
) where
    T: Flow,
    P: Packet,
{
    if let Some(packet_features) = extractor(packet, timestamp_us) {
        dispatcher.dispatch(packet_features).await;
    }
}

/// Creates shard channels to FlowTables and spawns processing tasks for each shard.
fn create_shard_senders<T>(
    num_shards: u8,
    exporter: impl FlowSink<T>,
    active_timeout: u64,
    idle_timeout: u64,
    early_export: Option<NonZeroU64>,
    expiration_check_interval: u64,
) -> Vec<mpsc::Sender<Vec<PacketFeatures>>>
where
    T: Flow,
{
    debug!("Creating {} sharded FlowTables...", num_shards);
    let mut shard_senders = Vec::with_capacity(num_shards as usize);
    for _ in 0..num_shards {
        let (tx, mut rx) = mpsc::channel::<Vec<PacketFeatures>>(SHARD_QUEUE_CAPACITY);
        let mut flow_table = FlowTable::new(
            active_timeout,
            idle_timeout,
            early_export,
            exporter.shard_sender(),
            expiration_check_interval,
        );

        tokio::spawn(async move {
            let mut last_timestamp = None;
            while let Some(packet_batch) = rx.recv().await {
                for packet_features in packet_batch {
                    last_timestamp = Some(packet_features.timestamp_us);
                    flow_table.process_packet(&packet_features).await;
                }
            }
            // Handle flow exporting when the receiver is closed
            if let Some(timestamp) = last_timestamp {
                flow_table.export_all_flows(timestamp).await;
            }
        });
        shard_senders.push(tx);
    }
    debug!("Sharded FlowTables created");

    shard_senders
}
