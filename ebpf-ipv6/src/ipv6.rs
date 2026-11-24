use aya_ebpf::{helpers::bpf_ktime_get_ns, macros::map, maps::RingBuf};
use aya_log_ebpf::debug;

use common::ipv6_extensions::Ipv6Extension;
use common::{
    EbpfEventIpv6, Icmpv6Hdr, NetworkHeader, TcpHdr, UdpHdr, REALTIME_EVENT_QUEUE_COUNT,
    REALTIME_EVENT_RINGBUF_BYTES,
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv6Hdr},
};
use num_traits::FromPrimitive;

use crate::counters::{increment_counter, DROPPED_PACKETS, MATCHED_PACKETS, SUBMITTED_EVENTS};
use crate::{
    packet::{PacketContext, WireHeader},
    IPV6_COUNTER_INDEX,
};

#[map]
static EVENTS_IPV6_0: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_1: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_2: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_3: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_4: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_5: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_6: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV6_7: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

const MAX_EXT_HEADERS: usize = 8;

fn skip_ipv6_ext_headers(ctx: &impl PacketContext, start_offset: usize) -> Result<(u8, usize), ()> {
    // Load the base IPv6 header
    let ipv6hdr = ctx.load_header::<Ipv6Hdr>(start_offset)?;

    // Current offset: skip the fixed 40-byte IPv6 header
    let mut offset = start_offset + Ipv6Hdr::LEN;
    let mut next_hdr = ipv6hdr.next_hdr;

    // Unrolled loop using a fixed number of iterations
    for _ in 0..MAX_EXT_HEADERS {
        let Some(extension) = Ipv6Extension::from_next_header(next_hdr) else {
            break;
        };
        let prefix = ctx.load_header::<[u8; 4]>(offset)?;
        let length = extension.header_length(prefix).ok_or(())?;
        // Validate the full extension, not just the prefix used to decode it.
        ctx.load_header::<u8>(offset + length - 1)?;
        offset += length;
        next_hdr = prefix[0];
    }

    Ok((next_hdr, offset))
}

pub(crate) fn process_packet(ctx: &impl PacketContext) -> Result<(), ()> {
    // 1) Skip over IPv6 extension headers to find the real upper-layer protocol and offset
    let (final_proto, offset_after_ext) = skip_ipv6_ext_headers(ctx, EthHdr::LEN)?;

    // 2) Build packet_info for IPv6
    let ipv6hdr = ctx.load_header::<Ipv6Hdr>(EthHdr::LEN)?;
    let network_header_length = offset_after_ext - EthHdr::LEN;
    let packet_info = PacketInfo::new(&ipv6hdr, final_proto, network_header_length)?;

    // 3) Dispatch on the final protocol
    match IpProto::from_u8(final_proto) {
        Some(IpProto::Tcp) => {
            process_transport_packet::<TcpHdr>(ctx, &packet_info, offset_after_ext)
        }
        Some(IpProto::Udp) => {
            process_transport_packet::<UdpHdr>(ctx, &packet_info, offset_after_ext)
        }
        Some(IpProto::Ipv6Icmp) => {
            process_transport_packet::<Icmpv6Hdr>(ctx, &packet_info, offset_after_ext)
        }
        _ => Ok(()),
    }
}

#[inline(always)]
fn submit_ipv6_event(ctx: &impl PacketContext, event: EbpfEventIpv6, queue_index: u32) {
    let reserved = match queue_index {
        0 => reserve_ipv6_event(&EVENTS_IPV6_0, event),
        1 => reserve_ipv6_event(&EVENTS_IPV6_1, event),
        2 => reserve_ipv6_event(&EVENTS_IPV6_2, event),
        3 => reserve_ipv6_event(&EVENTS_IPV6_3, event),
        4 => reserve_ipv6_event(&EVENTS_IPV6_4, event),
        5 => reserve_ipv6_event(&EVENTS_IPV6_5, event),
        6 => reserve_ipv6_event(&EVENTS_IPV6_6, event),
        _ => reserve_ipv6_event(&EVENTS_IPV6_7, event),
    };

    if !reserved {
        increment_counter(&DROPPED_PACKETS, IPV6_COUNTER_INDEX);
        debug!(ctx, "Failed to reserve entry in ring buffer.");
    }
}

#[inline(always)]
fn reserve_ipv6_event(queue: &RingBuf, event: EbpfEventIpv6) -> bool {
    if let Some(mut entry) = queue.reserve::<EbpfEventIpv6>(0) {
        *entry = core::mem::MaybeUninit::new(event);
        entry.submit(0);
        increment_counter(&MATCHED_PACKETS, IPV6_COUNTER_INDEX);
        increment_counter(&SUBMITTED_EVENTS, IPV6_COUNTER_INDEX);
        true
    } else {
        increment_counter(&MATCHED_PACKETS, IPV6_COUNTER_INDEX);
        false
    }
}

#[inline(always)]
fn queue_index_ipv6(packet_info: &PacketInfo, header: &impl NetworkHeader) -> u32 {
    let (first_ip, first_port, second_ip, second_port) = canonical_ipv6_endpoints(
        packet_info.ipv6_source,
        header.source_port(),
        packet_info.ipv6_destination,
        header.destination_port(),
    );
    let endpoint_ports = (u32::from(first_port) << 16) | u32::from(second_port);
    let mut hash = 0x811c_9dc5;
    hash = hash_combine(hash, mix_u128(first_ip));
    hash = hash_combine(hash, mix_u128(second_ip));
    hash = hash_combine(hash, endpoint_ports);
    hash = hash_combine(hash, u32::from(packet_info.protocol));
    hash = finish_hash32(hash);
    hash % REALTIME_EVENT_QUEUE_COUNT as u32
}

#[inline(always)]
fn canonical_ipv6_endpoints(
    source_ip: u128,
    source_port: u16,
    destination_ip: u128,
    destination_port: u16,
) -> (u128, u16, u128, u16) {
    if source_ip < destination_ip
        || (source_ip == destination_ip && source_port <= destination_port)
    {
        (source_ip, source_port, destination_ip, destination_port)
    } else {
        (destination_ip, destination_port, source_ip, source_port)
    }
}

#[inline(always)]
fn mix_u128(value: u128) -> u32 {
    let lower = value as u64;
    let upper = (value >> 64) as u64;
    mix_u64(lower) ^ mix_u64(upper).rotate_left(13)
}

#[inline(always)]
fn mix_u64(mut value: u64) -> u32 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    let mixed = value ^ (value >> 31);
    mixed as u32 ^ (mixed >> 32) as u32
}

#[inline(always)]
fn hash_combine(state: u32, value: u32) -> u32 {
    state
        ^ value
            .wrapping_add(0x9e37_79b9)
            .wrapping_add(state << 6)
            .wrapping_add(state >> 2)
}

#[inline(always)]
fn finish_hash32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x85eb_ca6b);
    value ^= value >> 13;
    value = value.wrapping_mul(0xc2b2_ae35);
    value ^ (value >> 16)
}

fn process_transport_packet<T: NetworkHeader + WireHeader>(
    ctx: &impl PacketContext,
    packet_info: &PacketInfo,
    transport_offset: usize,
) -> Result<(), ()> {
    let hdr = ctx.load_header::<T>(transport_offset)?;
    let packet_log = packet_info.to_packet_log(&hdr);
    let queue_index = queue_index_ipv6(packet_info, &hdr);

    submit_ipv6_event(ctx, packet_log, queue_index);

    Ok(())
}

struct PacketInfo {
    ipv6_source: u128,
    ipv6_destination: u128,
    total_length: u16,
    network_header_length: u16,
    protocol: u8,
    ttl: u8,
}

impl PacketInfo {
    fn new(ipv6hdr: &Ipv6Hdr, protocol: u8, network_header_length: usize) -> Result<Self, ()> {
        Ok(Self {
            ipv6_source: u128::from_ne_bytes(ipv6hdr.src_addr),
            ipv6_destination: u128::from_ne_bytes(ipv6hdr.dst_addr),
            total_length: Ipv6Hdr::LEN as u16 + ipv6hdr.payload_len(),
            network_header_length: network_header_length as u16,
            ttl: ipv6hdr.hop_limit,
            protocol,
        })
    }

    #[inline(always)]
    fn to_packet_log<T: NetworkHeader>(&self, header: &T) -> EbpfEventIpv6 {
        let header_length = header.header_length();
        let data_length = self
            .total_length
            .saturating_sub(self.network_header_length + u16::from(header_length));

        EbpfEventIpv6::new(
            unsafe { bpf_ktime_get_ns() },
            self.ipv6_destination.to_ne_bytes(),
            self.ipv6_source.to_ne_bytes(),
            header.destination_port(),
            header.source_port(),
            data_length,
            self.total_length,
            header.window_size(),
            header.combined_flags(),
            self.protocol,
            header_length,
            header.sequence_number(),
            header.sequence_number_ack(),
            header.icmp_type(),
            header.icmp_code(),
            self.ttl,
        )
    }
}
