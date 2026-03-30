#![no_std]
#![no_main]
#![allow(nonstandard_style)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::gen::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::debug;

use common::{
    EbpfEventIpv6, IcmpHdr, NetworkHeader, TcpHdr, UdpHdr, REALTIME_EVENT_QUEUE_COUNT,
    REALTIME_EVENT_RINGBUF_BYTES,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static DROPPED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static MATCHED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SUBMITTED_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv6ExtensionHdr {
    pub next_hdr: IpProto,
    pub hdr_ext_len: u8,
    // The rest is variable-length, but for the first 2 bytes, this is enough
}

const MAX_EXT_HEADERS: usize = 8; // Arbitrary safe limit

fn is_extension_header(proto: IpProto) -> bool {
    matches!(
        proto,
        IpProto::HopOpt     // 0   Hop-by-Hop
            | IpProto::Ipv6Route    // 43  Routing
            | IpProto::Ipv6Frag   // 44  Fragment
            | IpProto::Esp       // 50  ESP
            | IpProto::Ah        // 51  Auth
            | IpProto::Ipv6Opts // 60 Destination Options
            | IpProto::MobilityHeader    // 135 Mobility
            | IpProto::Hip         // 139 HIP
            | IpProto::Shim6 // 140 Shim6
    )
}

fn skip_ipv6_ext_headers(ctx: &TcContext, start_offset: usize) -> Result<(IpProto, usize), ()> {
    // Load the base IPv6 header
    let ipv6hdr = ctx.load::<Ipv6Hdr>(start_offset).map_err(|_| ())?;

    // Current offset: skip the fixed 40-byte IPv6 header
    let mut offset = start_offset + Ipv6Hdr::LEN;
    let mut next_hdr = ipv6hdr.next_hdr;

    // Unrolled loop using a fixed number of iterations
    for _ in 0..MAX_EXT_HEADERS {
        if !is_extension_header(next_hdr) {
            break;
        }

        // Load the extension header
        let ext_hdr = ctx.load::<Ipv6ExtensionHdr>(offset).map_err(|_| ())?;

        // Compute the total length of this extension header in bytes
        let ext_len_bytes = (ext_hdr.hdr_ext_len as usize + 1) * 8;

        offset += ext_len_bytes;
        next_hdr = ext_hdr.next_hdr;
    }

    Ok((next_hdr, offset))
}

fn process_packet(ctx: &TcContext) -> Result<i32, ()> {
    let ether_type = ctx.load::<EthHdr>(0).map_err(|_| ())?.ether_type;
    if ether_type != EtherType::Ipv6 {
        return Ok(TC_ACT_PIPE);
    }

    // 1) Skip over IPv6 extension headers to find the real upper-layer protocol and offset
    let (final_proto, offset_after_ext) = skip_ipv6_ext_headers(ctx, EthHdr::LEN)?;

    // 2) Build packet_info for IPv6
    let ipv6hdr = ctx.load::<Ipv6Hdr>(EthHdr::LEN).map_err(|_| ())?;
    let network_header_length = offset_after_ext - EthHdr::LEN;
    let packet_info = PacketInfo::new(&ipv6hdr, final_proto, network_header_length)?;

    // 3) Dispatch on the final protocol
    match final_proto {
        IpProto::Tcp => process_transport_packet::<TcpHdr>(ctx, &packet_info, offset_after_ext),
        IpProto::Udp => process_transport_packet::<UdpHdr>(ctx, &packet_info, offset_after_ext),
        IpProto::Ipv6Icmp => {
            process_transport_packet::<IcmpHdr>(ctx, &packet_info, offset_after_ext)
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

#[inline(always)]
fn submit_ipv6_event(ctx: &TcContext, event: EbpfEventIpv6, queue_index: u32) {
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
        increment_dropped_packets();
        debug!(ctx, "Failed to reserve entry in ring buffer.");
    }
}

#[inline(always)]
fn reserve_ipv6_event(queue: &RingBuf, event: EbpfEventIpv6) -> bool {
    if let Some(mut entry) = queue.reserve::<EbpfEventIpv6>(0) {
        *entry = core::mem::MaybeUninit::new(event);
        entry.submit(0);
        increment_counter(&MATCHED_PACKETS);
        increment_counter(&SUBMITTED_EVENTS);
        true
    } else {
        increment_counter(&MATCHED_PACKETS);
        false
    }
}

#[inline(always)]
fn increment_dropped_packets() {
    increment_counter(&DROPPED_PACKETS);
}

#[inline(always)]
fn increment_counter(counter_array: &PerCpuArray<u64>) {
    if let Some(counter) = counter_array.get_ptr_mut(0) {
        unsafe { *counter += 1 };
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

fn process_transport_packet<T: NetworkHeader>(
    ctx: &TcContext,
    packet_info: &PacketInfo,
    transport_offset: usize,
) -> Result<i32, ()> {
    let hdr = ctx.load::<T>(transport_offset).map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&hdr);
    let queue_index = queue_index_ipv6(packet_info, &hdr);

    submit_ipv6_event(ctx, packet_log, queue_index);

    Ok(TC_ACT_PIPE)
}

struct PacketInfo {
    ipv6_source: u128,
    ipv6_destination: u128,
    total_length: u16,
    network_header_length: u16,
    protocol: u8,
}

impl PacketInfo {
    fn new(
        ipv6hdr: &Ipv6Hdr,
        protocol: IpProto,
        network_header_length: usize,
    ) -> Result<Self, ()> {
        Ok(Self {
            ipv6_source: u128::from_be_bytes(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }),
            ipv6_destination: u128::from_be_bytes(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }),
            total_length: Ipv6Hdr::LEN as u16 + u16::from_be(ipv6hdr.payload_len),
            network_header_length: network_header_length as u16,
            protocol: protocol as u8,
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
            self.ipv6_destination,
            self.ipv6_source,
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
        )
    }
}
