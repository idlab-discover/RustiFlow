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

use common::EbpfEventIpv4;
use common::IcmpHdr;
use common::NetworkHeader;
use common::REALTIME_EVENT_RINGBUF_BYTES;
use common::TcpHdr;
use common::UdpHdr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static DROPPED_PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS_IPV4_0: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_1: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_2: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_3: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

fn process_packet(ctx: &TcContext) -> Result<i32, ()> {
    let ether_type = ctx.load::<EthHdr>(0).map_err(|_| ())?.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_PIPE);
    }

    let ipv4hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?;
    let ip_header_length = (ipv4hdr.ihl() as usize) * 4;
    let packet_info = PacketInfo::new(&ipv4hdr, ip_header_length)?;
    let hdr_offset = EthHdr::LEN + ip_header_length;

    match ipv4hdr.proto {
        IpProto::Tcp => process_transport_packet::<TcpHdr>(ctx, &packet_info, hdr_offset),
        IpProto::Udp => process_transport_packet::<UdpHdr>(ctx, &packet_info, hdr_offset),
        IpProto::Icmp => process_transport_packet::<IcmpHdr>(ctx, &packet_info, hdr_offset),
        _ => Ok(TC_ACT_PIPE),
    }
}

#[inline(always)]
fn submit_ipv4_event(ctx: &TcContext, event: EbpfEventIpv4, queue_index: u32) {
    let reserved = match queue_index {
        0 => reserve_ipv4_event(&EVENTS_IPV4_0, event),
        1 => reserve_ipv4_event(&EVENTS_IPV4_1, event),
        2 => reserve_ipv4_event(&EVENTS_IPV4_2, event),
        _ => reserve_ipv4_event(&EVENTS_IPV4_3, event),
    };

    if !reserved {
        increment_dropped_packets();
        debug!(ctx, "Failed to reserve entry in ring buffer.");
    }
}

#[inline(always)]
fn reserve_ipv4_event(queue: &RingBuf, event: EbpfEventIpv4) -> bool {
    if let Some(mut entry) = queue.reserve::<EbpfEventIpv4>(0) {
        *entry = core::mem::MaybeUninit::new(event);
        entry.submit(0);
        true
    } else {
        false
    }
}

#[inline(always)]
fn increment_dropped_packets() {
    if let Some(counter) = DROPPED_PACKETS.get_ptr_mut(0) {
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn queue_index_ipv4(packet_info: &PacketInfo, header: &impl NetworkHeader) -> u32 {
    let (first_ip, first_port, second_ip, second_port) = canonical_ipv4_endpoints(
        packet_info.ipv4_source,
        header.source_port(),
        packet_info.ipv4_destination,
        header.destination_port(),
    );
    let hash = mix_u32(first_ip)
        ^ mix_u32(second_ip).rotate_left(7)
        ^ mix_u16(first_port).rotate_left(13)
        ^ mix_u16(second_port).rotate_left(19)
        ^ u32::from(packet_info.protocol).rotate_left(27);
    hash & 0b11
}

#[inline(always)]
fn canonical_ipv4_endpoints(
    source_ip: u32,
    source_port: u16,
    destination_ip: u32,
    destination_port: u16,
) -> (u32, u16, u32, u16) {
    if source_ip < destination_ip || (source_ip == destination_ip && source_port <= destination_port)
    {
        (source_ip, source_port, destination_ip, destination_port)
    } else {
        (destination_ip, destination_port, source_ip, source_port)
    }
}

#[inline(always)]
fn mix_u32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

#[inline(always)]
fn mix_u16(value: u16) -> u32 {
    mix_u32(u32::from(value))
}

fn process_transport_packet<T: NetworkHeader>(
    ctx: &TcContext,
    packet_info: &PacketInfo,
    header_offset: usize,
) -> Result<i32, ()> {
    let hdr = ctx.load::<T>(header_offset).map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&hdr);
    let queue_index = queue_index_ipv4(packet_info, &hdr);

    submit_ipv4_event(ctx, packet_log, queue_index);

    Ok(TC_ACT_PIPE)
}

struct PacketInfo {
    ipv4_source: u32,
    ipv4_destination: u32,
    total_length: u16,
    network_header_length: u16,
    protocol: u8,
}

impl PacketInfo {
    fn new(ipv4hdr: &Ipv4Hdr, network_header_length: usize) -> Result<Self, ()> {
        Ok(Self {
            ipv4_source: ipv4hdr.src_addr,
            ipv4_destination: ipv4hdr.dst_addr,
            total_length: u16::from_be(ipv4hdr.tot_len),
            network_header_length: network_header_length as u16,
            protocol: ipv4hdr.proto as u8,
        })
    }

    #[inline(always)]
    fn to_packet_log<T: NetworkHeader>(&self, header: &T) -> EbpfEventIpv4 {
        let header_length = header.header_length();
        let data_length = self
            .total_length
            .saturating_sub(self.network_header_length + u16::from(header_length));

        EbpfEventIpv4::new(
            unsafe { bpf_ktime_get_ns() },
            self.ipv4_destination,
            self.ipv4_source,
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
