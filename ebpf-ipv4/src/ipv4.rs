use aya_ebpf::{helpers::bpf_ktime_get_ns, macros::map, maps::RingBuf};

use common::{
    ip_protocol,
    wire::{EthernetHeader, IcmpMessageHeader, Ipv4Header, TcpHeader, UdpHeader},
    EbpfEventIpv4, NetworkHeader, REALTIME_EVENT_QUEUE_COUNT, REALTIME_EVENT_RINGBUF_BYTES,
};
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

use crate::counters::{increment_counter, DROPPED_PACKETS, SUBMITTED_EVENTS};
use crate::{packet::PacketContext, IPV4_COUNTER_INDEX};

#[map]
static EVENTS_IPV4_0: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_1: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_2: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_3: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_4: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_5: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_6: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

#[map]
static EVENTS_IPV4_7: RingBuf = RingBuf::with_byte_size(REALTIME_EVENT_RINGBUF_BYTES, 0);

pub(crate) fn process_packet(ctx: &impl PacketContext) -> Result<(), ()> {
    let ipv4hdr = ctx.load_header::<Ipv4Header>(size_of::<EthernetHeader>())?;
    if ipv4hdr.fragment_offset() != 0 {
        return Ok(());
    }
    let ip_header_length = ipv4hdr.header_length();
    let packet_info = PacketInfo::new(&ipv4hdr, ip_header_length)?;
    let hdr_offset = size_of::<EthernetHeader>() + ip_header_length;

    match ipv4hdr.protocol {
        ip_protocol::TCP => process_transport_packet::<TcpHeader>(ctx, &packet_info, hdr_offset),
        ip_protocol::UDP => process_transport_packet::<UdpHeader>(ctx, &packet_info, hdr_offset),
        ip_protocol::ICMP => {
            process_transport_packet::<IcmpMessageHeader>(ctx, &packet_info, hdr_offset)
        }
        _ => Ok(()),
    }
}

#[inline(always)]
fn submit_ipv4_event(event: EbpfEventIpv4, queue_index: u32) {
    let reserved = match queue_index {
        0 => reserve_ipv4_event(&EVENTS_IPV4_0, event),
        1 => reserve_ipv4_event(&EVENTS_IPV4_1, event),
        2 => reserve_ipv4_event(&EVENTS_IPV4_2, event),
        3 => reserve_ipv4_event(&EVENTS_IPV4_3, event),
        4 => reserve_ipv4_event(&EVENTS_IPV4_4, event),
        5 => reserve_ipv4_event(&EVENTS_IPV4_5, event),
        6 => reserve_ipv4_event(&EVENTS_IPV4_6, event),
        _ => reserve_ipv4_event(&EVENTS_IPV4_7, event),
    };

    let counter = if reserved {
        &SUBMITTED_EVENTS
    } else {
        &DROPPED_PACKETS
    };
    increment_counter(counter, IPV4_COUNTER_INDEX);
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
fn queue_index_ipv4(packet_info: &PacketInfo, header: &impl NetworkHeader) -> u32 {
    let (first_ip, first_port, second_ip, second_port) = canonical_ipv4_endpoints(
        packet_info.ipv4_source,
        header.source_port(),
        packet_info.ipv4_destination,
        header.destination_port(),
    );
    let endpoint_ports = (u32::from(first_port) << 16) | u32::from(second_port);
    let mut hash = 0x811c_9dc5;
    hash = hash_combine(hash, mix_u32(first_ip));
    hash = hash_combine(hash, mix_u32(second_ip));
    hash = hash_combine(hash, endpoint_ports);
    hash = hash_combine(hash, u32::from(packet_info.protocol));
    hash = finish_hash32(hash);
    hash % REALTIME_EVENT_QUEUE_COUNT as u32
}

#[inline(always)]
fn canonical_ipv4_endpoints(
    source_ip: u32,
    source_port: u16,
    destination_ip: u32,
    destination_port: u16,
) -> (u32, u16, u32, u16) {
    if source_ip < destination_ip
        || (source_ip == destination_ip && source_port <= destination_port)
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

fn process_transport_packet<T: NetworkHeader + FromBytes + IntoBytes + Copy>(
    ctx: &impl PacketContext,
    packet_info: &PacketInfo,
    header_offset: usize,
) -> Result<(), ()> {
    let hdr = ctx.load_header::<T>(header_offset)?;
    let packet_log = packet_info.to_packet_log(&hdr);
    let queue_index = queue_index_ipv4(packet_info, &hdr);

    submit_ipv4_event(packet_log, queue_index);

    Ok(())
}

struct PacketInfo {
    ipv4_source: u32,
    ipv4_destination: u32,
    total_length: u16,
    network_header_length: u16,
    protocol: u8,
    ttl: u8,
}

impl PacketInfo {
    fn new(ipv4hdr: &Ipv4Header, network_header_length: usize) -> Result<Self, ()> {
        Ok(Self {
            ipv4_source: u32::from_ne_bytes(ipv4hdr.source),
            ipv4_destination: u32::from_ne_bytes(ipv4hdr.destination),
            total_length: ipv4hdr.total_length.get(),
            network_header_length: network_header_length as u16,
            ttl: ipv4hdr.ttl,
            protocol: ipv4hdr.protocol,
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
            self.ipv4_destination.to_ne_bytes(),
            self.ipv4_source.to_ne_bytes(),
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
