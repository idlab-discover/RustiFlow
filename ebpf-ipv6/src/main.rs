#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use common::BasicFeaturesIpv6;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS_IPV6: PerfEventArray<BasicFeaturesIpv6> = PerfEventArray::with_max_entries(1024, 0);

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

fn process_packet(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr = ctx.load::<EthHdr>(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv6 => process_ipv6_packet(ctx),
        _ => Ok(TC_ACT_PIPE),
    }
}

fn process_ipv6_packet(ctx: &TcContext) -> Result<i32, ()> {
    let ipv6hdr = ctx.load::<Ipv6Hdr>(EthHdr::LEN).map_err(|_| ())?;
    let packet_info = PacketInfo::new(&ipv6hdr, ctx.data_end() - ctx.data())?;

    match ipv6hdr.next_hdr {
        IpProto::Tcp => process_tcp_packet(ctx, packet_info),
        IpProto::Udp => process_udp_packet(ctx, packet_info),
        _ => Ok(TC_ACT_PIPE),
    }
}

fn process_tcp_packet(ctx: &TcContext, packet_info: PacketInfo) -> Result<i32, ()> {
    let tcphdr = ctx
        .load::<TcpHdr>(EthHdr::LEN + Ipv6Hdr::LEN)
        .map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&tcphdr);
    EVENTS_IPV6.output(ctx, &packet_log, 0);
    Ok(TC_ACT_PIPE)
}

fn process_udp_packet(ctx: &TcContext, packet_info: PacketInfo) -> Result<i32, ()> {
    let udphdr = ctx
        .load::<UdpHdr>(EthHdr::LEN + Ipv6Hdr::LEN)
        .map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&udphdr);
    EVENTS_IPV6.output(ctx, &packet_log, 0);
    Ok(TC_ACT_PIPE)
}

struct PacketInfo {
    ipv6_source: u128,
    ipv6_destination: u128,
    data_length: u16,
    protocol: u8,
}

impl PacketInfo {
    fn new(ipv6hdr: &Ipv6Hdr, data_length: usize) -> Result<Self, ()> {
        Ok(Self {
            ipv6_source: u128::from_be_bytes(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }),
            ipv6_destination: u128::from_be_bytes(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }),
            data_length: data_length as u16,
            protocol: ipv6hdr.next_hdr as u8,
        })
    }

    fn to_packet_log<T: NetworkHeader>(&self, header: &T) -> BasicFeaturesIpv6 {
        BasicFeaturesIpv6::new(
            self.ipv6_destination,
            self.ipv6_source,
            header.destination_port(),
            header.source_port(),
            self.data_length,
            self.data_length + header.header_length() as u16,
            header.window_size(),
            header.combined_flags(),
            self.protocol,
            header.header_length(),
        )
    }
}

trait NetworkHeader {
    fn source_port(&self) -> u16;
    fn destination_port(&self) -> u16;
    fn window_size(&self) -> u16;
    fn combined_flags(&self) -> u8;
    fn header_length(&self) -> u8;
}

impl NetworkHeader for TcpHdr {
    fn source_port(&self) -> u16 {
        self.source
    }
    fn destination_port(&self) -> u16 {
        self.dest
    }
    fn window_size(&self) -> u16 {
        self.window as u16
    }
    fn combined_flags(&self) -> u8 {
        ((self.fin() as u8) << 0)
            | ((self.syn() as u8) << 1)
            | ((self.rst() as u8) << 2)
            | ((self.psh() as u8) << 3)
            | ((self.ack() as u8) << 4)
            | ((self.urg() as u8) << 5)
            | ((self.ece() as u8) << 6)
            | ((self.cwr() as u8) << 7)
    }
    fn header_length(&self) -> u8 {
        TcpHdr::LEN as u8
    }
}

impl NetworkHeader for UdpHdr {
    fn source_port(&self) -> u16 {
        self.source
    }
    fn destination_port(&self) -> u16 {
        self.dest
    }
    fn window_size(&self) -> u16 {
        0
    }
    fn combined_flags(&self) -> u8 {
        0
    }
    fn header_length(&self) -> u8 {
        UdpHdr::LEN as u8
    }
}
