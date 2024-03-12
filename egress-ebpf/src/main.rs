#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

use common::PacketLog;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS_EGRESS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match try_tc_flow_track(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_flow_track(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4_destination = u32::from_be(ipv4hdr.dst_addr);
    let ipv4_source = u32::from_be(ipv4hdr.src_addr);
    let length: usize = ctx.data_end() - ctx.data();

    let source_port;
    let destination_port;
    let protocol: u8;

    let mut fin_flag_count = 0 as u8;
    let mut rst_flag_count = 0 as u8;
    let mut ack_flag_count = 0 as u8;

    match ipv4hdr.proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = u16::from_be(tcphdr.source);
            destination_port = u16::from_be(tcphdr.dest);

            fin_flag_count = (tcphdr.fin() != 0) as u8;
            rst_flag_count = (tcphdr.rst() != 0) as u8;
            ack_flag_count = (tcphdr.ack() != 0) as u8;

            protocol = IpProto::Tcp as u8;
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            source_port = u16::from_be(udphdr.source);
            destination_port = u16::from_be(udphdr.dest);

            protocol = IpProto::Udp as u8;
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    let flow = PacketLog {
        ipv4_destination: ipv4_destination,
        ipv4_source: ipv4_source,
        port_destination: destination_port,
        port_source: source_port,
        length: length as u32,
        fin_flag: fin_flag_count,
        rst_flag: rst_flag_count,
        ack_flag: ack_flag_count,
        protocol: protocol,
    };

    // the zero value is a flag
    EVENTS_EGRESS.output(&ctx, &flow, 0);

    Ok(TC_ACT_PIPE)
}
