#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    maps::PerfEventArray
};

use ingress_common::PacketLog;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_flow_track(ctx: XdpContext) -> u32{
    match try_xdp_flow_track(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn try_xdp_flow_track(ctx: XdpContext) -> Result<u32, ()>{
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let ipv4_source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let ipv4_destination = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let source_port;
    let destination_port;
    match unsafe { *ipv4hdr }.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            source_port = u16::from_be(unsafe { *tcphdr }.source);
            destination_port = u16::from_be(unsafe { *tcphdr }.dest);
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            source_port = u16::from_be(unsafe { *udphdr }.source);
            destination_port = u16::from_be(unsafe { *udphdr }.dest);
        }
        _ => return Ok(xdp_action::XDP_ABORTED),
    };

    let flow = PacketLog {
        ipv4_destination: ipv4_destination,
        ipv4_source: ipv4_source,
        port_destination: destination_port,
        port_source: source_port,
    };

    // the zero value is a flag
    EVENTS.output(&ctx, &flow, 0);

    Ok(xdp_action::XDP_PASS)
}