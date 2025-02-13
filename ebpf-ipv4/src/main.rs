#![no_std]
#![no_main]
#![allow(nonstandard_style)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::error;

use common::EbpfEventIpv4;
use common::IcmpHdr;
use common::NetworkHeader;
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
static EVENTS_IPV4: RingBuf = RingBuf::with_byte_size(1024 * 1024 * 10, 0); // 10 MB

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
    let packet_info = PacketInfo::new(&ipv4hdr, ctx.data_end() - ctx.data())?;
    let ip_header_length = (ipv4hdr.ihl() as usize) * 4;
    let hdr_offset = EthHdr::LEN + ip_header_length;

    match ipv4hdr.proto {
        IpProto::Tcp => process_transport_packet::<TcpHdr>(ctx, &packet_info, hdr_offset),
        IpProto::Udp => process_transport_packet::<UdpHdr>(ctx, &packet_info, hdr_offset),
        IpProto::Icmp => process_transport_packet::<IcmpHdr>(ctx, &packet_info, hdr_offset),
        _ => Ok(TC_ACT_PIPE),
    }
}

#[inline(always)]
fn submit_ipv4_event(ctx: &TcContext, event: EbpfEventIpv4) {
    if let Some(mut entry) = EVENTS_IPV4.reserve::<EbpfEventIpv4>(0) {
        *entry = core::mem::MaybeUninit::new(event);
        entry.submit(0);
    } else {
        if let Some(counter) = DROPPED_PACKETS.get_ptr_mut(0) {
            unsafe { *counter += 1 };
        }
        error!(ctx, "Failed to reserve entry in ring buffer.");
    }
}

fn process_transport_packet<T: NetworkHeader>(
    ctx: &TcContext,
    packet_info: &PacketInfo,
    header_offset: usize,
) -> Result<i32, ()> {
    let hdr = ctx.load::<T>(header_offset).map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&hdr);

    submit_ipv4_event(ctx, packet_log);

    Ok(TC_ACT_PIPE)
}

struct PacketInfo {
    ipv4_source: u32,
    ipv4_destination: u32,
    data_length: u16,
    protocol: u8,
}

impl PacketInfo {
    fn new(ipv4hdr: &Ipv4Hdr, data_length: usize) -> Result<Self, ()> {
        Ok(Self {
            ipv4_source: ipv4hdr.src_addr,
            ipv4_destination: ipv4hdr.dst_addr,
            data_length: data_length as u16,
            protocol: ipv4hdr.proto as u8,
        })
    }

    #[inline(always)]
    fn to_packet_log<T: NetworkHeader>(&self, header: &T) -> EbpfEventIpv4 {
        EbpfEventIpv4::new(
            self.ipv4_destination,
            self.ipv4_source,
            header.destination_port(),
            header.source_port(),
            self.data_length,
            self.data_length + header.header_length() as u16,
            header.window_size(),
            header.combined_flags(),
            self.protocol,
            header.header_length(),
            header.sequence_number(),
            header.sequence_number_ack(),
            header.icmp_type(),
        )
    }
}
