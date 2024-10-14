#![no_std]
#![no_main]
#![allow(nonstandard_style)]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{RingBuf, PerCpuArray},
    programs::TcContext,
};
use aya_log_ebpf::error;

use common::EbpfEventIpv4;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
    icmp::IcmpHdr,
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

    match ipv4hdr.proto {
        IpProto::Tcp => process_transport_packet::<TcpHdr>(ctx, packet_info),
        IpProto::Udp => process_transport_packet::<UdpHdr>(ctx, packet_info),
        IpProto::Icmp => process_transport_packet::<IcmpHdr>(ctx, packet_info),
        _ => Ok(TC_ACT_PIPE),
    }
}

fn process_transport_packet<T: NetworkHeader>(
    ctx: &TcContext,
    packet_info: PacketInfo,
) -> Result<i32, ()> {
    let hdr = ctx
        .load::<T>(EthHdr::LEN + Ipv4Hdr::LEN)
        .map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&hdr);

    // Reserve memory in the ring buffer for the event
    if let Some(mut entry) = EVENTS_IPV4.reserve::<EbpfEventIpv4>(0) {
        // Use MaybeUninit to write the packet_log data into the reserved memory
        *entry = core::mem::MaybeUninit::new(packet_log);
        // Submit the entry to make it visible to userspace
        entry.submit(0);
    } else {
        // Handle the case where the ring buffer is full
        if let Some(counter) = DROPPED_PACKETS.get_ptr_mut(0) {
            unsafe { *counter += 1; }
        }
        error!(ctx, "Failed to reserve entry in ring buffer, buffer might be full.");
    }
    
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
        )
    }
}

trait NetworkHeader {
    fn source_port(&self) -> u16;
    fn destination_port(&self) -> u16;
    fn window_size(&self) -> u16;
    fn combined_flags(&self) -> u8;
    fn header_length(&self) -> u8;
    fn sequence_number(&self) -> u32;
    fn sequence_number_ack(&self) -> u32;
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
    fn sequence_number(&self) -> u32 {
        self.seq
    }
    fn sequence_number_ack(&self) -> u32 {
        self.ack_seq
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
    fn sequence_number(&self) -> u32 {
        0
    }
    fn sequence_number_ack(&self) -> u32 {
        0
    }
}

impl NetworkHeader for IcmpHdr {
    fn source_port(&self) -> u16 {
        0
    }
    fn destination_port(&self) -> u16 {
        0
    }
    fn window_size(&self) -> u16 {
        0
    }
    fn combined_flags(&self) -> u8 {
        0
    }
    fn header_length(&self) -> u8 {
        IcmpHdr::LEN as u8
    }
    fn sequence_number(&self) -> u32 {
        0
    }
    fn sequence_number_ack(&self) -> u32 {
        0
    }
}
