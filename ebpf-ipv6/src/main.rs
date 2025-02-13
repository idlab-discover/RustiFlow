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

use common::EbpfEventIpv6;
use common::IcmpHdr;
use common::NetworkHeader;
use common::TcpHdr;
use common::UdpHdr;
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
static EVENTS_IPV6: RingBuf = RingBuf::with_byte_size(1024 * 1024 * 10 * 2, 0); // 20 MB

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
    let packet_info = PacketInfo::new(&ipv6hdr, ctx.data_end() - ctx.data(), final_proto)?;

    // 3) Dispatch on the final protocol
    match final_proto {
        IpProto::Tcp => {
            // For TCP, load `TcpHdr` at `offset_after_ext`
            process_transport_packet::<TcpHdr>(ctx, &packet_info, offset_after_ext)
        }
        IpProto::Udp => {
            // For UDP, load `UdpHdr` at `offset_after_ext`
            process_transport_packet::<UdpHdr>(ctx, &packet_info, offset_after_ext)
        }
        IpProto::Ipv6Icmp => {
            // For ICMPv6, load Icmpv6 at `offset_after_ext`
            process_transport_packet::<IcmpHdr>(ctx, &packet_info, offset_after_ext)
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

#[inline(always)]
fn submit_ipv6_event(ctx: &TcContext, event: EbpfEventIpv6) {
    if let Some(mut entry) = EVENTS_IPV6.reserve::<EbpfEventIpv6>(0) {
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
    transport_offset: usize,
) -> Result<i32, ()> {
    let hdr = ctx.load::<T>(transport_offset).map_err(|_| ())?;
    let packet_log = packet_info.to_packet_log(&hdr);

    submit_ipv6_event(ctx, packet_log);

    Ok(TC_ACT_PIPE)
}

struct PacketInfo {
    ipv6_source: u128,
    ipv6_destination: u128,
    data_length: u16,
    protocol: u8,
}

impl PacketInfo {
    fn new(ipv6hdr: &Ipv6Hdr, data_length: usize, protocol: IpProto) -> Result<Self, ()> {
        Ok(Self {
            ipv6_source: u128::from_be_bytes(unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 }),
            ipv6_destination: u128::from_be_bytes(unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }),
            data_length: data_length as u16,
            protocol: protocol as u8,
        })
    }

    #[inline(always)]
    fn to_packet_log<T: NetworkHeader>(&self, header: &T) -> EbpfEventIpv6 {
        EbpfEventIpv6::new(
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
            header.sequence_number(),
            header.sequence_number_ack(),
            header.icmp_type(),
        )
    }
}
