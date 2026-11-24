#![no_std]
#![no_main]

#[path = "../../ebpf-ipv4/src/counters.rs"]
mod counters;
#[path = "../../ebpf-ipv4/src/ipv4.rs"]
mod ipv4;
mod ipv6;
#[path = "../../ebpf-ipv4/src/packet.rs"]
mod packet;

use aya_ebpf::{
    bindings::{xdp_action::XDP_PASS, TC_ACT_PIPE},
    helpers::bpf_xdp_load_bytes,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use core::{
    mem::{size_of, MaybeUninit},
    ptr,
};
use network_types::eth::{EthHdr, EtherType};
use packet::{PacketContext, WireHeader};

const COUNTER_SLOTS: u32 = 2;
const IPV4_COUNTER_INDEX: u32 = 0;
const IPV6_COUNTER_INDEX: u32 = 1;

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    let _ = observe(&ctx);
    TC_ACT_PIPE
}

#[xdp(frags)]
pub fn xdp_flow_track(ctx: XdpContext) -> u32 {
    let _ = observe(&ctx);
    XDP_PASS
}

#[inline(always)]
fn observe(ctx: &impl PacketContext) -> Result<(), ()> {
    match ctx.load_header::<EthHdr>(0)?.ether_type() {
        Ok(EtherType::Ipv4) => ipv4::process_packet(ctx),
        Ok(EtherType::Ipv6) => ipv6::process_packet(ctx),
        _ => Ok(()),
    }
}

impl PacketContext for XdpContext {
    #[inline(always)]
    fn load_header<T: WireHeader>(&self, offset: usize) -> Result<T, ()> {
        // Keep the direct read within the verifier's range tracking. Longer
        // extension chains and headers spanning buffers use the copy helper.
        if offset <= 255 {
            let start = self.data() + offset;
            if start + size_of::<T>() <= self.data_end() {
                // SAFETY: the bounds check covers the whole header, whose fields
                // accept all bit patterns. Wire headers may be unaligned.
                return Ok(unsafe { ptr::read_unaligned(start as *const T) });
            }
        }

        // After at most eight IPv6 extension headers, this offset fits in u32.
        let mut header = MaybeUninit::<T>::uninit();
        // SAFETY: the helper writes size_of::<T>() bytes on success, and WireHeader
        // accepts all bit patterns.
        let result = unsafe {
            bpf_xdp_load_bytes(
                self.as_ptr().cast(),
                offset as u32,
                header.as_mut_ptr().cast(),
                size_of::<T>() as u32,
            )
        };
        if result == 0 {
            Ok(unsafe { header.assume_init() })
        } else {
            Err(())
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
