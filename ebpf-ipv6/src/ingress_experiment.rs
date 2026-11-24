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
use common::wire::{EthernetHeader, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6};
use core::{mem::size_of, ptr};
use packet::PacketContext;
use zerocopy::{FromBytes, IntoBytes};

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
    match ctx.load_header::<EthernetHeader>(0)?.ether_type.get() {
        ETHER_TYPE_IPV4 => ipv4::process_packet(ctx),
        ETHER_TYPE_IPV6 => ipv6::process_packet(ctx),
        _ => Ok(()),
    }
}

impl PacketContext for XdpContext {
    #[inline(always)]
    fn load_header<T: FromBytes + IntoBytes + Copy>(&self, offset: usize) -> Result<T, ()> {
        // Keep the direct read within the verifier's range tracking. Longer
        // extension chains and headers spanning buffers use the copy helper.
        if offset <= 255 {
            let start = self.data() + offset;
            if start + size_of::<T>() <= self.data_end() {
                // SAFETY: the bounds check covers the whole header, and
                // `FromBytes` accepts every bit pattern. Wire headers may be
                // unaligned.
                return Ok(unsafe { ptr::read_unaligned(start as *const T) });
            }
        }

        // After at most eight IPv6 extension headers, this offset fits in u32.
        let mut header = T::new_zeroed();
        let bytes = header.as_mut_bytes();
        // SAFETY: the helper writes at most `bytes.len()` bytes into `bytes`.
        let result = unsafe {
            bpf_xdp_load_bytes(
                self.as_ptr().cast(),
                offset as u32,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
            )
        };
        if result == 0 {
            Ok(header)
        } else {
            Err(())
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
