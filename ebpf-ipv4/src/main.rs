#![no_std]
#![no_main]

mod counters;
mod ipv4;
mod packet;

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use common::wire::{EthernetHeader, ETHER_TYPE_IPV4};
use packet::PacketContext;

const COUNTER_SLOTS: u32 = 1;
const IPV4_COUNTER_INDEX: u32 = 0;

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    if matches!(
        ctx.load_header::<EthernetHeader>(0)
            .map(|header| header.ether_type.get()),
        Ok(ETHER_TYPE_IPV4)
    ) {
        let _ = ipv4::process_packet(&ctx);
    }
    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
