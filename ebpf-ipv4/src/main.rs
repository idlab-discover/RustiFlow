#![no_std]
#![no_main]

mod counters;
mod ipv4;

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use network_types::eth::{EthHdr, EtherType};

const COUNTER_SLOTS: u32 = 1;
const IPV4_COUNTER_INDEX: u32 = 0;

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    match ctx.load::<EthHdr>(0).map(|header| header.ether_type()) {
        Ok(Ok(EtherType::Ipv4)) => ipv4::process_packet(&ctx).unwrap_or(TC_ACT_PIPE),
        _ => TC_ACT_PIPE,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
