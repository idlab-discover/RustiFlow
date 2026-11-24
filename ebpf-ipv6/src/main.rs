#![no_std]
#![no_main]

#[path = "../../ebpf-ipv4/src/counters.rs"]
mod counters;
mod ipv6;
#[path = "../../ebpf-ipv4/src/packet.rs"]
mod packet;

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use network_types::eth::{EthHdr, EtherType};

const COUNTER_SLOTS: u32 = 1;
const IPV6_COUNTER_INDEX: u32 = 0;

#[classifier]
pub fn tc_flow_track(ctx: TcContext) -> i32 {
    if matches!(
        ctx.load::<EthHdr>(0).map(|header| header.ether_type()),
        Ok(Ok(EtherType::Ipv6))
    ) {
        let _ = ipv6::process_packet(&ctx);
    }
    TC_ACT_PIPE
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
