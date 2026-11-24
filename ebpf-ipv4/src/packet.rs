use aya_ebpf::{programs::TcContext, EbpfContext};
use common::{Icmpv4Hdr, Icmpv6Hdr, TcpHdr, UdpHdr};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};

/// A fixed-size wire header whose fields accept every bit pattern.
///
/// # Safety
/// Implement only for plain header layouts that can be copied from arbitrary packet bytes.
pub(crate) unsafe trait WireHeader: Copy {}

// SAFETY: these layouts contain only integers and byte arrays, including the TCP bitfield.
unsafe impl WireHeader for EthHdr {}
unsafe impl WireHeader for Ipv4Hdr {}
unsafe impl WireHeader for Ipv6Hdr {}
unsafe impl WireHeader for TcpHdr {}
unsafe impl WireHeader for UdpHdr {}
unsafe impl WireHeader for Icmpv4Hdr {}
unsafe impl WireHeader for Icmpv6Hdr {}
unsafe impl WireHeader for [u8; 4] {}
unsafe impl WireHeader for u8 {}

pub(crate) trait PacketContext: EbpfContext {
    fn load_header<T: WireHeader>(&self, offset: usize) -> Result<T, ()>;
}

impl PacketContext for TcContext {
    #[inline(always)]
    fn load_header<T: WireHeader>(&self, offset: usize) -> Result<T, ()> {
        self.load(offset).map_err(|_| ())
    }
}
