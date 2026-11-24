use aya_ebpf::{programs::TcContext, EbpfContext};
use zerocopy::{FromBytes, IntoBytes};

/// Loads fixed-size wire headers from the packet. `FromBytes` limits loads to
/// layouts that accept every bit pattern; `IntoBytes` lets a copy helper fill
/// the header in place.
pub(crate) trait PacketContext: EbpfContext {
    fn load_header<T: FromBytes + IntoBytes + Copy>(&self, offset: usize) -> Result<T, ()>;
}

impl PacketContext for TcContext {
    #[inline(always)]
    fn load_header<T: FromBytes + IntoBytes + Copy>(&self, offset: usize) -> Result<T, ()> {
        self.load(offset).map_err(|_| ())
    }
}
