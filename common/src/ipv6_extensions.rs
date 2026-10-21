/// Extension headers whose layout must be handled before transport parsing.
#[derive(Clone, Copy)]
pub enum Ipv6Extension {
    Options,
    Fragment,
    Authentication,
    Encrypted,
}

impl Ipv6Extension {
    #[inline(always)]
    pub fn from_next_header(protocol: u8) -> Option<Self> {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 => Some(Self::Options),
            44 => Some(Self::Fragment),
            51 => Some(Self::Authentication),
            50 => Some(Self::Encrypted),
            _ => None,
        }
    }

    /// Returns the length to skip, or rejects encrypted/non-initial fragments.
    /// The caller must also check that the complete header is available.
    #[inline(always)]
    pub fn header_length(self, prefix: [u8; 4]) -> Option<usize> {
        match self {
            Self::Options => Some((usize::from(prefix[1]) + 1) * 8),
            Self::Fragment => {
                let offset_and_flags = u16::from_be_bytes([prefix[2], prefix[3]]);
                (offset_and_flags & 0xfff8 == 0).then_some(8)
            }
            Self::Authentication => Some((usize::from(prefix[1]) + 2) * 4),
            Self::Encrypted => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv6Extension;

    #[test]
    fn extension_lengths_and_fragment_offsets_follow_the_wire_format() {
        for (protocol, prefix, expected) in [
            (0, [6, 1, 0, 0], Some(16)),
            (44, [17, 0, 0, 1], Some(8)),
            (44, [17, 0, 0, 8], None),
            (44, [17, 0, 255, 249], None),
            (51, [6, 1, 0, 0], Some(12)),
            (50, [6, 0, 0, 0], None),
        ] {
            assert_eq!(
                Ipv6Extension::from_next_header(protocol)
                    .unwrap()
                    .header_length(prefix),
                expected,
                "protocol {protocol}"
            );
        }
        assert!(Ipv6Extension::from_next_header(6).is_none());
    }
}
