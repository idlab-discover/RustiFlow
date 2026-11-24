use std::{
    arch::x86_64::{__m256i, _mm256_cmpeq_epi8, _mm256_min_epu8, _mm256_movemask_epi8},
    net::IpAddr,
};

use crate::{flow_key::KeyOrientation, packet_features::PacketFeatures};

/// Expects a result slot for each packet. Only call on CPUs with AVX2.
#[target_feature(enable = "avx2")]
pub(super) fn orientations(packets: &[PacketFeatures], output: &mut [KeyOrientation]) {
    let (pairs, tail) = packets.as_chunks::<2>();
    let (result_pairs, result_tail) = output.as_chunks_mut::<2>();
    for ([first, second], result) in pairs.iter().zip(result_pairs) {
        if let (Some((first_src, first_dst)), Some((second_src, second_dst))) =
            (addresses(first), addresses(second))
        {
            // Each address occupies one 128-bit lane.
            let src: __m256i = zerocopy::transmute!([first_src, second_src]);
            let dst: __m256i = zerocopy::transmute!([first_dst, second_dst]);

            let differences = !_mm256_movemask_epi8(_mm256_cmpeq_epi8(src, dst)) as u32;
            let src_greater =
                !_mm256_movemask_epi8(_mm256_cmpeq_epi8(src, _mm256_min_epu8(src, dst))) as u32;
            result[0] = orientation(first, differences as u16, src_greater as u16);
            result[1] = orientation(
                second,
                (differences >> 16) as u16,
                (src_greater >> 16) as u16,
            );
        } else {
            result[0] = first.flow_key_value().canonicalize().1;
            result[1] = second.flow_key_value().canonicalize().1;
        }
    }

    if let [packet] = tail {
        result_tail[0] = packet.flow_key_value().canonicalize().1;
    }
}

fn addresses(packet: &PacketFeatures) -> Option<([u8; 16], [u8; 16])> {
    match (packet.source_ip, packet.destination_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Some((
            u128::from(src.to_bits()).to_be_bytes(),
            u128::from(dst.to_bits()).to_be_bytes(),
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Some((src.octets(), dst.octets())),
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => None,
    }
}

fn orientation(packet: &PacketFeatures, differences: u16, src_greater: u16) -> KeyOrientation {
    let reversed = if differences == 0 {
        packet.source_port > packet.destination_port
    } else {
        // Address octet zero is the least significant mask bit.
        src_greater & (1 << differences.trailing_zeros()) != 0
    };
    if reversed {
        KeyOrientation::Reversed
    } else {
        KeyOrientation::Canonical
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn avx2_orientations_match_scalar_in_packet_order() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        let mut packets = Vec::new();
        let mut add_both_directions = |src, dst, src_port, dst_port| {
            for (source_ip, destination_ip, source_port, destination_port) in [
                (src, dst, src_port, dst_port),
                (dst, src, dst_port, src_port),
            ] {
                packets.push(PacketFeatures {
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    ..PacketFeatures::default()
                });
            }
        };

        // Exercise each possible first differing IPv6 octet, an opposing
        // later difference, unsigned ordering and the address-equality tie.
        let base = [127; 16];
        let v6 = IpAddr::from(Ipv6Addr::from(base));
        for index in 0..16 {
            let mut other = base;
            other[15] = 0;
            other[index] = 128;
            add_both_directions(v6, Ipv6Addr::from(other).into(), 65535, 0);
        }
        let v4 = IpAddr::from(Ipv4Addr::new(127, 255, 0, 1));
        add_both_directions(v4, Ipv4Addr::new(128, 0, 0, 0).into(), 65535, 0);
        add_both_directions(v4, v4, 65535, 0);
        add_both_directions(v6, v6, 0, 65535);
        add_both_directions(v6, v6, 443, 443);
        add_both_directions(v4, v6, 65535, 0);
        packets.push(PacketFeatures::default());

        for input in [packets.as_slice(), &packets[1..], &packets[..1], &[]] {
            let expected: Vec<_> = input
                .iter()
                .map(|packet| packet.flow_key_value().canonicalize().1)
                .collect();
            let mut actual = vec![KeyOrientation::Reversed; input.len()];
            // SAFETY: AVX2 support was checked above.
            unsafe { orientations(input, &mut actual) };
            assert_eq!(actual, expected);
        }
    }
}
