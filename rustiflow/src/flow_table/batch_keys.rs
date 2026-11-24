//! Orders endpoints in pairs while preserving the order of the input packets.

#[cfg(target_arch = "x86_64")]
mod avx2;

use crate::{flow_key::KeyOrientation, packet_features::PacketFeatures};

pub(crate) struct BatchCanonicalizer {
    #[cfg(target_arch = "x86_64")]
    avx2_scratch: Option<Vec<KeyOrientation>>,
}

impl BatchCanonicalizer {
    pub(crate) fn new(enabled: bool) -> Self {
        #[cfg(not(target_arch = "x86_64"))]
        let _ = enabled;
        Self {
            #[cfg(target_arch = "x86_64")]
            avx2_scratch: (enabled && std::is_x86_feature_detected!("avx2")).then(Vec::new),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn prepare(&mut self, packets: &[PacketFeatures]) -> Option<&[KeyOrientation]> {
        if packets.len() < 2 {
            return None;
        }
        let orientations = self.avx2_scratch.as_mut()?;
        orientations.resize(packets.len(), KeyOrientation::Canonical);
        // SAFETY: new allocates scratch only after checking AVX2 support.
        unsafe { avx2::orientations(packets, orientations) };
        Some(orientations)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn prepare(&mut self, _: &[PacketFeatures]) -> Option<&[KeyOrientation]> {
        None
    }
}
