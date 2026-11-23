//! Orders endpoints in pairs while preserving the order of the input packets.

#[cfg(target_arch = "x86_64")]
mod avx2;

use crate::{flow_key::KeyOrientation, packet_features::PacketFeatures};

pub(crate) struct BatchCanonicalizer {
    #[cfg(target_arch = "x86_64")]
    avx2_scratch: Option<Vec<KeyOrientation>>,
}

impl BatchCanonicalizer {
    pub(super) fn restore(&mut self, scratch: Vec<KeyOrientation>) {
        #[cfg(target_arch = "x86_64")]
        {
            self.avx2_scratch = Some(scratch);
        }
        #[cfg(not(target_arch = "x86_64"))]
        drop(scratch);
    }

    pub(crate) fn from_env() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            avx2_scratch: (std::env::var_os("RUSTIFLOW_EXPERIMENT_SIMD_FLOW_KEYS").is_some()
                && std::is_x86_feature_detected!("avx2"))
            .then(Vec::new),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn prepare(
        &mut self,
        packets: &[PacketFeatures],
    ) -> Option<&mut Vec<KeyOrientation>> {
        if packets.len() < 2 {
            return None;
        }
        let orientations = self.avx2_scratch.as_mut()?;
        orientations.resize(packets.len(), KeyOrientation::Canonical);
        // SAFETY: from_env allocates scratch only after checking AVX2 support.
        unsafe { avx2::orientations(packets, orientations) };
        Some(orientations)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn prepare(&mut self, _: &[PacketFeatures]) -> Option<&mut Vec<KeyOrientation>> {
        None
    }
}
