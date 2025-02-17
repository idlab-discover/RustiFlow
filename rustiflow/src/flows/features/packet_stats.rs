use crate::packet_features::PacketFeatures;

use super::util::FeatureStats;

#[derive(Clone)]
pub struct PacketLengthStats {
    pub fwd_packet_len: FeatureStats,
    pub bwd_packet_len: FeatureStats,
}

impl PacketLengthStats {
    pub fn new() -> Self {
        PacketLengthStats {
            fwd_packet_len: FeatureStats::new(),
            bwd_packet_len: FeatureStats::new(),
        }
    }

    pub fn flow_min(&self) -> f64 {
        if self.fwd_packet_len.get_count() > 0 && self.bwd_packet_len.get_count() > 0 {
            return self
                .fwd_packet_len
                .get_min()
                .min(self.bwd_packet_len.get_min());
        } else if self.fwd_packet_len.get_count() > 0 {
            return self.fwd_packet_len.get_min();
        } else if self.bwd_packet_len.get_count() > 0 {
            return self.bwd_packet_len.get_min();
        } else {
            return 0.0;
        }
    }

    pub fn flow_max(&self) -> f64 {
        if self.fwd_packet_len.get_count() > 0 && self.bwd_packet_len.get_count() > 0 {
            return self
                .fwd_packet_len
                .get_max()
                .max(self.bwd_packet_len.get_max());
        } else if self.fwd_packet_len.get_count() > 0 {
            return self.fwd_packet_len.get_max();
        } else if self.bwd_packet_len.get_count() > 0 {
            return self.bwd_packet_len.get_max();
        } else {
            return 0.0;
        }
    }

    pub fn flow_mean(&self) -> f64 {
        let flow_count = self.flow_count();
        if flow_count == 0 {
            return 0.0;
        }
        self.flow_total() / self.flow_count() as f64
    }

    pub fn flow_total(&self) -> f64 {
        self.fwd_packet_len.get_total() + self.bwd_packet_len.get_total()
    }

    pub fn flow_count(&self) -> u32 {
        self.fwd_packet_len.get_count() + self.bwd_packet_len.get_count()
    }

    pub fn flow_variance(&self) -> f64 {
        let n1 = self.fwd_packet_len.get_count();
        let n2 = self.bwd_packet_len.get_count();
        let n = n1 + n2;

        // If there's 0 or 1 total packet, variance is 0.0 by definition.
        if n <= 1 {
            return 0.0;
        }

        let mean1 = self.fwd_packet_len.get_mean();
        let mean2 = self.bwd_packet_len.get_mean();
        let var1 = self.fwd_packet_len.get_std().powi(2);
        let var2 = self.bwd_packet_len.get_std().powi(2);

        // Combined mean of forward + backward
        let combined_mean = self.flow_mean();

        // Merge the variances
        //  [ n1*var1 + n2*var2
        //  + n1*(mean1 - combined_mean)^2 + n2*(mean2 - combined_mean)^2 ] / n
        let merged_variance = {
            let sum_of_variances = n1 as f64 * var1 + n2 as f64 * var2;
            let sum_of_squares = n1 as f64 * (mean1 - combined_mean).powi(2)
                + n2 as f64 * (mean2 - combined_mean).powi(2);

            (sum_of_variances + sum_of_squares) / (n as f64)
        };

        merged_variance
    }

    pub fn flow_std(&self) -> f64 {
        self.flow_variance().sqrt()
    }

    pub fn update(&mut self, packet: &PacketFeatures, is_fwd: bool) {
        if is_fwd {
            self.fwd_packet_len.add_value(packet.length as f64);
        } else {
            self.bwd_packet_len.add_value(packet.length as f64);
        }
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{},{}",
            self.fwd_packet_len.get_count(),
            self.bwd_packet_len.get_count(),
            self.fwd_packet_len.dump_values(),
            self.bwd_packet_len.dump_values(),
        )
    }

    pub fn header() -> String {
        format!(
            "{},{},{},{}",
            "fwd_packet_count",
            "bwd_packet_count",
            FeatureStats::dump_headers("fwd_packet_len"),
            FeatureStats::dump_headers("bwd_packet_len"),
        )
    }
}
