use crate::packet_features::PacketFeatures;

use super::util::FeatureStats;

#[derive(Clone)]
pub struct WindowSizeStats {
    pub fwd_init_window_size: u16,
    pub bwd_init_window_size: u16,
    pub window_size: FeatureStats,
    pub fwd_window_size: FeatureStats,
    pub bwd_window_size: FeatureStats,
}

impl WindowSizeStats {
    pub fn new() -> Self {
        WindowSizeStats {
            fwd_init_window_size: 0,
            bwd_init_window_size: 0,
            window_size: FeatureStats::new(),
            fwd_window_size: FeatureStats::new(),
            bwd_window_size: FeatureStats::new(),
        }
    }

    pub fn update(&mut self, packet: &PacketFeatures, is_fwd: bool) {
        self.window_size.add_value(packet.window_size as f64);
        if is_fwd {
            if self.fwd_window_size.get_count() == 0 {
                self.fwd_init_window_size = packet.window_size;
            }
            self.fwd_window_size.add_value(packet.window_size as f64);
        } else {
            if self.bwd_window_size.get_count() == 0 {
                self.bwd_init_window_size = packet.window_size;
            }
            self.bwd_window_size.add_value(packet.window_size as f64);
        }
    }

    pub fn dump(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.fwd_init_window_size,
            self.bwd_init_window_size,
            self.window_size.dump_values(),
            self.fwd_window_size.dump_values(),
            self.bwd_window_size.dump_values(),
        )
    }

    pub fn header() -> String {
        format!(
            "{},{},{},{},{}",
            "fwd_init_window_size",
            "bwd_init_window_size",
            FeatureStats::dump_headers("window_size"),
            FeatureStats::dump_headers("fwd_window_size"),
            FeatureStats::dump_headers("bwd_window_size"),
        )
    }
}
