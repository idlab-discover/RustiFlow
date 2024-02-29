use std::time::Instant;

use common::BasicFeatures;

pub trait Flow {
    fn update_flow(&mut self, packet: BasicFeatures, timestamp: Instant, fwd: bool);
    fn update_flow_first(&mut self, packet: BasicFeatures, timestamp: Instant, fwd: bool);
}
