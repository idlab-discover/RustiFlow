use std::time::Instant;

use common::BasicFeatures;

pub trait Flow {
    fn update_flow(
        &mut self,
        packet: BasicFeatures,
        timestamp: &Instant,
        fwd: bool,
    ) -> Option<String>;
    fn dump(&self) -> String;
}
