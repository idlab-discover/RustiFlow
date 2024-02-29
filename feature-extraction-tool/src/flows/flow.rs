use std::time::Instant;
use chrono::{DateTime, Utc};
use common::BasicFeatures;

pub trait Flow {
    fn update_flow(&mut self, packet: BasicFeatures, fwd: bool);
    fn print(&self);
} 