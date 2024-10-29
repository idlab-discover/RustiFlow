use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct PacketCountPerSecond {
    counts: HashMap<u64, u64>,
}

impl PacketCountPerSecond {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn increment(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            / 100;

        *self.counts.entry(now as u64).or_insert(0) += 1;
    }

    pub fn get_counts_for_last_intervals(&mut self, num_intervals: usize) -> Vec<(u64, u64)> {
        let mut sorted_counts: Vec<(u64, u64)> =
            self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        sorted_counts.sort_by_key(|&(timestamp, _)| timestamp);

        let recent_counts: Vec<(u64, u64)> = sorted_counts
            .iter()
            .rev()
            .take(num_intervals)
            .cloned()
            .collect();

        let recent_timestamps: std::collections::HashSet<u64> =
            recent_counts.iter().map(|&(ts, _)| ts).collect();

        self.counts
            .retain(|&timestamp, _| recent_timestamps.contains(&timestamp));

        recent_counts
    }
}
