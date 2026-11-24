use std::sync::Mutex;

use crate::packet_features::PacketFeatures;

const MAX_RETAINED_BATCHES: usize = 32;

/// Stores only empty batches from one worker, all with the pipeline's batch
/// capacity. Recycling is best effort, independent of the packet queues.
pub(super) struct BatchPool {
    free: Mutex<Vec<Vec<PacketFeatures>>>,
}

impl BatchPool {
    pub(super) fn new() -> Self {
        Self {
            free: Mutex::new(Vec::with_capacity(MAX_RETAINED_BATCHES)),
        }
    }

    pub(super) fn try_take(&self) -> Option<Vec<PacketFeatures>> {
        // Contention or poisoning is an ordinary cache miss. Allocate outside
        // the lock so the source never waits for a returned buffer.
        self.free.try_lock().ok()?.pop()
    }

    pub(super) fn recycle(&self, mut batch: Vec<PacketFeatures>) {
        batch.clear();
        if let Ok(mut free) = self.free.try_lock() {
            if free.len() < MAX_RETAINED_BATCHES {
                free.push(batch);
            }
        }
    }
}
