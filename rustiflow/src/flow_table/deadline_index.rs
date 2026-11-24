use std::collections::{btree_map::Entry, BTreeMap, HashSet};

use crate::flow_key::{FlowKey, FlowKeyHashBuilder};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct DeadlineBucket(i64);

impl DeadlineBucket {
    pub(super) fn containing(timestamp_us: i64) -> Self {
        Self(timestamp_us.div_euclid(1_000_000))
    }
}

/// One key per scheduled flow, bucketed by a lower bound on its deadline.
/// The bucket containing the check timestamp is eligible for exact checks too.
/// This keeps expiry precise at arbitrary sweep times and after clock jumps.
#[derive(Default)]
pub(super) struct DeadlineIndex {
    buckets: BTreeMap<DeadlineBucket, HashSet<FlowKey, FlowKeyHashBuilder>>,
}

impl DeadlineIndex {
    pub(super) fn insert(&mut self, key: FlowKey, bucket: Option<DeadlineBucket>) {
        if let Some(bucket) = bucket {
            self.buckets.entry(bucket).or_default().insert(key);
        }
    }

    pub(super) fn remove(&mut self, key: &FlowKey, bucket: Option<DeadlineBucket>) {
        let Some(bucket) = bucket else {
            return;
        };
        if let Entry::Occupied(mut entry) = self.buckets.entry(bucket) {
            entry.get_mut().remove(key);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
    }

    pub(super) fn due(&self, timestamp_us: i64) -> impl Iterator<Item = FlowKey> + '_ {
        self.buckets
            .range(..=DeadlineBucket::containing(timestamp_us))
            .flat_map(|(_, keys)| keys.iter().copied())
    }
}
