use aya_ebpf::{macros::map, maps::PerCpuArray};

use crate::COUNTER_SLOTS;

#[map]
pub(crate) static DROPPED_PACKETS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(COUNTER_SLOTS, 0);

#[map]
pub(crate) static MATCHED_PACKETS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(COUNTER_SLOTS, 0);

#[map]
pub(crate) static SUBMITTED_EVENTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(COUNTER_SLOTS, 0);

#[inline(always)]
pub(crate) fn increment_counter(counter_array: &PerCpuArray<u64>, index: u32) {
    if let Some(counter) = counter_array.get_ptr_mut(index) {
        // A per-CPU array gives this invocation its CPU's slot.
        unsafe { *counter += 1 };
    }
}
