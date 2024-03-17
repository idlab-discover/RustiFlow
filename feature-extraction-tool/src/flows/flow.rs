use std::time::Instant;
use common::BasicFeatures;

/// `Flow` defines the behavior of a network flow.
///
/// This trait should be implemented by structures that represent
/// a network flow, providing mechanisms to update the flow state
/// and to dump its current state into a string format.
pub trait Flow {
    /// Updates the flow with a new packet.
    ///
    /// This method processes a packet and updates the internal state of the flow
    /// based on the packet's features and the timestamp.
    ///
    /// # Arguments
    ///
    /// * `packet` - A `BasicFeatures` instance representing the packet to be processed.
    /// * `timestamp` - The timestamp at which the packet is received.
    /// * `fwd` - A boolean flag indicating the direction of the flow (forward or not).
    ///
    /// # Returns
    ///
    /// Returns an `Option<String>` which might contain a result after processing the packet.
    /// If the flow is terminated, you will get a dump of all features of the flow.
    fn update_flow(
        &mut self,
        packet: &BasicFeatures,
        timestamp: &Instant,
        fwd: bool,
    ) -> Option<String>;

    /// Dumps the current state of the flow.
    ///
    /// This method returns a string representation of the current state of the flow.
    ///
    /// # Returns
    ///
    /// Returns a `String` that represents the current state of the flow.
    fn dump(&self) -> String;
}
