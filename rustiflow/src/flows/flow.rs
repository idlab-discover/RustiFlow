use std::net::IpAddr;

use crate::packet_features::PacketFeatures;

use super::util::FlowExpireCause;

/// `Flow` defines the behavior of a network flow.
///
/// This trait should be implemented by structures that represent
/// a network flow, providing mechanisms to update the flow state
/// and to dump its current state into a string format.
pub trait Flow: Send + Sync + 'static + Clone {
    /// Constructs a new `Flow`.
    ///
    /// Initializes a `Flow` instance with the provided parameters, setting up
    /// the basic flow and initializing all other metrics to their default values.
    ///
    /// ### Arguments
    ///
    /// * `flow_key` - A unique identifier for the flow.
    /// * `ipv4_source` - The source IPv4 address.
    /// * `port_source` - The source port.
    /// * `ipv4_destination` - The destination IPv4 address.
    /// * `port_destination` - The destination port.
    /// * `protocol` - The protocol number.
    /// * `timestamp` - The time at which the flow is created.
    ///
    /// ### Returns
    ///
    /// Returns a new instance of `Flow`.
    fn new(
        flow_key: String,
        ipv4_source: IpAddr,
        port_source: u16,
        ipv4_destination: IpAddr,
        port_destination: u16,
        protocol: u8,
        timestamp_us: i64,
    ) -> Self;

    /// Returns the flow key.
    fn flow_key(&self) -> &String;

    /// Updates the flow with a new packet.
    ///
    /// This method processes a packet and updates the internal state of the flow
    /// based on the packet's features and the timestamp.
    ///
    /// ### Arguments
    ///
    /// * `packet` - A `BasicFeatures` instance representing the packet to be processed.
    /// * `fwd` - A boolean flag indicating the direction of the flow (forward or not).
    ///
    /// ### Returns
    ///
    /// Returns an `boolean` indicating if the flow is terminated.
    fn update_flow(&mut self, packet: &PacketFeatures, fwd: bool) -> bool;

    /// Closes the flow and performs final calculations.
    ///
    /// This method is called when a flow is being terminated, either due to
    /// timeouts, TCP termination, or exporter shutdown.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The timestamp when the flow is being closed
    /// * `cause` - The reason for closing the flow
    fn close_flow(&mut self, timestamp_us: i64, cause: FlowExpireCause);

    /// Dumps the current state of the flow.
    ///
    /// This method returns a string representation of the current state of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the current state of the flow.
    fn dump(&self) -> String;

    /// Dumps the current state of the flow without contaminant features.
    ///
    /// This method returns a string representation of the current state of the flow without contaminant features.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the current state of the flow without contaminant features.
    fn dump_without_contamination(&self) -> String;

    /// Returns the first timestamp of the flow.
    ///
    /// This method returns the first timestamp of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `DateTime<Utc>` representing the first timestamp of the flow.
    fn get_first_timestamp_us(&self) -> i64;

    /// Returns a first record with the features of the flow.
    ///
    /// This method returns a string representation of the features of the flow.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the features of the flow.
    fn get_features() -> String;

    /// Returns a first record with the features of the flow without contaminant features.
    ///
    /// This method returns a string representation of the features of the flow without contaminant features.
    ///
    /// ### Returns
    ///
    /// Returns a `String` that represents the features of the flow without contaminant features.
    fn get_features_without_contamination() -> String;

    /// Checks if the flow is expired.
    ///
    /// This method checks if the flow is expired based on the provided timestamp, active timeout, and idle timeout.
    ///
    /// ### Arguments
    ///
    /// * `timestamp` - The current timestamp.
    /// * `active_timeout` - The active timeout value.
    /// * `idle_timeout` - The idle timeout value.
    ///
    /// ### Returns
    ///
    /// Returns a `boolean` indicating if the flow is expired.
    fn is_expired(
        &self,
        timestamp_us: i64,
        active_timeout: u64,
        idle_timeout: u64,
    ) -> (bool, FlowExpireCause);
}
