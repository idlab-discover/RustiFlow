use std::net::Ipv4Addr;

/// Creates a unique identifier for a network flow.
///
/// This function generates a string identifier for a network flow based on source and destination
/// IP addresses, port numbers, and the protocol used. The identifier follows the format
/// "source_ip:source_port-destination_ip:destination_port-protocol".
///
/// # Arguments
///
/// * `ipv4_source` - The source IP address, represented as a u32.
/// * `port_source` - The source port number.
/// * `ipv4_destination` - The destination IP address, represented as a u32.
/// * `port_destination` - The destination port number.
/// * `protocol` - The protocol used, represented as a u8.
///
/// # Returns
///
/// A string representing the unique identifier of the network flow.
pub fn create_flow_id(
    ipv4_source: u32,
    port_source: u16,
    ipv4_destination: u32,
    port_destination: u16,
    protocol: u8,
) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        Ipv4Addr::from(ipv4_source),
        port_source,
        Ipv4Addr::from(ipv4_destination),
        port_destination,
        protocol
    )
}
