pub fn create_flow_id(
    ipv4_source: u32,
    port_source: u16,
    ipv4_destination: u32,
    port_destination: u16,
    protocol: u8,
) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        ipv4_source, port_source, ipv4_destination, port_destination, protocol
    )
}
