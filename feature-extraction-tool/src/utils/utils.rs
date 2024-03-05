use std::net::Ipv4Addr;

pub fn create_flow_id(
    ipv4_source: u32,
    port_source: u16,
    ipv4_destination: u32,
    port_destination: u16,
    protocol: u8,
) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        Ipv4Addr::from(ipv4_source), port_source, Ipv4Addr::from(ipv4_destination), port_destination, protocol
    )
}
