/// Use ports as IANA port categories ['well-known', 'registered', 'dynamic']
pub fn iana_port_mapping(port: u16) -> &'static str {
    match port {
        0..=1023 => "well-known",
        1024..=49151 => "registered",
        49152..=65535 => "dynamic",
    }
}
