pub struct BasicFlow {
    pub flow_id: String,
    pub ipv4_destination: u32,
    pub ipv4_source: u32,
    pub port_destination: u16,
    pub port_source: u16,
    pub protocol: u8,
    pub first_timestamp: DateTime<Utc>,
    pub last_timestamp: DateTime<Utc>,
    pub last_timestamp_iat: Instant,
    // Forward
    pub fwd_fin_flag_count: u32,
    pub fwd_syn_flag_count: u32,
    pub fwd_rst_flag_count: u32,
    pub fwd_psh_flag_count: u32,
    pub fwd_ack_flag_count: u32,
    pub fwd_urg_flag_count: u32,
    pub fwd_cwe_flag_count: u32,
    pub fwd_ece_flag_count: u32,
    pub fwd_packet_count: u32,
    // Backward
    pub bwd_fin_flag_count: u32,
    pub bwd_syn_flag_count: u32,
    pub bwd_rst_flag_count: u32,
    pub bwd_psh_flag_count: u32,
    pub bwd_ack_flag_count: u32,
    pub bwd_urg_flag_count: u32,
    pub bwd_cwe_flag_count: u32,
    pub bwd_ece_flag_count: u32,
    pub bwd_packet_count: u32,
}

impl BasicFlow {
    fn increase_fwd_fin_flag(&mut self) {
        self.fwd_fin_flag_count += 1;
    }
    fn increase_fwd_syn_flag(&mut self) {
        self.fwd_syn_flag_count += 1;
    }
    fn increase_fwd_rst_flag(&mut self) {
        self.fwd_rst_flag_count += 1;
    }
    fn increase_fwd_psh_flag(&mut self) {
        self.fwd_psh_flag_count += 1;
    }
    fn increase_fwd_ack_flag(&mut self) {
        self.fwd_ack_flag_count += 1;
    }
    fn increase_fwd_urg_flag(&mut self) {
        self.fwd_urg_flag_count += 1;
    }
    fn increase_fwd_cwe_flag(&mut self) {
        self.fwd_cwe_flag_count += 1;
    }
    fn increase_fwd_ece_flag(&mut self) {
        self.fwd_ece_flag_count += 1;
    }
    fn increase_bwd_fin_flag(&mut self) {
        self.bwd_fin_flag_count += 1;
    }
    fn increase_bwd_syn_flag(&mut self) {
        self.bwd_syn_flag_count += 1;
    }
    fn increase_bwd_rst_flag(&mut self) {
        self.bwd_rst_flag_count += 1;
    }
    fn increase_bwd_psh_flag(&mut self) {
        self.bwd_psh_flag_count += 1;
    }
    fn increase_bwd_ack_flag(&mut self) {
        self.bwd_ack_flag_count += 1;
    }
    fn increase_bwd_urg_flag(&mut self) {
        self.bwd_urg_flag_count += 1;
    }
    fn increase_bwd_cwe_flag(&mut self) {
        self.bwd_cwe_flag_count += 1;
    }
    fn increase_bwd_ece_flag(&mut self) {
        self.bwd_ece_flag_count += 1;
    }

    fn create_flow_id(&mut self, ipv4_source: u32, port_source: u16, ipv4_destination: u32, port_destination: u16, protocol: u8) {
        self.flow_id = format!("{}:{}-{}:{}-{}", ipv4_source, port_source, ipv4_destination, port_destination, protocol);
    }
    fn set_last_timestamp(&mut self) {
        self.last_timestamp = Utc::now();
    }
    fn set_last_timestamp_iat(&mut self) {
        self.last_timestamp_iat = Instant::now();
    }
    
    fn new(ipv4_source: u32, port_source: u16, ipv4_destination: u32, port_destination: u16, protocol: u8) -> Self {
        BasicFlow {
            flow_id: create_flow_id(ipv4_source, port_source, ipv4_destination, port_destination, protocol),
            ipv4_destination,
            ipv4_source,
            port_destination,
            port_source,
            protocol,
            first_timestamp: Utc::now(),
            last_timestamp: Utc::now(),
            last_timestamp_iat: Instant::now(),
            fwd_fin_flag_count: 0,
            fwd_syn_flag_count: 0,
            fwd_rst_flag_count: 0,
            fwd_psh_flag_count: 0,
            fwd_ack_flag_count: 0,
            fwd_urg_flag_count: 0,
            fwd_cwe_flag_count: 0,
            fwd_ece_flag_count: 0,
            fwd_packet_count: 0,
            bwd_fin_flag_count: 0,
            bwd_syn_flag_count: 0,
            bwd_rst_flag_count: 0,
            bwd_psh_flag_count: 0,
            bwd_ack_flag_count: 0,
            bwd_urg_flag_count: 0,
            bwd_cwe_flag_count: 0,
            bwd_ece_flag_count: 0,
            bwd_packet_count: 0,
        }
    }
}

impl Flow for BasicFlow {
    fn update_flow(&mut self, packet: BasicFeatures, fwd: bool) {
        if fwd {
            self.set_last_timestamp();
            self.fwd_packet_count += 1;
            if packet.fin_flag == 1 {
                self.increase_fwd_fin_flag();
            }
            if packet.syn_flag == 1 {
                self.increase_fwd_syn_flag();
            }
            if packet.rst_flag == 1 {
                self.increase_fwd_rst_flag();
            }
            if packet.psh_flag == 1 {
                self.increase_fwd_psh_flag();
            }
            if packet.ack_flag == 1 {
                self.increase_fwd_ack_flag();
            }
            if packet.urg_flag == 1 {
                self.increase_fwd_urg_flag();
            }
            if packet.cwe_flag == 1 {
                self.increase_fwd_cwe_flag();
            }
            if packet.ece_flag == 1 {
                self.increase_fwd_ece_flag();
            }
        } else {
            self.set_last_timestamp();
            self.bwd_packet_count += 1;
            if packet.fin_flag == 1 {
                self.increase_bwd_fin_flag();
            }
            if packet.syn_flag == 1 {
                self.increase_bwd_syn_flag();
            }
            if packet.rst_flag == 1 {
                self.increase_bwd_rst_flag();
            }
            if packet.psh_flag == 1 {
                self.increase_bwd_psh_flag();
            }
            if packet.ack_flag == 1 {
                self.increase_bwd_ack_flag();
            }
            if packet.urg_flag == 1 {
                self.increase_bwd_urg_flag();
            }
            if packet.cwe_flag == 1 {
                self.increase_bwd_cwe_flag();
            }
            if packet.ece_flag == 1 {
                self.increase_bwd_ece_flag();
            }
        }
    }
    fn print(&self) {
        println!("Flow ID: {}", self.flow_id);
        println!("IPv4 Source: {}", self.ipv4_source);
    }
}