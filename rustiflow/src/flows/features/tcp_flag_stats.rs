use chrono::{DateTime, Utc};

use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};

use super::util::FlowFeature;

#[derive(Clone)]
pub struct TcpFlagStats {
    /// The number of flags in the forward direction.
    pub fwd_fin_flag_count: u32,
    pub fwd_syn_flag_count: u32,
    pub fwd_rst_flag_count: u32,
    pub fwd_psh_flag_count: u32,
    pub fwd_ack_flag_count: u32,
    pub fwd_urg_flag_count: u32,
    pub fwd_cwr_flag_count: u32,
    pub fwd_ece_flag_count: u32,
    /// The number of flags in the backward direction.
    pub bwd_fin_flag_count: u32,
    pub bwd_syn_flag_count: u32,
    pub bwd_rst_flag_count: u32,
    pub bwd_psh_flag_count: u32,
    pub bwd_ack_flag_count: u32,
    pub bwd_urg_flag_count: u32,
    pub bwd_cwr_flag_count: u32,
    pub bwd_ece_flag_count: u32,
}

impl TcpFlagStats {
    pub fn new() -> Self {
        TcpFlagStats {
            fwd_fin_flag_count: 0,
            fwd_syn_flag_count: 0,
            fwd_rst_flag_count: 0,
            fwd_psh_flag_count: 0,
            fwd_ack_flag_count: 0,
            fwd_urg_flag_count: 0,
            fwd_cwr_flag_count: 0,
            fwd_ece_flag_count: 0,
            bwd_fin_flag_count: 0,
            bwd_syn_flag_count: 0,
            bwd_rst_flag_count: 0,
            bwd_psh_flag_count: 0,
            bwd_ack_flag_count: 0,
            bwd_urg_flag_count: 0,
            bwd_cwr_flag_count: 0,
            bwd_ece_flag_count: 0,
        }
    }

    pub fn get_flags(&self) -> String {
        let mut flags = String::with_capacity(6);
        if self.fwd_urg_flag_count + self.bwd_urg_flag_count != 0 {
            flags.push('U');
        } else {
            flags.push('.');
        }
        if self.fwd_ack_flag_count + self.bwd_ack_flag_count != 0 {
            flags.push('A');
        } else {
            flags.push('.');
        }
        if self.fwd_psh_flag_count + self.bwd_psh_flag_count != 0 {
            flags.push('P');
        } else {
            flags.push('.');
        }
        if self.fwd_rst_flag_count + self.bwd_rst_flag_count != 0 {
            flags.push('R');
        } else {
            flags.push('.');
        }
        if self.fwd_syn_flag_count + self.bwd_syn_flag_count != 0 {
            flags.push('S');
        } else {
            flags.push('.');
        }
        if self.fwd_fin_flag_count + self.bwd_fin_flag_count != 0 {
            flags.push('F');
        } else {
            flags.push('.');
        }
        flags
    }
}

impl FlowFeature for TcpFlagStats {
    fn update(
        &mut self,
        packet: &PacketFeatures,
        is_forward: bool,
        _last_timestamp: &DateTime<Utc>,
    ) {
        if is_forward {
            self.fwd_fin_flag_count += u32::from(packet.fin_flag);
            self.fwd_syn_flag_count += u32::from(packet.syn_flag);
            self.fwd_rst_flag_count += u32::from(packet.rst_flag);
            self.fwd_psh_flag_count += u32::from(packet.psh_flag);
            self.fwd_ack_flag_count += u32::from(packet.ack_flag);
            self.fwd_urg_flag_count += u32::from(packet.urg_flag);
            self.fwd_cwr_flag_count += u32::from(packet.cwr_flag);
            self.fwd_ece_flag_count += u32::from(packet.ece_flag);
        } else {
            self.bwd_fin_flag_count += u32::from(packet.fin_flag);
            self.bwd_syn_flag_count += u32::from(packet.syn_flag);
            self.bwd_rst_flag_count += u32::from(packet.rst_flag);
            self.bwd_psh_flag_count += u32::from(packet.psh_flag);
            self.bwd_ack_flag_count += u32::from(packet.ack_flag);
            self.bwd_urg_flag_count += u32::from(packet.urg_flag);
            self.bwd_cwr_flag_count += u32::from(packet.cwr_flag);
            self.bwd_ece_flag_count += u32::from(packet.ece_flag);
        }
    }

    fn close(&mut self, _last_timestamp: &DateTime<Utc>, _cause: FlowExpireCause) {
        // No active state to close
    }

    fn dump(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\
            ,{},{},{},{},{},{},{},{},{}",
            self.fwd_fin_flag_count,
            self.fwd_syn_flag_count,
            self.fwd_rst_flag_count,
            self.fwd_psh_flag_count,
            self.fwd_ack_flag_count,
            self.fwd_urg_flag_count,
            self.fwd_cwr_flag_count,
            self.fwd_ece_flag_count,
            self.bwd_fin_flag_count,
            self.bwd_syn_flag_count,
            self.bwd_rst_flag_count,
            self.bwd_psh_flag_count,
            self.bwd_ack_flag_count,
            self.bwd_urg_flag_count,
            self.bwd_cwr_flag_count,
            self.bwd_ece_flag_count,
            // Totals
            self.fwd_fin_flag_count + self.bwd_fin_flag_count,
            self.fwd_syn_flag_count + self.bwd_syn_flag_count,
            self.fwd_rst_flag_count + self.bwd_rst_flag_count,
            self.fwd_psh_flag_count + self.bwd_psh_flag_count,
            self.fwd_ack_flag_count + self.bwd_ack_flag_count,
            self.fwd_urg_flag_count + self.bwd_urg_flag_count,
            self.fwd_cwr_flag_count + self.bwd_cwr_flag_count,
            self.fwd_ece_flag_count + self.bwd_ece_flag_count,
            // Flags as a string
            self.get_flags()
        )
    }

    fn headers() -> String {
        [
            "fwd_fin_flag_count",
            "fwd_syn_flag_count",
            "fwd_rst_flag_count",
            "fwd_psh_flag_count",
            "fwd_ack_flag_count",
            "fwd_urg_flag_count",
            "fwd_cwr_flag_count",
            "fwd_ece_flag_count",
            "bwd_fin_flag_count",
            "bwd_syn_flag_count",
            "bwd_rst_flag_count",
            "bwd_psh_flag_count",
            "bwd_ack_flag_count",
            "bwd_urg_flag_count",
            "bwd_cwr_flag_count",
            "bwd_ece_flag_count",
            // Totals
            "total_fin_flag_count",
            "total_syn_flag_count",
            "total_rst_flag_count",
            "total_psh_flag_count",
            "total_ack_flag_count",
            "total_urg_flag_count",
            "total_cwr_flag_count",
            "total_ece_flag_count",
            // Flags as a string
            "flags",
        ]
        .join(",")
    }
}
