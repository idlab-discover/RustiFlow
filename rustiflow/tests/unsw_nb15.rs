use std::{fs, path::Path, process::Command};

use pnet_packet::{
    ethernet::{EtherTypes, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    tcp::{MutableTcpPacket, TcpFlags},
    udp::MutableUdpPacket,
};

struct Capture(Vec<u8>);

impl Capture {
    fn new() -> Self {
        Self(vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ])
    }

    fn packet(&mut self, timestamp_us: u32, reply: bool, protocol: u8, transport: &[u8]) {
        let mut frame = vec![0; 14 + 20 + transport.len()];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_ethertype(EtherTypes::Ipv4);
        let mut ip = MutableIpv4Packet::new(&mut frame[14..]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + transport.len()) as u16);
        let client = "192.0.2.1".parse().unwrap();
        let server = "192.0.2.2".parse().unwrap();
        let (source, destination, ttl) = if reply {
            (server, client, 252)
        } else {
            (client, server, 62)
        };
        ip.set_source(source);
        ip.set_destination(destination);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(pnet_packet::ip::IpNextHeaderProtocol(protocol));
        ip.set_payload(transport);
        for value in [
            timestamp_us / 1_000_000,
            timestamp_us % 1_000_000,
            frame.len() as u32,
            frame.len() as u32,
        ] {
            self.0.extend(value.to_le_bytes());
        }
        self.0.extend(frame);
    }

    fn tcp(
        &mut self,
        timestamp_us: u32,
        ports: (u16, u16),
        seq_ack: (u32, u32),
        flags: u8,
        body: &[u8],
    ) {
        let mut transport = vec![0; 20 + body.len()];
        let mut tcp = MutableTcpPacket::new(&mut transport).unwrap();
        tcp.set_source(ports.0);
        tcp.set_destination(ports.1);
        tcp.set_sequence(seq_ack.0);
        tcp.set_acknowledgement(seq_ack.1);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(2048);
        tcp.set_payload(body);
        self.packet(
            timestamp_us,
            ports.0 < ports.1,
            IpNextHeaderProtocols::Tcp.0,
            &transport,
        );
    }

    fn udp(&mut self, timestamp_us: u32, port: u16) {
        let mut transport = [0; 8];
        let mut udp = MutableUdpPacket::new(&mut transport).unwrap();
        udp.set_source(port);
        udp.set_destination(53);
        udp.set_length(8);
        self.packet(
            timestamp_us,
            false,
            IpNextHeaderProtocols::Udp.0,
            &transport,
        );
    }
}

fn export(path: &Path, threads: &str, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rustiflow"))
        .args([
            "-f",
            "unsw-nb15",
            "-o",
            "print",
            "--header",
            "--threads",
            threads,
            "--idle-timeout",
            "1",
            "--expiration-check-interval",
            "1",
        ])
        .args(extra)
        .arg("pcap")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn extracts_application_features_and_orders_connections_across_shards() {
    let mut capture = Capture::new();
    let (syn, ack) = (TcpFlags::SYN, TcpFlags::ACK);
    let client = (50000, 80);
    let server = (80, 50000);
    capture.tcp(2_000_000, client, (100, 0), syn, b"");
    // This flow starts after the HTTP flow and ends before it.
    capture.udp(2_050_000, 50001);
    capture.tcp(2_125_000, server, (200, 101), syn | ack, b"");
    capture.tcp(2_250_000, client, (101, 201), ack, b"HE");
    let rest = b"AD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n";
    capture.tcp(2_375_000, client, (103, 201), ack, rest);
    capture.tcp(2_500_000, client, (103, 201), ack, rest);
    capture.tcp(2_625_000, server, (201, 103 + rest.len() as u32), ack,
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n");

    let ftp = (50002, 21);
    capture.tcp(3_000_000, ftp, (900, 0), syn, b"");
    capture.tcp(3_125_000, ftp, (901, 0), ack, b"USER sample\r\nPA");
    capture.tcp(3_250_000, ftp, (916, 0), ack, b"SS example\r\nQUIT\r\n");
    for port in 51000..51105 {
        capture.udp(8_000_000, port);
    }
    capture.udp(12_000_000, 53000);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsw.pcap");
    fs::write(&path, capture.0).unwrap();
    let csv = export(&path, "1", &[]);
    assert_eq!(csv, export(&path, "4", &[]));

    let mut lines = csv.lines();
    let header: Vec<_> = lines.next().unwrap().split(',').collect();
    assert_eq!(header.len(), 47);
    let rows: Vec<_> = lines
        .map(|line| {
            header
                .iter()
                .copied()
                .zip(line.split(','))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .collect();
    assert_eq!(rows.len(), 109);
    assert_eq!(
        (
            rows[0]["sport"],
            rows[0]["ct_srv_src"],
            rows[0]["ct_src_ltm"]
        ),
        ("50001", "98", "100")
    );
    let http = &rows[1];
    assert_eq!(
        [
            http["service"],
            http["state"],
            http["sttl"],
            http["dttl"],
            http["ct_state_ttl"],
            http["tcprtt"],
            http["sloss"],
            http["trans_depth"],
            http["ct_flw_http_mthd"],
            http["res_bdy_len"]
        ],
        ["http", "CON", "62", "252", "3", "0.25", "1", "2", "2", "5"],
    );
    let ftp = &rows[2];
    assert_eq!(
        [ftp["service"], ftp["is_ftp_login"], ftp["ct_ftp_cmd"]],
        ["ftp", "1", "3"]
    );
    assert_eq!(rows[3]["sport"], "51000");
    assert_eq!(rows[3]["ct_src_dport_ltm"], "100");
    assert_eq!((rows[108]["Ltime"], rows[108]["ct_src_ltm"]), ("12", "1"));

    let clean = export(&path, "4", &["--drop-contaminant-features"]);
    let clean_header: Vec<_> = clean.lines().next().unwrap().split(',').collect();
    let removed = [
        "srcip", "sport", "dstip", "dsport", "stcpb", "dtcpb", "Stime", "Ltime",
    ];
    assert_eq!(
        clean_header,
        header
            .into_iter()
            .filter(|name| !removed.contains(name))
            .collect::<Vec<_>>()
    );
}
