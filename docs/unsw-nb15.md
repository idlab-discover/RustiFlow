# UNSW-NB15 feature extraction

```bash
rustiflow -f unsw-nb15 -o csv --header --export-path unsw.csv pcap trace.pcap
rustiflow -f unsw-nb15 --export-path unsw.parquet pcap trace.pcapng
sudo rustiflow -f unsw-nb15 --export-path live.parquet realtime eth0
```

The profile follows the 47 input columns of the full UNSW-NB15 feature
dictionary. `attack_cat` and `Label` come from UNSW's experiment ground truth.
For label-based comparisons, join with the ground truth separately. The
reduced training and test CSVs use a different schema.

UNSW published the captures, Argus and Bro logs, feature dictionary, and
ground truth. The original paper describes a join between Argus and Bro
outputs and twelve C# algorithms. Chapter 3 of Moustafa's thesis gives
pseudocode, including the exact `ct_state_ttl` rules. A public copy of the
original C# pipeline was not located. [UNSW dataset release](https://research.unsw.edu.au/projects/unsw-nb15-dataset),
[dataset paper](https://doi.org/10.1109/MilCIS.2015.7348942),
[Moustafa's thesis, chapter 3](https://www.researchgate.net/profile/Nour-Moustafa4/publication/328784548_Designing_an_online_and_reliable_statistical_anomaly_detection_framework_for_dealing_with_large_high-speed_network_traffic/links/5be2e4164585150b2ba57c6a/Designing-an-online-and-reliable-statistical-anomaly-detection-framework-for-dealing-with-large-high-speed-network-traffic.pdf),
[feature dictionary mirror](https://huggingface.co/datasets/Mouwiya/UNSW-NB15/blob/main/NUSW-NB15_features.csv).

## Definitions used by RustiFlow

| Fields | RustiFlow definition |
| --- | --- |
| `srcip`, `sport`, `dstip`, `dsport`, `proto` | Source and destination follow the first observed packet. Protocol is a name. Capture supports IPv4/IPv6 TCP, UDP, and ICMP. ICMP ports are zero. |
| `state` | Argus-style codes inferred from RustiFlow observations. TCP uses `REQ` for a lone SYN, `ACC` for an observed SYN-ACK awaiting the ACK, `CON` for a completed handshake or midstream bidirectional traffic, `INT` for other one-way traffic, `CLO` for observed FINs without a completed close, `FIN` for completed bidirectional teardown, and `RST` for a reset. UDP uses `CON` or `INT` based on whether both directions were observed. ICMP uses the first observed message type for `ECO`, `ECR`, `URN`, and `TXD`. Unmapped states use `-`. |
| `dur`, `Stime`, `Ltime` | Duration in seconds and first/last packet times in whole Unix seconds. Connection ordering uses the underlying microsecond timestamps. |
| `sbytes`, `dbytes`, `Spkts`, `Dpkts`, `smeansz`, `dmeansz` | Directional sums of IP lengths, packet counts, and integer mean IP packet sizes. Lengths exclude link-layer framing. |
| `sttl`, `dttl`, `swin`, `dwin`, `stcpb`, `dtcpb` | TTL or IPv6 hop limit, raw TCP window, and TCP sequence number from the first observed packet in each direction. Absent directions and inapplicable TCP fields use zero. |
| `sloss`, `dloss` | RustiFlow's directional TCP retransmission counts. Packets missing from the capture cannot be counted directly. UDP and ICMP use zero. |
| `service` | Transport and known service ports, preferring the destination port and falling back to the source port. Unknown services use `-`. |
| `Sload`, `Dload` | Directional bits per second over the flow duration, using total bytes minus one mean packet size. A zero duration produces zero. |
| `Sjit`, `Djit`, `Sintpkt`, `Dintpkt` | Population standard deviation and mean of directional inter-packet times in milliseconds. |
| `tcprtt`, `synack`, `ackdat` | Sum of SYN-to-SYN-ACK and SYN-ACK-to-ACK intervals, and the two component intervals, in seconds. Intervals require matching acknowledgment numbers. Unobserved intervals use zero. |
| `is_sm_ips_ports`, `ct_state_ttl` | Equality of both endpoints and thesis algorithm 3.3's state/TTL mapping, respectively. The mapping uses the thesis's capture-specific TTL values with the states above. |
| `trans_depth`, `res_bdy_len`, `ct_flw_http_mthd` | Count of parsed HTTP/1.x requests, total observed uncompressed response body bytes, and count of request methods. Fixed-length, chunked, and close-delimited bodies are supported. These are per-flow aggregates. |
| `is_ftp_login`, `ct_ftp_cmd` | Presence of FTP `USER` and `PASS` commands with arguments, and the count of observed client command lines. The presence indicator follows the thesis's credentials-present rule. It does not verify server acceptance. |
| `ct_srv_src`, `ct_srv_dst`, `ct_dst_ltm`, `ct_src_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm` | Count of matching service/source, service/destination, destination, source, source/destination port, destination/source port, and source/destination pairs, respectively. See the window definition below. |

Packet direction, segmentation, timeouts, service inference, and application
aggregation can produce values that differ from the published CSVs. This
profile has been tested with deterministic captures and has not been matched
row-for-row against the original dataset.

### Application metadata

Offline decoding inspects plaintext HTTP on TCP ports 80, 8000, and 8080
and FTP control traffic on TCP port 21. It handles in-order segments, split
headers and commands, and overlapping retransmissions. It does not reorder
segments or decrypt traffic. Position gaps, a packet missing required payload,
and unsupported HTTP framing make the affected fields unavailable. HTTP
response size is also unavailable for compressed bodies. The parser limits
copied TCP payload to 16 KiB per packet, buffered HTTP headers and FTP lines
to 8 KiB, and unmatched HTTP requests to 128. Request paths, payload bytes,
and FTP arguments are excluded from output.

Zero represents an observed zero or an inapplicable application field.
`-1` represents unavailable data. The realtime eBPF path exports header
metadata only, so application measurements for matching HTTP or FTP traffic
are unavailable. Rebuild the eBPF objects with the userspace binary to obtain
TTL and hop-limit metadata.

### Connection windows

Offline rows are ordered by last packet time, then first packet time and
directional five-tuple. Each row counts itself and the next 99 completed
connections across all workers. The final rows use as many remaining
connections as are available. The sorter buffers flows until all shards
have passed their end time. The buffer grows with flow throughput, timeout,
and sweep interval. If a flow ends before an already published watermark,
rerun on a capture ordered by packet timestamp.

Realtime and replay use the current flow and the preceding 99 completed
connections in global export order. This preserves streaming output. Early
exports receive a window count and do not enter other rows' windows.

`--drop-contaminant-features` omits exact addresses and ports, initial TCP
sequence numbers, and absolute timestamps. Derived service, endpoint
equality, and connection counts remain.
