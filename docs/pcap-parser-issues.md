# Draft upstream issues, not submitted

Checked 2026-11-06: crates.io reports 0.17.0 as the latest release.
Master commit `a5ca3c6ac8ade4694b6e6eeac0143e7e8de27784` retains both defects.
No dependency upgrade is proposed. RustiFlow keeps both workarounds and its
`nmap_tcp_syn_version_be_binary_tsresol.pcapng` regression fixture.

Sources:
- https://crates.io/api/v1/crates/pcap-parser
- https://github.com/rusticata/pcap-parser/blob/a5ca3c6ac8ade4694b6e6eeac0143e7e8de27784/src/pcapng/time.rs
- https://github.com/rusticata/pcap-parser/blob/a5ca3c6ac8ade4694b6e6eeac0143e7e8de27784/src/pcapng/interface_description.rs

## Issue 1: build_ts_resolution rejects all binary resolutions

Version: 0.17.0; also present in master above.

Minimal reproducer:

```rust
assert_eq!(pcap_parser::build_ts_resolution(0x94), Some(1 << 20));
```

Actual result is `None`. The binary flag is still included when the byte is
compared with 63. Mask the exponent before the bounds check. Preserve rejection
of exponents >= 64. Suggested tests: 0x80 -> 1, 0x94 -> 2^20, 0xbf -> 2^63,
0xc0 -> None; decimal 19 succeeds and 20 fails.

## Issue 2: big-endian IDB if_tsoffset is decoded as little-endian

Version: 0.17.0; also present in master above.

A big-endian interface-description block containing option code 14, length 8,
and value bytes `00 00 00 00 00 00 00 01` should expose a one-second offset.
The parser instead exposes 72057594037927936 seconds.

Minimal reproducer:

```rust
let bytes: [u8; 36] = [
    0,0,0,1, 0,0,0,36, // IDB type and total length
    0,1,0,0, 0,0,255,255, // Ethernet, reserved, snaplen
    0,14,0,8, 0,0,0,0,0,0,0,1, // if_tsoffset = 1
    0,0,0,0, // end of options
    0,0,0,36,
];
let (_, idb) = pcap_parser::parse_interfacedescriptionblock_be(&bytes).unwrap();
assert_eq!(idb.ts_offset(), 1);
```

`if_extract_tsoffset_and_tsresol` uses `i64::from_le_bytes` regardless of the
section's byte order. Pass the parser's endianness into this helper and use it
for the signed offset. Cover positive and negative offsets in both byte orders,
and files that switch section byte order.
