# Session 09 · Locating a capture count discrepancy

**Keep the interval diagnostic as an opt-in profiling tool.** A complete RustiFlow shutdown can reconcile submissions, decodes and file totals while missing most of the independently observed frames. On this private routed veth, sender GSO moved the first count difference to the capture link. Receive GRO alone moved it between link RX accounting and the TC classifiers. Stacking two VLAN tags produced a separate parser coverage gap. A stopped-reader control localized actual capture loss to the IPv6 ring.

**Hypothesis.** With an independent frame census, counters from the same capture epoch can locate the earliest observable discrepancy. TC metadata can distinguish coalesced skbs from an unrecognized Ethernet header when the packet counters alone admit either explanation.

The base is `0dca76d5d8dfc1235178758282ce0682bfd96b90`. All performance comparisons ran the same pinned userspace and split legacy TC ingress programs, built in this worktree. A separate semantics run used a profiling-only userspace patch to read progress before shutdown. Session commits `8f6d10b3`, `f83ae32a` and `c21af02b` add the frame census, interval diagnostic and bracketed sampler. No earlier session commit was imported. The branch contains profiling tools and the review record under `docs/profiling/`.

## Where the counts parted

One run offered 16,000 UDP datagrams per family plus 16 deliberately unhandled Ethernet frames. An independent packet socket counted complete, sequence-checked frames after the router. Every measured run delivered exactly 16,000 IPv4 and 16,000 IPv6 reference frames with zero reference socket drops. Every count in the table was identical across all four repetitions of both arms. The table uses lower-device TC on `cap0`. GRO is the receive-side setting and GSO the sender-side setting.

| Tagging | GRO | GSO | Link RX units incl. 16 other | Link RX bytes | TC submitted IPv4 / IPv6 | File rows | First observed difference |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| Plain | off | off | 32,016 | 18,048,960 | 16,000 / 16,000 | 2 | All target counts agree |
| Plain | off | on | 2,016 | 16,488,960 | 1,000 / 1,000 | 2 | By link RX |
| Plain | on | off | 32,016 | 17,600,736 | 1,000 / 1,000 | 2 | Between link RX and TC |
| Plain | on | on | 2,016 | 16,460,736 | 1,000 / 1,000 | 2 | By link RX |
| C-tag | off | off | 32,016 | 18,048,960 | 16,000 / 16,000 | 2 | All target counts agree |
| C-tag | on | on | 2,016 | 16,460,736 | 1,000 / 1,000 | 2 | By link RX |
| S+C tags | off | off | 32,016 | 18,176,960 | 0 / 0 | 0 | Lower TC EtherType dispatch |
| S+C tags | on | on | 2,016 | 16,468,736 | 0 / 0 | 0 | By link RX, then lower TC dispatch |

In the diagnostic arm the before/after maps, shutdown counter log, successful source decodes and family-specific Parquet counts agreed in every cell. All ring drops and veth queue-0 drops were zero. The reference received 8,864,000 IPv4 and 9,184,000 IPv6 Ethernet bytes per run. Every successfully parsed plain or single-tag case exported 8,192,000 payload bytes per family. Example IPv4 `packet_len_total` changed from 8,640,000 to 8,220,000 with 16-to-one aggregation. One set of IPv4 and UDP headers entered the export per TC event. Packet-count, length-distribution and timing features depend on this observation point even when payload-byte totals agree.

A separate pass inserted a read-only skb observer at TC priority 10, ahead of both classifiers. It bucketed the actual Ethernet field at byte 12, VLAN metadata TPID, multi-segment skbs, the sum of their `gso_segs`, and how many reported `gso_size=512`. The program always continued classification. In the plain off/off control the observer saw individual IP skbs. The plain GRO-only and GSO-only controls showed 1,000 multi-segment skbs per family, all with 512-byte segment size, summing to 16,000 segments per family. In the double-tag on/on run the observer saw the same segment grouping alongside the inline inner tag. This tests the representation of these UDP groups. Multiplying an arbitrary aggregated event by a segment count cannot recover its individual timestamps or header measurements.

**Hook location.** With one 802.1Q tag, lower TC saw the IP EtherType and a VLAN metadata tag. With 802.1ad VID 9 around 802.1Q VID 17, lower TC saw an outer S-tag in metadata and an Ethernet field of 0x8100. The split programs dispatch only on outer IPv4 or IPv6 at byte 12. In a holdout with GRO and GSO off, disabling both C-tag and S-tag TX insertion on `send0` and RX parsing on `cap0` gave the same 16,000 / 16,000 submissions on the single-tag lower device and zero on the stacked lower device. The four feature readbacks confirmed both configurations. Attaching RustiFlow to the innermost `tag17` on the same routed path restored both families. The upper reported 32,000 RX units and 17,600,000 bytes, and the untagged 0x88b5 markers stayed on the lower device.

**Independent raw Ethernet control.** The first 32,000 complete records of the shared CAIDA-shaped `final-a-4096.pcap` contained 29,881 IPv4 and 2,119 IPv6 frames, 30,211,815 Ethernet bytes, and 27,323,411 / 2,440,404 declared IP bytes. One warmup and three reversed-order pairs replayed the identical slice at 32 kpps, with GRO/GSO both off or both on. In every file TC, source decodes and exported packet sums agreed with each family's pcap count. The 9,953 rows retained the exact declared IP byte sums. All sender successes and failures were checked. RX remained 32,000 in either condition, while RX bytes changed from 30,211,815 to 29,763,815, exactly 14 bytes per input frame. In this mixed trace the enabled flags alone predicted neither a packet-count deficit nor a common Ethernet-byte convention.

## Counter scope and interval handling

| Observation | Source and interpretation |
| --- | --- |
| Independent frame truth | Successful UDP sends establish the offered segment count. A separate AF_PACKET receiver on the outgoing reference leg checks every family marker, unique sequence, payload body, frame size and declared IP/UDP lengths. The final packet socket statistics include its own drop count. The raw holdout uses the input pcap record census and tcpreplay success/failed/truncated/retry counts. |
| Link packets, bytes, errors, drops, missed | RTM_GETLINK `stats64.rx` via `ip -j -s -s link show dev DEV`. All traffic at this device participates. The veth measurements above show why RX packets and bytes need an explicit unit. A virtual device can expose a generic zero missed counter despite lacking a physical MAC. |
| NIC misses/no-buffer, queue packets/bytes/drops/allocation failures | Named `ethtool -S` fields, including igc `rx_missed_errors`, `rx_no_buffer_count` and `rx_queue_N_*`. Raw names survive subtraction. The sum covers the reported RX queues only when each exposes a packet delta. Aliases and possible overlapping drop reasons are kept separate. |
| Softnet | First three hexadecimal columns of `/proc/net/softnet_stat` for processed, dropped and time_squeeze. The 13th column identifies the CPU. Deltas are taken per CPU before summing. These counters include other devices and protocol processing. A squeeze counts an exhausted processing budget. |
| Parsed TC matches, submissions, ring reserve failures | The exact program IDs attached to this interface's legacy ingress hook, their referenced map IDs, ring-family names and the native per-CPU `u64` slots. `SUBMITTED_EVENT` is the kernel-truncated name for `SUBMITTED_EVENTS`. Matched equals submitted plus `DROPPED_PACKETS`. Unrecognized frames can run both classifiers and increment neither. |
| Decoded events | With existing `RUSTIFLOW_REALTIME_STATS=1`, one unique terminal event count or zero-drained message per ring, summed separately for each family. The baseline independently enforces combined decoded equals submitted after detachment and drain. Its per-family decoder reading is unknown. |
| Live userspace progress (profiling build) | SIGUSR1 samples each ingress source’s existing decoded event count and the writer’s successfully appended Parquet groups. The writer publishes cumulative rows and packet sums per family after group close. Appended groups can still be buffered. |
| Exported packets and bytes | Inotify `IN_CLOSE_WRITE` on the *regular output file*, followed by successful process exit. An independent Rust reader checks the 203-column footer and projects IP version, endpoints, protocol, packet count and IP/payload byte totals from every row. The two fixture flows can be separated from incidental flows. Early cumulative exports were disabled. |

Each snapshot records boot ID, network namespace inode, interface name/index/MAC, program/map identity and monotonic begin/end. The pair provides a lower and upper bound on source-to-source elapsed time. Real reads are sequential. Samples around a quiet sender isolate the traffic interval. With ongoing traffic, read skew and work in flight can contribute differences. The pinned binary exposes per-family source totals at shutdown. The optional profiling build also exposes live decode and row-group progress at requested barriers.

A change of boot/namespace/interface identity or backwards/overlapping sample times rejects the pair. A change of program or map ID invalidates that counter. A decrease in any link or selected driver field invalidates the corresponding source group. A decrease in a per-CPU TC slot, including one hidden by a rising sum, invalidates that map delta. A softnet CPU-set change or falling counter invalidates the softnet interval. Missing fields produce nulls. Same-identity resets followed by regrowth beyond the previous reading, complete undetected wraps and remove/recreate with identical visible identity require an external reset/maintenance epoch.

**Three intervals, one capture.** With no detach, 32,000 new reference frames and 16 other frames were offered in each phase. Starting off/off, enabling receive GRO, then enabling sender GSO produced link RX deltas of 32,016 / 32,016 / 2,016. IPv4 and IPv6 map submission deltas were 16,000 / 1,000 / 1,000 *each*. The same maps started the second and third phases at nonzero counts. Source stats and file totals were observable on finalization. Each showed 18,000 events per family. The reference received 48,000 individual frames per family. Across two subsequent capture lifetimes on the same interface, the IPv4 submission program/map pair changed from 43459/85906 to 43468/85969. All four TC outcome deltas and both derived matches became unknown, including ring-drop maps that read zero on both sides. A sample from another namespace with the same device name, ifindex and MAC was rejected.

**Noise controls.** The main veth link's `rx.dropped` rose by 16 alongside the deliberately unhandled frames. All target frames reached the reference. Injecting another 16 IPv4 UDP datagrams on a different port raised link RX to 32,032, IPv4 submissions to 16,016 and file rows to three. The reference still contained the two complete target streams. The diagnostic flagged a mixed cohort. Simultaneous reads of the unused `lo` in the capture namespace reported zero link RX and 64,270 softnet processed. The primary matrix had 34,133–128,187 processed units in D and zero softnet drop or squeeze deltas across all measured arms. Neither host softnet nor an unqualified link-drop delta estimates target-flow loss.

**Ring-loss control.** With GRO and GSO off, every capture TID was stopped before the sender, keeping both TC producers attached. The sender issued 54,000 groups per family over 54 s. The reference received 864,000 frames per family with zero socket drops. Link RX was 1,728,844 including 844 unhandled frames. TC matched 864,000 per family. IPv4 submitted all frames. IPv6 submitted 838,860 and counted 25,140 reserve failures. One hot 64 MiB IPv6 ring admits 838,860 aligned 80-byte records. SIGINT followed by SIGCONT drained the finite rings and finalized two rows containing 1,702,860 packets. This case exercises capture loss while forwarding remains complete.

## Performance and measurement cost

Each setting had one warmup pair and four measured pairs. Each successive round reversed both the order of settings and the order of arms within each setting. B is the pinned binary with terminal TC counters. D uses the same binary, enables the existing per-source stats and reads the TC maps before and after sending. Both arms take link/driver/softnet snapshots and run the identical reference reader. Only D reads the second snapshot before SIGINT. All rates use the 32,000 independently verified IP frames as the denominator.

The in-send reference rate was 32.024 (32.018–32.028) kpps across all measured runs (median and full range). The detached runs omitted RustiFlow and the packet socket, used the same routed topology at top speed and reconciled exactly 32,000 sink RX frames in every repetition. Cells are medians with observed min–max. A single number means the range collapses at the displayed precision.

| Tag / GRO / GSO | Detached Mpps | First send to writer close ms, B / D | SIGINT to writer close ms, B / D |
| --- | ---: | ---: | ---: |
| Plain / off / off | 1.87 (1.53–2.24) | 1099.0 (1087.1–1108.1) / 1308.4 (1304.2–1313.5) | 55.8 (55.1–62.7) / 56.4 (54.4–57.3) |
| Plain / off / on | 2.29 (2.05–2.43) | 1096.6 (1093.7–1097.1) / 1310.9 (1244.0–1321.2) | 55.6 (54.7–57.4) / 58.0 (54.3–60.5) |
| Plain / on / off | 1.50 (1.40–1.88) | 1099.6 (1092.7–1109.7) / 1310.8 (1309.7–1343.1) | 55.3 (53.4–56.2) / 58.8 (55.4–62.6) |
| Plain / on / on | 1.94 (1.74–2.70) | 1103.7 (1095.5–1108.6) / 1313.8 (1310.9–1331.8) | 55.1 (53.4–56.3) / 56.4 (54.4–58.3) |
| C-tag / off / off | 1.61 (1.40–1.83) | 1104.0 (1095.5–1111.7) / 1310.1 (1300.0–1316.0) | 54.8 (54.4–56.0) / 57.3 (54.5–65.9) |
| C-tag / on / on | 1.97 (1.70–2.32) | 1099.7 (1086.3–1118.5) / 1323.4 (1274.8–1340.6) | 56.5 (56.1–63.8) / 56.7 (55.1–64.0) |
| S+C tags / off / off | 1.35 (1.30–1.54) | 1094.3 (1090.8–1110.5) / 1320.3 (1304.6–1335.5) | 55.0 (53.5–58.5) / 56.4 (55.2–58.2) |
| S+C tags / on / on | 2.56 (1.76–3.33) | 1101.6 (1093.2–1102.9) / 1323.5 (1309.4–1331.7) | 56.4 (55.3–62.1) / 60.2 (55.3–64.3) |

CPU time is additive across capture threads. The sender-command window attaches perf stat to the multithreaded capture PID. Task-clock includes scheduled userspace and kernel CPU. Cycles and retired L3 load misses count P-core userspace only. The full CPU column uses the capture process CPU clock before launching the sender command and wait4 user + system time at exit, including final drain and file close. The wall clock begins at the sender's first group, after payload preparation, and ends when inotify reports file close. It measures completion to the filesystem cache. These scopes exclude sender/forwarding CPU from the capture-process PMU and include no CPU sampling.

| Tag / GRO / GSO | Arm | Sender window CPU ns/frame | Through-exit CPU ns/frame | Sender window user cycles/frame | Sender window retired L3 load misses/frame |
| --- | --- | ---: | ---: | ---: | ---: |
| Plain / off / off | B | 2262 (2101–2426) | 4163 (3973–4393) | 1746 (1736–1789) | 0.0037 (0.0035–0.0039) |
| Plain / off / off | D | 2563 (2398–2601) | 4515 (4431–4590) | 1962 (1946–2022) | 0.0040 (0.0037–0.0042) |
| Plain / off / on | B | 1668 (1641–1690) | 3607 (3537–3654) | 1051 (1022–1067) | 0.0040 (0.0037–0.0042) |
| Plain / off / on | D | 1740 (1550–1748) | 3691 (3415–3754) | 1123 (1018–1141) | 0.0038 (0.0036–0.0040) |
| Plain / on / off | B | 1628 (1568–1729) | 3570 (3438–3676) | 1053 (994–1085) | 0.0035 (0.0033–0.0038) |
| Plain / on / off | D | 1664 (1633–1735) | 3642 (3590–3646) | 1100 (1057–1130) | 0.0036 (0.0034–0.0038) |
| Plain / on / on | B | 1618 (1555–1674) | 3544 (3513–3627) | 1032 (1006–1061) | 0.0036 (0.0035–0.0131) |
| Plain / on / on | D | 1679 (1553–1691) | 3636 (3490–3699) | 1089 (1062–1109) | 0.0037 (0.0036–0.0038) |
| C-tag / off / off | B | 2257 (2197–2381) | 4217 (4117–4328) | 1796 (1746–1800) | 0.0037 (0.0036–0.0038) |
| C-tag / off / off | D | 2464 (2373–2498) | 4418 (4222–4467) | 1986 (1937–2031) | 0.0039 (0.0037–0.0044) |
| C-tag / on / on | B | 1681 (1534–1708) | 3649 (3519–3753) | 1056 (984–1074) | 0.0036 (0.0035–0.0037) |
| C-tag / on / on | D | 1726 (1670–1813) | 3681 (3590–3801) | 1124 (1088–1167) | 0.0039 (0.0033–0.0047) |
| S+C tags / off / off | B | unavailable | 1761 (1705–1833) | unavailable | unavailable |
| S+C tags / off / off | D | unavailable | 1781 (1757–1859) | unavailable | unavailable |
| S+C tags / on / on | B | unavailable | 1794 (1765–1880) | unavailable | unavailable |
| S+C tags / on / on | D | unavailable | 1809 (1750–1844) | unavailable | unavailable |

In the plain off/off control D changed sender-window capture CPU by 12.1 (6.3–17.8)% and first-send-to-close wall time by 19.4 (17.7–20.1)% within pairs. The gap from the final send to SIGINT was 42.6 (32.3–49.0) ms in B and 252.2 (248.7–259.8) ms in D. D launches another Python process on low-power CPU 15 before signaling capture. These are controller and observer costs as well as per-event instrumentation costs. Through-close reference rates for this pair were 29.12 (28.88–29.44) and 24.46 (24.36–24.54) kpps. The final D snapshot's internal observation span was 25.71 (17.35–30.54) ms across the matrix, excluding interpreter launch. These costs and the counters' non-atomic read windows favor sampling on quiet boundaries for this experiment. For zero-match cases perf reported zero task counting time and `<not counted>` in the sender window. Counted hardware events ran for 100% of the reported scheduled event time.

## Sequential reads during active traffic

A resident collector on CPU 15 took two RTM_GETLINK RX packet readings around ethtool, softnet and TC map reads. For consecutive snapshots A and B the interval of observable link counts is **[B.first − A.last, B.last − A.first]**. A decrease across any bracket invalidates that link interval. The tool exposes the bounds with `--bracket-rx` and checks whether parsed matches plus known out-of-scope link units fit. Units, hook coverage, device buffering and stage backlog still require independent evidence.

The raw pcap slice repeated 40 times at an offered 320 kpps with both offloads off, one warmup and four matched pairs. Both arms enabled the same source stats. One arm sampled at quiescent ends only. The other added a resident poll every 250 ms during replay. Each measured run produced exactly 1,280,000 link RX, 1,195,240 IPv4 and 84,760 IPv6 submissions and decodes, zero ring drops and 9,953 Parquet rows containing all 1,280,000 packets. Both quiescent RX bounds equaled the exact input count.

All **60 active interior windows** had a nonzero difference between the unbracketed link delta and the TC match sum. The signed median was +8 units (−2,254 to +1,946), and the median absolute difference was 44 (3–2,254). In the largest case the first-read link delta was 77,837 and TC matched 80,091. The link bracket was [71,207, 86,612]. **All 60 TC sums fit their brackets.** Median bracket width was 14,896 units (11,356–16,380). That width limits the loss magnitude this sampling scheme can resolve inside an active window.

| Raw trace control | Quiescent ends | Plus periodic reads |
| --- | ---: | ---: |
| Delivered kpps while sending | 320.00 | 320.00 |
| Reference kpps from perf/sender command launch to file close | 290.63 (289.85–291.54) | 290.71 (290.06–291.16) |
| SIGINT to writer close, ms | 79.76 (78.96–81.43) | 80.12 (77.77–88.03) |
| Capture CPU ns/frame, sender command | 3,208 (3,171–3,246) | 3,241 (3,212–3,281) |
| Capture CPU ns/frame, command through exit | 3,373 (3,335–3,398) | 3,404 (3,376–3,437) |
| Capture user cycles/frame, sender command | 4,391 (4,339–4,440) | 4,437 (4,398–4,477) |
| Retired user L3 load misses/frame, sender command | 1.1243 (1.0792–1.1833) | 1.1731 (1.0934–1.2425) |

Detached headroom was 881.85 (871.93–882.76) kpps for this exact tcpreplay loop with a quiescent link census. The completed-file throughput ranges overlap. The resident comparison holds startup and per-event instrumentation fixed and measures the added reads at this offer. It uses the same PMU/thread scope as the preceding experiment.

## Decodes and row groups before shutdown

The optional userspace probe in `e9982f0f` adds two live observations to the collector’s existing TC map deltas. On SIGUSR1 a Tokio task sums existing decoded-event counters across the eight ingress rings in each family. The Parquet writer publishes a row count and per-family packet sums after each successful group append. These quantities have separate read times. Flow expiration, encoder batching and the writer can hold decoded packets across an interval boundary.

Three identical 32,000-frame bursts ran at 100 kpps, with 1.6 seconds from each sender command’s end to the next burst, idle timeout 1 s, active timeout 30 s and expiry checks every second. Both arms used the same release eBPF, CPU placement, export and source stats. One warmup pair preceded three alternating measured pairs. Each measured burst supplied exactly 29,881 IPv4 and 2,119 IPv6 link-layer input frames. The link gained 32,000, both families’ matched and submitted deltas equaled their offers, and neither ring dropped an event. In every probe sample the decoded delta equaled submissions in both families.

| Interval | Appended rows | IPv4 packets in those rows | IPv6 packets in those rows |
| --- | ---: | ---: | ---: |
| First burst | 0 | 0 | 0 |
| Second burst | 3,072 | 5,200 (4,963–5,274) | 1,037 (1,016–1,039) |
| Third burst | 4,096 | 6,282 (5,448–6,690) | 1,461 (1,434–1,674) |
| Last live sample through file finish | 15,194 (14,404–15,371) | 78,087 (77,753–79,232) | 3,880 (3,644–3,886) |

Entries are separate column medians and full ranges over three probe runs. Every closed file contained exactly 89,643 IPv4 packets and 6,357 IPv6 packets, accounting for 81,970,233 and 7,321,212 declared IP bytes respectively. Footer-time probe totals matched independent reads of all rows. The pinned file contained 21,960 rows (21,483–22,631) and the probe file 22,362 (21,572–22,539). Timed expiration partitioned otherwise identical replayed traffic into different rows. Zero appended packets just after the first burst therefore represented pending work. Request-to-reading latency, including controller polling, was 2.47 ms (2.33–2.75) at the nine measured barriers. This experiment measured count semantics.

Enable this profiling copy with `RUSTIFLOW_PROBE_COUNTS=1`, existing `RUSTIFLOW_REALTIME_STATS=1`, ingress-only capture and info logging. Send SIGUSR1 only after the process logs that the accounting listener is ready. The harness checks the executable and uses a pidfd. Explicit `RUSTIFLOW_PROBE_COUNTS=0` kept the listener disabled. A basic-schema capture lacking the required columns returned decoded counts and unknown appended counts and closed a valid file. The normal binary takes no new option.

## Physical observations and the outstanding test

The I226-V `enp86s0` reported igc, PCI 8086:125c, PCIe ×1 at 5 GT/s, Ethernet 1,000 Mb/s full duplex, four combined channels and 256 RX descriptors. RX/TX VLAN acceleration, GRO and GSO were enabled. Three passive intervals with four-second sleeps gave the following deltas. The time bounds include collection skew. No program was attached to the physical interface.

| Seconds (lower–upper) | Link RX | Queue 0 / 1 / 2 / 3 | Missed / no buffer | Softnet processed |
| --- | ---: | ---: | ---: | ---: |
| 4.218–4.244 | 56 | 11 / 28 / 17 / 0 | 0 / 0 | 424 |
| 4.205–4.230 | 145 | 9 / 111 / 6 / 19 | 0 / 0 | 605 |
| 4.209–4.233 | 28 | 6 / 21 / 1 / 0 | 0 / 0 | 429 |

Queue packet sums equaled link RX in all three intervals. Queue drop/allocation-failure, link error, softnet drop and time_squeeze deltas were zero. Physical TC, independent wire truth, decode and export were unknown. On lower veth the driver exposed `rx_queue_0_drops` but no per-queue packet/byte or missed/no-buffer counter. The VLAN upper returned “no stats available” from ethtool. Neither case manufactured a driver zero.

Session 01 (`5b6631e6`) and the shared investigation observed 401 physical RX packets in 12.023 s, distributed 22 / 212 / 19 / 148 across the four igc queues, with zero queue drops, misses and no-buffer increments. Session 01's raw-frame veth control reconciled 150,000 submissions per family through Parquet at 200 kpps. The shared 24-million-frame mixed control reconciled 22,378,428 IPv4 and 1,621,572 IPv6 submissions and 884,603 file rows, reaching 6.08 Mpps while sending and 5.24 Mpps through close. Session 05 (`d42699e8`) localized 160,362 reserve failures in its IPv6-heavy 180,000-frame holdout using its explicit 65 MiB plan. Those measurements supply independent examples of quiet, high-volume and ring-pressure regimes. This session used the pinned ring sizes.

For physical acceptance, use a dedicated port and an independent calibrated peer with per-family sequence and frame counters. Record host and peer MAC/PHY RX/TX/CRC, missed/no-buffer and queue drops, plus the intervals above. Establish a quiet cohort, check RSS queue distribution for port-only and many-address TCP/UDP, and ramp paced minimum, MTU, jumbo and trace-sized frames until the first sustained discrepancy. Repeat both directions, duplex, tagged/stacked traffic and supported offload states, holding the remainder fixed. Compare skb count and metadata at the intended hook with independently transmitted and received frame counts. This can decide whether the first boundary lies in the physical link, NIC buffering/DMA or queue service, hardware/software aggregation, parser coverage or the userspace pipeline. High-rate physical thresholds, cross-vendor NIC counter definitions and the timestamp fidelity of individual aggregated frames remain physical acceptance questions.

## Reproduction and diagnostic use

Linux 6.18.65-1-lts on nuccore, Intel Core Ultra 7 255H, rustc 1.99.0, clang 23.1.5, libbpf 1.8.0, Python 3.14.10, perf 7.3.5 and iproute2 7.3.0. Run from the session worktree with fresh output directories. The deterministic UDP input hash covers the ordered 512-byte payloads, family 4 then 6 per group, including each sequence. SHA-256 was `9b660d80318b6221cb82d0b78ee98dddd2226d8fcf9c22a44dc732970bc45fce` for 1,000 groups per family and `41a1b757b9830aeaecb31ca9d1eeced0c9aaa889f6c1e4b439e40cee0c50a324` for the stopped-reader run. The raw pcap slice hash was `b58d070b8dfc2c225f430cc05501e787b800c3c0bc9588277fc481e7470b4b86`.

```bash
d=docs/profiling/accounting
out=target/accounting
mkdir -p "$out"
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
cargo build --locked --profile profiling -p rustiflow --bin rustiflow
gcc -Wall -Wextra -Werror -O2 "$d/read_maps.c" -lbpf -o "$out/read_maps"
clang -O2 -g -target bpfel -Wall -Werror -c "$d/shape.bpf.c" -o "$out/shape.bpf.o"
rustc --edition=2021 "$d/read_export.rs" -L dependency=target/profiling/deps \
  --extern parquet="$(ls target/profiling/deps/libparquet-*.rlib)" -o "$out/read_export"
lab() {
  sudo -n env PYTHONDONTWRITEBYTECODE=1 bash "$d/topology.sh" taskset -c 15 python3 "$@"
}
lab "$d/run.py" headroom final-headroom --reps 4
lab "$d/run.py" paired final-paired --reps 4
lab "$d/run.py" shape final-witness --reps 1
lab "$d/run.py" vlan final-vlan --reps 1
lab "$d/run.py" background final-noise --reps 1
lab "$d/run.py" steps final-steps --reps 0
lab "$d/run.py" pressure final-pressure --groups 54000 --reps 0
lab "$d/trace.py" /home/strgenix/postdoc/RustiFlow/target/caida-100g.lCElEa/final-a-4096.pcap final-trace
lab "$d/moving.py" "$out/final-trace" final-moving

# Build the diagnostic copy from the pinned tree with its own target directory.
probe="$out/probe-src"
mkdir "$probe"
git archive 0dca76d5d8dfc1235178758282ce0682bfd96b90 Cargo.toml Cargo.lock \
  rust-toolchain.toml .cargo common rustiflow xtask ebpf-ipv4 ebpf-ipv6 | tar -x -C "$probe"
git apply --directory="$probe" "$d/userspace-probe.patch"
(cd "$probe" && cargo fmt --all -- --check && \
  cargo build --locked --profile profiling -p rustiflow --bin rustiflow && \
  cargo test --locked -p rustiflow && cargo clippy --locked -p rustiflow --all-targets -- -D warnings)
lab "$d/userspace.py" "$out/final-trace" "$probe/target/profiling/rustiflow" verified-userspace
```

The shell driver owns three disposable namespaces and two veth pairs. `send0 → cap0` is the experimental hop. The capture namespace routes via `exit0 → sink0` with TX segmentation disabled on exit0 and GRO disabled on sink0. Permanent neighbors and isolated addresses constrain the traffic to those links. `UDP_SEGMENT` sends sixteen 512-byte UDP payloads per call, alternating families at 32 kpps total. The independent reference sees 554/574-byte Ethernet frames with 540/560 declared IP bytes. The sender emits one 60-byte EtherType 0x88b5 frame per 64 groups. These counts exclude FCS, preamble/SFD and interframe gap. For sender GSO, the reference verifies segments as individual frames on the outgoing hop. The incoming veth can carry the entire group in one skb.

The controller ran on CPU 15, sender on P core 4, reference on P core 5 and RustiFlow on P cores 0–3 with two flow shards, ingress only and default full RustiFlow Parquet export. The harness sets capture GRO and receive UDP GRO forwarding explicitly and sets sender GSO and TX UDP segmentation together. It saves `ethtool -k` readbacks for all four ends. Single tags use VID 17, stacked tags outer VID 9 and inner VID 17. Capture/export options and addresses were fixed across paired arms. The shape observer ran only in the separate witness/VLAN controls.

```bash
# Inspect any completed generated interval, including both family exports
python3 -B "$d/ledger.py" "$out/final-paired/1-plain-on-off-maps"
```

For an operator-supplied interval, run snapshots in the capture namespace. `--split-tc` selects the pinned split-ingress map layout. Omit it for NIC-only measurements. Access failures return partial observations with diagnostics. The optional evidence file supplies an independently verified cohort, non-target link units excluded by the classifier, and comparable drained totals. Use mixed or unknown scope when other packets cannot be separated, and leave unavailable evidence absent. Terminal export counts require non-overlapping finalized flows with early cumulative snapshots excluded.

```bash
python3 -B "$d/counters.py" snapshot "$dev" --split-tc --bracket-rx > "$out/before.json"
# Bracket the intended interval
python3 -B "$d/counters.py" snapshot "$dev" --split-tc --bracket-rx > "$out/after.json"
python3 -B "$d/counters.py" delta "$out/before.json" "$out/after.json" > "$out/delta.json"
python3 -B "$d/ledger.py" "$out/delta.json" --evidence "$out/cohort.json"
```

For the raw pcap holdout the sidecar is `{"scope":"isolated","reference_frames":{"4":29881,"6":2119},"other_link_units":0,"drained":true,"decoded":{"4":29881,"6":2119},"exported":{"4":29881,"6":2119}}`. For a live interval set `drained` to false and supply per-family `decoded` and `appended_packets` deltas. The signed interval balances are submitted minus decoded and decoded minus appended. Previously buffered work may make either balance negative. Physical passive snapshots use no sidecar. The diagnostic reports device-wide pressure separately from cohort attribution. A difference identifies the earliest observed accounting disagreement. Balanced losses and unrelated traffic can cancel, and absent hardware fields limit localization.

The physical observation used only these queries, with CPU 15 affinity for ethtool and snapshots.

```bash
dev=enp86s0
physical="$out/final-physical"
mkdir "$physical"
sudo -n taskset -c 15 ethtool "$dev" >"$physical/link.txt"
for flag in i l g k c; do
  sudo -n taskset -c 15 ethtool "-$flag" "$dev" >"$physical/$flag.txt"
done
for attr in vendor device current_link_speed current_link_width; do
  cat "/sys/class/net/$dev/device/$attr" >"$physical/pci-$attr"
done
for n in 0 1 2 3; do
  sudo -n taskset -c 15 python3 -B "$d/counters.py" snapshot "$dev" >"$physical/s$n.json"
  if (( n < 3 )); then sleep 4; fi
done
for n in 1 2 3; do
  python3 -B "$d/counters.py" delta "$physical/s$((n-1)).json" "$physical/s$n.json" >"$physical/d$n.json"
  python3 -B "$d/ledger.py" "$physical/d$n.json" >"$physical/a$n.json"
done
```

## Validation and disposition

| Binary used | SHA-256 |
| --- | --- |
| Pinned optimized userspace with symbols | `d861207e686d5a259eedb0c98221177fe18c3747753dfa6e763e63da59f79edd` |
| Release eBPF IPv4 | `0875dd75be7512ce6f59af736e19a6621ae7c625e0f0bf56af4fd55c5a17ae6c` |
| Release eBPF IPv6 | `50c994a8e5e19bc7e2451d363d86494bdf26ab07b4ea41dc79fee10695ec1a97` |
| Separate skb observer | `2385dd5c77aeb9d81f91ae08a8f3e4be8d71faa37870e5e0fe2e729669261ceb` |
| Optional optimized userspace probe | `df79d990e1b6043cc14fcee16eacbcbe62d2e9068b0ff4f56cadc26a5fb3ee7c` |

```bash
cargo fmt --all -- --check
cargo check --locked -p rustiflow
cargo clippy --locked -p rustiflow --all-targets -- -D warnings
cargo test --locked -p rustiflow
cargo test --locked -p rustiflow --features experiment-deadline-index,staged-flow-lookup
rustfmt --check --edition 2021 "$d/read_export.rs"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$d"
git apply --check "$d/userspace-probe.patch"
```

Default tests passed 122 with one ignored, and the feature combination passed 124 with one ignored. The optional build passed its default tests and strict Clippy. A TERM cleanup test interrupted a live namespace child and released all three namespaces. After the campaign there were no session TC programs, namespaces or running capture, replay or perf workers, and kernel BPF runtime stats were disabled. All 13 Python counter and evidence tests passed, including identity changes, falling per-CPU counters, missing queue fields, mixed traffic, bounded read skew and live export lag. Raw captures, per-trial settings, snapshots, perf counts, logs and regular Parquet files are under `target/accounting/`.

Keep the scoped sampler, skb witness and userspace probe for investigations. Quiet barriers allow exact reconciliation. Under continuing traffic the link bracket bounds what this procedure can distinguish. A saturated physical peer and an independent frame census are still required before setting a NIC policy or interpreting a device-wide pressure count as target loss.
