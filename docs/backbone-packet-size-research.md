# Backbone and CDN packet sizes for RustiFlow capacity estimates

Research date: 11 November 2026.

Public measurements support a more demanding workload than the local NIC sample. RustiFlow's measured 12.343 Mpps median synthetic userspace replay corresponds arithmetically to about 68–93 Gbit/s for the two backbone profiles below. These are byte-rate equivalents, not measured capture capacities.

## Recent backbone measurements

CAIDA publishes monthly captures from a commercial 100 Gbit/s backbone link, currently Los Angeles–Dallas. The 16 April 2026 capture spans 3,566 seconds and reports zero capture loss in both directions. [Dataset statistics](https://www.caida.org/catalog/datasets/100g_trace_stats/), [deployment background](https://www.caida.org/about/annualreports/2025/).

| Measurement | Direction A | Direction B |
|---|---:|---:|
| Mean size, total bytes / total packets | 940.66 B | 685.21 B |
| IPv4/IPv6 histogram packets ≤128 B | 28.02% | 42.67% |
| IPv4/IPv6 histogram packets 1400–1536 B | 46.17% | 32.01% |
| Observed packet rate | 7.815 Mpps | 9.214 Mpps |
| Observed source-reported bitrate | 58.810 Gbit/s | 50.509 Gbit/s |

Means and rates come from [public metadata](https://www.caida.org/catalog/datasets/100g_trace_stats/metadata/100g-passive-metadata.json). Size percentages were calculated from the IPv4 and IPv6 total columns in the [A histogram](https://www.caida.org/catalog/datasets/100g_trace_stats/metadata/100g-01/2026/20260416-130000/20260416-130000.dira.stats) and [B histogram](https://www.caida.org/catalog/datasets/100g_trace_stats/metadata/100g-01/2026/20260416-130000/20260416-130000.dirb.stats). Protocol subcolumns are not added again. Histogram coverage differs from metadata IP totals by 3,935 packets in A and 839 in B, less than 0.00002%. Percentages use available histogram counts.

Together the directions carried 17.029 Mpps. That exceeds the replay result before allowing for capture overhead. A 100 Gbit/s full-duplex port can require processing both directions simultaneously.

June 2026 direction B was excluded from the capacity example because its metadata reports over 10.8 billion lost packets. April is a quality-selected example, not a claim about a universal Internet distribution. Metadata median-size fields were not used; they conflict with cumulative histogram counts.

## Exchange measurements

Seattle Internet Exchange publishes an Ethernet frame-size histogram from core-switch sFlow sampling, approximately one in 100,000 frames. The monthly graph snapshot dated 11 November 2026 shows 25.64% at ≤128 bytes and 47.61% at 1409–1536 bytes. [Method and graphs](https://www.seattleix.net/statistics/), [monthly graph](https://www.seattleix.net/statistics/agg_framesizes.monthly.png).

Weighting each displayed bin by its midpoint gives approximately 967 bytes; using bin endpoints gives 912–1021 bytes. This is an estimate from rounded, time-averaged chart percentages, not a published exact packet-weighted mean. It corroborates a mixture of small packets and near-MTU frames, rather than uniformly large packets.

## CDN-facing links

Cisco reported interface byte-counter / packet-counter measurements from ISPs in the US and Western Europe in February 2018. These are means, not distributions, and are historical ISP observations rather than current CDN self-reports. Interpreting ingress as delivery follows the ISP interface context. [Original measurements](https://xrdocs.io/ncs5500/tutorials/2018-02-19-netflow-sampling-interval-and-the-mythical-internet-packet-size).

| CDN-facing link | ISP ingress mean | ISP egress mean |
|---|---:|---:|
| Fastly | 1407 B | 140 B |
| Akamai customer 1 | 1471 B | 72 B |
| Akamai customer 2 | 1443 B | 82 B |
| Netflix customer 1 | 1495 B | 73 B |
| Netflix customer 2 | 1470 B | 74 B |

Duration and exact byte accounting are unspecified. Large delivery packets coexist with small return packets; combine directions using packet counts, never an unweighted average of their means.

Cloudflare's [2025 TCP connection measurements](https://blog.cloudflare.com/measuring-network-connections-at-scale) report connection-level packet counts, byte counts and PMTU. Those separate distributions do not establish an all-packet size histogram and were not converted into one.

## Capacity arithmetic and its limits

Use pps = bit/s / (8 × mean packet bytes). The following table retains CAIDA's reported byte convention and adds no wire overhead. Exact L2/FCS accounting was not established. Physical line-rate conversion additionally requires preamble, interpacket gap, and any omitted link-layer bytes.

| Profile | Mpps at 40 Gbit/s | Mpps at 100 Gbit/s | Byte-rate equivalent of 12.343 Mpps |
|---|---:|---:|---:|
| CAIDA A, 940.66 B | 5.32 | 13.29 | 92.88 Gbit/s |
| CAIDA B, 685.21 B | 7.30 | 18.24 | 67.66 Gbit/s |

If the sizes include complete Ethernet frames including FCS, adding 20 bytes for preamble/SFD and gap changes the 100 Gbit/s estimates to about 13.01 and 17.73 Mpps. This accounting uncertainty does not remove the packet-budget shortfall.

The local replay used 20 million synthetic events, 100,000 stable flows, eight sources and twelve workers, full RustiFlow features and CSV export. Five runs ranged from 11.828 to 12.430 Mpps. It excludes NIC reception, kernel/eBPF work and ring reads; it does not model realistic flow churn or demonstrate a recent speedup against an older build. Local evidence: `target/nic-observation/20261111-223117/`.

A sensible next validation target is 40 Gbit/s aggregate traffic with both CAIDA size profiles, followed by increasing rates while reconciling offered, captured, processed and exported packets. Test stable flows and churn separately, and include bidirectional traffic and bursts. Forty Gbit/s in each direction is a different target: these profiles together require about 12.61 Mpps before wire-overhead adjustment, leaving essentially no margin against the current userspace replay.

Downloaded public metadata, histogram parsers and the Seattle graph snapshot are in `target/packet-size-research/`; these build-directory artifacts are not committed. No restricted CAIDA packet traces were downloaded.
