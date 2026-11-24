# Backbone vision

The long-term goal is realtime flow reconstruction and feature extraction at
backbone rates of 100, 200, and 400 Gbit/s. Raw throughput is not enough on its
own. RustiFlow should also keep CPU cost low relative to captured traffic, keep
memory predictable under bursts, report overload and drops clearly, and keep
flow semantics trustworthy under load. With those properties, deployment on
production networks for dataset collection becomes a realistic proposal.

## Deployment path

1. Validate locally at 10 Gbit/s, then 25 and if possible 40 Gbit/s.
   RustiFlow reached 10 Gbit/s in earlier work by the master's student who
   wrote the original implementation. The current work rebuilds that
   confidence on today's code.
2. Use that evidence to deploy on the team's slice of the datacenter network.
3. Use datacenter results to discuss deployment on university infrastructure.
4. If RustiFlow proves efficient and trustworthy there, approach national ISPs.

Local validation exposes ingestion bottlenecks early, allows repeatable
adversarial tests, and establishes CPU, memory, and drop baselines before
asking operators for access.

## Technical implication

The current tc/eBPF ring-buffer path is good for proving semantics and reaching
moderate-to-high rates. It should not be assumed to be the final architecture
for 100 Gbit/s and above. That may need stronger parallel ingestion, tighter
batching and memory movement, core and NUMA locality, careful flow sharding,
and possibly a different transport if measurements show the ring design
saturates. [Packet-size research](backbone-packet-size-research.md) relates
measured packet rates to backbone traffic profiles.

## What operators will ask

- What sustained throughput does it handle, and at what drop rate under
  realistic and bursty load?
- How many cores and how much memory does each throughput tier need?
- Does overload fail visibly and predictably?
- Are the flows and features trustworthy enough for datasets and analysis?

Success means repeatable throughput results, well-characterized resource use,
clear overload behavior, stable export semantics, and operator confidence. A
single large lab number does not meet that bar.
