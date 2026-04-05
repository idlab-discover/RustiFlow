# Local Harness Testing Matrix

This document defines the trusted local software-path regression matrix for the
`rustiflow-t0` / `rustiflow-peer` / `rustiflow-p0` veth harness on `rgbcore`.

The purpose of this harness is not to answer a true physical-wire `40G`
question. The local harness is for repeatable software-path validation at the
rates this machine can credibly sustain today.

Current working interpretation from the recorded experiments:

- large-packet local control traffic is credible in roughly the `20-25 Gbit/s`
  band depending on the generator shape
- the harness is still useful well below that ceiling for adversarial shape
  testing and regression detection
- true `40G` validation for the current tc/eBPF realtime path remains a
  physical-hardware problem rather than a one-host virtual-harness problem

## What To Measure

Every scenario in this matrix should record more than pass or fail.

For each run, record:

- generator shape and exact command
- CPU placement for generator, RustiFlow, and control shell
- RustiFlow feature set: `basic` or `rustiflow`
- RustiFlow `--threads` value
- achieved bitrate from the generator
- RustiFlow `Total dropped packets`
- run duration
- optional notes about instability, jitter, receiver loss, or exporter size

For every non-control scenario, compute headroom against the matching control
run:

```text
headroom_loss_pct = ((control_bitrate - rustiflow_bitrate) / control_bitrate) * 100
```

This matters more than a binary pass/fail result when the local generator, not
RustiFlow, is the real ceiling.

## CPU Partition

Keep the CPU split fixed so results stay comparable.

Use this split on the current `32` logical CPU host:

| Role | CPUs | Notes |
| --- | --- | --- |
| Peer-side traffic sender | `0-7` | `iperf3` server, `tcpreplay`, or other sender |
| RustiFlow capture and userspace processing | `8-23` | `16` logical CPUs, `--threads 16` baseline |
| Control shell and client processes | `24-31` | `iperf3` client control path, Docker, logs |

Notes:

- For `iperf3 -R`, the peer-side server is the active sender. Pin the server,
  not only the client.
- This harness has no physical NIC IRQ placement to manage. The relevant
  contention surface is userspace generator CPU time versus RustiFlow CPU time.
- If a run deviates from this CPU split, record it explicitly.

## Common Setup

Run the matrix from the repository root.

```bash
export GEN_CPUS=0-7
export UDP_CPUS=0-3
export TCP_CPUS=4-7
export RF_CPUS=8-23
export CTRL_CPUS=24-31
export RF_THREADS=16
export RF_IMAGE=rustiflow:test-slim
export RF_OUT_DIR="$PWD/target/realtime-matrix"
mkdir -p "$RF_OUT_DIR"
```

Verify the harness once before starting:

```bash
systemctl status --no-pager rustiflow-swtest-veth.service
ip -details link show rustiflow-t0
sudo ip netns exec rustiflow-peer ip -details link show rustiflow-p0
```

Quick packet-rate reference:

| Shape | Approximate packet rate |
| --- | --- |
| UDP payload `1400` at `20 Gbit/s` | about `1.75 Mpps` |
| UDP payload `1400` at `25 Gbit/s` | about `2.2 Mpps` |
| UDP payload `512` at `10 Gbit/s` | about `2.3 Mpps` |
| UDP payload `256` at `10 Gbit/s` | about `4.4 Mpps` |

## Harness Helpers

Start RustiFlow pinned to its CPU set:

```bash
start_rustiflow() {
  local name="$1"
  local features="$2"
  local export_file="$3"

  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d \
    --rm \
    --name "$name" \
    --privileged \
    --network host \
    --cpuset-cpus "$RF_CPUS" \
    -e RUST_LOG=info \
    -v "$RF_OUT_DIR:/tmp" \
    "$RF_IMAGE" \
    -f "$features" \
    -o csv \
    --header \
    --export-path "/tmp/$export_file" \
    --threads "$RF_THREADS" \
    realtime rustiflow-t0 --ingress-only >/dev/null
  sleep 2
}
```

Stop RustiFlow cleanly and print the dropped-packet summary:

```bash
stop_rustiflow() {
  local name="$1"
  docker kill -s INT "$name" >/dev/null
  sleep 1
  docker logs "$name" 2>&1 | rg "Total dropped packets|Duration:"
}
```

Start a long-lived reverse-mode `iperf3` sender in the peer namespace:

```bash
start_iperf_server() {
  local cpus="$1"
  local port="$2"

  sudo pkill -f "iperf3 -s -B 10.203.0.2 -p $port" >/dev/null 2>&1 || true
  sudo ip netns exec rustiflow-peer \
    taskset -c "$cpus" \
    iperf3 -s -B 10.203.0.2 -p "$port" --daemon
}
```

Stop background `iperf3` servers:

```bash
stop_iperf_servers() {
  sudo pkill -f "iperf3 -s -B 10.203.0.2" >/dev/null 2>&1 || true
}
```

## Operating Rules

Each scenario should be executed as a three-run bundle:

1. control run without RustiFlow
2. RustiFlow `-f basic`
3. RustiFlow `-f rustiflow`

Additional rules:

- Keep the generator command identical across the three runs for a scenario.
- If the control run cannot reach the nominal target, record the actual control
  ceiling and compare RustiFlow against that result, not against the nominal
  target.
- Prefer `basic` as the first RustiFlow run for any new or unstable traffic
  shape.
- The local harness is allowed to answer different ceilings for different
  traffic shapes. Do not force every shape to a single headline bitrate.

## Baseline Matrix

This matrix is the default regression set for the local harness.

| ID | Scenario | Default target | Runs required | Primary result |
| --- | --- | --- | --- | --- |
| `B1` | Large-packet UDP steady baseline | `20G`, payload `1400`, `-P 8`, `30s` | control, `basic`, `rustiflow` | clean baseline and headroom |
| `B2` | Large-packet UDP near local ceiling | highest clean control in `23-25G` band, payload `1400`, `30s` | control, `basic`, `rustiflow` | high-load headroom near ceiling |
| `B3` | Small-packet UDP PPS stress, `512` | shape-specific control ceiling, start at `10G` and step upward | control, `basic`, `rustiflow` | PPS sensitivity |
| `B4` | Small-packet UDP PPS stress, `256` | shape-specific control ceiling, start at `5G` or `10G` and step upward | control, `basic`, `rustiflow` | worst-case PPS sensitivity |
| `B5` | Mixed UDP plus TCP | about `20-23G` aggregate | control, `basic`, `rustiflow` | mixed-protocol behavior |
| `B6` | Short-lived flow churn | highest clean control for the chosen churn recipe | control, `basic`, `rustiflow` | flow lifecycle churn |
| `B7` | Long soak | `20G` large-packet UDP for `900s` | control optional, `basic`, `rustiflow` | long-run stability |
| `B8` | Representative replay trace | highest clean replay rate for the chosen trace | control, `basic`, `rustiflow` | parser and exporter realism |

## Recipes

### `B1` Large-packet UDP steady baseline

Use this as the routine daily or pre-change regression case.

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201
```

Control:

```bash
taskset -c "$CTRL_CPUS" \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 20G -l 1400 -P 8 -t 30 -R
```

`basic`:

```bash
start_rustiflow rustiflow-b1-basic basic b1-basic.csv
taskset -c "$CTRL_CPUS" \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 20G -l 1400 -P 8 -t 30 -R
stop_rustiflow rustiflow-b1-basic
```

`rustiflow`:

```bash
start_rustiflow rustiflow-b1-rustiflow rustiflow b1-rustiflow.csv
taskset -c "$CTRL_CPUS" \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 20G -l 1400 -P 8 -t 30 -R
stop_rustiflow rustiflow-b1-rustiflow
```

### `B2` Large-packet UDP near local ceiling

This is the high-load regression case. Use the best clean local control bitrate
that still looks credible for the current generator shape. Today that usually
means the `23-25G` band rather than a nominal `40G`.

Suggested first pass:

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201

taskset -c "$CTRL_CPUS" \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 23G -l 1400 -P 8 -t 30 -R
```

If the control run is clean and still below the known local ceiling, repeat at
`24G` or `25G`. Then run the same chosen bitrate with `basic` and `rustiflow`.

### `B3` Small-packet UDP PPS stress, `512`

Use a stepped sweep. Do not assume this shape can sustain the same bitrate as
`1400`-byte payloads.

Suggested progression:

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201
```

Control sweep:

```bash
for rate in 10G 15G 20G; do
  taskset -c "$CTRL_CPUS" \
    iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
    -u -b "$rate" -l 512 -P 8 -t 30 -R
done
```

Choose the highest clean control result and repeat that rate with `basic` and
`rustiflow`.

### `B4` Small-packet UDP PPS stress, `256`

This is the more adversarial PPS-focused case. Start conservatively.

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201
```

Control sweep:

```bash
for rate in 5G 10G 15G 20G; do
  taskset -c "$CTRL_CPUS" \
    iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
    -u -b "$rate" -l 256 -P 8 -t 30 -R
done
```

Choose the highest clean control result and repeat that rate with `basic` and
`rustiflow`.

### `B5` Mixed UDP plus TCP

Run two peer-side `iperf3` servers on different ports and keep UDP and TCP on
separate control CPU ranges so the mixed case does not collapse into client
self-contention.

```bash
stop_iperf_servers
start_iperf_server "$UDP_CPUS" 5201
start_iperf_server "$TCP_CPUS" 5202
```

Control:

```bash
taskset -c 24-27 \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 10G -l 1400 -P 8 -t 30 -R >/tmp/b5-udp.log &
udp_pid=$!

taskset -c 28-31 \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5202 \
  -P 8 -t 30 -R >/tmp/b5-tcp.log &
tcp_pid=$!

wait "$udp_pid"
wait "$tcp_pid"
cat /tmp/b5-udp.log
cat /tmp/b5-tcp.log
```

Then repeat the same generator shape with `basic` and `rustiflow`. Record both
the per-protocol results and the aggregate.

### `B6` Short-lived flow churn

The goal here is flow lifecycle churn, not pure bulk throughput. Use many
short-lived connections or short bursts across many source ports.

One simple starting point is repeated short reverse TCP runs:

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201

for i in $(seq 1 200); do
  taskset -c "$CTRL_CPUS" \
    iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
    -P 4 -t 1 -R >/dev/null
done
```

If this case becomes important, replace it with a dedicated churn helper script
that varies ports and inter-arrival timing in a more controlled way.

### `B7` Long soak

Use a rate that is known to be stable for this host, not a speculative
headline. The goal is long-run correctness and stability.

Suggested starting point:

```bash
stop_iperf_servers
start_iperf_server "$GEN_CPUS" 5201
start_rustiflow rustiflow-b7-basic basic b7-basic.csv

taskset -c "$CTRL_CPUS" \
  iperf3 -c 10.203.0.2 -B 10.203.0.1 -p 5201 \
  -u -b 20G -l 1400 -P 8 -t 900 -R

stop_rustiflow rustiflow-b7-basic
```

Repeat with `rustiflow` after `basic` is stable.

### `B8` Representative replay trace

Use this only with a trace that is representative of the traffic mix you
actually care about. The right answer is the highest replay rate that stays
clean for that trace.

Control:

```bash
sudo ip netns exec rustiflow-peer \
  taskset -c "$GEN_CPUS" \
  tcpreplay --intf1=rustiflow-p0 --topspeed --loop=10 path/to/trace.pcap
```

`basic`:

```bash
start_rustiflow rustiflow-b8-basic basic b8-basic.csv
sudo ip netns exec rustiflow-peer \
  taskset -c "$GEN_CPUS" \
  tcpreplay --intf1=rustiflow-p0 --topspeed --loop=10 path/to/trace.pcap
stop_rustiflow rustiflow-b8-basic
```

`rustiflow`:

```bash
start_rustiflow rustiflow-b8-rustiflow rustiflow b8-rustiflow.csv
sudo ip netns exec rustiflow-peer \
  taskset -c "$GEN_CPUS" \
  tcpreplay --intf1=rustiflow-p0 --topspeed --loop=10 path/to/trace.pcap
stop_rustiflow rustiflow-b8-rustiflow
```

## Reporting Template

Use one row per run:

| Scenario | Variant | Feature set | Generator | Shape | Sender CPUs | RustiFlow CPUs | Threads | Duration | Achieved bitrate | Dropped packets | Headroom loss | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `B1` | control | none | `iperf3` | UDP `1400`, `20G`, `P8` | `0-7` | n/a | n/a | `30s` | | n/a | n/a | |
| `B1` | capture | `basic` | `iperf3` | UDP `1400`, `20G`, `P8` | `0-7` | `8-23` | `16` | `30s` | | | | |
| `B1` | capture | `rustiflow` | `iperf3` | UDP `1400`, `20G`, `P8` | `0-7` | `8-23` | `16` | `30s` | | | | |

## Practical Guidance

- Keep this matrix focused on the local harness as a software-path regression
  rig, not a substitute for real-NIC wire-rate validation.
- Use `basic` to localize ingestion and exporter regressions before spending
  time on the full `rustiflow` feature set.
- Do not hide generator ceilings. If the control path tops out below the
  nominal target, write that down and compare against the measured control
  result.
- Prefer fixed, repeatable recipes over ad hoc peak chasing. Stability across
  repeated runs matters more than one unusually good number.
