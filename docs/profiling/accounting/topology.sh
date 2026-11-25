#!/usr/bin/env bash
# Run a single command in an isolated three-namespace test topology.
set -euo pipefail
export SEND=rf09-s-$$ CAP=rf09-c-$$ SINK=rf09-r-$$
created=()
driver=
cleanup() {
    if [[ -n $driver ]]; then
        kill -TERM -- "-$driver" 2>/dev/null || true
        kill -CONT -- "-$driver" 2>/dev/null || true
        for _ in {1..50}; do
            kill -0 -- "-$driver" 2>/dev/null || break
            sleep .02
        done
        kill -KILL -- "-$driver" 2>/dev/null || true
        wait "$driver" 2>/dev/null || true
    fi
    for ns in "${created[@]}"; do
        for pid in $(ip netns pids "$ns"); do kill -KILL "$pid" 2>/dev/null || true; done
        ip netns del "$ns"
    done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for ns in "$SEND" "$CAP" "$SINK"; do
    ip netns add "$ns"
    created+=("$ns")
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.default.addr_gen_mode=1 net.ipv6.conf.default.router_solicitations=0 net.ipv6.conf.default.accept_ra=0 net.ipv6.conf.default.mldv2_unsolicited_report_interval=1
done
ip -n "$SEND" link add send0 address 02:00:00:00:00:01 type veth peer name cap0 address 02:00:00:00:00:02 netns "$CAP"
ip -n "$CAP" link add exit0 address 02:00:00:00:00:03 type veth peer name sink0 address 02:00:00:00:00:04 netns "$SINK"
ip netns exec "$SINK" sysctl -qw net.ipv6.conf.sink0.disable_ipv6=1
ip netns exec "$CAP" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip -n "$CAP" link set exit0 up
ip -n "$SINK" link set sink0 up
ip netns exec "$CAP" ethtool -K exit0 gso off tso off tx-udp-segmentation off
ip netns exec "$SINK" ethtool -K sink0 gro off
ip -n "$CAP" address add 198.18.10.1/24 dev exit0
ip -n "$CAP" address add fd09:2::1/64 dev exit0 nodad
ip -n "$CAP" neigh add 198.18.10.2 lladdr 02:00:00:00:00:04 nud permanent dev exit0
ip -n "$CAP" -6 neigh add fd09:2::2 lladdr 02:00:00:00:00:04 nud permanent dev exit0
ip -n "$SEND" link set send0 up
ip -n "$CAP" link set cap0 up
setsid "$@" &
driver=$!
wait "$driver"
driver=
