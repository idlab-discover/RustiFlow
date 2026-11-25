#!/usr/bin/env bash
# Run only inside topology.sh. Plain, C-tagged or S+C-tagged ingress with independently selected GRO and GSO.
set -euo pipefail
vlan=$1 gro=$2 gso=$3
[[ $SEND == rf09-s-* && $CAP == rf09-c-* ]]
for ns in "$SEND" "$CAP"; do
    if [[ $ns == "$SEND" ]]; then lower=send0; id=2; else lower=cap0; id=1; fi
    ip -n "$ns" addr flush dev "$lower" scope global
    if ip -n "$ns" link show tag17 &>/dev/null; then ip -n "$ns" link del tag17; fi
    if ip -n "$ns" link show outer9 &>/dev/null; then ip -n "$ns" link del outer9; fi
    parent=$lower
    if [[ $vlan == stack ]]; then
        parent=outer9
        ip -n "$ns" link add link "$lower" name "$parent" type vlan protocol 802.1ad id 9
        ip -n "$ns" link set "$parent" up
    fi
    dev=$lower
    if [[ $vlan != plain ]]; then
        dev=tag17
        ip -n "$ns" link add link "$parent" name "$dev" type vlan id 17
        ip -n "$ns" link set "$dev" up
    fi
    ip -n "$ns" addr add "198.18.9.$id/24" dev "$dev"
    ip -n "$ns" addr add "fd09:1::$id/64" dev "$dev" nodad
    if [[ $ns == "$SEND" ]]; then
        ip -n "$ns" neigh replace 198.18.9.1 lladdr 02:00:00:00:00:02 nud permanent dev "$dev"
        ip -n "$ns" -6 neigh replace fd09:1::1 lladdr 02:00:00:00:00:02 nud permanent dev "$dev"
        ip -n "$ns" route replace 198.18.10.2 via 198.18.9.1 dev "$dev"
        ip -n "$ns" -6 route replace fd09:2::2 via fd09:1::1 dev "$dev"
    fi
done
ip netns exec "$CAP" ethtool -K cap0 gro "$gro" rx-udp-gro-forwarding on
ip netns exec "$SEND" ethtool -K send0 gso "$gso" tx-udp-segmentation "$gso"
