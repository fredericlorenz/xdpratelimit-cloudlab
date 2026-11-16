#!/usr/bin/env bash
# Fixed unsteered batch for the victim's RSS A/B/C/D controls.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
iface=${IFACE:-}
victim_ip=${VICTIM_IP:-10.77.0.1}

if [[ -z "$iface" ]]; then
    iface=$(
        ip -o -4 addr show |
            awk '$4 ~ /^10\.77\.0\.2\// { print $2; exit }'
    )
fi
if [[ -z "$iface" ]]; then
    printf 'Could not identify the experiment interface; set IFACE explicitly\n' >&2
    exit 1
fi

case ${1:-send} in
    prepare)
        git -C "$script_dir" rev-parse HEAD
        make -B -C "$script_dir"
        ping -I "$iface" -c 1 -W 2 "$victim_ip"
        ;;
    send)
        exec sudo "$script_dir/trafficgen" --interface "$iface" --dst "$victim_ip" \
            --profile random --key source --proto udp --keys 256 --pkts-per-key 1
        ;;
    *)
        printf 'Usage: bash %s [prepare|send] (IFACE=<experiment-iface> VICTIM_IP=10.77.0.1)\n' "$0" >&2
        exit 2
        ;;
esac
