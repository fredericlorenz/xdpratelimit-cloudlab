#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

repo=$1
trial_dir=$2
address=$3
queue_count=$4
rate_pps=$5
burst=$6
entries=$7
key_mode=$8
map_mode=$9
target_source=${10}
trial_id=${11}
input_transform=${12}
apply_equal=${13}

iface=$(find_experiment_interface "$address")
cd "$repo/victim/ratelimit"
sudo ./ratelimit \
    --interface "$iface" \
    --rate "$rate_pps" \
    --burst "$burst" \
    --entries "$entries" \
    --key "$key_mode" \
    --map-mode "$map_mode" \
    --target-source "$target_source" \
    --trial-id "$trial_id" \
    --replace

if [[ $apply_equal == 1 ]]; then
    sudo ethtool -X "$iface" equal "$queue_count"
fi

transform_args=()
if [[ $input_transform != auto ]]; then
    transform_args=(--input-transform "$input_transform")
fi
sudo ethtool -x "$iface" | \
    python3 "$repo/attacker/trafficgen/extract_rss.py" "${transform_args[@]}" \
        > "$trial_dir/rss.conf"

{
    uname -a
    sudo ethtool -i "$iface"
    sudo ethtool -l "$iface"
    sudo ethtool -x "$iface"
    sudo ethtool -n "$iface" rx-flow-hash udp4
    sudo bpftool net show dev "$iface"
    test ! -f "$trial_dir/irq-map.txt" || cat "$trial_dir/irq-map.txt"
    for file in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
        test -e "$file" || continue
        printf '%s=' "$file"
        cat "$file"
    done
} > "$trial_dir/victim-diagnostics.txt"
