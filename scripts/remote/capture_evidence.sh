#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

repo=$1
address=$2
trial_dir=$3
drain_seconds=$4

iface=$(find_experiment_interface "$address")
sleep "$drain_seconds"
program_id=$(
    sudo ip -details link show dev "$iface" |
        awk '/prog\/xdp/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "id") {print $(i + 1); exit}
            }
        }'
)
test -n "$program_id"
sudo python3 "$script_dir/capture_evidence.py" \
    "$repo" "$program_id" "$trial_dir/evidence.json"
