#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

repo=$1
address=$2
destination=$3
source_address=$4
key_mode=$5
protocol=$6
keys=$7
packets_per_key=$8
rate_pps=$9
rss_file=${10}
source_port=${11}
destination_port=${12}
warmup_packets=${13}
retry_packets=${14}
deadline_ms=${15}
trial_id=${16}
chaff=${17}
target_queue=${18}
dry_run=${19}
summary=${20}

iface=$(find_experiment_interface "$address")
cd "$repo/attacker/trafficgen"
command=(
    sudo ./trafficgen
    --interface "$iface"
    --profile attack
    --dst "$destination"
    --src "$source_address"
    --key "$key_mode"
    --proto "$protocol"
    --keys "$keys"
    --pkts-per-key "$packets_per_key"
    --rate "$rate_pps"
    --rss-file "$rss_file"
    --sport "$source_port"
    --dport "$destination_port"
    --warmup-pkts "$warmup_packets"
    --retry-pkts "$retry_packets"
    --deadline-ms "$deadline_ms"
    --trial-id "$trial_id"
    --chaff "$chaff"
)

if [[ -n $target_queue ]]; then
    command+=(--target-queue "$target_queue")
fi
if [[ $dry_run == 1 ]]; then
    command+=(--dry-run)
else
    command+=(--summary "$summary")
fi

exec "${command[@]}"
