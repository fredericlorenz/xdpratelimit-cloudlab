#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

trial_dir=$1
address=$2
victim_address=$3

mkdir -p "$trial_dir"
iface=$(find_experiment_interface "$address")
ping -I "$iface" -c 1 -W 2 "$victim_address" >/dev/null
printf '%s\n' "$iface"
