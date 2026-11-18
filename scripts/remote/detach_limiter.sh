#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

repo=$1
address=$2

iface=$(find_experiment_interface "$address")
cd "$repo/victim/ratelimit"
sudo ./ratelimit --interface "$iface" --detach
