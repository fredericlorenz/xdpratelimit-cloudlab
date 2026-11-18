#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"

trial_dir=$1
address=$2
queue_count=$3
stop_irqbalance=$4
disable_rps=$5
irq_enabled=$6
irq_pattern=$7
irq_cpus_csv=$8
shift 8
blackhole_routes=("$@")

mkdir -p "$trial_dir"
iface=$(find_experiment_interface "$address")

if [[ $stop_irqbalance == 1 ]] && \
        systemctl list-unit-files irqbalance.service >/dev/null 2>&1; then
    sudo systemctl stop irqbalance
fi
sudo ethtool -L "$iface" combined "$queue_count"

if [[ $disable_rps == 1 ]]; then
    for file in /sys/class/net/"$iface"/queues/rx-*/rps_cpus; do
        test -e "$file" || continue
        printf '0\n' | sudo tee "$file" >/dev/null
    done
fi

for route in "${blackhole_routes[@]}"; do
    sudo ip route replace blackhole "$route"
done

if [[ $irq_enabled == 1 ]]; then
    IFS=, read -r -a irq_cpus <<< "$irq_cpus_csv"
    for queue in "${!irq_cpus[@]}"; do
        cpu=${irq_cpus[$queue]}
        pattern=${irq_pattern//\{queue\}/$queue}
        mapfile -t irq_matches < <(
            grep -F -- "$pattern" /proc/interrupts |
                awk '{gsub(":", "", $1); print $1}'
        )
        if [[ ${#irq_matches[@]} -ne 1 ]]; then
            printf 'expected one IRQ for queue %s pattern %s\n' "$queue" "$pattern" >&2
            exit 1
        fi

        irq=${irq_matches[0]}
        printf '%s\n' "$cpu" | sudo tee "/proc/irq/$irq/smp_affinity_list" >/dev/null
        effective=$(cat "/proc/irq/$irq/effective_affinity_list")
        test "$effective" = "$cpu"
        printf 'queue=%s irq=%s cpu=%s effective=%s\n' \
            "$queue" "$irq" "$cpu" "$effective" >> "$trial_dir/irq-map.txt"
    done
fi

printf '%s\n' "$iface"
