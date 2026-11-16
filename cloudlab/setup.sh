#!/usr/bin/env bash
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
diagnostics=/local/cloudlab-node-diagnostics.txt
log=/local/cloudlab-setup.log
status=/local/cloudlab-setup.status

if [[ $EUID -ne 0 ]]; then
    echo "Run this provisioning script as root (sudo bash cloudlab/setup.sh)." >&2
    exit 1
fi
mkdir -p /local
exec > >(tee -a "$log") 2>&1
trap 'code=$?; if (( code != 0 )); then printf "failed (exit %s)\n" "$code" >"$status"; fi' EXIT
printf 'running\n' >"$status"
date -u

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    ethtool \
    git \
    iproute2 \
    iputils-ping \
    libbpf-dev \
    libelf-dev \
    pciutils \
    pkg-config \
    python3

# Ubuntu 24.04's bpftool is a virtual package whose launcher normally needs
# versioned linux-tools. CloudLab images may run a custom kernel, so use the
# packaged standalone binary if that launcher cannot find its kernel's tool.
source /etc/os-release
if [[ $ID == ubuntu ]]; then
    apt-get install -y --no-install-recommends linux-tools-common linux-tools-generic
    if ! bpftool version; then
        tool=$(find /usr/lib -maxdepth 3 -type f -path '*/linux-tools*/*' -name bpftool |
            sort -V | tail -n 1)
        if [[ -z "$tool" ]]; then
            echo "No usable bpftool found; install a standalone bpftool for this image." >&2
            exit 1
        fi
        install -m 0755 "$tool" /usr/local/sbin/bpftool
        hash -r
    fi
else
    apt-get install -y --no-install-recommends bpftool
fi
bpftool version

make -B -C "$repo/victim/ratelimit"
make -B -C "$repo/attacker/trafficgen"

experiment_iface=$(
    ip -o -4 addr show |
        awk '$4 ~ /^10\.77\.0\./ { print $2; exit }'
)
if [[ -z "$experiment_iface" ]]; then
    echo "Could not identify the experiment interface from 10.77.0.0/24" >&2
    exit 1
fi

{
    printf 'UTC=%s\n' "$(date -u +%FT%TZ)"
    printf 'REPOSITORY_COMMIT=%s\n' "$(git -C "$repo" rev-parse HEAD)"
    printf '\n## kernel\n'
    uname -a
    printf '\n## package versions\n'
    dpkg-query -W clang libbpf-dev ethtool linux-tools-common 2>/dev/null || true
    bpftool version
    printf '\n## CPU topology\n'
    lscpu
    printf 'CPU_POSSIBLE_LIST=%s\n' "$(cat /sys/devices/system/cpu/possible)"
    printf 'CPU_ONLINE_LIST=%s\n' "$(cat /sys/devices/system/cpu/online)"
    printf 'EXPERIMENT_IFACE=%s\n' "$experiment_iface"
    printf 'EXPERIMENT_ADDRESS=%s\n' "$(
        ip -o -4 addr show dev "$experiment_iface" |
            awk '$4 ~ /^10\.77\.0\./ { print $4; exit }'
    )"
    printf 'CONFIGURED_CPUS=%s\n' "$(getconf _NPROCESSORS_CONF)"
    printf '\n## ip -br address\n'
    ip -br address
    printf '\n## ethtool -i %s\n' "$experiment_iface"
    ethtool -i "$experiment_iface" || true
    printf '\n## ethtool -l %s\n' "$experiment_iface"
    ethtool -l "$experiment_iface" || true
    printf '\n## ethtool -x %s\n' "$experiment_iface"
    ethtool -x "$experiment_iface" || true
    printf '\n## ethtool -n %s rx-flow-hash udp4\n' "$experiment_iface"
    ethtool -n "$experiment_iface" rx-flow-hash udp4 || true
    printf '\n## link details and offloads\n'
    ip -details link show dev "$experiment_iface"
    ethtool -k "$experiment_iface" || true
    printf '\n## NIC NUMA node\n'
    cat /sys/class/net/"$experiment_iface"/device/numa_node || true
    printf '\n## IRQs\n'
    for irq_path in /sys/class/net/"$experiment_iface"/device/msi_irqs/*; do
        [[ -e "$irq_path" ]] || continue
        irq=${irq_path##*/}
        grep -E "^[[:space:]]*$irq:" /proc/interrupts || true
        printf 'irq=%s effective_affinity=' "$irq"
        cat /proc/irq/"$irq"/effective_affinity_list || true
    done
    printf '\n## irqbalance\n'
    systemctl is-active irqbalance || true
    printf '\n## RPS\n'
    for rps_file in /sys/class/net/"$experiment_iface"/queues/rx-*/rps_cpus; do
        [[ -e "$rps_file" ]] || continue
        printf '%s: ' "$rps_file"
        cat "$rps_file"
    done
} | tee "$diagnostics"

printf 'ready\n' >"$status"
printf '\nExperiment interface: %s\nDiagnostics: %s\n' \
    "$experiment_iface" "$diagnostics"
