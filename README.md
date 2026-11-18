# RSS-steered XDP eviction lab

This CloudLab deployment provides two bare-metal nodes for investigating whether deterministic RSS steering can concentrate eBPF LRU eviction pressure and reset an XDP rate limiter's state.

| Node | Experiment address | Role |
|---|---|---|
| `victim` | `10.77.0.1/24` | XDP GCRA rate limiter and evidence capture |
| `attacker` | `10.77.0.2/24` | RSS-aware raw traffic generator |

The nodes share an isolated experiment link. CloudLab supplies separate control interfaces for SSH and file transfer; spoofed traffic must never be sent through the control network.

## Profile and setup

Import `profile.py` as a CloudLab profile. It defaults to Ubuntu 24.04 and Utah `c6525-25g` nodes with Mellanox ConnectX-5 NICs. Profile parameters also expose `c6620` with Intel E810 and `xl170` with Mellanox ConnectX-4.

At startup, `cloudlab/setup.sh` installs dependencies, builds both components and records system and NIC diagnostics. Check provisioning with:

```sh
cat /local/cloudlab-setup.status
cat /local/cloudlab-setup.log
cat /local/cloudlab-node-diagnostics.txt
```

`ready` confirms setup only. It does not validate RSS steering.

Identify the experiment interface on either node with:

```sh
export IFACE=$(ip -o -4 addr show | awk '$4 ~ /^10\.77\.0\./ {print $2; exit}')
```

## Components

- `victim/ratelimit`: native-XDP GCRA limiter with shared or per-CPU values, common or per-CPU LRU policies, non-evicting controls and persistent target auditing.
- `attacker/trafficgen`: raw IPv4 generator with ordinary and symmetric OR-XOR Toeplitz prediction, queue-targeted tuple search, matched random controls and JSON trial summaries.

Both programs provide `--help` and Python regression tests. Their component READMEs contain build and trial commands.

## Automated trials

Install the controller's YAML dependency on a machine with management SSH access to both nodes:

```sh
python3 -m pip install -r scripts/requirements.txt
```

Validate and inspect the expanded experiments without connecting to CloudLab:

```sh
python3 scripts/run_trial.py \
    --victim user@victim-control-host \
    --attacker user@attacker-control-host \
    --config configs/cloudlab-mlx5-smoke.yaml \
    --plan
```

Remove `--plan` to synchronize the remote revisions, prepare the NIC, run every experiment defined by the YAML file, capture evidence and verify each result locally from the frozen evidence. `scripts/run_trial.py` handles orchestration; the commands executed for each remote phase are kept in the named helpers under `scripts/remote/`. The controller derives blackhole routes from the generated source-key range automatically unless the value is explicitly configured. Start with `configs/cloudlab-mlx5-smoke.yaml` to validate the setup. `configs/cloudlab-mlx5-sweep.yaml` runs the full sweep over map modes, capacities and chaff strategies with repetitions. Each trial is archived under `results/<experiment-name>-<trial-id>/` on the controller with its summary, evidence, verification report, manifest, RSS configuration, diagnostics and logs. Sweep names use a compact format such as `lru-sweep_mode-percpu-local_entries-64_chaff-steered_r01-<trial-id>`.

## Trial preparation

Before collecting results:

1. Configure the intended RX queue count and RSS indirection table, then record `ethtool -i`, `-l`, `-x` and the UDP/IPv4 hash fields.
2. Stop `irqbalance`, pin each tested RX queue IRQ to a known CPU and disable RPS on those queues.
3. Prevent victim replies to the generated source ranges from following another route:

```sh
sudo ip route replace blackhole 10.100.0.0/16
sudo ip route replace blackhole 10.200.0.0/16
```

4. Attach a fresh limiter for every run, reapply RSS after the final attachment, and export the current key and indirection table.
5. Validate a small steered batch against `rl_queue_stats` before running an attack.
6. Keep generated traffic on the experiment link and transfer RSS configuration and evidence through the control network.

Linux 6.8 mlx5 uses symmetric OR-XOR RSS input transformation without exposing it through older `ethtool -x` output. Export it with `--input-transform symmetric-or-xor`; Intel and newer/reporting configurations should use the transformation reported by `ethtool`.

## CloudLab documentation

- [Creating profiles](https://docs.cloudlab.us/creating-profiles.html)
- [Reservations](https://docs.cloudlab.us/reservations.html)
- [Control network](https://docs.cloudlab.us/control-net.html)
- [Hardware](https://docs.cloudlab.us/hardware.html)
