#!/usr/bin/env python3
"""Capture program-scoped evidence and verify a fresh, isolated source-key trial."""

import argparse
import json
import re
import socket
import struct
import subprocess
import sys
from pathlib import Path

from stats import counters, number

CONFIG_FIELDS = ("interval_ns", "tolerance_ns", "rate_pps", "burst", "key_mode",
                 "map_mode", "target_saddr", "target_enabled", "trial_id")
FIELDS = ("first_created_ns", "latest_created_ns", "initializations", "map_insertions",
          "passed", "dropped", "first_cpu", "latest_cpu", "first_queue", "latest_queue",
          "event_count", "event_overflow")
EVENT_FIELDS = ("observed_ns", "prior_tat_ns", "created_ns", "cpu", "queue", "action", "inserted")
MAP_MODES = ("shared-global", "shared-local", "percpu-global", "percpu-local",
             "hash-shared", "hash-percpu")
RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


def result_name(value):
    if (len(value) > 160 or "__" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise argparse.ArgumentTypeError(
            "result name must contain only letters, digits, hyphens and single underscores")
    return value


def decode(value, fields, fmt):
    if isinstance(value, dict):
        return {field: number(value[field]) for field in fields}
    raw = bytes(int(byte, 16) if isinstance(byte, str) else byte for byte in value)
    if len(raw) != struct.calcsize(fmt):
        raise ValueError(f"incompatible audit ABI: {len(raw)} bytes for {fmt}")
    return dict(zip(fields, struct.unpack(fmt, raw)))


def decode_target_stats(value):
    return decode(value, FIELDS, "=QQQQQQIIIIQQ")


def bpf(*args):
    result = subprocess.run(["bpftool", "-j", *map(str, args)], check=True,
                            capture_output=True, text=True)
    return json.loads(result.stdout)


def one(value):
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("expected exactly one BPF object")
        return value[0]
    return value


def capture(program_id):
    # Resolve IDs through the selected program; never select by ambiguous map names.
    program = one(bpf("prog", "show", "id", program_id))
    maps = {}
    for map_id in program["map_ids"]:
        info = one(bpf("map", "show", "id", map_id))
        name = info["name"]
        if name in ("rl_config", "rl_target_stats", "rl_events", "rl_state", "rl_stats",
                    "rl_queue_stats"):
            if name in maps:
                raise ValueError(f"duplicate map {name}")
            maps[name] = {"info": info}
    for name in ("rl_config", "rl_target_stats", "rl_events", "rl_stats", "rl_queue_stats"):
        maps[name]["entries"] = bpf("map", "dump", "id", maps[name]["info"]["id"])
    # All trial traffic must have stopped before capture.
    for name in ("rl_config", "rl_target_stats", "rl_stats", "rl_queue_stats"):
        if bpf("map", "dump", "id", maps[name]["info"]["id"]) != maps[name]["entries"]:
            raise ValueError("configuration or traffic counters changed during capture")
    return {"schema_version": 2, "program": program, "maps": maps}


def unpack_evidence(evidence):
    if evidence["schema_version"] != 2:
        raise ValueError("unsupported evidence schema")
    maps = evidence["maps"]
    def single(name):
        entry = one(maps[name]["entries"])
        if number(entry["key"]) != 0:
            raise ValueError(f"unexpected {name} key")
        return entry["value"]
    config = decode(single("rl_config"), CONFIG_FIELDS, "=QQIIIIIIQ")
    stats = decode_target_stats(single("rl_target_stats"))
    event_slots = {number(e["key"]): decode(e["value"], EVENT_FIELDS, "=QQQIIII")
                   for e in maps["rl_events"]["entries"]}
    if stats["event_overflow"] or stats["event_count"] > 256:
        raise ValueError("target audit overflowed")
    events = [event_slots[i] for i in range(stats["event_count"])]
    return config, stats, events


def packet_counts(entries):
    counts = {}
    for entry in entries:
        slot = number(entry["key"])
        for value in entry["values"]:
            fields = counters(value["value"])
            counts[slot, number(value["cpu"])] = fields["passed"] + fields["dropped"]
    return counts


def evaluate(summary, evidence):
    """Separate invalid trials from valid resets and valid retained-state controls."""
    config, stats, events = unpack_evidence(evidence)
    failures = []
    def require(condition, message):
        if not condition:
            failures.append(message)
    require(summary["schema_version"] == 2, "unsupported sender schema")
    require(summary.get("chaff_profile") in ("random", "steered"),
            "missing or invalid chaff profile")
    require(config["trial_id"] > 0 and summary["trial_id"] == config["trial_id"],
            "trial identity mismatch")
    require(config["target_enabled"] == 1 and config["key_mode"] == 0,
            "verification requires an audited source-address key")
    source = int.from_bytes(socket.inet_aton(summary["target_source"]), sys.byteorder)
    require(config["target_saddr"] == source, "audited source differs from sender target")
    require(0 <= config["map_mode"] < len(MAP_MODES), "invalid map mode")
    require(config["rate_pps"] > 0 and config["interval_ns"] > 0 and config["burst"] > 0,
            "invalid limiter configuration")
    if config["rate_pps"] > 0:
        require(config["interval_ns"] == 1000000000 // config["rate_pps"],
                "interval differs from configured rate")
    require(config["tolerance_ns"] == (config["burst"] - 1) * config["interval_ns"],
            "invalid GCRA tolerance")
    for phase in ("warmup", "chaff", "retry"):
        require(summary[f"{phase}_sent"] == summary[f"{phase}_intended"],
                f"{phase} transmission was incomplete")
    require(summary["within_deadline"] is True, "sender exceeded its diagnostic deadline")
    times = [summary[k] for k in ("start_ns", "warmup_end_ns", "chaff_end_ns", "retry_end_ns")]
    require(times[0] > 0 and times == sorted(times), "invalid sender phase timestamps")
    require(times[-1] - times[1] <= summary["deadline_ns"], "inconsistent sender deadline")
    warmup_count, retry_count = summary["warmup_sent"], summary["retry_sent"]
    require(warmup_count > config["burst"] and retry_count > 0,
            "warmup must exhaust the burst and include a blocked packet")
    require(len(events) == warmup_count + retry_count,
            "missing or extra target packets; phase assignment is ambiguous")
    expected_packets = warmup_count + summary["chaff_sent"] + retry_count
    global_counts = packet_counts(evidence["maps"]["rl_stats"]["entries"])
    queue_counts = packet_counts(evidence["maps"]["rl_queue_stats"]["entries"])
    diagnostics = {
        "expected_target_packets": warmup_count + retry_count,
        "observed_target_packets": len(events),
        "expected_ipv4_packets": expected_packets,
        "observed_ipv4_packets": sum(global_counts.values()),
        "observed_queue_ipv4_packets": sum(queue_counts.values()),
        "victim_packets_by_queue_cpu": [
            {"queue": queue, "cpu": cpu, "packets": count}
            for (queue, cpu), count in sorted(queue_counts.items()) if count],
    }
    require(sum(global_counts.values()) == expected_packets and
            sum(queue_counts.values()) == expected_packets,
            "victim packet count differs from sender; chaff loss or background traffic")
    require(all(slot == 0 and count == sum(n for (q, c), n in queue_counts.items()
                                         if c == cpu)
                for (slot, cpu), count in global_counts.items()),
            "victim global and queue counters disagree by CPU")
    if failures:
        return {"valid": False, "outcome": "invalid", "failures": failures,
                **diagnostics}
    warmup, retry = events[:warmup_count], events[warmup_count:]
    first = warmup[0]
    require(first["action"] == 3 and first["inserted"] == 1,
            "target did not start with a fresh global insertion")
    require(all(e["cpu"] == first["cpu"] and e["queue"] == first["queue"] for e in events),
            "target moved CPU or RX queue")
    require(first["queue"] == summary["target_queue"], "target RSS prediction was incorrect")
    if summary["chaff_profile"] == "steered":
        require(queue_counts.get((first["queue"], first["cpu"]), 0) == expected_packets,
                "steered chaff did not all reach the target queue and CPU")
    require(all(e["observed_ns"] > 0 for e in events) and
            all(a["observed_ns"] <= b["observed_ns"] for a, b in zip(events, events[1:])),
            "target event timestamps are incomplete or unordered")
    require(first["created_ns"] == first["observed_ns"] and
            all(e["created_ns"] == first["created_ns"] for e in warmup),
            "target state changed during warmup")
    require([e["action"] for e in warmup] ==
            [3] + [0] * (config["burst"] - 1) + [1] * (warmup_count - config["burst"]),
            "warmup did not show exactly one burst followed by rate drops")
    blocked = warmup[-1]
    # The last observed GCRA rate drop exposes the exact earliest next allowance.
    # Both times below come from bpf_ktime_get_ns on the VICTIM.
    recover_at = max(0, blocked["prior_tat_ns"] - config["tolerance_ns"])
    require(blocked["observed_ns"] < recover_at, "warmup drop lacks a future recovery bound")
    margin = recover_at - max(e["observed_ns"] for e in retry)
    require(margin > 0, "retry reached victim at or after natural recovery")
    inits = [e for e in events if e["action"] == 3]
    require(stats["initializations"] == len(inits) and
            stats["map_insertions"] == sum(e["inserted"] for e in inits),
            "aggregate initialization audit disagrees with packet evidence")
    require(stats["passed"] == sum(e["action"] in (0, 3) for e in events) and
            stats["dropped"] == sum(e["action"] in (1, 2, 4) for e in events),
            "aggregate decisions disagree with packet evidence")
    require(stats["first_created_ns"] == first["created_ns"] and
            stats["latest_created_ns"] == inits[-1]["created_ns"] and
            stats["first_cpu"] == stats["latest_cpu"] == first["cpu"] and
            stats["first_queue"] == stats["latest_queue"] == first["queue"],
            "aggregate placement or creation audit disagrees with packet evidence")
    reset = (retry[0]["action"] == 3 and retry[0]["inserted"] == 1 and
             retry[0]["created_ns"] == retry[0]["observed_ns"] > first["created_ns"] and
             all(e["action"] in (0, 1) and e["created_ns"] == retry[0]["created_ns"]
                 for e in retry[1:]) and len(inits) == 2)
    retained = (all(e["action"] == 1 and e["created_ns"] == first["created_ns"]
                    for e in retry) and len(inits) == 1)
    require(reset or retained, "retry is neither a proven reinsertion nor retained-state rate drop")
    if config["map_mode"] in (4, 5):
        require(not reset, "unexpected reinsertion in non-evicting control")
    return {"valid": not failures, "outcome": "invalid" if failures else
            ("reset" if reset else "retained"), "failures": failures,
            "recover_at_ns": recover_at, "victim_margin_ns": margin,
            **diagnostics,
            "config": config, "target_stats": stats}


def save_json(path, value):
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--program-id", type=int, help="victim XDP program ID from bpftool net")
    source.add_argument("--evidence", type=Path, help="previously saved victim evidence")
    parser.add_argument("--save-evidence", type=Path)
    parser.add_argument("--output", type=Path, help="save machine-readable verification report")
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR,
                        help="archive root (default: repository results directory)")
    parser.add_argument("--result-name", type=result_name,
                        help="descriptive prefix for the archived trial directory")
    parser.add_argument("--expect", choices=("reset", "retained", "either"), default="reset")
    args = parser.parse_args()

    summary = evidence = None
    try:
        summary = json.loads(args.summary.read_text())
        evidence = (json.loads(args.evidence.read_text()) if args.evidence else
                    capture(args.program_id))
        if args.save_evidence:
            save_json(args.save_evidence, evidence)
        report = evaluate(summary, evidence)
    except (OSError, ValueError, KeyError, TypeError, IndexError, struct.error,
            subprocess.CalledProcessError) as error:
        report = {"valid": False, "outcome": "invalid", "failures": [str(error)]}

    trial_id = summary.get("trial_id") if isinstance(summary, dict) else None
    archive_failed = False
    if type(trial_id) is int and trial_id > 0:
        try:
            directory = (f"{args.result_name}-{trial_id}" if args.result_name else str(trial_id))
            destination = args.results_dir / directory
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.mkdir()

            save_json(destination / "summary.json", summary)
            if evidence is not None:
                save_json(destination / "evidence.json", evidence)
            save_json(destination / "verification.json", report)
            print(f"Saved results: {destination}", file=sys.stderr)
        except OSError as error:
            print(f"Could not save results: {error}", file=sys.stderr)
            archive_failed = True

    if args.output:
        save_json(args.output, report)
    print(json.dumps(report, indent=2))
    outcome_matches = (args.expect == "either" or args.expect == report["outcome"])
    success = not archive_failed and report["valid"] and outcome_matches
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
