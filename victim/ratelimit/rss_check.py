#!/usr/bin/env python3
"""Capture RSS controls; prepare/replace explicitly reset the experimental limiter."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from stats import counters, map_entries, number

BASE = Path(__file__).resolve().parent


def run(command, *, capture=False):
    return subprocess.run(command, check=True, text=True, capture_output=capture)


def privileged(*command, capture=False):
    prefix = [] if os.geteuid() == 0 else ["sudo"]
    return run(prefix + list(command), capture=capture)


def default_interface():
    address = subprocess.run(
        ["ip", "-o", "-4", "addr", "show"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    for line in address.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[3].split("/")[0] == "10.77.0.1":
            return fields[1].split("@")[0]
    raise ValueError("could not identify the experiment interface")


def attach(interface):
    privileged(str(BASE / "ratelimit"), "--interface", interface,
               "--object", str(BASE / "ratelimit.bpf.o"), "--map-mode", "hash-shared",
               "--entries", "4096", "--rate", "1000000", "--burst", "1000000", "--replace")


def save(path, text):
    # Keep an earlier trial's evidence instead of silently overwriting it.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(text)


def read_counts(path):
    with path.open(encoding="utf-8") as source:
        entries = map_entries(json.load(source))
    result = {}
    for entry in entries:
        total = 0
        for value in entry["values"]:
            fields = counters(value["value"])
            total += fields["passed"] + fields["dropped"]
        result[number(entry["key"])] = total
    return result


def queue_map_id(interface):
    """Resolve counters through the attached program, avoiding stale named maps."""
    def bpf(*args):
        return json.loads(privileged("bpftool", "-j", *map(str, args), capture=True).stdout)

    programs = bpf("net", "show", "dev", interface).get("xdp", [])
    if len(programs) != 1:
        raise ValueError("expected exactly one attached XDP program")
    program = bpf("prog", "show", "id", programs[0]["id"])
    if isinstance(program, list):
        program, = program
    matches = []
    for map_id in program.get("map_ids", []):
        info = bpf("map", "show", "id", map_id)
        if isinstance(info, list):
            info, = info
        if info.get("name") == "rl_queue_stats":
            matches.append(map_id)
    if len(matches) != 1:
        raise ValueError("attached program must reference exactly one rl_queue_stats map")
    return matches[0]


def compare(args):
    before = read_counts(args.output_dir / f"rss-{args.label}-before.json")
    after = read_counts(args.output_dir / f"rss-{args.label}-after.json")
    if before.keys() != after.keys():
        raise ValueError("queue keys changed between snapshots")
    deltas = {q: after[q] - before[q] for q in after}
    for q, delta in sorted(deltas.items()):
        if q < 4 or delta:
            print(f"queue={q} IPv4_packets={delta}")
    print(f"total={sum(deltas.values())}")
    if any(delta < 0 for delta in deltas.values()) or sum(deltas.values()) != args.expected:
        raise ValueError("unexpected total/counter reset; check delivery and background traffic")
    if args.expected_queue is not None and deltas.get(args.expected_queue, 0) != args.expected:
        raise ValueError(f"packets did not all enter expected queue {args.expected_queue}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=os.environ.get("IFACE"))
    parser.add_argument("--output-dir", type=Path,
                        default=Path(os.environ.get("RSS_DIR", "/tmp/rss-check")))
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "replace"):
        commands.add_parser(command)
    export = commands.add_parser("export")
    export.add_argument("--input-transform",
                        choices=("auto", "none", "symmetric-or-xor"), default="auto")
    apply = commands.add_parser("apply", help="apply a queue-0, queue-1 or four-queue table")
    apply.add_argument("table", choices=("zero", "one", "balanced"))
    for command in ("before", "report", "compare"):
        sub = commands.add_parser(command)
        sub.add_argument("label")
        if command != "before":
            sub.add_argument("--expected", type=int, default=256)
            sub.add_argument("--expected-queue", type=int)
    args = parser.parse_args()
    if hasattr(args, "label") and (not args.label or
            any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in args.label)):
        parser.error("label must contain only letters, digits, underscores or hyphens")
    if hasattr(args, "expected") and args.expected < 1:
        parser.error("--expected must be positive")
    if getattr(args, "expected_queue", None) is not None and args.expected_queue < 0:
        parser.error("--expected-queue must be nonnegative")

    try:
        if args.command != "compare" and args.interface is None:
            args.interface = default_interface()
        if args.command == "prepare":
            run(["git", "-C", str(BASE), "rev-parse", "HEAD"])
            run(["make", "-B", "-C", str(BASE)])
        if args.command in ("prepare", "replace"):
            attach(args.interface)
        if args.command == "prepare":
            privileged("bpftool", "net", "show", "dev", args.interface)
            for option in ("-i", "-l", "-k"):
                privileged("ethtool", option, args.interface)
            privileged("ethtool", "-n", args.interface, "rx-flow-hash", "udp4")
            feature_file = Path("/sys/class/net") / args.interface / "device/features"
            if feature_file.is_file():
                bits = feature_file.read_text().strip()
                for name, bit in (("MQ", 22), ("HASH_REPORT", 57), ("RSS", 60)):
                    if bit < len(bits):
                        print(f"VirtIO {name}={bits[bit]}")
            else:
                print("VirtIO feature bits: not applicable to this NIC")
        elif args.command == "before":
            save(args.output_dir / f"rss-{args.label}-table.txt",
                 privileged("ethtool", "-x", args.interface, capture=True).stdout)
            save(args.output_dir / f"rss-{args.label}-before.json",
                 privileged("bpftool", "-j", "map", "dump", "id", str(queue_map_id(args.interface)),
                            capture=True).stdout)
        elif args.command == "report":
            time.sleep(1)
            save(args.output_dir / f"rss-{args.label}-after.json",
                 privileged("bpftool", "-j", "map", "dump", "id", str(queue_map_id(args.interface)),
                            capture=True).stdout)
            compare(args)
        elif args.command == "compare":
            compare(args)
        elif args.command == "apply":
            tables = {"zero": ["equal", "1"], "one": ["weight", "0", "1", "0", "0"],
                      "balanced": ["equal", "4"]}
            privileged("ethtool", "-X", args.interface, *tables[args.table])
        elif args.command == "export":
            text = privileged("ethtool", "-x", args.interface, capture=True).stdout
            extractor = BASE.parent.parent / "attacker/trafficgen/extract_rss.py"
            command = [sys.executable, str(extractor)]
            if args.input_transform != "auto":
                command.extend(("--input-transform", args.input_transform))
            result = subprocess.run(command, input=text,
                                    check=True, text=True, capture_output=True)
            save(args.output_dir / f"{args.interface}-rss.txt", text)
            save(args.output_dir / f"{args.interface}-rss.conf", result.stdout)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
