#!/usr/bin/env python3
"""Decode a JSON dump of rl_stats or rl_queue_stats from bpftool."""

import json
import struct
import sys


FIELDS = (
    "rx",
    "bypassed",
    "passed",
    "dropped",
    "new_entries",
    "map_inserts",
    "insert_fail",
    "contention_drop",
)


def number(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int.from_bytes(
        bytes(int(byte, 16) if isinstance(byte, str) else byte for byte in value),
        sys.byteorder,
    )


def counters(value):
    if isinstance(value, dict):
        return {field: number(value.get(field, 0)) for field in FIELDS}

    raw = bytes(int(byte, 16) if isinstance(byte, str) else byte for byte in value)
    expected = len(FIELDS) * 8
    if len(raw) < expected:
        raise ValueError(f"counter value has {len(raw)} bytes, expected {expected}")
    values = struct.unpack_from("=" + "Q" * len(FIELDS), raw)
    return dict(zip(FIELDS, values))


def format_row(slot, cpu, values):
    fields = " ".join(f"{name}={values[name]}" for name in FIELDS)
    return f"slot={slot} cpu={cpu} {fields}"


def map_entries(dump):
    """Accept bpftool's single-map wrapper, but never combine different maps."""
    if isinstance(dump, dict):
        dump = [dump]
    if not isinstance(dump, list):
        raise ValueError("expected a bpftool JSON map dump")
    if any(isinstance(entry, dict) and "elements" in entry for entry in dump):
        if len(dump) != 1:
            raise ValueError("multiple maps matched; dump by map ID from the attached "
                             "program (bpftool -j map dump id MAP_ID)")
        dump = dump[0]["elements"]
    if not isinstance(dump, list) or any(
            not isinstance(entry, dict) or "key" not in entry for entry in dump):
        raise ValueError("expected map entries with keys; dump by map ID from the "
                         "attached program (bpftool -j map dump id MAP_ID)")
    return dump


def main():
    entries = map_entries(json.load(sys.stdin))
    totals = {field: 0 for field in FIELDS}

    for entry in entries:
        slot = number(entry["key"])
        per_cpu = entry.get("values")
        if per_cpu is None:
            per_cpu = [{"cpu": "-", "value": entry["value"]}]

        for cpu_value in per_cpu:
            values = counters(cpu_value["value"])
            if not any(values.values()):
                continue
            print(format_row(slot, cpu_value.get("cpu", "-"), values))
            for field in FIELDS:
                totals[field] += values[field]

    print("total " + " ".join(f"{name}={totals[name]}" for name in FIELDS))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError) as error:
        sys.exit(f"ERROR: {error}")
