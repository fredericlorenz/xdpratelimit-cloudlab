#!/usr/bin/env python3
"""Parse `ethtool -x <iface>` output from stdin into rss.conf format."""

import argparse
import re
import sys

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-transform",
        choices=("auto", "none", "symmetric-or-xor"),
        default="auto",
        help="override an input transformation that legacy ethtool cannot report",
    )
    args = parser.parse_args()
    text = sys.stdin.read()

    # Parse indirection table rows (eg "    0:     0     1     2     3 ...")
    indir = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+:\s+([0-9\s]+)$", line)
        if m:
            indir.extend(int(x) for x in m.group(1).split())

    # Common NICs expose 40- or 52-byte keys. Preserve the complete key.
    key_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){15,})", text)
    if not indir or not key_match:
        sys.exit("Could not parse RSS key or indirection table from stdin")
    if len(indir) > 4096 or len(indir) & (len(indir) - 1):
        sys.exit("RSS table must have a power-of-two length of at most 4096 entries")
    if len(key_match.group(1).split(":")) > 128:
        sys.exit("RSS hash key exceeds the supported 128 bytes")

    functions = re.search(r"RSS hash function:(.*?)(?:RSS input transformation:|\Z)",
                          text, re.S | re.I)
    if functions and not re.search(r"\btoeplitz:\s*on\b", functions.group(1), re.I):
        sys.exit("RSS prediction requires the ordinary Toeplitz hash function")
    transformations = re.search(r"RSS input transformation:(.*)", text, re.S | re.I)
    reported_transform = None
    if transformations:
        section = transformations.group(1)
        if re.search(r"\bsymmetric-xor:\s*on\b", section, re.I):
            sys.exit("RSS prediction does not support the symmetric-xor transformation")
        if re.search(r"\bsymmetric-or-xor:\s*on\b", section, re.I):
            reported_transform = "symmetric-or-xor"
        elif re.search(r"\bsymmetric[\w-]*:\s*on\b", section, re.I):
            sys.exit("RSS prediction does not support the reported input transformation")
        else:
            reported_transform = "none"

    if args.input_transform == "auto":
        transform = reported_transform or "none"
    else:
        transform = args.input_transform
        if reported_transform is not None and reported_transform != transform:
            sys.exit("input-transform override conflicts with ethtool output")

    print(f"key={key_match.group(1).lower()}")
    print(f"indir={','.join(str(x) for x in indir)}")
    print(f"xfrm={transform}")

if __name__ == "__main__":
    main()
