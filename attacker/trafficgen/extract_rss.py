#!/usr/bin/env python3
"""Parse `ethtool -x <iface>` output from stdin into rss.conf format."""

import re
import sys

def main():
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
    if transformations and re.search(r"symmetric[\w-]*:\s*on\b",
                                     transformations.group(1), re.I):
        sys.exit("RSS prediction does not support symmetric input transformations")

    print(f"key={key_match.group(1).lower()}")
    print(f"indir={','.join(str(x) for x in indir)}")

if __name__ == "__main__":
    main()
