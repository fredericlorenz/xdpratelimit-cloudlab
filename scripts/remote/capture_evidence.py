#!/usr/bin/env python3
"""Capture frozen BPF evidence using the victim verifier implementation."""

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("program_id", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    sys.path.insert(0, str(args.repository / "victim/ratelimit"))
    from verify_attack import capture, save_json

    save_json(args.output, capture(args.program_id))


if __name__ == "__main__":
    main()
