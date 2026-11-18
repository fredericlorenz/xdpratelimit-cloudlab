#!/usr/bin/env python3
"""Build, test and describe one remote experiment checkout."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

FILES = [
    "attacker/trafficgen/trafficgen",
    "attacker/trafficgen/extract_rss.py",
    "victim/ratelimit/ratelimit",
    "victim/ratelimit/ratelimit.bpf.o",
    "victim/ratelimit/verify_attack.py",
    "scripts/remote/common.sh",
    "scripts/remote/prepare_victim.sh",
    "scripts/remote/prepare_attacker.sh",
    "scripts/remote/attach_limiter.sh",
    "scripts/remote/run_traffic.sh",
    "scripts/remote/capture_evidence.py",
    "scripts/remote/capture_evidence.sh",
    "scripts/remote/detach_limiter.sh",
    "scripts/remote/preflight.py",
]


def run(*arguments, cwd=None):
    subprocess.run(arguments, cwd=cwd, check=True)


def output(*arguments):
    return subprocess.check_output(arguments, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--require-setup-ready", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--run-tests", action="store_true")
    args = parser.parse_args()
    repo = args.repository

    if not (repo / ".git").exists():
        parser.error(f"not a Git checkout: {repo}")

    if args.require_setup_ready:
        status = Path("/local/cloudlab-setup.status").read_text(encoding="utf-8").strip()
        if status != "ready":
            parser.error(f"CloudLab setup is not ready: {status!r}")

    if args.build:
        run("make", "-B", "-C", repo / "victim/ratelimit")
        run("make", "-B", "-C", repo / "attacker/trafficgen")

    if args.run_tests:
        run(sys.executable, "-m", "unittest", "-v", "test_rss.py",
            cwd=repo / "attacker/trafficgen")
        run(sys.executable, "-m", "unittest", "-v", "test_stats.py",
            "test_rss_check.py", "test_verify_attack.py", cwd=repo / "victim/ratelimit")

    result = {
        "commit": output("git", "-C", repo, "rev-parse", "HEAD"),
        "dirty": output("git", "-C", repo, "status", "--porcelain", "--untracked-files=no"),
        "sha256": {},
    }

    for relative in FILES:
        result["sha256"][relative] = hashlib.sha256((repo / relative).read_bytes()).hexdigest()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
