#!/usr/bin/env python3

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_trial


def defaults():
    return {
        "network": {
            "victim_experiment_ip": "10.77.0.1",
            "attacker_experiment_ip": "10.77.0.2",
            "queue_count": 4,
            "stop_irqbalance": True,
            "disable_rps": True,
            "blackhole_routes": ["10.100.0.0/16"],
            "irq_affinity": {
                "enabled": True,
                "name_pattern": "mlx5_comp{queue}@",
                "cpus": [0, 1, 2, 3],
            },
        },
        "rss": {"input_transform": "symmetric-or-xor", "apply_equal": True},
        "limiter": {
            "rate_pps": 1,
            "burst": 10,
            "entries": 64,
            "key": "source",
            "map_mode": "percpu-local",
            "target_source": "10.77.0.2",
        },
        "traffic": {
            "destination": "10.77.0.1",
            "source": "10.77.0.2",
            "key": "source",
            "protocol": "udp",
            "target_queue": None,
            "keys": 256,
            "packets_per_key": 2,
            "rate_pps": 0,
            "source_port": 50000,
            "destination_port": 1234,
            "warmup_packets": 11,
            "retry_packets": 1,
            "deadline_ms": 900,
            "chaff": "steered",
            "dry_run_first": True,
        },
        "verification": {"expect": "reset", "drain_seconds": 1.0},
        "cleanup": {"detach": True},
    }


class CommandTests(unittest.TestCase):
    def test_attack_command_contains_static_options(self):
        arguments = run_trial.traffic_arguments(
            defaults(), 123, "/tmp/rss.conf", "/tmp/attack.json", "/local/repository"
        )
        self.assertEqual(
            ["bash", "/local/repository/scripts/remote/run_traffic.sh"],
            arguments[:2],
        )
        self.assertEqual(123, arguments[-5])
        self.assertEqual("steered", arguments[-4])
        self.assertEqual(0, arguments[-2])
        self.assertEqual("/tmp/attack.json", arguments[-1])

    def test_dry_run_has_no_summary(self):
        arguments = run_trial.traffic_arguments(
            defaults(), 123, "/tmp/rss.conf", "", "/local/repository", True
        )
        self.assertEqual(1, arguments[-2])
        self.assertEqual("", arguments[-1])


class ResultArchiveTests(unittest.TestCase):
    def test_extras_are_added_without_overwriting_verifier_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            result = root / "results" / "123"
            work.mkdir()
            result.mkdir(parents=True)
            (result / "verification.json").write_text("canonical")
            (work / "verification.json").write_text("stale")
            (work / "rss.conf").write_text("rss")
            run_trial.archive_trial_extras(work, result, {"status": "passed"})
            self.assertEqual("canonical", (result / "verification.json").read_text())
            self.assertEqual("rss", (result / "rss.conf").read_text())
            self.assertIn('"passed"', (result / "manifest.json").read_text())


if __name__ == "__main__":
    unittest.main()
