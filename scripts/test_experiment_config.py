#!/usr/bin/env python3

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiment_config


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


class ConfigurationTests(unittest.TestCase):
    def test_example_configs(self):
        root = Path(__file__).resolve().parents[1]
        _, single = experiment_config.load_configuration(
            root / "configs/cloudlab-mlx5-smoke.yaml")
        _, matrix = experiment_config.load_configuration(
            root / "configs/cloudlab-mlx5-sweep.yaml")
        self.assertEqual(1, len(single))
        self.assertEqual(108, len(matrix))
        settings = single[0]["settings"]
        self.assertEqual(["10.100.0.0/16"], settings["network"]["blackhole_routes"])
        self.assertEqual(900, settings["traffic"]["deadline_ms"])

    def test_routes_and_deadline_are_derived(self):
        trial = defaults()
        del trial["network"]["blackhole_routes"]
        del trial["traffic"]["deadline_ms"]
        trial["traffic"]["keys"] = 65536
        trial["limiter"]["rate_pps"] = 4
        experiment_config.validate_trial(trial)
        self.assertEqual(["10.100.0.0/15"], trial["network"]["blackhole_routes"])
        self.assertEqual(225, trial["traffic"]["deadline_ms"])

    def test_single_experiment(self):
        document = {"defaults": defaults(), "experiments": [{"name": "single"}]}
        trials = experiment_config.expand_experiments(document)
        self.assertEqual(1, len(trials))
        self.assertEqual("single", trials[0]["name"])

    def test_matrix_is_cartesian_product_with_repetitions(self):
        document = {
            "defaults": defaults(),
            "experiments": [{
                "name": "sweep",
                "repetitions": 2,
                "matrix": {
                    "limiter.map_mode": ["percpu-local", "shared-global"],
                    "limiter.entries": [64, 128],
                    "traffic.chaff": ["steered", "random"],
                },
            }],
        }
        trials = experiment_config.expand_experiments(document)
        self.assertEqual(16, len(trials))
        self.assertEqual({64, 128}, {
            trial["settings"]["limiter"]["entries"] for trial in trials})
        self.assertEqual(
            "sweep_mode-percpu-local_entries-64_chaff-steered_r01",
            trials[0]["name"],
        )
        self.assertTrue(all("." not in trial["name"] and "__" not in trial["name"]
                            for trial in trials))

    def test_overrides_are_merged_before_matrix(self):
        document = {
            "defaults": defaults(),
            "experiments": [{
                "name": "controls",
                "overrides": {"verification": {"expect": "retained"}},
                "matrix": {"limiter.map_mode": ["hash-shared", "hash-percpu"]},
            }],
        }
        trials = experiment_config.expand_experiments(document)
        self.assertEqual(2, len(trials))
        self.assertTrue(all(trial["settings"]["verification"]["expect"] == "retained"
                            for trial in trials))

    def test_unknown_matrix_path_is_rejected(self):
        document = {
            "defaults": defaults(),
            "experiments": [{"name": "bad", "matrix": {"limiter.typo": [1]}}],
        }
        with self.assertRaisesRegex(ValueError, "matrix path"):
            experiment_config.expand_experiments(document)

    def test_target_and_attacker_source_must_match(self):
        trial = copy.deepcopy(defaults())
        trial["limiter"]["target_source"] = "10.77.0.3"
        with self.assertRaisesRegex(ValueError, "target_source"):
            experiment_config.validate_trial(trial)


if __name__ == "__main__":
    unittest.main()
