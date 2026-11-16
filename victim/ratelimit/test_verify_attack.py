"""Regression cases for isolated attack evidence, without loading BPF programs."""

import socket
import struct
import sys
import unittest

from verify_attack import evaluate


def trial(*, reset=True, retries=1):
    interval, created, retry_time = 1_000_000_000, 10_000_000_000, 10_001_000_000
    config = dict(interval_ns=interval, tolerance_ns=9 * interval, rate_pps=1,
                  burst=10, key_mode=0, map_mode=3, target_enabled=1, trial_id=123,
                  target_saddr=int.from_bytes(socket.inet_aton("10.77.0.2"), sys.byteorder))

    def event(now, action, tat, born, inserted=0):
        return dict(observed_ns=now, action=action, prior_tat_ns=tat,
                    created_ns=born, inserted=inserted, queue=1, cpu=1)

    events = [event(created, 3, 0, created, 1)]
    events.extend(event(created + i * 1000, 0, created + i * interval, created)
                  for i in range(1, 10))
    events.append(event(created + 10_000, 1, created + 10 * interval, created))
    for i in range(retries):
        if reset:
            events.append(event(retry_time + i * 1000,
                                3 if i == 0 else (0 if i < 10 else 1),
                                retry_time + min(i, 10) * interval if i else 0,
                                retry_time, int(i == 0)))
        else:
            events.append(event(retry_time + i * 1000, 1,
                                created + 10 * interval, created))
    passed = 10 + (min(retries, 10) if reset else 0)
    dropped = len(events) - passed
    stats = dict(first_created_ns=created, latest_created_ns=retry_time if reset else created,
                 initializations=2 if reset else 1, map_insertions=2 if reset else 1,
                 passed=passed, dropped=dropped, first_cpu=1, latest_cpu=1,
                 first_queue=1, latest_queue=1, event_count=len(events), event_overflow=0)
    counts = dict(rx=len(events) + 512, passed=passed + 512, dropped=dropped,
                  bypassed=0, new_entries=0, map_inserts=0, insert_fail=0, contention_drop=0)
    maps = {name: {"entries": [{"key": 0, "value": value}]}
            for name, value in (("rl_config", config), ("rl_target_stats", stats))}
    maps["rl_events"] = {"entries": [{"key": i, "value": e} for i, e in enumerate(events)]}
    for name, key in (("rl_stats", 0), ("rl_queue_stats", 1)):
        maps[name] = {"entries": [{"key": key, "values": [{"cpu": 1, "value": counts.copy()}]}]}
    summary = dict(schema_version=2, trial_id=123, target_source="10.77.0.2",
                   chaff_profile="steered", target_queue=1, within_deadline=True,
                   start_ns=1, warmup_end_ns=2, chaff_end_ns=3, retry_end_ns=4,
                   deadline_ns=900_000_000, warmup_sent=11, warmup_intended=11,
                   chaff_sent=512, chaff_intended=512, retry_sent=retries, retry_intended=retries)
    return summary, dict(schema_version=2, maps=maps)


class VerifyAttackTests(unittest.TestCase):
    def test_reset_and_retained(self):
        for reset in (True, False):
            with self.subTest(reset=reset):
                report = evaluate(*trial(reset=reset))
                self.assertTrue(report["valid"], report["failures"])
                self.assertEqual(report["outcome"], "reset" if reset else "retained")

    def test_retry_can_exhaust_fresh_burst(self):
        report = evaluate(*trial(retries=11))
        self.assertTrue(report["valid"], report["failures"])
        self.assertEqual(report["outcome"], "reset")

    def test_missing_chaff_rejected_for_both_outcomes(self):
        for reset in (True, False):
            with self.subTest(reset=reset):
                summary, evidence = trial(reset=reset)
                for name in ("rl_stats", "rl_queue_stats"):
                    evidence["maps"][name]["entries"][0]["values"][0]["value"]["passed"] -= 512
                report = evaluate(summary, evidence)
                self.assertFalse(report["valid"])
                self.assertTrue(any("chaff loss" in f for f in report["failures"]))

    def test_extra_traffic_reports_counts_without_accepting_trial(self):
        summary, evidence = trial()
        for name in ("rl_stats", "rl_queue_stats"):
            evidence["maps"][name]["entries"][0]["values"][0]["value"]["passed"] += 89
        report = evaluate(summary, evidence)
        self.assertFalse(report["valid"])
        self.assertEqual(report["expected_ipv4_packets"], 524)
        self.assertEqual(report["observed_ipv4_packets"], 613)
        self.assertEqual(report["observed_target_packets"], 12)

    def test_missteered_chaff_rejected_but_unsteered_control_allowed(self):
        summary, evidence = trial(reset=False)
        entry = evidence["maps"]["rl_queue_stats"]["entries"][0]
        entry["values"][0]["value"]["passed"] -= 512
        evidence["maps"]["rl_queue_stats"]["entries"].append(
            {"key": 2, "values": [{"cpu": 1, "value": {"passed": 512, "dropped": 0}}]})
        report = evaluate(summary, evidence)
        self.assertFalse(report["valid"])
        self.assertIn("steered chaff did not all reach the target queue and CPU", report["failures"])
        summary["chaff_profile"] = "random"
        report = evaluate(summary, evidence)
        self.assertTrue(report["valid"], report["failures"])
        self.assertEqual(report["victim_packets_by_queue_cpu"],
                         [{"queue": 1, "cpu": 1, "packets": 12},
                          {"queue": 2, "cpu": 1, "packets": 512}])

    def test_inconsistent_cpu_counters_rejected(self):
        summary, evidence = trial()
        evidence["maps"]["rl_stats"]["entries"][0]["values"][0]["cpu"] = 2
        report = evaluate(summary, evidence)
        self.assertFalse(report["valid"])
        self.assertIn("victim global and queue counters disagree by CPU", report["failures"])

    def test_raw_counter_decoding(self):
        summary, evidence = trial()
        for name in ("rl_stats", "rl_queue_stats"):
            value = evidence["maps"][name]["entries"][0]["values"][0]
            value["value"] = list(struct.pack("=8Q", 524, 0, 523, 1, 0, 0, 0, 0))
        report = evaluate(summary, evidence)
        self.assertTrue(report["valid"], report["failures"])

    def test_natural_recovery_rejected(self):
        summary, evidence = trial()
        retry = evidence["maps"]["rl_events"]["entries"][-1]["value"]
        retry["observed_ns"] = retry["created_ns"] = 11_000_000_000
        evidence["maps"]["rl_target_stats"]["entries"][0]["value"]["latest_created_ns"] = 11_000_000_000
        report = evaluate(summary, evidence)
        self.assertFalse(report["valid"])
        self.assertIn("retry reached victim at or after natural recovery", report["failures"])

    def test_overflow_rejected(self):
        summary, evidence = trial()
        evidence["maps"]["rl_target_stats"]["entries"][0]["value"]["event_overflow"] = 1
        with self.assertRaisesRegex(ValueError, "overflowed"):
            evaluate(summary, evidence)


if __name__ == "__main__":
    unittest.main()
