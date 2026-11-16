"""Portable interface discovery and program-scoped RSS diagnostics."""

import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rss_check import default_interface, queue_map_id


class RSSCheckTests(unittest.TestCase):
    def test_detects_only_victim_experiment_address(self):
        result = SimpleNamespace(stdout="2: eth0 inet 192.0.2.1/24\n"
                                 "3: eth1@parent inet 10.77.0.1/24\n")
        with patch("rss_check.subprocess.run", return_value=result):
            self.assertEqual(default_interface(), "eth1")

    def test_missing_interface_has_clear_error(self):
        with patch("rss_check.subprocess.run", return_value=SimpleNamespace(stdout="")):
            with self.assertRaisesRegex(ValueError, "experiment interface"):
                default_interface()

    def test_map_selected_by_program_reference(self):
        replies = [dict(xdp=[dict(id=17)]), [dict(map_ids=[31, 32])],
                   dict(name="rl_state"), [dict(name="rl_queue_stats")]]
        with patch("rss_check.privileged", side_effect=[
                SimpleNamespace(stdout=json.dumps(value)) for value in replies]) as run:
            self.assertEqual(queue_map_id("eth1"), 32)
            self.assertEqual(run.call_args_list[1].args,
                             ("bpftool", "-j", "prog", "show", "id", "17"))


if __name__ == "__main__":
    unittest.main()
