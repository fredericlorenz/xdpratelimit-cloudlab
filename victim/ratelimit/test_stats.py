"""bpftool dump shapes, including ambiguous name-based dumps."""

import unittest

from stats import map_entries


class MapEntriesTests(unittest.TestCase):
    def test_plain_and_single_wrapped_dump(self):
        entries = [{"key": ["0x00"] * 4, "values": []}]
        self.assertEqual(map_entries(entries), entries)
        self.assertEqual(map_entries([{"elements": entries}]), entries)
        self.assertEqual(map_entries({"elements": entries}), entries)

    def test_multiple_maps_are_not_silently_combined(self):
        with self.assertRaisesRegex(ValueError, "multiple maps matched"):
            map_entries([{"elements": []}, {"elements": []}])

    def test_unexpected_shape_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, "dump by map ID"):
            map_entries([{"error": "map unavailable"}])


if __name__ == "__main__":
    unittest.main()
