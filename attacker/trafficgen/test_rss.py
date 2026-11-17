"""Offline RSS portability checks; no sockets or NIC privileges needed."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
# Intel's IPv4 RSS verification vector, also used by DPDK's test_thash.c:
# https://github.com/DPDK/dpdk/blob/main/app/test/test_thash.c
KEY = bytes.fromhex("6d5a56da255b0ec24167253d43a38fb0d0ca2bcbae7b30b4"
                    "77cb2da38030f20c6a42b73bbeac01fa")


class RSSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.path = Path(cls.work.name)
        source = cls.path / "check.c"
        source.write_text('''
#include <arpa/inet.h>
#include <stdio.h>
#include "trafficgen.h"
int main(int argc, char **argv) {
    struct rss_config rss;
    if (argc != 2 || rss_load_file(argv[1], &rss)) return 1;
    printf("%zu %d %08x %u %u\\n", rss.indir_len, rss.input_transform,
        rss_toeplitz_hash(inet_addr("66.9.149.187"), inet_addr("161.142.100.80"),
                          htons(2794), htons(1766), rss.key),
        rss_predict_queue(&rss, inet_addr("66.9.149.187"), inet_addr("161.142.100.80"),
                          htons(2794), htons(1766)),
        rss_predict_queue(&rss, inet_addr("161.142.100.80"), inet_addr("66.9.149.187"),
                          htons(1766), htons(2794)));
    return 0;
}
''')
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(BASE), str(source), str(BASE / "rss.c"),
                        "-o", str(cls.path / "check")], check=True)

    def load(self, key=KEY, entries=128, transform=None):
        config = self.path / "rss.conf"
        config.write_text("key=" + key.hex(":") + "\nindir=" +
                          ",".join(str(i % 4) for i in range(entries)) + "\n" +
                          (f"xfrm={transform}\n" if transform is not None else ""))
        return subprocess.run([str(self.path / "check"), str(config)],
                              text=True, capture_output=True)

    def export(self, extra="", key=KEY, entries=128, transform=None):
        table = "\n".join(f"{i}: " + " ".join(str(j % 4)
                            for j in range(i, min(i + 8, entries)))
                            for i in range(0, entries, 8))
        text = table + "\nRSS hash key:\n" + key.hex(":") + "\n" + extra
        command = [sys.executable, str(BASE / "extract_rss.py")]
        if transform is not None:
            command.extend(("--input-transform", transform))
        return subprocess.run(command,
                              input=text, text=True, capture_output=True)

    def test_reference_hash_with_40_and_52_byte_keys(self):
        for key in (KEY, KEY + bytes(12)):
            result = self.load(key)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "128 0 51ccc178 0 2")

    def test_symmetric_or_xor_prediction(self):
        result = self.load(transform="symmetric-or-xor")
        self.assertEqual(result.returncode, 0, result.stderr)
        # The documented OR-XOR tuple transforms the reference hash to a65524fa.
        self.assertEqual(result.stdout.strip(), "128 1 51ccc178 2 2")

    def test_large_table_is_not_truncated(self):
        for entries in (512, 4096):
            result = self.load(entries=entries)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"{entries} 0 51ccc178 0 2")

    def test_invalid_lengths_are_rejected(self):
        for key, entries in ((KEY[:15], 128), (bytes(129), 128),
                             (KEY, 3), (KEY, 8192)):
            self.assertNotEqual(self.load(key, entries).returncode, 0)

    def test_export_preserves_long_key_and_table(self):
        result = self.export("RSS hash function:\n toeplitz: on\n",
                             KEY + bytes(12), 512)
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(fields["key"], (KEY + bytes(12)).hex(":"))
        self.assertEqual(len(fields["indir"].split(",")), 512)
        self.assertEqual(fields["xfrm"], "none")

    def test_incompatible_hash_and_transform_are_rejected(self):
        for mode in ("RSS hash function:\n toeplitz: off\n xor: on\n",
                     "RSS hash function:\n toeplitz: on\n"
                     "RSS input transformation:\n symmetric-xor: on\n"):
            result = self.export(mode)
            self.assertNotEqual(result.returncode, 0)

    def test_symmetric_or_xor_export_and_legacy_override(self):
        reported = self.export("RSS hash function:\n toeplitz: on\n"
                               "RSS input transformation:\n symmetric-or-xor: on\n")
        overridden = self.export("RSS hash function:\n toeplitz: on\n",
                                 transform="symmetric-or-xor")
        for result in (reported, overridden):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("xfrm=symmetric-or-xor", result.stdout)

    def test_transform_override_conflict_and_unknown_config_are_rejected(self):
        conflict = self.export("RSS input transformation:\n symmetric-or-xor: on\n",
                               transform="none")
        self.assertNotEqual(conflict.returncode, 0)
        self.assertNotEqual(self.load(transform="unknown").returncode, 0)


if __name__ == "__main__":
    unittest.main()
