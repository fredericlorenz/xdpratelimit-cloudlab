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
    printf("%zu %08x\\n", rss.indir_len,
        rss_toeplitz_hash(inet_addr("66.9.149.187"), inet_addr("161.142.100.80"),
                          htons(2794), htons(1766), rss.key));
    return 0;
}
''')
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(BASE), str(source), str(BASE / "rss.c"),
                        "-o", str(cls.path / "check")], check=True)

    def load(self, key=KEY, entries=128):
        config = self.path / "rss.conf"
        config.write_text("key=" + key.hex(":") + "\nindir=" +
                          ",".join(str(i % 4) for i in range(entries)) + "\n")
        return subprocess.run([str(self.path / "check"), str(config)],
                              text=True, capture_output=True)

    def export(self, extra="", key=KEY, entries=128):
        table = "\n".join(f"{i}: " + " ".join(str(j % 4)
                            for j in range(i, min(i + 8, entries)))
                            for i in range(0, entries, 8))
        text = table + "\nRSS hash key:\n" + key.hex(":") + "\n" + extra
        return subprocess.run([sys.executable, str(BASE / "extract_rss.py")],
                              input=text, text=True, capture_output=True)

    def test_reference_hash_with_40_and_52_byte_keys(self):
        for key in (KEY, KEY + bytes(12)):
            result = self.load(key)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "128 51ccc178")

    def test_large_table_is_not_truncated(self):
        for entries in (512, 4096):
            result = self.load(entries=entries)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"{entries} 51ccc178")

    def test_invalid_lengths_are_rejected(self):
        for key, entries in ((KEY[:15], 128), (bytes(129), 128),
                             (KEY, 3), (KEY, 8192)):
            self.assertNotEqual(self.load(key, entries).returncode, 0)

    def test_export_preserves_long_key_and_table(self):
        result = self.export("RSS hash function:\n toeplitz: on\n",
                             KEY + bytes(12), 512)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("key=" + (KEY + bytes(12)).hex(":"), result.stdout)
        self.assertEqual(len(result.stdout.split("indir=")[1].strip().split(",")), 512)

    def test_incompatible_hash_and_transform_are_rejected(self):
        for mode in ("RSS hash function:\n toeplitz: off\n xor: on\n",
                     "RSS hash function:\n toeplitz: on\n"
                     "RSS input transformation:\n symmetric-xor: on\n"):
            result = self.export(mode)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
