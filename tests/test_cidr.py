import hashlib
import ipaddress
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cidr_witness.core import InputError, compare


class CidrTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = self.root / "before.txt"
        self.after = self.root / "after.txt"

    def run_compare(self, before, after, **kwargs):
        self.before.write_text("\n".join(before), encoding="utf-8")
        self.after.write_text("\n".join(after), encoding="utf-8")
        return compare(self.before, self.after, **kwargs)

    def test_split_merge_overlap_and_duplicates_are_equivalent(self):
        report = self.run_compare(
            ["192.0.2.0/24", "192.0.2.0/25", "2001:db8::/126", "192.0.2.0/24"],
            ["192.0.2.128/25", "192.0.2.0/25", "2001:db8::/127", "2001:db8::2/127"],
            fail_on_change=True,
        )
        self.assertTrue(report["equivalent"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["families"]["ipv4"]["before_addresses"], "256")

    def test_hand_computed_expansion_and_shrinkage(self):
        report = self.run_compare(
            ["192.0.2.0/25", "198.51.100.0/24"], ["192.0.2.0/24"], fail_on_expansion=True
        )
        v4 = report["families"]["ipv4"]
        self.assertEqual(v4["added_cidrs"], ["192.0.2.128/25"])
        self.assertEqual(v4["removed_cidrs"], ["198.51.100.0/24"])
        self.assertEqual((v4["added_addresses"], v4["removed_addresses"]), ("128", "256"))
        self.assertFalse(report["ok"])
        self.assertEqual(v4["added_witness"]["address"], "192.0.2.128")

    def test_ipv6_zero_and_whole_space_extremes(self):
        result = self.run_compare([], ["::/0", "0.0.0.0/0"])
        self.assertEqual(result["families"]["ipv6"]["added_addresses"], str(2**128))
        self.assertEqual(result["families"]["ipv6"]["added_cidrs"], ["::/0"])
        self.assertEqual(result["families"]["ipv4"]["added_addresses"], str(2**32))
        self.assertEqual(result["families"]["ipv6"]["added_witness"]["address"], "::")
        result = self.run_compare(
            ["::/0"], ["::/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"]
        )
        self.assertEqual(result["families"]["ipv6"]["removed_addresses"], str(2**128 - 2))
        self.assertEqual(result["families"]["ipv6"]["after_addresses"], "2")

    def test_mapped_ipv6_is_not_folded_into_ipv4(self):
        report = self.run_compare(["192.0.2.1"], ["::ffff:192.0.2.1"])
        self.assertEqual(report["families"]["ipv4"]["removed_addresses"], "1")
        self.assertEqual(report["families"]["ipv6"]["added_addresses"], "1")

    def test_randomized_comparison_against_address_enumeration(self):
        rng = random.Random(29871)
        for version in (4, 6):
            width = 32 if version == 4 else 128
            base = int(ipaddress.ip_address("192.0.2.0" if version == 4 else "2001:db8::"))
            address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
            family = "ipv4" if version == 4 else "ipv6"
            for trial in range(120):
                groups = []
                sets = []
                for _ in range(2):
                    networks = []
                    for _ in range(rng.randrange(20)):
                        bits = rng.randrange(0, 6)
                        start = base + (rng.randrange(256) >> bits << bits)
                        networks.append(ipaddress.ip_network(f"{address(start)}/{width - bits}"))
                    groups.append([str(net) for net in networks])
                    sets.append({int(ip) for net in networks for ip in net})
                with self.subTest(version=version, trial=trial):
                    report = self.run_compare(*groups)
                    detail = report["families"][family]
                    added = {
                        int(ip) for net in detail["added_cidrs"] for ip in ipaddress.ip_network(net)
                    }
                    removed = {
                        int(ip)
                        for net in detail["removed_cidrs"]
                        for ip in ipaddress.ip_network(net)
                    }
                    self.assertEqual(added, sets[1] - sets[0])
                    self.assertEqual(removed, sets[0] - sets[1])
                    self.assertEqual(detail["added_addresses"], str(len(added)))
                    self.assertEqual(detail["removed_addresses"], str(len(removed)))
                    self.assertEqual(report["equivalent"], sets[0] == sets[1])
                    all_output = detail["added_cidrs"] + detail["removed_cidrs"]
                    self.assertEqual(len(all_output), len(set(all_output)))
                    if added:
                        witness = int(ipaddress.ip_address(detail["added_witness"]["address"]))
                        self.assertIn(witness, sets[1])
                        self.assertNotIn(witness, sets[0])

    def test_witness_source_lines_and_truncation(self):
        result = self.run_compare([], ["# comment", "", "192.0.2.0/24 # explanation"] * 25)
        witness = result["families"]["ipv4"]["added_witness"]
        self.assertEqual(witness["source_lines"], list(range(3, 61, 3)))
        self.assertEqual(witness["matching_source_line_count"], 25)
        self.assertTrue(witness["source_lines_truncated"])

    def test_empty_sets_and_single_hosts(self):
        self.assertTrue(self.run_compare([], ["# nothing", ""])["equivalent"])
        report = self.run_compare([], ["192.0.2.0", "192.0.2.255", "::", "::1"])
        self.assertEqual(report["families"]["ipv4"]["added_addresses"], "2")
        self.assertEqual(report["families"]["ipv6"]["added_cidrs"], ["::/127"])

    def test_policy_defaults_and_exact_budget(self):
        self.assertTrue(self.run_compare([], ["192.0.2.0/24"])["ok"])
        self.assertFalse(self.run_compare([], ["192.0.2.0/24"], fail_on_change=True)["ok"])
        self.assertTrue(self.run_compare([], ["192.0.2.0/24"], max_added_v4=256)["ok"])
        self.assertFalse(self.run_compare([], ["192.0.2.0/24"], max_added_v4=255)["ok"])
        self.assertFalse(self.run_compare([], ["::1"], max_added_v6=0)["ok"])
        self.assertTrue(self.run_compare(["::1"], [], fail_on_expansion=True)["ok"])

    def test_bom_utf8_and_invalid_networks(self):
        self.before.write_text("", encoding="utf-8")
        self.after.write_bytes(b"\xef\xbb\xbf192.0.2.0/24\r\n")
        self.assertEqual(
            compare(self.before, self.after)["families"]["ipv4"]["added_addresses"], "256"
        )
        for data in (
            b"192.0.2.1/24",
            b"host.example",
            b"fe80::1%eth0",
            b"!192.0.2.0/24",
            b"192.0.2.0/255.255.255.0",
            b"192.0.2.0/024",
            b"\xff",
            b"192.0.2.0/999",
        ):
            with self.subTest(data=data):
                self.after.write_bytes(data)
                with self.assertRaises(InputError):
                    compare(self.before, self.after)

    def test_bounds_and_no_partial_success(self):
        self.run_compare([], ["192.0.2.0", "192.0.2.2"])
        for options in (
            {"max_entries": 1},
            {"max_bytes": 4},
            {"max_output_cidrs": 1},
            {"max_added_v4": -1},
            {"max_entries": 0},
        ):
            with self.subTest(options=options), self.assertRaises(InputError):
                compare(self.before, self.after, **options)
        self.after.write_bytes(b"#" + b"x" * 4096)
        with self.assertRaises(InputError):
            compare(self.before, self.after)
        self.after.write_bytes(b"::")
        self.assertEqual(
            compare(self.before, self.after, max_bytes=2)["families"]["ipv6"]["added_addresses"],
            "1",
        )

    def test_input_hashes_unchanged(self):
        self.run_compare(["192.0.2.0/24"], ["192.0.2.0/25"])
        hashes = [
            hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.before, self.after)
        ]
        compare(self.before, self.after)
        self.assertEqual(
            hashes,
            [hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.before, self.after)],
        )

    def test_cli_pass_policy_failure_and_input_error(self):
        self.run_compare([], ["192.0.2.0/24"])
        command = [
            sys.executable,
            "-m",
            "cidr_witness",
            str(self.before),
            str(self.after),
            "--format",
            "json",
        ]
        good = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(good.returncode, 0)
        self.assertFalse(json.loads(good.stdout)["equivalent"])
        bad = subprocess.run(command + ["--fail-on-expansion"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(json.loads(bad.stdout)["findings"][0]["code"], "expansion_detected")
        error = subprocess.run(command + ["--max-bytes", "1"], capture_output=True, text=True)
        self.assertEqual(error.returncode, 2)
        self.assertEqual(error.stdout, "")


if __name__ == "__main__":
    unittest.main()
