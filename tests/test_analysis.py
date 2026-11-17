import csv
import gzip
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


# 2026-04-08 05:00:00 UTC (14:00 JST)
START = 1775624400


def ethernet(payload, ethertype=0x0800, *, tagged=False):
    tag = b"\x88\xa8\0\x01\x81\x00\0\x02" if tagged else b""
    return bytes(12) + tag + struct.pack("!H", ethertype) + payload


def ipv4(protocol=6, length=40, *, fragment=0, ihl=5):
    return struct.pack(
        "!BBHHHBBH8s", 0x40 | ihl, 0, length, 0, fragment, 64, protocol, 0, bytes(8)
    )


def ipv6(next_header, length, payload=b""):
    return struct.pack("!IHBB32s", 6 << 28, length, next_header, 64, bytes(32)) + payload


def pcap(records, *, endian="<", nano=False, link=1, snaplen=96):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, snaplen, link)
    return header + b"".join(
        struct.pack(endian + "IIII", sec, frac, len(data), orig) + data
        for sec, frac, data, orig in records
    )


class PacketTests(unittest.TestCase):
    def classify(self, frame, original, fcs=0):
        from mawi_protocol_analysis.protocols import classify_ethernet

        return classify_ethernet(frame, original, fcs)

    def test_ipv4_protocols_vlan_and_fragment(self):
        for protocol in (1, 4, 6, 17, 41, 47, 50, 51, 222):
            with self.subTest(protocol=protocol):
                packet = self.classify(
                    ethernet(ipv4(protocol, 76, fragment=0x2000), tagged=True), 98
                )
                self.assertEqual((packet.kind, packet.number, packet.ip_bytes), ("ipv4", protocol, 76))
                self.assertTrue(packet.fragment)

    def test_ipv6_walks_options_and_ah_but_stops_at_esp(self):
        hop = bytes((51, 0)) + bytes(6)
        ah = bytes((50, 2)) + bytes(14)
        packet = self.classify(ethernet(ipv6(0, 48, hop + ah), 0x86DD), 102)
        self.assertEqual((packet.kind, packet.number, packet.ip_bytes), ("ipv6", 50, 88))
        self.assertFalse(packet.fragment)

    def test_ipv6_hop_by_hop_after_routing_is_malformed(self):
        routing = bytes((0, 0)) + bytes(6)
        hop = bytes((6, 0)) + bytes(6)
        packet = self.classify(ethernet(ipv6(43, 36, routing + hop), 0x86DD), 90)
        self.assertEqual((packet.number, packet.ip_bytes), (None, 76))
        self.assertEqual(packet.header_issue, "ipv6_misplaced_hop_by_hop")

    def test_ipv6_fragment_flags_are_counted_if_the_identifier_is_truncated(self):
        fragment_prefix = bytes((17, 0, 0, 1))
        packet = self.classify(ethernet(ipv6(44, 16, fragment_prefix), 0x86DD), 70)
        self.assertEqual((packet.number, packet.ip_bytes), (17, 56))
        self.assertTrue(packet.fragment)
        self.assertIsNone(packet.protocol_issue)
        self.assertEqual(packet.header_issue, "ipv6_truncated_extension")

    def test_ipv6_truncated_extension_preserves_observed_terminal_protocol(self):
        for extension in (0, 43, 44, 51, 60):
            for terminal in (6, 17, 50, 58, 59, 222):
                for saved in (1, 2, 4, 7):
                    with self.subTest(extension=extension, terminal=terminal, saved=saved):
                        prefix = bytes((terminal, 2 if extension == 51 else 0)) + bytes(14)
                        frame = ethernet(ipv6(extension, 16, prefix[:saved]), 0x86DD)
                        packet = self.classify(frame, 70)
                        self.assertEqual((packet.number, packet.ip_bytes), (terminal, 56))
                        self.assertIsNone(packet.protocol_issue)
                        self.assertEqual(packet.header_issue, "ipv6_truncated_extension")

    def test_ipv6_chain_can_end_in_a_truncated_extension_with_known_protocol(self):
        hop = bytes((60, 0)) + bytes(6)
        packet = self.classify(ethernet(ipv6(0, 24, hop + b"\x11"), 0x86DD), 78)
        self.assertEqual((packet.number, packet.ip_bytes), (17, 64))
        self.assertIsNone(packet.protocol_issue)
        self.assertEqual(packet.header_issue, "ipv6_truncated_extension")

    def test_ipv6_truncated_extension_without_terminal_stays_indeterminate(self):
        for prefix in (b"", b"\x00", b"\x2b", b"\x2c", b"\x33", b"\x3c", b"\x87"):
            with self.subTest(prefix=prefix):
                packet = self.classify(ethernet(ipv6(60, 16, prefix), 0x86DD), 70)
                self.assertIsNone(packet.number)
                self.assertEqual(packet.protocol_issue, "ipv6_truncated_extension")
                self.assertEqual(packet.header_issue, "ipv6_truncated_extension")

    def test_ipv6_observed_terminal_does_not_hide_invalid_extension_length(self):
        for extension, prefix in ((60, bytes((17, 2))), (51, bytes((17, 1)))):
            with self.subTest(extension=extension):
                packet = self.classify(ethernet(ipv6(extension, 16, prefix), 0x86DD), 70)
                self.assertIsNone(packet.number)
                self.assertEqual(packet.protocol_issue, "ipv6_invalid_extension_length")

    def test_ipv6_fragment_with_unavailable_extension_or_visible_terminal(self):
        for following, number in ((60, None), (17, 17)):
            with self.subTest(following=following):
                fragment = bytes((following, 0, 0, 8)) + bytes(4)
                packet = self.classify(ethernet(ipv6(44, 16, fragment), 0x86DD), 70)
                self.assertEqual((packet.kind, packet.number, packet.ip_bytes), ("ipv6", number, 56))
                self.assertTrue(packet.fragment)

    def test_ipv6_first_and_atomic_fragment_walks_destination_options(self):
        for flags, is_fragment in ((1, True), (0, False)):
            fragment = bytes((60, 0, 0, flags)) + bytes(4)
            destination = bytes((58, 0)) + bytes(6)
            data = ethernet(ipv6(44, 24, fragment + destination), 0x86DD)
            packet = self.classify(data, 78)
            self.assertEqual((packet.number, packet.ip_bytes, packet.fragment), (58, 64, is_fragment))

    def test_length_and_protocol_fail_independently(self):
        bad_length = self.classify(ethernet(ipv4(length=19)), 54)
        self.assertEqual((bad_length.number, bad_length.ip_bytes), (6, None))
        self.assertEqual(bad_length.length_issue, "ipv4_invalid_total_length")
        with_fcs = self.classify(ethernet(ipv4(length=40)), 54, 4)
        self.assertIsNone(with_fcs.ip_bytes)
        short = self.classify(ethernet(ipv4()[:9]), 54)
        self.assertEqual((short.kind, short.number, short.ip_bytes), ("ipv4", None, None))
        extension = self.classify(ethernet(ipv6(60, 16, b"\x11"), 0x86DD), 70)
        self.assertEqual((extension.kind, extension.number, extension.ip_bytes), ("ipv6", 17, 56))
        self.assertIsNone(extension.protocol_issue)
        self.assertEqual(extension.header_issue, "ipv6_truncated_extension")
        padding = ethernet(ipv6(60, 4, bytes((17, 0)) + bytes(6)), 0x86DD)
        self.assertEqual(self.classify(padding, len(padding)).protocol_issue, "ipv6_invalid_extension_length")

    def test_non_ip_and_missing_link_header_are_distinct(self):
        self.assertEqual(self.classify(ethernet(b"", 0x0806), 60).kind, "non_ip")
        self.assertEqual(self.classify(bytes(12), 60).kind, "unknown")
        self.assertEqual(self.classify(ethernet(b""), 60).kind, "unknown")
        self.assertEqual(self.classify(ethernet(ipv6(59, 0)), 54).kind, "unknown")

    def test_ipv6_jumbo_candidate_and_empty_packet(self):
        jumbo = self.classify(ethernet(ipv6(0, 0, bytes(8)), 0x86DD), 100_054)
        self.assertEqual((jumbo.number, jumbo.ip_bytes), (None, None))
        self.assertEqual(jumbo.length_issue, "ipv6_jumbo_unsupported")
        empty = self.classify(ethernet(ipv6(59, 0), 0x86DD), 60)
        self.assertEqual((empty.number, empty.ip_bytes), (59, 40))


class CLITests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.results = self.root / "out" / "202604081400"

    def run_capture(self, data, *, compressed=False):
        source = self.root / ("capture.pcap.gz" if compressed else "capture.pcap")
        source.write_bytes(gzip.compress(data) if compressed else data)
        return subprocess.run(
            [sys.executable, "-m", "mawi_protocol_analysis", str(source),
             "--output-root", str(self.root / "out")],
            capture_output=True, text=True,
        )

    def read_csv(self, name):
        with (self.results / name).open(newline="") as stream:
            return list(csv.DictReader(stream))

    def read_json(self, name):
        return json.loads((self.results / name).read_text())

    def test_counts_and_time_bins_reconcile_including_unclassified_records(self):
        v4 = ethernet(ipv4(length=120, fragment=1))
        v6 = ethernet(ipv6(17, 8), 0x86DD)
        unknown_v6 = ethernet(ipv6(60, 16), 0x86DD)
        arp = ethernet(b"", 0x0806)
        bad_v4 = ethernet(ipv4(47, 19))
        result = self.run_capture(pcap([
            (START - 1, 999_999_999, v4, 134),
            (START, 0, v4, 134),
            (START + 59, 999_999_999, arp, 60),
            (START + 60, 0, v6, 62),
            (START + 60, 1, unknown_v6, 70),
            (START + 90, 1_000_000_000, v4, 134),
            (START + 120, 0, v4, 20),  # invalid orig_len; next record stays aligned
            (START + 899, 999_999_999, bad_v4, 60),
            (START + 899, 999_999_999, b"\x00", 60),
            (START + 900, 0, v4, 134),
        ], endian=">", nano=True, link=0x04000001), compressed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.read_json("summary.json")
        self.assertEqual([summary[x] for x in (
            "records_read", "included_packets", "out_of_window_records", "invalid_records",
            "ipv4_packets", "ipv6_packets", "non_ip_packets", "unknown_version_packets",
            "unclassifiable_packets", "tcp_packets", "udp_packets", "non_tcp_udp_packets",
            "fragment_packets", "ip_length_unavailable_packets", "truncated_capture_packets",
        )], [10, 6, 2, 2, 2, 2, 1, 1, 2, 1, 1, 1, 1, 2, 6])
        self.assertEqual(summary["invalid_record_reasons"], {"invalid_timestamp_fraction": 1, "orig_len_below_incl_len": 1})
        self.assertEqual(summary["ip_length_issue_reasons"], {"ethernet_truncated_header": 1, "ipv4_invalid_total_length": 1})
        self.assertAlmostEqual(summary["populations"]["overall"]["packets_per_second"], 6 / 900)
        manifest = self.read_json("manifest.json")
        self.assertEqual(manifest["pcap"]["snaplen"], 96)
        self.assertEqual(manifest["pcap"]["declared_fcs_bytes"], 0)
        self.assertEqual(manifest["pcap"]["timestamp_resolution"], "nanosecond")
        self.assertEqual(manifest["pcap"]["linktype"], 1)

        counts = self.read_csv("protocol_counts.csv")
        tcp = next(row for row in counts if row["protocol_number"] == "6")
        self.assertEqual((tcp["original_frame_bytes"], tcp["ip_packet_bytes"]), ("134", "120"))
        self.assertAlmostEqual(float(tcp["packet_ratio_overall"]), 1 / 6)
        self.assertAlmostEqual(float(tcp["packet_ratio_ip_version"]), 1 / 2)
        self.assertAlmostEqual(float(tcp["ip_packet_byte_ratio_ip_version"]), 1.0)
        series = self.read_csv("protocol_timeseries_60s.csv")
        self.assertEqual(len({row["interval_start_jst"] for row in series}), 15)
        self.assertEqual(len(series), 15 * len(counts))
        self.assertEqual(sum(int(r["packet_count"]) for r in series if r["interval_start_jst"] ==
                             "2026-04-08T14:01:00+09:00"), 2)
        for field, total in (("packet_count", 6), ("original_frame_bytes", 446),
                             ("ip_packet_bytes", 224), ("fragment_packets", 1),
                             ("ip_length_unavailable_packets", 2)):
            by_group = Counter()
            for row in series:
                by_group[row["category"], row["protocol_number"]] += int(row[field])
            self.assertEqual(sum(int(row[field]) for row in counts), total)
            self.assertEqual(sum(by_group.values()), total)
            for row in counts:
                self.assertEqual(by_group[row["category"], row["protocol_number"]], int(row[field]))

    def test_truncated_extensions_count_under_known_protocols_and_retain_issues(self):
        result = self.run_capture(pcap([
            (START, 0, ethernet(ipv6(60, 16, b"\x11"), 0x86DD), 70),
            (START, 1, ethernet(ipv6(51, 16, b"\x06\x02"), 0x86DD), 70),
            (START + 60, 0, ethernet(ipv6(43, 16, b"\x32\x00"), 0x86DD), 70),
            (START + 60, 1, ethernet(ipv6(60, 16, b"\x3c"), 0x86DD), 70),
            (START + 120, 0, ethernet(ipv6(60, 16), 0x86DD), 70),
        ]))
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = self.read_json("summary.json")
        self.assertEqual(summary["included_packets"], 5)
        self.assertEqual((summary["tcp_packets"], summary["udp_packets"],
                          summary["non_tcp_udp_packets"], summary["ip_protocol_indeterminate_packets"]),
                         (1, 1, 1, 2))
        self.assertEqual(summary["unclassifiable_packets"], 2)
        self.assertEqual(summary["protocol_issue_reasons"], {"ipv6_truncated_extension": 2})
        self.assertEqual(summary["header_issue_reasons"], {"ipv6_truncated_extension": 5})
        self.assertEqual(summary["truncated_capture_packets"], 5)
        self.assertEqual(summary["invalid_or_missing_header_packets"], 5)
        self.assertEqual(summary["ip_length_unavailable_packets"], 0)
        counts = self.read_csv("protocol_counts.csv")
        udp = next(row for row in counts if row["protocol_number"] == "17")
        self.assertEqual((udp["packet_count"], udp["original_frame_bytes"], udp["ip_packet_bytes"]),
                         ("1", "70", "56"))
        self.assertEqual(udp["invalid_or_missing_header_packets"], "1")
        self.assertAlmostEqual(float(udp["packet_ratio_overall"]), 0.2)
        series = self.read_csv("protocol_timeseries_60s.csv")
        for row in counts:
            matching = [minute for minute in series if minute["protocol_number"] == row["protocol_number"]]
            for field in ("packet_count", "original_frame_bytes", "ip_packet_bytes",
                          "invalid_or_missing_header_packets"):
                self.assertEqual(sum(int(minute[field]) for minute in matching), int(row[field]))

    def test_incomplete_or_unsupported_input_has_no_results(self):
        valid = pcap([(START, 0, ethernet(ipv4()), 54)])
        for data, message in (
            (valid[:-1], "truncated PCAP record payload"),
            (valid + b"x", "truncated PCAP record header"),
            (pcap([], link=113), "unsupported link type"),
            (b"\x0a\x0d\x0d\x0a" + bytes(24), "PCAPNG"),
        ):
            with self.subTest(message=message):
                result = self.run_capture(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.results.exists())

    def test_empty_capture_keeps_all_intervals_without_fabricating_a_protocol(self):
        result = self.run_capture(pcap([]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.read_csv("protocol_counts.csv"), [])
        self.assertEqual(self.read_csv("protocol_timeseries_60s.csv"), [])
        summary = self.read_json("summary.json")
        self.assertEqual(len(summary["intervals"]), 15)
        self.assertIsNone(summary["populations"]["ipv6"]["mean_ip_packet_size"])

    def test_tunnel_labels_describe_inner_and_outer_ip_versions(self):
        result = self.run_capture(pcap([
            (START, 0, ethernet(ipv4(41, 60)), 74),
            (START, 0, ethernet(ipv6(4, 20), 0x86DD), 74),
        ]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {(r["ip_version"], r["protocol_number"]): r["protocol_name"]
             for r in self.read_csv("protocol_counts.csv")},
            {("4", "41"): "IPv6-in-IPv4", ("6", "4"): "IPv4-in-IPv6"},
        )

    def test_existing_results_are_preserved_on_rerun(self):
        first = self.run_capture(pcap([(START, 0, ethernet(ipv4()), 54)]))
        self.assertEqual(first.returncode, 0, first.stderr)
        before = {path.name: path.read_bytes() for path in self.results.iterdir()}
        second = self.run_capture(pcap([]))
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("output directory already exists", second.stderr)
        self.assertEqual({path.name: path.read_bytes() for path in self.results.iterdir()}, before)
