import tempfile
import io
import csv
import gzip
import hashlib
import json
import os
import textwrap
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout
import unittest
from ipaddress import IPv4Address
from pathlib import Path

from mawi_protocol_analysis.prefixes import PrefixMatcher, load_prefixes, sha256_file
from mawi_protocol_analysis.protocols import classify_ethernet, classify_ethernet_with_endpoints
from test_analysis import START, ethernet, ipv4, pcap
from mawi_protocol_analysis.aggregate import PrefixAnalysis, analyze
from mawi_protocol_analysis.pcap import PcapReader
from mawi_protocol_analysis.cli import main
from test_notebook import EXTRAS_AVAILABLE


def frame(protocol=6, *, src="192.0.2.10", dst="198.51.100.10", length=40,
          fragment=0, tagged=False):
    header = bytearray(ipv4(protocol, length, fragment=fragment))
    header[12:16] = IPv4Address(src).packed
    header[16:20] = IPv4Address(dst).packed
    return ethernet(bytes(header), tagged=tagged)


class EndpointTests(unittest.TestCase):
    def test_shared_parser_compatibility_and_observed_outer_endpoints(self):
        for protocol in (1, 6, 17, 47, 50, 222):
            for tagged in (False, True):
                data = frame(protocol, tagged=tagged, fragment=1)
                result, src, dst = classify_ethernet_with_endpoints(data, 100)
                self.assertEqual(result, classify_ethernet(data, 100))
                self.assertEqual(len(result), 7)  # Preserve the public tuple API.
                self.assertEqual((result.number, result.fragment), (protocol, True))
                self.assertEqual((src, dst), (int(IPv4Address("192.0.2.10")), int(IPv4Address("198.51.100.10"))))

    def test_missing_or_invalid_addresses_never_match(self):
        for data, orig in ((frame()[:33], 54), (frame(), 33), (b"", 60),
                           (ethernet(ipv4(ihl=4)), 60)):
            result, src, dst = classify_ethernet_with_endpoints(data, orig)
            self.assertEqual((src, dst), (None, None))
        result, src, dst = classify_ethernet_with_endpoints(frame(length=19), 54)
        self.assertEqual(result.number, 6)
        self.assertIsNone(result.ip_bytes)
        self.assertIsNotNone(src)  # IP length failure is independent of addresses.


class PrefixInputTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "prefixes.csv"

    def load(self, text, count=2):
        self.path.write_text(text)
        return load_prefixes(self.path, count)

    def test_order_selection_and_containment_are_preserved(self):
        selection = self.load("prefix,selected_for_analysis\n192.0.2.128/25,True\n0.0.0.0/0,False\n192.0.2.0/24,1\n")
        self.assertEqual([str(n) for n in selection.networks], ["192.0.2.128/25", "192.0.2.0/24"])
        self.assertEqual(selection.source_rows, (2, 4))
        self.assertEqual(selection.sha256, sha256_file(self.path))
        self.assertEqual(len(selection.overlaps()), 1)
        matcher = PrefixMatcher(selection)
        self.assertEqual(matcher.match(int(IPv4Address("192.0.2.1")), None), 2)
        self.assertEqual(matcher.match(None, int(IPv4Address("192.0.2.200"))), 3)
        self.assertEqual(matcher.match(None, None), 0)

    def test_never_guesses_or_normalizes_input(self):
        for text in (
            "prefix\n192.0.2.1/24\n", "prefix\n2001:db8::/32\n",
            "prefix\n192.0.0.0/16\n", "prefix\n192.0.2.0/24\n192.0.2.0/24\n",
            "prefix,analysis_scope\n192.0.2.0/24,normalized_24\n",
            "prefix,selected_for_analysis\n192.0.2.0/24,maybe\n",
            "normalized_prefix_24\n192.0.2.0/24\n", "prefix\n",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text, 1)
        with self.assertRaisesRegex(ValueError, "expected 18"):
            self.path.write_text("prefix\n192.0.2.0/24\n")
            load_prefixes(self.path)


class PrefixAggregationTests(unittest.TestCase):
    setUp = PrefixInputTests.setUp
    load = PrefixInputTests.load
    def test_one_pass_membership_native_union_bytes_and_boundaries(self):
        selection = self.load("prefix\n192.0.2.128/25\n198.51.100.0/24\n192.0.2.0/24\n", 3)
        analysis = PrefixAnalysis(selection)
        records = [
            (START - 1, 0, frame(), 100),
            (START, 0, frame(src="192.0.2.130", dst="203.0.113.1"), 100), # src only
            (START + 59, 999999, frame(17, src="203.0.113.1", dst="192.0.2.131"), 200), # dst only
            (START + 60, 0, frame(1, src="192.0.2.130", dst="192.0.2.131"), 300), # both once
            (START + 61, 0, frame(47, src="192.0.2.130", fragment=1, tagged=True), 400), # cross-prefix
            (START + 899, 999999, frame(50), 500), # parent /24 only (and second prefix)
            (START + 899, 999999, frame(222, length=19), 600), # protocol known, length missing
            (START, 0, frame()[:33], 1000), # missing endpoints, Overall only
            (START, 0, ethernet(ipv4(ihl=4)), 100), # indeterminate, invalid IHL
            (START + 900, 0, frame(), 700),
        ]
        data = pcap(records)
        overall = analyze(PcapReader(io.BytesIO(data)), prefixes=analysis)
        legacy = analyze(PcapReader(io.BytesIO(data)))
        self.assertEqual(overall.summary(overall.populations()), legacy.summary(legacy.populations()))
        first = analysis.scopes["192.0.2.128/25"]
        self.assertEqual(first.overall.packet_count, 4)
        self.assertEqual(first.overall.original_frame_bytes, 1000)
        self.assertEqual(first.overall.ip_packet_bytes, 160)
        self.assertEqual(first.bins[0][("ipv4", 17)].packet_count, 1)
        self.assertEqual(first.bins[1][("ipv4", 1)].packet_count, 1)
        self.assertEqual(first.overall.fragment_packets, 1)
        parent = analysis.scopes["192.0.2.0/24"]
        self.assertEqual(parent.overall.packet_count, 6)
        self.assertEqual(parent.overall.ip_length_unavailable_packets, 1)
        union = analysis.scopes["selected_union"]
        self.assertEqual(union.overall.packet_count, 6)
        self.assertLess(union.overall.packet_count, sum(analysis.scopes[n].overall.packet_count for n in analysis.prefix_ids))
        self.assertEqual(analysis.address_unavailable.packet_count, 2)
        self.assertEqual(analysis.scopes["overall_ipv4"].groups[("ipv4", None)].packet_count, 2)


class PrefixOutputTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "fixture.pcap.gz"
        self.data = pcap([
            (START, 0, frame(6, src="192.0.2.130", dst="192.0.2.131"), 100),
            (START + 60, 0, frame(1, src="192.0.2.130", dst="198.51.100.1"), 200),
            (START + 60, 0, frame(222, length=19), 300),
            (START, 0, frame()[:33], 100),
        ])
        self.source.write_bytes(gzip.compress(self.data))
        self.ledger = self.root / "prefixes.csv"
        self.ledger.write_text("prefix\n192.0.2.128/25\n192.0.2.0/24\n203.0.113.0/24\n")
        self.destination = self.root / "results/202604081400/prefix_protocol_distribution"

    def run_cli(self, *options):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        with redirect_stderr(self.stderr), redirect_stdout(self.stdout):
            return main([str(self.source), "--prefixes", str(self.ledger),
                         "--expected-prefix-count", "3", "--output-root", str(self.root / "results"), *options])

    def read_csv(self, name):
        with (self.destination / name).open(newline="") as stream:
            return list(csv.DictReader(stream))

    def test_csv_json_counts_ratios_hashes_and_no_overwrite(self):
        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        self.assertEqual({p.name for p in self.destination.iterdir()}, {
            "selected_prefixes.csv", "prefix_protocol_counts.csv", "prefix_summary.csv",
            "prefix_protocol_timeseries_60s.csv", "summary.json", "manifest.json"})
        summary = json.loads((self.destination / "summary.json").read_text())
        manifest = json.loads((self.destination / "manifest.json").read_text())
        self.assertEqual(manifest["input"]["sha256"], sha256_file(self.source))
        self.assertEqual(manifest["input"]["decompressed_pcap_sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(manifest["prefix_selection"]["historical_selection_verification"], "pending_external_audit")
        self.assertEqual(len(manifest["prefix_selection"]["overlaps"]), 1)
        self.assertEqual(manifest["configuration"]["sha256"], hashlib.sha256(manifest["configuration"]["canonical_json"].encode()).hexdigest())
        for name, digest in manifest["output_sha256"].items():
            self.assertEqual(digest, sha256_file(self.destination / name))
        counts = self.read_csv("prefix_protocol_counts.csv")
        times = self.read_csv("prefix_protocol_timeseries_60s.csv")
        for scope, total in summary["populations"].items():
            rows = [row for row in counts if row["scope"] == scope]
            for field in ("packet_count", "original_frame_bytes", "ip_packet_bytes"):
                self.assertEqual(sum(int(row[field]) for row in rows), total[field])
                self.assertEqual(sum(int(row[field]) for row in times if row["scope"] == scope), total[field])
        unknown = next(row for row in counts if row["scope"] == "192.0.2.0/24" and row["protocol_number"] == "222")
        self.assertAlmostEqual(float(unknown["packet_ratio"]), 1 / 3)
        self.assertEqual(float(unknown["original_frame_byte_ratio"]), .5)
        self.assertEqual(float(unknown["ip_packet_byte_ratio"]), 0)
        overall = summary["populations"]["overall_ipv4"]
        self.assertEqual(overall["indeterminate_packet_count"], 1)
        self.assertAlmostEqual(overall["non_tcp_udp_packet_ratio"], .5)
        self.assertEqual(summary["populations"]["203.0.113.0/24"]["non_tcp_udp_packet_ratio"], None)
        before = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        self.assertEqual(self.run_cli(), 1)
        self.assertIn("already exists", self.stderr.getvalue())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.destination.iterdir()})

    def test_source_identity_matches_but_authenticity_stays_pending(self):
        source_manifest = self.root / "run_manifest.json"
        source_manifest.write_text(json.dumps({"status": "success", "input": {
            "sha256": hashlib.sha256(self.data).hexdigest()}, "config": {"text": "prefix: native\n"}}))
        config = self.root / "config.yaml"
        config.write_text("prefix: native\n")
        self.assertEqual(self.run_cli("--selection-manifest", str(source_manifest),
                                      "--selection-config", str(config)), 0, self.stderr.getvalue())
        evidence = json.loads((self.destination / "manifest.json").read_text())["prefix_selection"]
        self.assertEqual(evidence["input_identity"], "matching_decompressed_pcap_bytes")
        self.assertEqual(evidence["historical_selection_verification"], "pending_external_audit")

    def test_mismatched_input_or_config_and_incomplete_capture_never_publish(self):
        source_manifest = self.root / "run_manifest.json"
        source_manifest.write_text(json.dumps({"status": "success", "input": {"sha256": "0" * 64}}))
        self.assertEqual(self.run_cli("--selection-manifest", str(source_manifest)), 1)
        self.assertIn("SHA-256 differs", self.stderr.getvalue())
        self.assertFalse(self.destination.exists())
        source_manifest.write_text(json.dumps({"status": "success", "config": {"text": "old"}}))
        config = self.root / "config.yaml"
        config.write_text("new")
        self.assertEqual(self.run_cli("--selection-manifest", str(source_manifest), "--selection-config", str(config)), 1)
        self.assertIn("config differs", self.stderr.getvalue())
        self.source.write_bytes(gzip.compress(self.data[:-1]))
        self.assertEqual(self.run_cli(), 1)
        self.assertFalse(self.destination.exists())

    def test_uncompressed_and_empty_inputs(self):
        self.source = self.root / "empty.pcap"
        self.source.write_bytes(pcap([]))
        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        manifest = json.loads((self.destination / "manifest.json").read_text())
        self.assertEqual(manifest["input"]["sha256"], manifest["input"]["decompressed_pcap_sha256"])
        self.assertEqual(self.read_csv("prefix_protocol_counts.csv"), [])
        self.assertEqual(self.read_csv("prefix_protocol_timeseries_60s.csv"), [])
        self.assertEqual(len(self.read_csv("prefix_summary.csv")), 5)

    def test_default_eighteen_prefix_contract(self):
        self.ledger.write_text("prefix\n" + "".join(f"10.0.{i}.0/24\n" for i in range(18)))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = main([str(self.source), "--prefixes", str(self.ledger),
                           "--output-root", str(self.root / "results")])
        self.assertEqual(status, 0)
        self.assertEqual(len(self.read_csv("selected_prefixes.csv")), 18)
        self.assertEqual(len(self.read_csv("prefix_summary.csv")), 20)

    def test_staging_failure_and_existing_overall_are_preserved(self):
        overall = self.destination.parent
        overall.mkdir(parents=True)
        marker = overall / "summary.json"
        marker.write_text("existing Overall result")
        with patch("mawi_protocol_analysis.cli._write_prefix_tables", side_effect=OSError("write failed")):
            self.assertEqual(self.run_cli(), 1)
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(overall.glob(".mawi-*")))
        self.assertEqual(marker.read_text(), "existing Overall result")
        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        self.assertEqual(marker.read_text(), "existing Overall result")


@unittest.skipUnless(EXTRAS_AVAILABLE, "install the notebook extra to execute notebook tests")
class PrefixNotebookTests(unittest.TestCase):
    setUp = PrefixOutputTests.setUp
    run_cli = PrefixOutputTests.run_cli

    def execute(self, settings="", assertions="", from_notebook=False):
        import nbformat
        from nbclient import NotebookClient

        notebook = Path(__file__).resolve().parents[1] / "notebook/02_prefix_protocol_distribution.ipynb"
        nb = nbformat.read(notebook, as_version=4)
        nbformat.validate(nb)
        code_cells = [cell for cell in nb.cells if cell.cell_type == "code"]
        self.assertTrue(all(not cell.outputs and cell.execution_count is None for cell in code_cells))
        code_cells[0].source += '\nDATA_LABEL = "Synthetic fixture (not MAWI measurements)"\n' + settings
        if assertions:
            nb.cells.append(nbformat.v4.new_code_cell(textwrap.dedent(assertions)))
        cwd = self.root / "notebook" if from_notebook else self.root
        cwd.mkdir(exist_ok=True)
        env = os.environ | {"MPLCONFIGDIR": str(self.root / "matplotlib"),
                            "IPYTHONDIR": str(self.root / "ipython"),
                            "JUPYTER_RUNTIME_DIR": str(self.root / "jupyter")}
        return NotebookClient(nb, kernel_name="python3", timeout=90).execute(cwd=str(cwd), env=env)

    def test_five_figures_totals_full_precision_and_display_only_others(self):
        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        # Removing the PCAP proves that the Notebook reads aggregates only.
        self.source.unlink()
        for metric in ("original_frame_bytes", "ip_packet_bytes"):
            nb = self.execute(settings=f'''BYTE_METRIC = {metric!r}
DISPLAY_PROTOCOLS = (6,)
OTHERS_THRESHOLD_PCT = None
''', from_notebook=metric == "ip_packet_bytes", assertions='''
            assert "Synthetic fixture" in dataset_caption
            assert prefix_order == ["192.0.2.128/25", "192.0.2.0/24", "203.0.113.0/24"]
            assert scope_order == ["overall_ipv4", *prefix_order]
            assert packet_shares.loc["203.0.113.0/24"].isna().all()
            assert np.isclose(packet_shares.loc["overall_ipv4"].sum(), 100)
            assert np.isclose(non_tcp_ratios["packet_count"].loc["overall_ipv4"], 50)
            assert np.isclose(comparison.loc["192.0.2.0/24", "packet_count_delta_pp"], 100 / 6)
            assert set(plot_order) == {"6", "Indeterminate", "Others"}
            assert "222" in set(counts["protocol"])
            assert "222" not in plot_order
            assert plot_scope_order == ["overall_ipv4", "192.0.2.0/24", "192.0.2.128/25", "203.0.113.0/24"]
            assert packet_shares.index.tolist() == plot_scope_order
            expected_byte_prefixes = sorted(prefix_order, key=lambda p: -totals.loc[p, BYTE_METRIC])
            assert byte_shares.index.tolist() == ["overall_ipv4", *expected_byte_prefixes]
            assert heatmap_shares.index.tolist() == plot_scope_order
            assert plot_comparison.index.tolist() == plot_prefix_order
            assert detail_prefixes == prefix_order[:2]
            assert set(detail_table["protocol_number"]) == {1, 222}
            for metric in MEASURES:
                np.testing.assert_allclose(shown_values(metric).sum(axis=1), totals.loc[scope_order, metric])
            ''')
            figures = [output for cell in nb.cells if cell.cell_type == "code"
                       for output in cell.outputs if "image/png" in output.get("data", {})]
            self.assertEqual(len(figures), 5)

    def test_empty_capture_generates_five_undefined_figures(self):
        self.source.write_bytes(gzip.compress(pcap([])))
        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        nb = self.execute(assertions='''
        assert counts.empty and timeseries.empty
        assert packet_shares.empty
        assert detail_table.empty
        assert comparison.isna().all().all()
        ''')
        self.assertEqual(sum("image/png" in output.get("data", {}) for cell in nb.cells
                             if cell.cell_type == "code" for output in cell.outputs), 5)

    def test_notebook_rejects_mixed_or_modified_outputs(self):
        from nbclient.exceptions import CellExecutionError

        self.assertEqual(self.run_cli(), 0, self.stderr.getvalue())
        path = self.destination / "prefix_protocol_counts.csv"
        path.write_text(path.read_text().replace("TCP", "Changed", 1))
        with self.assertRaisesRegex(CellExecutionError, "CSV checksum mismatch"):
            self.execute()
