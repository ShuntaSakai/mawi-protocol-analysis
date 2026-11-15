"""Run the visualization against actual Task 1 output in temporary directories."""
import csv
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from test_analysis import START, ethernet, ipv4, ipv6, pcap


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebook" / "01_overall_protocol_distribution.ipynb"
EXTRAS_AVAILABLE = all(importlib.util.find_spec(name) is not None for name in
                       ("pandas", "matplotlib", "nbformat", "nbclient", "ipykernel"))


@unittest.skipUnless(EXTRAS_AVAILABLE, "install the notebook extra to execute notebook tests")
class NotebookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        # Mirror both supported working directories without writing fixtures to the repo.
        (self.work / "notebook").mkdir()

    def analyze(self, records):
        source = self.work / "synthetic.pcap"
        source.write_bytes(pcap(records))
        subprocess.run(
            [sys.executable, "-m", "mawi_protocol_analysis", str(source),
             "--output-root", str(self.work / "results")],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )

    def execute(self, cwd, settings="", assertions=""):
        import nbformat
        from nbclient import NotebookClient

        nb = nbformat.read(NOTEBOOK, as_version=4)
        nbformat.validate(nb)
        stored = [cell for cell in nb.cells if cell.cell_type == "code"]
        self.assertTrue(all(not cell.outputs and cell.execution_count is None for cell in stored))
        stored[0].source += '\nDATA_LABEL = "Synthetic fixture (not MAWI measurements)"\n' + settings
        if assertions:
            nb.cells.append(nbformat.v4.new_code_cell(textwrap.dedent(assertions)))
        env = os.environ | {
            "MPLCONFIGDIR": str(self.work / "matplotlib"),
            "IPYTHONDIR": str(self.work / "ipython"),
            "JUPYTER_RUNTIME_DIR": str(self.work / "jupyter"),
        }
        return NotebookClient(nb, kernel_name="python3", timeout=90).execute(cwd=str(cwd), env=env)

    def test_populations_ratios_and_rates_against_task1_schema(self):
        self.analyze([
            (START, 0, ethernet(ipv4(6, 100)), 114),
            (START, 1, ethernet(ipv6(6, 40), 0x86DD), 94),
            (START + 60, 0, ethernet(ipv4(17, 40)), 54),
            (START + 60, 1, ethernet(ipv4(1, 50)), 64),
            (START + 60, 2, ethernet(ipv6(50, 24), 0x86DD), 78),
            (START + 60, 3, ethernet(ipv6(60, 16, b"\x11"), 0x86DD), 70),
            (START + 120, 0, ethernet(ipv6(58, 20), 0x86DD), 74),
            (START + 240, 0, ethernet(ipv4(47, 19)), 60),
            (START, 2, ethernet(b"", 0x0806), 60),
            (START, 3, b"\x00", 60),
        ])
        for version, byte_field, ratio_field, totals, minute, non_tcp_udp in (
            ("both", "original_frame_bytes", "packet_count", (8, 608), (2, 208), {1, 47, 50, 58}),
            ("ipv4", "ip_packet_bytes", "bytes", (4, 190), (1, 100), {1, 47}),
            ("ipv6", "original_frame_bytes", "bytes", (4, 316), (1, 94), {50, 58}),
        ):
            with self.subTest(version=version, byte_field=byte_field, ratio_field=ratio_field):
                cwd = self.work if version != "ipv4" else self.work / "notebook"
                nb = self.execute(cwd, settings=f"""
IP_VERSION = {version!r}
BYTE_METRIC = {byte_field!r}
TIMESERIES_RATIO_METRIC = {ratio_field!r}
DISPLAY_PROTOCOLS = (6, 17, 47)
OTHERS_THRESHOLD_PCT = {100.0 if version == "both" else None!r}
SAVE_FIGURES = {version == "ipv4"!r}
""", assertions=f"""
                from math import isclose
                assert "Synthetic fixture" in dataset_caption
                assert summary["included_packets"] == 10
                assert summary["non_ip_packets"] == 1
                assert summary["unclassifiable_packets"] == 2
                assert summary["ip_length_unavailable_packets"] == 2
                assert tuple(protocol_totals[["packet_count", BYTE_METRIC]].sum()) == {totals!r}
                assert isclose(protocol_ratios["packet_count"].sum(), 100)
                assert isclose(protocol_ratios[BYTE_METRIC].sum(), 100)
                assert set(non_tcp_udp_table["protocol_number"]) == {non_tcp_udp!r}
                assert isclose(non_tcp_udp_table["packet_pct"].sum(), 100)
                assert isclose(non_tcp_udp_table["byte_pct"].sum(), 100)
                assert "Others" in shown_totals.index
                assert len(interval_starts) == 15
                assert list(interval_starts.strftime("%H:%M")) == [f"14:{{i:02}}" for i in range(15)]
                assert len(time_ratios) == 15 and time_ratios.iloc[3].isna().all()
                assert isclose(time_ratios.iloc[0].sum(), 100)
                assert isclose(packet_rates.iloc[0].sum(), {minute[0]} / 60)
                assert isclose(byte_rates.iloc[0].sum(), {minute[1]} / 60)
                assert packet_rates.iloc[3].eq(0).all() and byte_rates.iloc[3].eq(0).all()
                if IP_VERSION == "ipv4":
                    assert time_ratios.iloc[4].isna().all()
                    assert isclose(packet_rates.iloc[4].sum(), 1 / 60)
                if IP_VERSION == "both":
                    assert protocol_totals.loc["6", "packet_count"] == 2
                    assert protocol_totals.loc["Indeterminate", "packet_count"] == 1
                    assert tuple(shown_totals.loc["Others", ["packet_count", BYTE_METRIC]]) == (3, 216)
                pd.testing.assert_frame_equal(counts, read_csv("protocol_counts.csv"))
                pd.testing.assert_frame_equal(timeseries, read_csv("protocol_timeseries_60s.csv"))
                """)
                figures = [output for cell in nb.cells if cell.cell_type == "code"
                           for output in cell.outputs if "image/png" in output.get("data", {})]
                self.assertEqual(len(figures), 4)
                saved = list((self.work / "results" / "202604081400" / "figures").glob("*.png"))
                if version == "ipv4":
                    self.assertEqual(len(saved), 4)
                elif version == "both":
                    self.assertEqual(saved, [])

    def test_inconsistent_csv_groups_are_rejected(self):
        from nbclient.exceptions import CellExecutionError

        self.analyze([(START, 0, ethernet(ipv4(6, 100)), 114)])
        counts_file = self.work / "results" / "202604081400" / "protocol_counts.csv"
        with counts_file.open(newline="") as stream:
            reader = csv.DictReader(stream)
            columns, row = reader.fieldnames, next(reader)
        row.update(protocol_number="17", protocol_name="UDP")
        with counts_file.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(CellExecutionError, "group totals differ"):
            self.execute(self.work)

    def test_empty_and_missing_results(self):
        from nbclient.exceptions import CellExecutionError

        with self.assertRaises(CellExecutionError) as caught:
            self.execute(self.work)
        self.assertIn("python3 -m mawi_protocol_analysis", str(caught.exception))
        self.assertIn("protocol_counts.csv", str(caught.exception))
        self.analyze([])
        self.execute(self.work, assertions="""
        assert len(interval_starts) == 15
        assert time_ratios.shape == (15, 0)
        assert protocol_totals.empty
        assert non_tcp_udp_table.empty
        """)
