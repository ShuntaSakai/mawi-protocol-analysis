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
        for cell in stored:
            cell.outputs = []
            cell.execution_count = None
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
            (START + 60, 3, ethernet(ipv6(60, 16), 0x86DD), 70),
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
                variation = ratio_variation_table.set_index("protocol")
                assert variation.loc["6", "packet_max_pct"] == 100
                assert variation.loc["6", "packet_min_pct"] == 0
                assert variation.loc["6", "byte_range_pp"] == 100
                assert set(ratio_variation_series) == {{"packet_count", "original_frame_bytes"}}
                category_table = category_variation_table.set_index("category")
                for category, protocol in (("TCP", "6"), ("UDP", "17")):
                    for column in ("packet_max_pct", "packet_min_pct", "packet_range_pp",
                                   "byte_max_pct", "byte_min_pct", "byte_range_pp"):
                        assert category_table.loc[category, column] == variation.loc[protocol, column]
                for metric, values in category_minute_totals.items():
                    expected = selected_timeseries.assign(
                        minute=pd.to_datetime(selected_timeseries[starts], utc=True).dt.tz_convert(jst)
                    ).groupby("minute")[metric].sum().reindex(interval_starts, fill_value=0)
                    pd.testing.assert_series_equal(values.sum(axis=1), expected, check_names=False)
                    assert category_variation_series[metric].iloc[3].isna().all()
                if IP_VERSION == "both":
                    assert isclose(ratio_variation_series["packet_count"].iloc[1]["Indeterminate"], 25)
                    assert isclose(ratio_variation_series["original_frame_bytes"].iloc[1]["Indeterminate"], 70 / 266 * 100)
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

    def test_ratio_variation_uses_all_ip_bins_and_original_bytes(self):
        # TCP: 2/3, 1/2, 0 packets; 300/400, 100/400, 0 bytes.
        # Non-IP and unknown-version records must never enter either denominator.
        self.analyze([
            (START, 0, ethernet(ipv4(6, 40)), 100),
            (START, 1, ethernet(ipv6(6, 20), 0x86DD), 200),
            (START, 2, ethernet(ipv6(60, 16), 0x86DD), 100),
            (START, 3, ethernet(b"", 0x0806), 1000),
            (START, 4, b"\x00", 1000),
            (START + 60, 0, ethernet(ipv4(6, 40)), 100),
            (START + 60, 1, ethernet(ipv4(17, 40)), 300),
            (START + 840, 0, ethernet(ipv4(17, 40)), 100),
        ])
        self.execute(self.work, settings='''
BYTE_METRIC = "ip_packet_bytes"
TIMESERIES_RATIO_METRIC = "bytes"
DISPLAY_PROTOCOLS = ()
OTHERS_THRESHOLD_PCT = None
SAVE_RATIO_TABLES = True
''', assertions='''
        from math import isclose
        assert "ratio_variation_table" in globals(), "missing ratio variation tables"
        table = ratio_variation_table.set_index("protocol")
        assert {"6", "17", "1", "50", "58", "47", "Indeterminate"} <= set(table.index)
        assert "Others" not in table.index
        assert isclose(table.loc["6", "packet_max_pct"], 200 / 3)
        assert table.loc["6", "packet_min_pct"] == 0
        assert isclose(table.loc["6", "packet_range_pp"], 200 / 3)
        assert table.loc["6", "byte_max_pct"] == 75
        assert table.loc["6", "byte_min_pct"] == 0
        assert table.loc["6", "byte_range_pp"] == 75
        assert table.loc["1", "packet_max_pct"] == 0
        for ratios in ratio_variation_series.values():
            assert len(ratios) == 15
            assert ratios.iloc[2:14].isna().all().all()
            assert isclose(ratios.iloc[0].sum(), 100)
        assert ratio_variation_series["packet_count"].loc[interval_starts[14], "17"] == 100
        detail = ratio_variation_details.set_index(["protocol", "metric"])
        tcp = detail.loc[("6", "packet_count")]
        assert tcp["defined_intervals"] == 3 and tcp["undefined_intervals"] == 12
        assert tcp["max_interval_starts_jst"] == "2026-04-08T14:00:00+09:00"
        assert tcp["min_interval_starts_jst"] == "2026-04-08T14:14:00+09:00"
        absent = detail.loc[("1", "packet_count")]
        assert absent["min_interval_starts_jst"].split("; ") == [
            "2026-04-08T14:00:00+09:00", "2026-04-08T14:01:00+09:00",
            "2026-04-08T14:14:00+09:00"]
        first_export = ratio_table_export_dir
        second_export = save_ratio_variation_tables()
        assert first_export != second_export
        for directory in (first_export, second_export):
            saved = pd.read_csv(directory / "protocol_ratio_variation_60s.csv", dtype={"protocol": str})
            assert isclose(saved.set_index("protocol").loc["6", "packet_range_pp"], 200 / 3)
            metadata = json.loads((directory / "metadata.json").read_text())
            assert metadata["byte_metric"] == "original_frame_bytes"
            assert metadata["interval_count"] == 15
            assert "Synthetic fixture" in metadata["dataset"]
        pd.testing.assert_frame_equal(timeseries, read_csv("protocol_timeseries_60s.csv"))
        ''')

    def test_zero_byte_denominator_is_independent_of_packet_denominator(self):
        self.analyze([
            (START, 0, ethernet(ipv4(6, 40)), 100),
            (START + 60, 0, ethernet(ipv4(17, 40)), 100),
        ])
        # Deliberately synthetic counters: packets exist but their byte total is zero.
        # Keep the CSV group totals and the summary validation consistent.
        result_dir = self.work / "results" / "202604081400"
        for name in ("protocol_counts.csv", "protocol_timeseries_60s.csv"):
            path = result_dir / name
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream)
                columns, rows = reader.fieldnames, list(reader)
            for row in rows:
                if row["protocol_number"] == "17":
                    row["original_frame_bytes"] = "0"
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=columns)
                writer.writeheader()
                writer.writerows(rows)
        import json

        path = result_dir / "summary.json"
        summary = json.loads(path.read_text())
        summary["populations"]["overall"]["original_frame_bytes"] = 100
        path.write_text(json.dumps(summary))
        self.execute(self.work, settings='TIMESERIES_RATIO_METRIC = "packet_count"', assertions='''
        packets = ratio_variation_series["packet_count"]
        byte_shares = ratio_variation_series["original_frame_bytes"]
        assert packets.iloc[1]["17"] == 100
        assert byte_shares.iloc[1].isna().all()
        table = ratio_variation_table.set_index("protocol")
        assert table.loc["6", "packet_range_pp"] == 100
        assert table.loc["6", "byte_min_pct"] == 100
        assert table.loc["6", "byte_range_pp"] == 0
        detail = ratio_variation_details.set_index(["protocol", "metric"])
        assert detail.loc[("6", "packet_count"), "defined_intervals"] == 2
        assert detail.loc[("6", "original_frame_bytes"), "defined_intervals"] == 1
        grouped = category_variation_table.set_index("category")
        assert grouped.loc["TCP", "byte_min_pct"] == 100
        assert grouped.loc["TCP", "byte_range_pp"] == 0
        assert category_variation_series["original_frame_bytes"].iloc[1].isna().all()
        ''')

    def test_non_tcp_udp_variation_aggregates_counts_before_extrema(self):
        # Minute 0: 1 known non-TCP/UDP + 1 indeterminate among 5 IP packets.
        # Minute 1: ESP only; minute 14: ICMP and ESP together.
        self.analyze([
            (START, 0, ethernet(ipv4(6, 40)), 100),
            (START, 1, ethernet(ipv6(6, 20), 0x86DD), 100),
            (START, 2, ethernet(ipv4(17, 40)), 100),
            (START, 3, ethernet(ipv4(1, 40)), 100),
            (START, 4, ethernet(ipv6(60, 16), 0x86DD), 200),
            (START, 5, ethernet(b"", 0x0806), 1000),
            (START, 6, b"\x00", 1000),
            (START + 60, 0, ethernet(ipv4(6, 40)), 100),
            (START + 60, 1, ethernet(ipv4(17, 40)), 100),
            (START + 60, 2, ethernet(ipv6(50, 20), 0x86DD), 300),
            (START + 840, 0, ethernet(ipv4(17, 40)), 100),
            (START + 840, 1, ethernet(ipv4(1, 40)), 100),
            (START + 840, 2, ethernet(ipv6(50, 20), 0x86DD), 100),
        ])
        self.execute(self.work, settings='''
BYTE_METRIC = "ip_packet_bytes"
TIMESERIES_RATIO_METRIC = "packet_count"
DISPLAY_PROTOCOLS = ()
OTHERS_THRESHOLD_PCT = None
SAVE_RATIO_TABLES = True
''', assertions='''
        from math import isclose
        assert "category_variation_table" in globals(), "missing three-category variation table"
        table = category_variation_table.set_index("category")
        assert list(table.index) == ["TCP", "UDP", "非TCP/UDP"]
        non_tcp_udp = table.loc["非TCP/UDP"]
        assert isclose(non_tcp_udp["packet_max_pct"], 200 / 3)
        assert non_tcp_udp["packet_min_pct"] == 20
        assert isclose(non_tcp_udp["packet_range_pp"], 140 / 3)
        assert isclose(non_tcp_udp["byte_max_pct"], 200 / 3)
        assert isclose(non_tcp_udp["byte_min_pct"], 50 / 3)
        assert isclose(non_tcp_udp["byte_range_pp"], 50)
        individual = ratio_variation_table.set_index("protocol")
        assert not isclose(non_tcp_udp["packet_range_pp"], individual.loc[["1", "50"], "packet_range_pp"].sum())
        assert not isclose(non_tcp_udp["byte_range_pp"], individual.loc[["1", "50"], "byte_range_pp"].sum())
        for metric, values in category_minute_totals.items():
            assert len(values) == 15
            expected = selected_timeseries.assign(
                minute=pd.to_datetime(selected_timeseries[starts], utc=True).dt.tz_convert(jst)
            ).groupby("minute")[metric].sum().reindex(interval_starts, fill_value=0)
            pd.testing.assert_series_equal(values.sum(axis=1), expected, check_names=False)
            assert category_variation_series[metric].iloc[2:14].isna().all().all()
        assert category_minute_totals["packet_count"].iloc[0].to_dict() == {
            "TCP": 2, "UDP": 1, "非TCP/UDP": 1, "Indeterminate": 1}
        assert category_minute_totals["original_frame_bytes"].iloc[0].to_dict() == {
            "TCP": 200, "UDP": 100, "非TCP/UDP": 100, "Indeterminate": 200}
        detail = category_variation_details.set_index(["category", "metric"])
        for metric in ("packet_count", "original_frame_bytes"):
            row = detail.loc[("非TCP/UDP", metric)]
            assert row["max_interval_starts_jst"] == "2026-04-08T14:14:00+09:00"
            assert row["min_interval_starts_jst"] == "2026-04-08T14:00:00+09:00"
            assert row["defined_intervals"] == 3 and row["undefined_intervals"] == 12
        first = ratio_table_export_dir
        second = save_ratio_variation_tables()
        assert first != second
        for directory in (first, second):
            saved = pd.read_csv(directory / "category_ratio_variation_60s.csv").set_index("category")
            assert isclose(saved.loc["非TCP/UDP", "packet_range_pp"], 140 / 3)
            saved_detail = pd.read_csv(directory / "category_ratio_variation_60s_details.csv")
            assert len(saved_detail) == 6
            metadata = json.loads((directory / "metadata.json").read_text())
            assert metadata["category_tables"]["summary_file"] == "category_ratio_variation_60s.csv"
            assert metadata["category_tables"]["definitions"]["非TCP/UDP"] == "Known IP protocol numbers except 6 and 17"
            saved_protocols = pd.read_csv(directory / "protocol_ratio_variation_60s.csv")
            assert list(saved_protocols.columns) == list(ratio_variation_table.columns)
            assert list(saved_protocols["protocol"].astype(str)) == list(ratio_variation_table["protocol"])
        ''')

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
        assert ratio_variation_table.filter(regex="_(pct|pp)$").isna().all().all()
        assert ratio_variation_details["defined_intervals"].eq(0).all()
        assert ratio_variation_details["undefined_intervals"].eq(15).all()
        assert ratio_variation_details["max_interval_starts_jst"].eq("").all()
        assert category_variation_table.filter(regex="_(pct|pp)$").isna().all().all()
        assert category_variation_details["defined_intervals"].eq(0).all()
        assert category_variation_details["undefined_intervals"].eq(15).all()
        assert category_variation_details["max_interval_starts_jst"].eq("").all()
        assert category_variation_details["min_interval_starts_jst"].eq("").all()
        """)
