"""Exercise the Notebook's plotting cells without a Jupyter socket or PCAP."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


NOTEBOOK = Path(__file__).resolve().parents[1] / "notebook/02_prefix_protocol_distribution.ipynb"
AVAILABLE = all(importlib.util.find_spec(name) for name in ("numpy", "pandas", "matplotlib"))


@unittest.skipUnless(AVAILABLE, "install the notebook extra to test plots")
class PrefixPlotTests(unittest.TestCase):
    def setUp(self):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib import font_manager
        from matplotlib.colors import to_rgb
        from matplotlib.ticker import PercentFormatter
        import numpy as np
        import pandas as pd

        self.np, self.pd, self.plt = np, pd, plt
        self.addCleanup(plt.close, "all")
        self.addCleanup(plt.rcParams.update, plt.rcParams.copy())
        self.cells = json.loads(NOTEBOOK.read_text())["cells"]
        font_setup = "".join(self.cells[3]["source"]).split("%matplotlib inline", 1)[1].split(
            "if BYTE_METRIC", 1)[0]
        exec(font_setup, {"font_manager": font_manager, "plt": plt})
        prefixes = [f"192.0.2.{i}/32" for i in range(18)]
        scopes = ["overall_ipv4", *prefixes]
        # Includes ties, a zero denominator and ratios just below/at 3%.
        sizes = [1000000, 10000, 30000, 30000, 0, *range(50000, 190000, 10000)]
        totals = pd.DataFrame({"packet_count": sizes,
                               "original_frame_bytes": np.array(sizes) * 100,
                               "ip_packet_bytes": np.array(sizes) * 40}, index=scopes)
        # Byte rankings differ from packet rankings and from each other.
        totals.loc[prefixes[0], "original_frame_bytes"] *= 10
        totals.loc[prefixes[0], "ip_packet_bytes"] *= 100
        rows = []
        for scope, size in zip(scopes, sizes):
            for number, name, ratio in ((6, "TCP", .03), (17, "UDP", .0299),
                                        (222, "Unknown", .03), (None, "Indeterminate", .9101)):
                rows.append({"scope": scope, "protocol_number": number, "protocol_name": name,
                             "protocol": str(number) if number is not None else "Indeterminate",
                             "packet_count": size * ratio,
                             "original_frame_bytes": totals.loc[scope, "original_frame_bytes"] * ratio,
                             "ip_packet_bytes": totals.loc[scope, "ip_packet_bytes"] * ratio})
        counts = pd.DataFrame(rows)
        counts["protocol_number"] = counts["protocol_number"].astype("Int64")
        self.ns = dict(np=np, pd=pd, plt=plt, to_rgb=to_rgb, PercentFormatter=PercentFormatter,
                       counts=counts, totals=totals, prefix_order=prefixes, scope_order=scopes,
                       labels={s: "Overall IPv4" if s == "overall_ipv4" else s for s in scopes},
                       byte_label="PCAP orig_len bytes", caption="Synthetic fixture, not MAWI measurements",
                       display=lambda *args: None)
        self.run_cell(1)
        self.ns.update(DISPLAY_PROTOCOLS=(6, 17), OTHERS_THRESHOLD_PCT=None)
        self.run_cell(4)

    def run_cell(self, index):
        exec(compile("".join(self.cells[index]["source"]), f"{NOTEBOOK.name}:cell{index}", "exec"), self.ns)

    def test_stable_display_order_keeps_canonical_data_and_ratios(self):
        ns, pd, np = self.ns, self.pd, self.np
        canonical = ns["scope_order"].copy()
        before = ns["totals"].copy(deep=True)
        order = ns["plot_scope_order"]
        self.assertEqual(order[0], "overall_ipv4")
        self.assertEqual(len(order), 19)
        self.assertEqual(set(order[1:]), set(ns["prefix_order"]))
        self.assertTrue(ns["totals"].loc[order[1:], "packet_count"].is_monotonic_decreasing)
        first, second = ns["prefix_order"][1:3]
        self.assertLess(order.index(first), order.index(second))
        for metric in ns["MEASURES"]:
            shares = ns["percent"](ns["shown_values"](metric), metric)
            plotted = shares.reindex(order)
            pd.testing.assert_frame_equal(plotted.reindex(canonical), shares)
            positive = ns["totals"].loc[canonical, metric].gt(0)
            np.testing.assert_allclose(shares.loc[positive].sum(axis=1), 100)
            self.assertTrue(shares.loc[~positive].isna().all().all())
        pd.testing.assert_frame_equal(ns["totals"], before)
        self.assertEqual(ns["scope_order"], canonical)

    def test_threshold_contrast_counts_and_rendered_label_bounds(self):
        ns, plt, np, pd = self.ns, self.plt, self.np, self.pd
        shares = pd.DataFrame([[3, 2.999, 0, 94.001], [np.nan] * 4,
                               [3, 3, 3, 91]],
                              index=["overall_ipv4", ns["prefix_order"][3], ns["prefix_order"][0]],
                              columns=["6", "17", "Others", "Indeterminate"])
        for metric in ("packet_count", "original_frame_bytes", "ip_packet_bytes"):
            with self.subTest(metric=metric):
                fig, (ax, packet_ax) = plt.subplots(1, 2, sharey=True, width_ratios=(8, 1.25),
                                                  figsize=(13, 7), layout="constrained")
                annotations = ns["stacked"](ax, shares, metric, packet_ax)
                with patch.object(plt, "show"), patch.object(plt, "close"):
                    ns["finish"](fig, "Synthetic threshold and layout check", annotations)
                self.assertEqual([value for _, _, value in annotations], [3, 3, 3, 3, 94.001, 91])
                self.assertTrue(all(text.get_text().endswith("%") for text, _, _ in annotations))
                self.assertTrue(any("Undefined" in text.get_text() for text in ax.texts))
                self.assertEqual(tuple(ax.get_xlim()), (0, 100))
                self.assertTrue(ax.yaxis_inverted())
                self.assertEqual(packet_ax.get_title(loc="right"),
                                 "総パケット数" if metric == "packet_count" else "総バイト数")
                expected = [f"{int(ns['totals'].loc[s, metric]):,}" for s in shares.index]
                self.assertEqual([text.get_text() for text in packet_ax.texts], expected)
                fig.canvas.draw()
                renderer = fig.canvas.get_renderer()
                bounds = []
                for text, bar, _ in annotations:
                    box, bar_box = text.get_window_extent(renderer), bar.get_window_extent(renderer)
                    self.assertGreaterEqual(box.x0, bar_box.x0)
                    self.assertLessEqual(box.x1, bar_box.x1)
                    self.assertGreaterEqual(box.y0, bar_box.y0)
                    self.assertLessEqual(box.y1, bar_box.y1)
                    bounds.append(box)
                for i, box in enumerate(bounds):
                    self.assertFalse(any(box.overlaps(other) for other in bounds[i + 1:]))
                legend = fig.legends[0].get_window_extent(renderer)
                for text in packet_ax.texts:
                    box = text.get_window_extent(renderer)
                    self.assertFalse(box.overlaps(ax.get_window_extent(renderer)))
                    self.assertFalse(box.overlaps(legend))
                    self.assertTrue(fig.bbox.contains(box.x0, box.y0))
                    self.assertTrue(fig.bbox.contains(box.x1, box.y1))
                    y = ax.transData.transform((0, text.get_position()[1]))[1]
                    self.assertAlmostEqual(text.get_transform().transform(text.get_position())[1], y)
        self.assertEqual(ns["label_color"]("#000000"), "white")
        self.assertEqual(ns["label_color"]("#ffffff"), "black")

    def test_byte_order_tracks_selected_metric_with_stable_ties(self):
        ns, plt = self.ns, self.plt
        orders = []
        for metric in ("original_frame_bytes", "ip_packet_bytes"):
            with self.subTest(metric=metric), patch.object(plt, "show"):
                ns["BYTE_METRIC"] = metric
                self.run_cell(4)
                self.run_cell(6)
                expected = ["overall_ipv4", *sorted(
                    ns["prefix_order"], key=lambda p: -ns["totals"].loc[p, metric])]
                self.assertEqual(ns["byte_shares"].index.tolist(), expected)
                self.assertEqual(ns["plot_byte_scope_order"], expected)
                self.assertEqual(ns["packet_shares"].index.tolist(), ns["plot_scope_order"])
                self.assertNotEqual(expected, ns["plot_scope_order"])
                first, second = ns["prefix_order"][1:3]
                self.assertLess(expected.index(first), expected.index(second))
                orders.append(expected)
        self.assertNotEqual(*orders)

    def test_overview_order_and_ranking_selection_is_unchanged(self):
        ns, plt = self.ns, self.plt
        with patch.object(plt, "show") as show:
            for cell in (6, 8, 10, 12):
                self.run_cell(cell)
        self.assertEqual(show.call_count, 5)
        for name in ("packet_shares", "heatmap_shares"):
            self.assertEqual(ns[name].index.tolist(), ns["plot_scope_order"])
        self.assertEqual(ns["byte_shares"].index.tolist(), ns["plot_byte_scope_order"])
        self.assertEqual(ns["plot_comparison"].index.tolist(), ns["plot_prefix_order"])
        ranked = ns["non_tcp_ratios"]["packet_count"].reindex(ns["prefix_order"]).dropna().sort_values(
            ascending=False, kind="stable")
        chosen = set(ranked.head(ns["DETAIL_TOP_N"]).index)
        self.assertEqual(ns["detail_prefixes"], [p for p in ns["prefix_order"] if p in chosen])
