"""Run the analysis and write reproducible CSV and JSON results."""

import argparse
import csv
import hashlib
import json
import platform
import sys
import subprocess
import zlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from . import __version__
from .aggregate import (
    COUNTER_FIELDS, INTERVAL_COUNT, TRACE_ID, TRACE_INFO, Analysis, Group, Totals,
    PrefixAnalysis, analyze, interval, rates_and_means, ratio, window,
)
from .pcap import MAX_CAPTURED_LENGTH, Header, PcapReader, open_capture, open_hashed_capture
from .prefixes import load_prefixes, sha256_file
from .protocols import PROTOCOL_NAMES

_GROUP_FIELDS = ("category", "ip_version", "protocol_number", "protocol_name")
_FRACTIONS = ("packet_ratio", "original_frame_byte_ratio", "ip_packet_byte_ratio")
_SCOPE_FIELDS = ("scope_order", "scope", "prefix")


def _protocol_category(number):
    return {6: "tcp", 17: "udp", None: "indeterminate"}.get(number, "non_tcp_udp")


def _scope_summary(scope: Analysis) -> dict:
    total = scope.overall
    categories = {name: Totals() for name in ("tcp", "udp", "non_tcp_udp", "indeterminate")}
    for (_, number), value in scope.groups.items():
        categories[_protocol_category(number)].merge(value)
    return asdict(total) | rates_and_means(total) | {
        f"{name}_{field}": getattr(value, field)
        for name, value in categories.items()
        for field in COUNTER_FIELDS
    } | {
        f"{name}_{field}": value
        for name, totals in categories.items()
        for field, value in zip(_FRACTIONS, _ratios(totals, total))
    }


def _write_prefix_tables(stage: Path, prefixes: PrefixAnalysis, result: Analysis) -> dict:
    selection = prefixes.selection
    with (stage / "selected_prefixes.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("prefix_order", "prefix", "analysis_scope", "source_row"))
        writer.writerows((i, str(n), "native", row) for i, (n, row) in
                         enumerate(zip(selection.networks, selection.source_rows), 1))
    summaries = {name: _scope_summary(scope) for name, scope in prefixes.scopes.items()}
    with (stage / "prefix_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow((*_SCOPE_FIELDS, *next(iter(summaries.values()))))
        for order, (name, values) in enumerate(summaries.items()):
            writer.writerow((order, name, name if name in prefixes.prefix_ids else "", *values.values()))
    # All numbers observed in Overall IPv4 are retained, including unknown numbers.
    keys = sorted(prefixes.scopes["overall_ipv4"].groups, key=lambda k: -1 if k[1] is None else k[1])
    protocol_fields = ("protocol_number", "protocol_name", "protocol_category")
    empty = Totals()
    for filename, time_series in (("prefix_protocol_counts.csv", False),
                                  ("prefix_protocol_timeseries_60s.csv", True)):
        with (stage / filename).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow((*_SCOPE_FIELDS, *(interval(0) if time_series else ()),
                             *protocol_fields, *COUNTER_FIELDS, *_FRACTIONS))
            for order, (name, scope) in enumerate(prefixes.scopes.items()):
                for index, groups in enumerate(scope.bins if time_series else [scope.groups]):
                    denominator = Totals()
                    for value in groups.values():
                        denominator.merge(value)
                    for key in keys:
                        total = groups.get(key, empty)
                        _, _, number, label = _group_fields(key)
                        writer.writerow((order, name, name if name in prefixes.prefix_ids else "",
                                         *(interval(index).values() if time_series else ()),
                                         number, label, _protocol_category(number),
                                         *asdict(total).values(), *_ratios(total, denominator)))
    return {
        "schema_version": 2, "analysis_window": window(),
        "intervals": [interval(i) for i in range(INTERVAL_COUNT)],
        "scope_order": list(prefixes.scopes), "populations": summaries,
        "address_unavailable_ipv4": asdict(prefixes.address_unavailable),
        "issue_reasons_by_scope": {
            name: {"protocol": dict(scope.protocol_issues), "ip_length": dict(scope.length_issues),
                   "header": dict(scope.header_issues)} for name, scope in prefixes.scopes.items()
        },
        "overall_analysis": result.summary(result.populations()),
    }


def _source_evidence(args, selection) -> dict:
    evidence = {"historical_selection_verification": "pending_external_audit",
                "native_origin": "declared_by_external_ledger_provider",
                "order": "selected CSV row order; historical Notebook order pending audit",
                "prefixes_csv": {"path": str(selection.source), "sha256": selection.sha256}}
    for name, path in (("manifest", args.selection_manifest), ("config", args.selection_config),
                       ("membership_csv", args.selection_membership)):
        if path is None:
            evidence[name] = None
            continue
        entry = {"path": str(path.absolute()), "sha256": sha256_file(path)}
        if name == "manifest":
            entry["content"] = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(entry["content"], dict):
                raise ValueError("selection manifest must be a JSON object")
            if entry["content"].get("status") != "success":
                raise ValueError("selection source run must have status=success")
            for key in ("input", "config"):
                if entry["content"].get(key) is not None and not isinstance(entry["content"][key], dict):
                    raise ValueError(f"selection manifest {key} must be an object")
        elif name == "config":
            entry["text"] = path.read_text(encoding="utf-8")
        evidence[name] = entry
    saved = (evidence.get("manifest") or {}).get("content", {}).get("config") or {}
    if evidence.get("config") and saved.get("text") is not None and saved["text"] != evidence["config"]["text"]:
        raise ValueError("selection config differs from saved manifest config text")
    return evidence


def _prefix_manifest(base, prefixes, evidence, file_hash, pcap_hash, expected_count):
    base["schema_version"] = 2
    base["scope"] = "Overall IPv4, fixed native prefixes, and deduplicated selected_union; no scan removal"
    base["input"].update(sha256=file_hash, decompressed_pcap_sha256=pcap_hash)
    source_input = (evidence.get("manifest") or {}).get("content", {}).get("input") or {}
    expected_hash = source_input.get("sha256")
    if expected_hash:
        if expected_hash not in (file_hash, pcap_hash):
            raise ValueError("selection source input SHA-256 differs from analyzed PCAP")
        evidence["input_identity"] = "matching_file_bytes" if expected_hash == file_hash else "matching_decompressed_pcap_bytes"
    else:
        evidence["input_identity"] = "pending_source_input_hash"
    config = {"prefixes": list(prefixes.prefix_ids), "expected_prefix_count": expected_count,
              "membership": "src_ip in prefix OR dst_ip in prefix", "analysis_scope": "native",
              "selected_union": True, "scan_removal": False, "analysis_window": window()}
    text = json.dumps(config, sort_keys=True, separators=(",", ":"))
    base["configuration"] = {"content": config, "canonical_json": text,
                             "sha256": hashlib.sha256(text.encode()).hexdigest()}
    base["prefix_selection"] = evidence | {"overlaps": prefixes.selection.overlaps()}
    base["metrics"].update(
        prefix_ratios="All IPv4 packets or corresponding bytes within each scope, including indeterminate protocols",
        membership="Observed complete outer IPv4 base header with valid IHL; unavailable endpoints never matched",
        selected_union="Count once when either endpoint matches any selected prefix; never sum prefix counters",
    )
    package = Path(__file__).resolve().parent
    root = package.parents[1]
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                    capture_output=True, text=True, check=True).stdout)
    except (OSError, subprocess.CalledProcessError):
        commit, dirty = None, None
    base["program"].update(git_commit=commit, dirty=dirty, source_sha256={
        p.name: sha256_file(p) for p in sorted(package.glob("*.py"))})
    return base


def _group_fields(key: Group) -> tuple:
    kind, number = key
    version = {"ipv4": 4, "ipv6": 6}.get(kind)
    if number in (4, 41):
        name = f"{PROTOCOL_NAMES[number]}-in-IPv{version}"
    elif number is not None:
        name = PROTOCOL_NAMES.get(number, f"Protocol {number}")
    else:
        name = "Non-IP" if kind == "non_ip" else "Indeterminate"
    return kind, version, number, name


def _ratios(total: Totals, denominator: Totals) -> tuple:
    return (
        ratio(total.packet_count, denominator.packet_count),
        ratio(total.original_frame_bytes, denominator.original_frame_bytes),
        ratio(total.ip_packet_bytes, denominator.ip_packet_bytes),
    )


def _write_counts(path: Path, result: Analysis, keys: list[Group], populations: dict[str, Totals]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            (*_GROUP_FIELDS, *COUNTER_FIELDS,
             *(f"{field}_overall" for field in _FRACTIONS),
             *(f"{field}_ip_version" for field in _FRACTIONS),
             *rates_and_means(result.overall))
        )
        for key in keys:
            total = result.groups[key]
            within_version = _ratios(total, populations[key[0]]) if key[0] in ("ipv4", "ipv6") else (None,) * 3
            writer.writerow(
                (*_group_fields(key), *asdict(total).values(), *_ratios(total, result.overall),
                 *within_version, *rates_and_means(total).values())
            )


def _write_timeseries(path: Path, result: Analysis, keys: list[Group]) -> None:
    empty = Totals()
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow((*interval(0), *_GROUP_FIELDS, *COUNTER_FIELDS))
        for index, bins in enumerate(result.bins):
            times = interval(index)
            for key in keys:
                writer.writerow((*times.values(), *_group_fields(key), *asdict(bins.get(key, empty)).values()))


def _manifest(source: Path, header: Header, size: int, mtime_ns: int) -> dict:
    compressed = source.suffix.lower() == ".gz"
    return {
        "schema_version": 1,
        "program": {"name": "mawi-protocol-analysis", "version": __version__},
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "libraries": {"stdlib (struct, datetime, gzip, csv, json)": platform.python_version(),
                          **({"zlib": zlib.ZLIB_RUNTIME_VERSION} if compressed else {})},
        },
        "dataset": {"name": "MAWI Traffic Archive", "samplepoint": "Samplepoint-F",
                    "trace_id": TRACE_ID, "published_statistics": TRACE_INFO},
        "input": {
            "path": str(source),
            "size_bytes": size,
            "mtime_ns": mtime_ns,
            "mtime_utc": datetime.fromtimestamp(mtime_ns / 1_000_000_000, timezone.utc).isoformat(),
            "compression": "gzip" if compressed else None,
        },
        "pcap": asdict(header) | {
            "format": "classic PCAP", "max_supported_incl_len": MAX_CAPTURED_LENGTH,
            "timestamp_basis": "Unix epoch (UTC); fractional field validated; integer seconds suffice for exact minute boundaries",
            "record_error_policy": (
                "Exclude complete invalid records before window filtering; one reason per record "
                "(timestamp fraction, incl_len > snaplen, orig_len < incl_len, zero orig_len). "
                "Abort on incomplete record header/payload or an incl_len above the supported limit."
            ),
        },
        "analysis_window": window(),
        "scope": "Overall: all valid records in the time window, without prefix filtering",
        "classification": {
            "link_layer": "Ethernet II; VLAN tags with TPID 0x8100, 0x88A8 or 0x9100; no tunnel decapsulation",
            "ipv4": "Outer IPv4 Protocol field, including in fragments",
            "ipv6": (
                "Follow Hop-by-Hop, Routing, Destination Options, Fragment and AH. Stop at ESP or "
                "another terminal number. A captured terminal Next Header is classified even if its "
                "containing extension is truncated; retain the header issue separately. Reject known "
                "invalid extension lengths; do not infer a terminal protocol from an incomplete chain. "
                "For non-initial fragments only use an explicitly identified "
                "terminal protocol; do not parse fragment contents as extension headers."
            ),
            "fragments": "IPv4 MF or nonzero offset; IPv6 Fragment header with M or nonzero offset. No reassembly.",
            "protocol_registry": "https://www.iana.org/assignments/protocol-numbers/",
            "unmapped_numbers": "Preserve the numeric value and label it Protocol N",
            "non_tcp_udp": "Classified IPv4/IPv6 with a protocol number other than 6 or 17",
            "unclassifiable": "Unknown link/IP version or known IP version with indeterminate protocol",
        },
        "byte_definitions": {
            "original_frame_bytes": (
                "Sum of PCAP record orig_len, including the Ethernet and VLAN headers. FCS presence "
                "depends on capture metadata. This is not total physical wire traffic."
            ),
            "ip_packet_bytes": (
                "Sum of valid outer IPv4 Total Length or IPv6 40 + Payload Length, including IP headers. "
                "Validate against orig_len minus the parsed link header and any declared FCS. "
                "IPv6 jumbogram candidates are unavailable; non-IP does not have an IP length."
            ),
        },
        "metrics": {
            "overall_ratios": "Group count/bytes divided by all included packets/the matching byte total",
            "ip_version_ratios": "Same ratios within IPv4 or IPv6, including IP with indeterminate protocol",
            "ip_byte_ratio_denominator": "Sum over packets with a known IP packet length in the population",
            "mean_original_frame_size_denominator": "All packets in the group or population",
            "mean_ip_packet_size_denominator": "ip_length_known_packets in the group or population",
            "rates": "Counts or matching byte totals divided by the full 900-second analysis window",
            "undefined_values": "Empty CSV cell or JSON null for a zero denominator",
            "time_series": f"{INTERVAL_COUNT} one-minute bins for each observed group; all boundaries in summary.json",
        },
    }


def _write_outputs(destination: Path, result: Analysis, manifest: dict,
                   prefixes: PrefixAnalysis | None = None) -> None:
    keys = sorted(result.groups, key=lambda key: (key[0], -1 if key[1] is None else key[1]))
    populations = result.populations()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".mawi-", dir=destination.parent) as scratch:
        stage = Path(scratch) / TRACE_ID
        stage.mkdir()
        if prefixes is None:
            _write_counts(stage / "protocol_counts.csv", result, keys, populations)
            _write_timeseries(stage / "protocol_timeseries_60s.csv", result, keys)
            summary = result.summary(populations)
        else:
            summary = _write_prefix_tables(stage, prefixes, result)
            manifest["output_sha256"] = {p.name: sha256_file(p) for p in sorted(stage.glob("*.csv"))}
        for name, value in (("summary", summary), ("manifest", manifest)):
            with (stage / f"{name}.json").open("w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
        # Publish the complete set together. The rename fails if another run
        # has already published a nonempty destination on this filesystem.
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"output directory already exists: {destination}")
        stage.rename(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze MAWI Samplepoint-F, 2026-04-08 14:00–14:15 JST")
    parser.add_argument("pcap", type=Path, help="classic Ethernet PCAP file (.pcap or .pcap.gz)")
    parser.add_argument("--output-root", type=Path, default=Path("results"),
                        help=f"write under ROOT/{TRACE_ID}; Prefix mode uses a separate subdirectory (default: results)")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--prefixes", type=Path, help="externally selected native IPv4 ledger; no selection is performed")
    parser.add_argument("--expected-prefix-count", type=int, default=18)
    parser.add_argument("--selection-manifest", type=Path, help="historical run_manifest.json, if available")
    parser.add_argument("--selection-config", type=Path, help="historical config, if available")
    parser.add_argument("--selection-membership", type=Path, help="historical flow_prefix_membership.csv, hashed only")
    args = parser.parse_args(argv)
    try:
        output = args.output_root / TRACE_ID
        if args.prefixes is not None:
            output /= "prefix_protocol_distribution"
        elif any((args.selection_manifest, args.selection_config, args.selection_membership)) or args.expected_prefix_count != 18:
            raise ValueError("selection options require --prefixes")
        if output.exists() or output.is_symlink():
            raise ValueError(f"output directory already exists: {output}; use --output-root to choose another")
        # Keep the given filename's suffix for opening it even when it is a symlink.
        source = args.pcap.absolute()
        before = source.stat()
        if not source.is_file():
            raise ValueError("input must be a regular file")
        prefixes = PrefixAnalysis(load_prefixes(args.prefixes, args.expected_prefix_count)) if args.prefixes else None
        evidence = _source_evidence(args, prefixes.selection) if prefixes is not None else None
        if prefixes is None:
            with open_capture(source) as stream:
                reader = PcapReader(stream)
                result = analyze(reader)
        else:
            with open_hashed_capture(source) as (stream, file_hash, pcap_hash):
                reader = PcapReader(stream)
                result = analyze(reader, prefixes=prefixes)
        after = source.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("input file changed during analysis")
        manifest = _manifest(source, reader.header, before.st_size, before.st_mtime_ns)
        if prefixes is not None:
            manifest = _prefix_manifest(manifest, prefixes, evidence, file_hash.hexdigest(),
                                        pcap_hash.hexdigest(), args.expected_prefix_count)
        _write_outputs(output, result, manifest, prefixes)
    except (OSError, ValueError, EOFError, zlib.error) as exc:
        print(f"mawi-protocol-analysis: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0
