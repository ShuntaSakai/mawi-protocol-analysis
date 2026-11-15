"""Run the analysis and write reproducible CSV and JSON results."""

import argparse
import csv
import json
import platform
import sys
import zlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from . import __version__
from .aggregate import (
    COUNTER_FIELDS, INTERVAL_COUNT, TRACE_ID, TRACE_INFO, Analysis, Group, Totals,
    analyze, interval, rates_and_means, ratio, window,
)
from .pcap import MAX_CAPTURED_LENGTH, Header, PcapReader, open_capture
from .protocols import PROTOCOL_NAMES

_GROUP_FIELDS = ("category", "ip_version", "protocol_number", "protocol_name")
_FRACTIONS = ("packet_ratio", "original_frame_byte_ratio", "ip_packet_byte_ratio")


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
                "another terminal number. For non-initial fragments only use an explicitly identified "
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


def _write_outputs(destination: Path, result: Analysis, manifest: dict) -> None:
    keys = sorted(result.groups, key=lambda key: (key[0], -1 if key[1] is None else key[1]))
    populations = result.populations()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".mawi-", dir=destination.parent) as scratch:
        stage = Path(scratch) / TRACE_ID
        stage.mkdir()
        _write_counts(stage / "protocol_counts.csv", result, keys, populations)
        _write_timeseries(stage / "protocol_timeseries_60s.csv", result, keys)
        for name, value in (("summary", result.summary(populations)), ("manifest", manifest)):
            with (stage / f"{name}.json").open("w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
        # Publish the complete set together. The rename fails if another run
        # has already published a nonempty destination on this filesystem.
        stage.rename(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze MAWI Samplepoint-F, 2026-04-08 14:00–14:15 JST")
    parser.add_argument("pcap", type=Path, help="classic Ethernet PCAP file (.pcap or .pcap.gz)")
    parser.add_argument("--output-root", type=Path, default=Path("results"),
                        help=f"write the four output files under ROOT/{TRACE_ID} (default: results)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        output = args.output_root / TRACE_ID
        if output.exists() or output.is_symlink():
            raise ValueError(f"output directory already exists: {output}; use --output-root to choose another")
        # Keep the given filename's suffix for opening it even when it is a symlink.
        source = args.pcap.absolute()
        before = source.stat()
        if not source.is_file():
            raise ValueError("input must be a regular file")
        with open_capture(source) as stream:
            reader = PcapReader(stream)
            result = analyze(reader)
        after = source.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("input file changed during analysis")
        _write_outputs(output, result, _manifest(source, reader.header, before.st_size, before.st_mtime_ns))
    except (OSError, ValueError, EOFError, zlib.error) as exc:
        print(f"mawi-protocol-analysis: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0
