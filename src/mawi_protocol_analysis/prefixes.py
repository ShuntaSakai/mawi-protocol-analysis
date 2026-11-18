"""Read an externally selected native ledger; never select or normalize CIDRs."""

import csv
import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Network
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class PrefixSelection:
    networks: tuple[IPv4Network, ...]
    source: Path
    sha256: str
    source_rows: tuple[int, ...]

    def overlaps(self) -> list[dict]:
        return [
            {"first": str(first), "second": str(second), "relationship": "containment"}
            for index, first in enumerate(self.networks)
            for second in self.networks[index + 1:]
            if first.overlaps(second)
        ]


def load_prefixes(path: Path, expected_count: int = 18) -> PrefixSelection:
    """Preserve selected file-row order, rejecting duplicate/noncanonical CIDRs.

    Accept the global-analysis prefixes.csv (including unselected rows), or a
    fixed external ledger with a prefix column. Native origin is an external
    assertion until the historical run and notebook have been audited.
    """
    if expected_count < 1:
        raise ValueError("expected prefix count must be positive")
    raw = path.read_bytes()
    reader = csv.DictReader(raw.decode("utf-8-sig").splitlines())
    if not reader.fieldnames or "prefix" not in reader.fieldnames:
        raise ValueError("prefix ledger requires a prefix column")
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("duplicate prefix ledger columns")
    networks, rows = [], []
    for line, row in enumerate(reader, 2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"malformed prefix ledger row {line}")
        if "selected_for_analysis" in row:
            flag = row["selected_for_analysis"].strip().lower()
            if flag not in {"true", "false", "1", "0"}:
                raise ValueError(f"invalid selected_for_analysis at row {line}")
            if flag in {"false", "0"}:
                continue
        if "analysis_scope" in row and row["analysis_scope"] != "native":
            raise ValueError(f"selected row {line} is not native")
        value = row["prefix"]
        network = IPv4Network(value, strict=True)
        if str(network) != value or network.prefixlen < 24:
            raise ValueError(f"expected canonical native IPv4 /24 or longer at row {line}: {value}")
        if network in networks:
            raise ValueError(f"duplicate selected prefix: {value}")
        networks.append(network)
        rows.append(line)
    if len(networks) != expected_count:
        raise ValueError(f"expected {expected_count} selected prefixes, found {len(networks)}")
    return PrefixSelection(tuple(networks), path.absolute(), hashlib.sha256(raw).hexdigest(), tuple(rows))


class PrefixMatcher:
    """Integer masks indexed by prefix length; memory bounded by the selection."""

    def __init__(self, selection: PrefixSelection):
        self.by_mask: dict[int, dict[int, int]] = {}
        for index, network in enumerate(selection.networks):
            self.by_mask.setdefault(int(network.netmask), {})[int(network.network_address)] = 1 << index

    def match(self, src: int | None, dst: int | None) -> int:
        # Bitwise OR deduplicates src/dst and preserves cross-prefix membership.
        matches = 0
        for mask, networks in self.by_mask.items():
            if src is not None:
                matches |= networks.get(src & mask, 0)
            if dst is not None:
                matches |= networks.get(dst & mask, 0)
        return matches
