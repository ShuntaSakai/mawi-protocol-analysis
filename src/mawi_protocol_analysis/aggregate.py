"""Count packets in the MAWI observation window and reconcile the outputs."""

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone

from .pcap import PcapReader
from .prefixes import PrefixMatcher, PrefixSelection
from .protocols import Classification, classify_ethernet, classify_ethernet_with_endpoints

JST = timezone(timedelta(hours=9), "JST")
START = datetime(2026, 4, 8, 14, tzinfo=JST)
DURATION_SECONDS = 900
INTERVAL_SECONDS = 60
INTERVAL_COUNT = DURATION_SECONDS // INTERVAL_SECONDS
END = START + timedelta(seconds=DURATION_SECONDS)
TRACE_ID = START.strftime("%Y%m%d%H%M")
START_EPOCH = int(START.timestamp())
END_EPOCH = START_EPOCH + DURATION_SECONDS
TRACE_INFO = "https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.html"

Group = tuple[str, int | None]


@dataclass(slots=True)
class Totals:
    packet_count: int = 0
    original_frame_bytes: int = 0
    ip_packet_bytes: int = 0
    ip_length_known_packets: int = 0
    ip_length_unavailable_packets: int = 0
    fragment_packets: int = 0
    truncated_capture_packets: int = 0
    invalid_or_missing_header_packets: int = 0

    def count(self, packet: Classification, original: int, truncated: bool) -> None:
        self.packet_count += 1
        self.original_frame_bytes += original
        if packet.ip_bytes is not None:
            self.ip_packet_bytes += packet.ip_bytes
            self.ip_length_known_packets += 1
        elif packet.kind != "non_ip":
            self.ip_length_unavailable_packets += 1
        self.fragment_packets += packet.fragment
        self.truncated_capture_packets += truncated
        self.invalid_or_missing_header_packets += packet.header_issue is not None

    def merge(self, other: "Totals") -> None:
        for name in COUNTER_FIELDS:
            setattr(self, name, getattr(self, name) + getattr(other, name))


COUNTER_FIELDS = tuple(field.name for field in fields(Totals))


def ratio(value: int, denominator: int) -> float | None:
    return value / denominator if denominator else None


def rates_and_means(totals: Totals) -> dict:
    return {
        "mean_original_frame_size": ratio(totals.original_frame_bytes, totals.packet_count),
        "mean_ip_packet_size": ratio(totals.ip_packet_bytes, totals.ip_length_known_packets),
        "packets_per_second": totals.packet_count / DURATION_SECONDS,
        "original_frame_bytes_per_second": totals.original_frame_bytes / DURATION_SECONDS,
        "ip_packet_bytes_per_second": totals.ip_packet_bytes / DURATION_SECONDS,
    }


def interval(index: int) -> dict:
    start = START + timedelta(seconds=index * INTERVAL_SECONDS)
    return {
        "interval_start_jst": start.isoformat(),
        "interval_end_jst": (start + timedelta(seconds=INTERVAL_SECONDS)).isoformat(),
    }


def window() -> dict:
    return {"start_jst": START.isoformat(), "end_jst": END.isoformat(),
            "duration_seconds": DURATION_SECONDS, "interval_seconds": INTERVAL_SECONDS,
            "interval_count": INTERVAL_COUNT, "boundary": "[start, end)"}


class Analysis:
    def __init__(self) -> None:
        self.groups: dict[Group, Totals] = defaultdict(Totals)
        self.bins: list[dict[Group, Totals]] = [defaultdict(Totals) for _ in range(INTERVAL_COUNT)]
        self.overall = Totals()
        self.records_read = 0
        self.outside = 0
        self.invalid_records: Counter[str] = Counter()
        self.protocol_issues: Counter[str] = Counter()
        self.length_issues: Counter[str] = Counter()
        self.header_issues: Counter[str] = Counter()

    def count(self, packet: Classification, orig: int, truncated: bool, minute: int) -> None:
        key = (packet.kind, packet.number)
        self.groups[key].count(packet, orig, truncated)
        self.bins[minute][key].count(packet, orig, truncated)
        # An independent total catches dropped or doubled protocol groups.
        self.overall.count(packet, orig, truncated)
        if packet.protocol_issue:
            self.protocol_issues[packet.protocol_issue] += 1
        if packet.length_issue:
            self.length_issues[packet.length_issue] += 1
        if packet.header_issue:
            self.header_issues[packet.header_issue] += 1

    def populations(self) -> dict[str, Totals]:
        result = {"overall": self.overall, "ipv4": Totals(), "ipv6": Totals(),
                  "non_ip": Totals(), "unknown": Totals()}
        for (category, _), total in self.groups.items():
            result[category].merge(total)
        return result

    def validate(self) -> None:
        rolled_up: dict[Group, Totals] = defaultdict(Totals)
        for minute in self.bins:
            for key, total in minute.items():
                rolled_up[key].merge(total)
        if rolled_up != self.groups:
            raise ValueError("inconsistent per-protocol and time series counters")

        group_total = Totals()
        unclassifiable = 0
        for (kind, number), total in self.groups.items():
            accounted_lengths = total.ip_length_known_packets + total.ip_length_unavailable_packets
            expected_lengths = 0 if kind == "non_ip" else total.packet_count
            if accounted_lengths != expected_lengths:
                raise ValueError("inconsistent IP length coverage")
            if kind != "non_ip" and number is None:
                unclassifiable += total.packet_count
            group_total.merge(total)
        if group_total != self.overall:
            raise ValueError("inconsistent overall and per-protocol counters")
        if self.records_read != group_total.packet_count + self.outside + self.invalid_records.total():
            raise ValueError("inconsistent included and excluded record counts")
        if (
            self.protocol_issues.total() != unclassifiable
            or self.length_issues.total() != group_total.ip_length_unavailable_packets
            or self.header_issues.total() != group_total.invalid_or_missing_header_packets
        ):
            raise ValueError("inconsistent parse issue counts")

    def summary(self, populations: dict[str, Totals]) -> dict:
        transport: Counter[int] = Counter()
        unknown_ip_protocol = non_tcp_udp = 0
        for (kind, number), total in self.groups.items():
            if kind not in ("ipv4", "ipv6"):
                continue
            if number is None:
                unknown_ip_protocol += total.packet_count
            elif number in (6, 17):
                transport[number] += total.packet_count
            else:
                non_tcp_udp += total.packet_count

        return {
            "analysis_window": window(),
            "intervals": [interval(index) for index in range(INTERVAL_COUNT)],
            "records_read": self.records_read,
            "included_packets": self.overall.packet_count,
            "out_of_window_records": self.outside,
            "invalid_records": self.invalid_records.total(),
            "invalid_record_reasons": dict(self.invalid_records),
            "ipv4_packets": populations["ipv4"].packet_count,
            "ipv6_packets": populations["ipv6"].packet_count,
            "non_ip_packets": populations["non_ip"].packet_count,
            "unknown_version_packets": populations["unknown"].packet_count,
            "unclassifiable_packets": populations["unknown"].packet_count + unknown_ip_protocol,
            "ip_protocol_indeterminate_packets": unknown_ip_protocol,
            "tcp_packets": transport[6],
            "udp_packets": transport[17],
            "non_tcp_udp_packets": non_tcp_udp,
            "fragment_packets": self.overall.fragment_packets,
            "truncated_capture_packets": self.overall.truncated_capture_packets,
            "invalid_or_missing_header_packets": self.overall.invalid_or_missing_header_packets,
            "ip_length_unavailable_packets": self.overall.ip_length_unavailable_packets,
            "protocol_issue_reasons": dict(self.protocol_issues),
            "ip_length_issue_reasons": dict(self.length_issues),
            "header_issue_reasons": dict(self.header_issues),
            "populations": {
                name: asdict(total) | rates_and_means(total)
                for name, total in populations.items()
            },
        }


class PrefixAnalysis:
    """Bounded counters for native populations and their deduplicated union."""

    def __init__(self, selection: PrefixSelection):
        self.selection = selection
        self.matcher = PrefixMatcher(selection)
        self.prefix_ids = tuple(str(network) for network in selection.networks)
        self.scopes = {name: Analysis() for name in
                       ("overall_ipv4", *self.prefix_ids, "selected_union")}
        self.address_unavailable = Totals()

    def count(self, packet: Classification, src: int | None, dst: int | None,
              orig: int, truncated: bool, minute: int) -> None:
        if packet.kind != "ipv4":
            return
        self._count_scope("overall_ipv4", packet, orig, truncated, minute)
        if src is None or dst is None:
            self.address_unavailable.count(packet, orig, truncated)
        matches = self.matcher.match(src, dst)
        if matches:
            self._count_scope("selected_union", packet, orig, truncated, minute)
        while matches:
            bit = matches & -matches
            self._count_scope(self.prefix_ids[bit.bit_length() - 1], packet, orig, truncated, minute)
            matches ^= bit

    def _count_scope(self, name, packet, orig, truncated, minute):
        scope = self.scopes[name]
        scope.records_read += 1
        scope.count(packet, orig, truncated, minute)

    def validate(self, overall: Analysis) -> None:
        for scope in self.scopes.values():
            scope.validate()
        ipv4 = self.scopes["overall_ipv4"]
        if ipv4.overall != overall.populations()["ipv4"]:
            raise ValueError("prefix Overall IPv4 differs from existing Overall analysis")
        if ipv4.groups != {key: total for key, total in overall.groups.items() if key[0] == "ipv4"}:
            raise ValueError("prefix Overall IPv4 protocol counters differ")
        union = self.scopes["selected_union"].overall
        for name in self.prefix_ids:
            for field in COUNTER_FIELDS:
                if not getattr(self.scopes[name].overall, field) <= getattr(union, field) <= getattr(ipv4.overall, field):
                    raise ValueError("prefix/union/Overall containment totals differ")


def analyze(reader: PcapReader, *, prefixes: PrefixAnalysis | None = None) -> Analysis:
    result = Analysis()
    fcs_bytes = reader.header.declared_fcs_bytes or 0
    for sec, incl, orig, data, issue in reader:
        result.records_read += 1
        if issue:
            result.invalid_records[issue] += 1
            continue
        if not START_EPOCH <= sec < END_EPOCH:
            result.outside += 1
            continue

        minute = (sec - START_EPOCH) // INTERVAL_SECONDS
        if prefixes is None:
            packet = classify_ethernet(data, orig, fcs_bytes)
        else:
            packet, src, dst = classify_ethernet_with_endpoints(data, orig, fcs_bytes)
        truncated = incl < orig
        result.count(packet, orig, truncated, minute)
        if prefixes is not None:
            prefixes.count(packet, src, dst, orig, truncated, minute)
    result.validate()
    if prefixes is not None:
        prefixes.validate(result)
    return result
