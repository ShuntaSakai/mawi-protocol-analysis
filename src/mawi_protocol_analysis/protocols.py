"""Classify the outer IP header in an Ethernet frame, without decoding payloads."""

from typing import NamedTuple


# Common names from https://www.iana.org/assignments/protocol-numbers/
PROTOCOL_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 9: "IGP",
    17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag",
    46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 58: "IPv6-ICMP",
    59: "IPv6-NoNxt", 60: "IPv6-Opts", 89: "OSPFIGP", 97: "ETHERIP", 103: "PIM",
    112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLite",
}
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_IPV6_EXTENSIONS = {0, 43, 44, 51, 60}
# IANA extension types that this parser does not traverse.
_UNSUPPORTED_IPV6_EXTENSIONS = {135, 139, 140, 253, 254}


class Classification(NamedTuple):
    kind: str # "ipv4" or "ipv6" or "non_ip" or "unknown"
    number: int | None = None # IPプロトコル番号（TCPなら6, UDPなら17）
    ip_bytes: int | None = None # IPヘッダを含むIPパケット長
    fragment: bool = False # 分割されたパケットだと確認できた場合はTrue
    protocol_issue: str | None = None # IPプロトコル番号が不明な場合の理由
    length_issue: str | None = None # IPパケット長が不正な場合の理由
    header_issue: str | None = None # IPヘッダに問題がある場合の理由


def _missing(kind: str, reason: str) -> Classification:
    return Classification(kind, protocol_issue=reason, length_issue=reason, header_issue=reason)


def classify_ethernet(data: bytes, orig_len: int, fcs_bytes: int = 0) -> Classification:
    frame_end = orig_len - fcs_bytes
    captured_end = min(len(data), frame_end)
    # 最低14バイトのEthernetヘッダが必要
    if captured_end < 14:
        return _missing("unknown", "ethernet_truncated_header")
    ethertype = (data[12] << 8) | data[13]
    start = 14
    while ethertype in _VLAN_TYPES:
        if captured_end < start + 4:
            return _missing("unknown", "ethernet_truncated_vlan")
        ethertype = (data[start + 2] << 8) | data[start + 3]
        start += 4

    if ethertype not in (0x0800, 0x86DD):
        # An 802.3 length field may be followed by LLC/SNAP, which can carry IP.
        if ethertype < 1536:
            reason = "ethernet_unsupported_802_3" if ethertype <= 1500 else "ethernet_invalid_type"
            if ethertype <= 1500:
                return Classification("unknown", protocol_issue=reason, length_issue=reason)
            return _missing("unknown", reason)
        return Classification("non_ip")

    version = 4 if ethertype == 0x0800 else 6
    if captured_end <= start:
        return _missing("unknown", "missing_ip_version")
    if data[start] >> 4 != version:
        return _missing("unknown", "ip_version_ethertype_mismatch")
    if version == 4:
        return _ipv4(data, start, captured_end, frame_end)
    return _ipv6(data, start, captured_end, frame_end)


def _ipv4(data: bytes, start: int, captured_end: int, frame_end: int) -> Classification:
    if captured_end < start + 20:
        return _missing("ipv4", "ipv4_truncated_base_header")
    ihl = (data[start] & 0x0F) * 4
    if ihl < 20:
        return _missing("ipv4", "ipv4_invalid_ihl")

    length = (data[start + 2] << 8) | data[start + 3]
    fragment = bool(((data[start + 6] << 8) | data[start + 7]) & 0x3FFF)
    number = data[start + 9]
    if not ihl <= length <= frame_end - start:
        reason = "ipv4_invalid_total_length"
        return Classification("ipv4", number, fragment=fragment, length_issue=reason, header_issue=reason)
    header_issue = "ipv4_truncated_options" if captured_end < start + ihl else None
    return Classification("ipv4", number, length, fragment, header_issue=header_issue)


def _ipv6(data: bytes, start: int, captured_end: int, frame_end: int) -> Classification:
    offset = start + 40
    if captured_end < offset:
        return _missing("ipv6", "ipv6_truncated_base_header")
    payload_length = (data[start + 4] << 8) | data[start + 5]
    number = data[start + 6]
    end = offset + payload_length
    length = 40 + payload_length
    length_issue = None
    if payload_length == 0 and number == 0:
        # The 16-bit field alone cannot establish a jumbogram's actual length.
        reason = "ipv6_jumbo_unsupported"
        return Classification("ipv6", protocol_issue=reason, length_issue=reason)
    if end > frame_end:
        length_issue = "ipv6_length_exceeds_original_frame"
    elif payload_length == 0 and number != 59:
        length_issue = "ipv6_invalid_zero_payload_length"
    if length_issue:
        length = None
    end = min(end, frame_end)

    fragment = False
    seen_fragment_header = False
    protocol_issue = None
    header_issue = length_issue

    while number in _IPV6_EXTENSIONS:
        minimum = 12 if number == 51 else 8
        if offset + minimum > end:
            protocol_issue = header_issue = "ipv6_invalid_extension_length"
            break
        if offset >= captured_end:
            protocol_issue = header_issue = "ipv6_truncated_extension"
            break
        following = data[offset]

        if number == 44:
            if seen_fragment_header:
                protocol_issue = header_issue = "ipv6_repeated_fragment_header"
                break
            seen_fragment_header = True
            non_initial = False
            if offset + 4 <= captured_end:
                fragment_field = (data[offset + 2] << 8) | data[offset + 3]
                non_initial = bool(fragment_field & 0xFFF8)
                fragment = non_initial or bool(fragment_field & 1)
            size = 8
        elif offset + 2 > captured_end:
            size = None
        elif number == 51:
            size = (data[offset + 1] + 2) * 4
            if size % 8:
                protocol_issue = header_issue = "ipv6_invalid_extension_length"
                break
        else:
            size = (data[offset + 1] + 1) * 8
        if size is not None and (size < minimum or offset + size > end):
            protocol_issue = header_issue = "ipv6_invalid_extension_length"
            break
        if size is None or offset + size > captured_end:
            # The observed Next Header can identify a terminal protocol even
            # when the rest of this extension was not captured. Keep the
            # header issue separately; never infer an unseen extension's Next Header.
            header_issue = "ipv6_truncated_extension"
            if following in _IPV6_EXTENSIONS or following in _UNSUPPORTED_IPV6_EXTENSIONS:
                protocol_issue = header_issue
            else:
                number = following
            break

        if following == 0:
            protocol_issue = header_issue = "ipv6_misplaced_hop_by_hop"
            break
        if number == 44 and non_initial and following in _IPV6_EXTENSIONS:
            protocol_issue = "ipv6_non_initial_fragment_extension"
            break

        number = following
        offset += size

    if not protocol_issue and number in _UNSUPPORTED_IPV6_EXTENSIONS:
        protocol_issue = "ipv6_unsupported_extension"

    # ESP is itself observable. Do not infer its encrypted Next Header.
    return Classification(
        "ipv6", None if protocol_issue else number, length, fragment,
        protocol_issue, length_issue, header_issue,
    )
