"""Read classic Ethernet PCAP records without losing their original lengths."""

import gzip
import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from struct import Struct
from typing import BinaryIO, Iterator, NamedTuple


_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
MAX_CAPTURED_LENGTH = 16 * 1024 * 1024


class PcapError(ValueError):
    """The capture format is unsupported or record alignment cannot be trusted."""


@dataclass(frozen=True, slots=True)
class Header:
    byte_order: str
    timestamp_resolution: str
    snaplen: int
    linktype: int
    linktype_field: int
    declared_fcs_bytes: int | None
    version: str = "2.4"
    linktype_name: str = "LINKTYPE_ETHERNET"


class Record(NamedTuple):
    epoch_seconds: int
    incl_len: int
    orig_len: int
    data: bytes
    issue: str | None


def open_capture(path: Path) -> BinaryIO:
    return gzip.open(path, "rb") if path.suffix.lower() == ".gz" else path.open("rb")


class _HashingReader:
    def __init__(self, stream, digest):
        self.stream = stream
        self.digest = digest

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        return data


@contextmanager
def open_hashed_capture(path: Path):
    """Hash file bytes and decompressed PCAP bytes during the same forward scan."""
    file_hash, pcap_hash = hashlib.sha256(), hashlib.sha256()
    with path.open("rb") as raw:
        hashed = _HashingReader(raw, file_hash)
        if path.suffix.lower() == ".gz":
            with gzip.GzipFile(fileobj=hashed, mode="rb") as stream:
                yield _HashingReader(stream, pcap_hash), file_hash, pcap_hash
        else:
            yield _HashingReader(hashed, pcap_hash), file_hash, pcap_hash


class PcapReader:
    def __init__(self, stream: BinaryIO):
        raw = stream.read(24)
        if raw.startswith(b"\x0a\x0d\x0d\x0a"):
            raise PcapError("PCAPNG is unsupported; provide classic PCAP")
        if len(raw) != 24:
            raise PcapError("truncated PCAP global header")
        if raw[:4] not in _MAGIC:
            raise PcapError("unrecognized classic PCAP magic")
        endian, self.fraction_limit = _MAGIC[raw[:4]]
        major, minor, _, _, snaplen, network = Struct(endian + "HHIIII").unpack_from(raw, 4)
        if (major, minor) != (2, 4) or snaplen == 0:
            raise PcapError(f"unsupported PCAP header: version {major}.{minor}, snaplen {snaplen}")
        linktype = network & 0xFFFF
        if linktype != 1:
            raise PcapError(f"unsupported link type {linktype}; classic Ethernet PCAP is required")
        if network & 0x0BFF0000:
            raise PcapError(f"nonzero reserved bits in PCAP link type field: {network:#010x}")
        fcs = (network >> 28) * 2 if network & (1 << 26) else None
        if fcs not in (None, 0, 4):
            raise PcapError(f"unsupported Ethernet FCS length: {fcs} bytes")
        self.header = Header(
            "little" if endian == "<" else "big",
            "microsecond" if self.fraction_limit == 1_000_000 else "nanosecond",
            snaplen, linktype, network, fcs,
        )
        self._stream = stream
        self._record = Struct(endian + "IIII")

    def __iter__(self) -> Iterator[Record]:
        read = self._stream.read
        unpack = self._record.unpack
        snaplen = self.header.snaplen
        fraction_limit = self.fraction_limit
        index = 0
        while raw := read(16):
            index += 1
            if len(raw) != 16:
                raise PcapError(f"truncated PCAP record header at record {index}")
            sec, frac, incl, orig = unpack(raw)
            if incl > MAX_CAPTURED_LENGTH:
                raise PcapError(f"captured length exceeds {MAX_CAPTURED_LENGTH} bytes at record {index}")
            data = read(incl)
            if len(data) != incl:
                raise PcapError(f"truncated PCAP record payload at record {index}")
            issue = None
            if frac >= fraction_limit:
                issue = "invalid_timestamp_fraction"
            elif incl > snaplen:
                issue = "incl_len_above_snaplen"
            elif orig < incl:
                issue = "orig_len_below_incl_len"
            elif orig == 0:
                issue = "zero_orig_len"
            yield Record(sec, incl, orig, data, issue)
