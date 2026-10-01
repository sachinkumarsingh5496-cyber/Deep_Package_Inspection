"""
pcap_reader.py – Read and write libpcap (.pcap) files.
Mirrors pcap_reader.h / pcap_reader.cpp from the C++ project.

PCAP global header (24 bytes):
  magic_number  uint32  0xa1b2c3d4 (little-endian) or 0xd4c3b2a1 (big-endian)
  version_major uint16
  version_minor uint16
  thiszone      int32
  sigfigs       uint32
  snaplen       uint32
  network       uint32  1 = Ethernet

Packet header (16 bytes):
  ts_sec   uint32
  ts_usec  uint32
  incl_len uint32  (captured length)
  orig_len uint32  (original length)
"""

from __future__ import annotations
import struct
from pathlib import Path
from typing import Iterator, Optional

from .dpi_types import RawPacket


PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
GLOBAL_HEADER_LEN = 24
PKT_HEADER_LEN    = 16


class PcapReader:
    """Iterate over raw packets in a pcap file."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._fh = open(self._path, "rb")
        self._endian = self._read_global_header()

    # ------------------------------------------------------------------
    def _read_global_header(self) -> str:
        hdr = self._fh.read(GLOBAL_HEADER_LEN)
        if len(hdr) < GLOBAL_HEADER_LEN:
            raise ValueError(f"File too short to be a pcap: {self._path}")

        magic = struct.unpack_from("<I", hdr, 0)[0]
        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            raise ValueError(f"Invalid pcap magic: 0x{magic:08x}")

        return endian

    # ------------------------------------------------------------------
    def __iter__(self) -> Iterator[RawPacket]:
        return self._packet_gen()

    def _packet_gen(self) -> Iterator[RawPacket]:
        fmt = self._endian + "IIII"
        while True:
            raw_hdr = self._fh.read(PKT_HEADER_LEN)
            if not raw_hdr:
                break
            if len(raw_hdr) < PKT_HEADER_LEN:
                break

            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(fmt, raw_hdr)
            data = self._fh.read(incl_len)
            if len(data) < incl_len:
                break

            yield RawPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=data)

    # ------------------------------------------------------------------
    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PcapWriter:
    """Write raw packets to a pcap file."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._fh = open(self._path, "wb")
        self._write_global_header()

    def _write_global_header(self):
        # little-endian, version 2.4, Ethernet linktype
        hdr = struct.pack("<IHHiIII",
                          PCAP_MAGIC_LE,
                          2, 4,       # version
                          0,          # timezone
                          0,          # sigfigs
                          65535,      # snaplen
                          1)          # linktype = Ethernet
        self._fh.write(hdr)

    def write_packet(self, pkt: RawPacket):
        pkt_hdr = struct.pack("<IIII",
                              pkt.ts_sec,
                              pkt.ts_usec,
                              len(pkt.data),
                              len(pkt.data))
        self._fh.write(pkt_hdr)
        self._fh.write(pkt.data)

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
