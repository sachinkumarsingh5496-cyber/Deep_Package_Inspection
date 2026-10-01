"""
dpi_types.py – Shared data structures for the DPI engine.
Mirrors types.h / types.cpp from the original C++ project.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ---------------------------------------------------------------------------
# Application classification
# ---------------------------------------------------------------------------

class AppType(Enum):
    UNKNOWN  = auto()
    HTTPS    = auto()   # Generic HTTPS (no recognisable SNI)
    HTTP     = auto()   # Plain HTTP
    DNS      = auto()
    GOOGLE   = auto()
    YOUTUBE  = auto()
    FACEBOOK = auto()
    INSTAGRAM= auto()
    TWITTER  = auto()
    AMAZON   = auto()
    NETFLIX  = auto()
    GITHUB   = auto()
    DISCORD  = auto()
    ZOOM     = auto()
    TELEGRAM = auto()
    TIKTOK   = auto()
    SPOTIFY  = auto()
    CLOUDFLARE=auto()
    MICROSOFT= auto()
    APPLE    = auto()


# Keyword → AppType mapping (checked against SNI / HTTP Host)
_SNI_MAP: list[tuple[str, AppType]] = [
    ("youtube",     AppType.YOUTUBE),
    ("googlevideo", AppType.YOUTUBE),
    ("ytimg",       AppType.YOUTUBE),
    ("instagram",   AppType.INSTAGRAM),
    ("facebook",    AppType.FACEBOOK),
    ("fbcdn",       AppType.FACEBOOK),
    ("twitter",     AppType.TWITTER),
    ("netflix",     AppType.NETFLIX),
    ("nflxvideo",   AppType.NETFLIX),
    ("amazon",      AppType.AMAZON),
    ("github",      AppType.GITHUB),
    ("discord",     AppType.DISCORD),
    ("zoom",        AppType.ZOOM),
    ("telegram",    AppType.TELEGRAM),
    ("tiktok",      AppType.TIKTOK),
    ("spotify",     AppType.SPOTIFY),
    ("cloudflare",  AppType.CLOUDFLARE),
    ("microsoft",   AppType.MICROSOFT),
    ("apple",       AppType.APPLE),
    ("google",      AppType.GOOGLE),
]


def classify_sni(sni: str) -> AppType:
    """Map a domain/SNI string to an AppType."""
    lower = sni.lower()
    for keyword, app in _SNI_MAP:
        if keyword in lower:
            return app
    return AppType.HTTPS  # encrypted but unrecognised


# ---------------------------------------------------------------------------
# Packet data structures
# ---------------------------------------------------------------------------

@dataclass
class FiveTuple:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip,
                     self.src_port, self.dst_port,
                     self.protocol))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)


@dataclass
class RawPacket:
    ts_sec:  int
    ts_usec: int
    data:    bytes


@dataclass
class ParsedPacket:
    raw: RawPacket

    # Ethernet
    src_mac:  str = ""
    dst_mac:  str = ""
    ethertype: int = 0

    # IP
    src_ip:   str = ""
    dst_ip:   str = ""
    ip_proto: int = 0          # 6 TCP / 17 UDP
    has_ip:   bool = False

    # TCP / UDP
    src_port:  int = 0
    dst_port:  int = 0
    has_tcp:   bool = False
    has_udp:   bool = False
    tcp_flags: int = 0
    payload:   bytes = b""

    # DPI results (filled later)
    sni:      Optional[str] = None
    http_host:Optional[str] = None
    app_type: AppType = AppType.UNKNOWN

    @property
    def five_tuple(self) -> FiveTuple:
        return FiveTuple(self.src_ip, self.dst_ip,
                         self.src_port, self.dst_port,
                         self.ip_proto)


# ---------------------------------------------------------------------------
# Flow (connection) tracking
# ---------------------------------------------------------------------------

class FlowAction(Enum):
    FORWARD = auto()
    DROP    = auto()


@dataclass
class FlowState:
    action:   FlowAction = FlowAction.FORWARD
    app_type: AppType    = AppType.UNKNOWN
    sni:      str        = ""
