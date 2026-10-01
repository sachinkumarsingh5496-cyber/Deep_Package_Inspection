"""
packet_parser.py – Parse Ethernet / IP / TCP / UDP headers.
Mirrors packet_parser.h / packet_parser.cpp from the C++ project.
"""

from __future__ import annotations
import struct
from typing import Optional

from .dpi_types import RawPacket, ParsedPacket, AppType


# EtherType values
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD

# IP protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17

# Header sizes
ETH_HDR_LEN = 14
IP_HDR_MIN   = 20
TCP_HDR_MIN  = 20
UDP_HDR_LEN  = 8


def _mac_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse(raw: RawPacket) -> Optional[ParsedPacket]:
    """
    Parse a raw packet into a ParsedPacket.
    Returns None if the packet is too short or not Ethernet/IPv4.
    """
    data = raw.data
    pkt  = ParsedPacket(raw=raw)

    # ---------------------------------------------------------------
    # Ethernet header (14 bytes)
    # ---------------------------------------------------------------
    if len(data) < ETH_HDR_LEN:
        return pkt

    pkt.dst_mac   = _mac_to_str(data[0:6])
    pkt.src_mac   = _mac_to_str(data[6:12])
    ethertype     = struct.unpack_from(">H", data, 12)[0]
    pkt.ethertype = ethertype

    if ethertype != ETH_TYPE_IPV4:
        return pkt   # Only handle IPv4 for now

    # ---------------------------------------------------------------
    # IPv4 header (variable length)
    # ---------------------------------------------------------------
    ip_start = ETH_HDR_LEN
    if len(data) < ip_start + IP_HDR_MIN:
        return pkt

    version_ihl = data[ip_start]
    ihl         = (version_ihl & 0x0F) * 4   # header length in bytes
    ip_proto    = data[ip_start + 9]

    pkt.src_ip   = _ip_to_str(data[ip_start + 12: ip_start + 16])
    pkt.dst_ip   = _ip_to_str(data[ip_start + 16: ip_start + 20])
    pkt.ip_proto = ip_proto
    pkt.has_ip   = True

    transport_start = ip_start + ihl

    # ---------------------------------------------------------------
    # TCP header
    # ---------------------------------------------------------------
    if ip_proto == PROTO_TCP:
        if len(data) < transport_start + TCP_HDR_MIN:
            return pkt

        pkt.src_port  = struct.unpack_from(">H", data, transport_start)[0]
        pkt.dst_port  = struct.unpack_from(">H", data, transport_start + 2)[0]
        data_offset   = (data[transport_start + 12] >> 4) * 4
        pkt.tcp_flags = data[transport_start + 13]
        pkt.has_tcp   = True

        payload_start = transport_start + data_offset
        pkt.payload   = data[payload_start:]

    # ---------------------------------------------------------------
    # UDP header
    # ---------------------------------------------------------------
    elif ip_proto == PROTO_UDP:
        if len(data) < transport_start + UDP_HDR_LEN:
            return pkt

        pkt.src_port = struct.unpack_from(">H", data, transport_start)[0]
        pkt.dst_port = struct.unpack_from(">H", data, transport_start + 2)[0]
        pkt.has_udp  = True

        pkt.payload  = data[transport_start + UDP_HDR_LEN:]

    return pkt
