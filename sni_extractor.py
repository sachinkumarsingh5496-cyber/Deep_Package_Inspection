"""
sni_extractor.py – Extract SNI from TLS Client Hello and Host from HTTP.
Mirrors sni_extractor.h / sni_extractor.cpp from the C++ project.

TLS Record layout:
  [0]     content type   (0x16 = Handshake)
  [1-2]   version        (0x0301 = TLS 1.0, etc.)
  [3-4]   length (uint16)
  [5...]  handshake data

Handshake layout:
  [0]     handshake type (0x01 = Client Hello)
  [1-3]   length (uint24)
  [4-5]   client version
  [6-37]  random (32 bytes)
  [38]    session ID length
  [38+N]  session ID (N bytes)
  ...     cipher suites, compression, extensions
"""

from __future__ import annotations
import struct
from typing import Optional


TLS_HANDSHAKE_TYPE  = 0x16
CLIENT_HELLO_TYPE   = 0x01
SNI_EXTENSION_TYPE  = 0x0000
HOST_NAME_TYPE      = 0x00


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS Client Hello and return the SNI hostname,
    or None if the payload is not a valid Client Hello / has no SNI.
    """
    if len(payload) < 5:
        return None

    # TLS record header
    if payload[0] != TLS_HANDSHAKE_TYPE:
        return None

    record_len = struct.unpack_from(">H", payload, 3)[0]
    if len(payload) < 5 + record_len:
        return None

    hs = payload[5:]   # handshake bytes

    if not hs or hs[0] != CLIENT_HELLO_TYPE:
        return None

    # 3-byte handshake length
    if len(hs) < 4:
        return None
    hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    if len(hs) < 4 + hs_len:
        return None

    body = hs[4:]   # Client Hello body

    # Skip: client_version(2) + random(32) = 34 bytes
    offset = 34
    if len(body) <= offset:
        return None

    # Session ID
    sid_len = body[offset]
    offset += 1 + sid_len
    if len(body) <= offset + 1:
        return None

    # Cipher suites
    cs_len = struct.unpack_from(">H", body, offset)[0]
    offset += 2 + cs_len
    if len(body) <= offset:
        return None

    # Compression methods
    comp_len = body[offset]
    offset += 1 + comp_len
    if len(body) <= offset + 1:
        return None

    # Extensions
    ext_total = struct.unpack_from(">H", body, offset)[0]
    offset += 2
    ext_end = offset + ext_total

    while offset + 4 <= ext_end and offset + 4 <= len(body):
        ext_type = struct.unpack_from(">H", body, offset)[0]
        ext_len  = struct.unpack_from(">H", body, offset + 2)[0]
        offset  += 4

        if ext_type == SNI_EXTENSION_TYPE:
            # SNI list length (2 bytes)
            if offset + 2 > len(body):
                break
            list_len = struct.unpack_from(">H", body, offset)[0]
            p = offset + 2

            list_end = p + list_len
            while p + 3 <= list_end and p + 3 <= len(body):
                name_type = body[p]
                name_len  = struct.unpack_from(">H", body, p + 1)[0]
                p += 3
                if name_type == HOST_NAME_TYPE:
                    if p + name_len <= len(body):
                        return body[p: p + name_len].decode("ascii", errors="replace")
                p += name_len

        offset += ext_len

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """
    Extract the Host header from an HTTP/1.x request.
    Returns None if not found.
    """
    try:
        text = payload.decode("ascii", errors="ignore")
    except Exception:
        return None

    if not (text.startswith("GET ") or text.startswith("POST ") or
            text.startswith("PUT ") or text.startswith("HEAD ") or
            text.startswith("DELETE ")):
        return None

    for line in text.splitlines():
        if line.lower().startswith("host:"):
            host = line[5:].strip()
            # Strip port if present
            if ":" in host:
                host = host.split(":")[0]
            return host

    return None
