#!/usr/bin/env python3
"""
tests/test_dpi.py – Unit tests for the Python DPI engine.
Run with:  python -m pytest tests/ -v
       or: python tests/test_dpi.py
"""

import sys, os, struct, random, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from DPI.dpi_types import AppType, FiveTuple, classify_sni
from DPI.pcap_reader import PcapReader, PcapWriter, RawPacket
from DPI.packet_parser import parse
from DPI.sni_extractor import extract_sni, extract_http_host
from DPI.rule_manager import RuleManager
from DPI.connection_tracker import ConnectionTracker, FlowAction
from DPI.engine import DPIEngine


# ---------------------------------------------------------------------------
# Helpers – build minimal packet bytes
# ---------------------------------------------------------------------------

def _eth(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff"):
    s = bytes.fromhex(src.replace(":", ""))
    d = bytes.fromhex(dst.replace(":", ""))
    return d + s + struct.pack(">H", 0x0800)

def _ip(src="192.168.1.1", dst="8.8.8.8", proto=6, payload_len=20):
    total = 20 + payload_len
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total,
                      0x1234, 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src.split("."))
    hdr += bytes(int(x) for x in dst.split("."))
    return hdr

def _tcp(sport=12345, dport=443, flags=0x02, payload=b""):
    hdr = struct.pack(">HHIIBBHHH",
                      sport, dport,
                      1000, 0,
                      0x50, flags,
                      65535, 0, 0)
    return hdr + payload

def _udp(sport=12345, dport=53, payload=b""):
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload

def _make_raw(data: bytes) -> RawPacket:
    return RawPacket(ts_sec=1700000000, ts_usec=0, data=data)


# ---------------------------------------------------------------------------
# TLS Client Hello builder (simplified)
# ---------------------------------------------------------------------------

def _tls_client_hello(sni: str) -> bytes:
    sni_b = sni.encode()
    sni_entry = struct.pack(">BH", 0, len(sni_b)) + sni_b
    sni_list  = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext   = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    exts      = sni_ext
    exts_data = struct.pack(">H", len(exts)) + exts

    random_b  = bytes(32)
    ch_body   = (struct.pack(">H", 0x0303) + random_b +
                 struct.pack("B", 0) +
                 struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302) +
                 struct.pack("BB", 1, 0) + exts_data)

    hs = (struct.pack("B", 0x01) +
          struct.pack(">I", len(ch_body))[1:] +
          ch_body)

    record = (struct.pack("B", 0x16) +
              struct.pack(">H", 0x0301) +
              struct.pack(">H", len(hs)) +
              hs)
    return record


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestClassifySNI(unittest.TestCase):
    def test_youtube(self):
        self.assertEqual(classify_sni("www.youtube.com"), AppType.YOUTUBE)

    def test_facebook(self):
        self.assertEqual(classify_sni("www.facebook.com"), AppType.FACEBOOK)

    def test_unknown(self):
        self.assertEqual(classify_sni("www.example.com"), AppType.HTTPS)

    def test_case_insensitive(self):
        self.assertEqual(classify_sni("WWW.GITHUB.COM"), AppType.GITHUB)


class TestSNIExtractor(unittest.TestCase):
    def test_extract_youtube(self):
        tls = _tls_client_hello("www.youtube.com")
        sni = extract_sni(tls)
        self.assertEqual(sni, "www.youtube.com")

    def test_extract_google(self):
        tls = _tls_client_hello("www.google.com")
        self.assertEqual(extract_sni(tls), "www.google.com")

    def test_no_sni_on_garbage(self):
        self.assertIsNone(extract_sni(b"\x00\x01\x02\x03"))

    def test_http_host(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertEqual(extract_http_host(req), "example.com")

    def test_http_host_with_port(self):
        req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        self.assertEqual(extract_http_host(req), "example.com")

    def test_no_http_host_on_binary(self):
        self.assertIsNone(extract_http_host(b"\x16\x03\x01"))


class TestPacketParser(unittest.TestCase):
    def test_parse_tcp(self):
        payload = b"hello"
        data = _eth() + _ip(proto=6, payload_len=20 + len(payload)) + _tcp(payload=payload)
        pkt = parse(_make_raw(data))
        self.assertTrue(pkt.has_ip)
        self.assertTrue(pkt.has_tcp)
        self.assertEqual(pkt.src_ip, "192.168.1.1")
        self.assertEqual(pkt.dst_ip, "8.8.8.8")
        self.assertEqual(pkt.dst_port, 443)
        self.assertEqual(pkt.payload, payload)

    def test_parse_udp(self):
        payload = b"\x00\x01dns"
        data = _eth() + _ip(proto=17, payload_len=8 + len(payload)) + _udp(payload=payload)
        pkt = parse(_make_raw(data))
        self.assertTrue(pkt.has_udp)
        self.assertFalse(pkt.has_tcp)

    def test_parse_too_short(self):
        pkt = parse(_make_raw(b"\x00" * 5))
        self.assertFalse(pkt.has_ip)


class TestRuleManager(unittest.TestCase):
    def _pkt(self, src_ip="1.2.3.4", app=AppType.UNKNOWN, sni=None):
        class _P:
            pass
        p = _P()
        p.src_ip = src_ip
        p.app_type = app
        p.sni = sni
        p.http_host = None
        return p

    def test_block_ip(self):
        r = RuleManager()
        r.block_ip("1.2.3.4")
        self.assertTrue(r.should_drop(self._pkt(src_ip="1.2.3.4")))
        self.assertFalse(r.should_drop(self._pkt(src_ip="5.6.7.8")))

    def test_block_app(self):
        r = RuleManager()
        r.block_app("YouTube")
        self.assertTrue(r.should_drop(self._pkt(app=AppType.YOUTUBE)))
        self.assertFalse(r.should_drop(self._pkt(app=AppType.GOOGLE)))

    def test_block_domain(self):
        r = RuleManager()
        r.block_domain("tiktok")
        self.assertTrue(r.should_drop(self._pkt(sni="www.tiktok.com")))
        self.assertFalse(r.should_drop(self._pkt(sni="www.google.com")))


class TestConnectionTracker(unittest.TestCase):
    def _ft(self, src="1.1.1.1", dst="2.2.2.2", sp=1000, dp=443, proto=6):
        return FiveTuple(src, dst, sp, dp, proto)

    def test_bidirectional(self):
        ct = ConnectionTracker()
        ft_fwd = self._ft()
        ft_rev = self._ft(src="2.2.2.2", dst="1.1.1.1", sp=443, dp=1000)
        ct.update(ft_fwd, FlowAction.DROP, AppType.YOUTUBE)
        state = ct.get_or_create(ft_rev)
        self.assertEqual(state.action, FlowAction.DROP)

    def test_new_flow_forward(self):
        ct = ConnectionTracker()
        state = ct.get_or_create(self._ft())
        self.assertEqual(state.action, FlowAction.FORWARD)


class TestDPIEngineEndToEnd(unittest.TestCase):
    """Build a tiny in-memory pcap and run the engine against it."""

    def _write_pcap(self, path, packets):
        with PcapWriter(path) as w:
            for raw in packets:
                w.write_packet(raw)

    def _make_tls_packet(self, sni, src_ip="192.168.1.100",
                         dst_ip="8.8.8.8", sport=50000, dport=443):
        payload = _tls_client_hello(sni)
        data = (_eth() +
                _ip(src=src_ip, dst=dst_ip, proto=6,
                    payload_len=20 + len(payload)) +
                _tcp(sport=sport, dport=dport, flags=0x18, payload=payload))
        return _make_raw(data)

    def test_passthrough(self):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "in.pcap")
            out = os.path.join(d, "out.pcap")
            pkts = [self._make_tls_packet("www.google.com")]
            self._write_pcap(inp, pkts)

            engine = DPIEngine()
            stats  = engine.run(inp, out)
            self.assertEqual(stats.total, 1)
            self.assertEqual(stats.forwarded, 1)
            self.assertEqual(stats.dropped, 0)

    def test_block_youtube(self):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "in.pcap")
            out = os.path.join(d, "out.pcap")
            pkts = [
                self._make_tls_packet("www.youtube.com", sport=50001),
                self._make_tls_packet("www.google.com",  sport=50002),
            ]
            self._write_pcap(inp, pkts)

            rules = RuleManager()
            rules.block_app("YouTube")
            engine = DPIEngine(rules=rules)
            stats  = engine.run(inp, out)

            self.assertEqual(stats.total, 2)
            self.assertEqual(stats.dropped, 1)
            self.assertEqual(stats.forwarded, 1)

    def test_block_ip(self):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "in.pcap")
            out = os.path.join(d, "out.pcap")
            pkts = [
                self._make_tls_packet("www.google.com", src_ip="192.168.1.50"),
                self._make_tls_packet("www.google.com", src_ip="192.168.1.1"),
            ]
            self._write_pcap(inp, pkts)

            rules = RuleManager()
            rules.block_ip("192.168.1.50")
            engine = DPIEngine(rules=rules)
            stats  = engine.run(inp, out)

            self.assertEqual(stats.dropped, 1)
            self.assertEqual(stats.forwarded, 1)

    def test_pcap_roundtrip(self):
        """Packets written then read back should be identical."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rt.pcap")
            original = [_make_raw(b"\xaa\xbb" * 30),
                        _make_raw(b"\xcc\xdd" * 20)]
            self._write_pcap(path, original)
            with PcapReader(path) as reader:
                recovered = list(reader)
            self.assertEqual(len(recovered), 2)
            self.assertEqual(recovered[0].data, original[0].data)
            self.assertEqual(recovered[1].data, original[1].data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
