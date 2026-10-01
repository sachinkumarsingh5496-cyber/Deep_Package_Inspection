import sys
from pathlib import Path

# Insert parent directory to path so we can import DPI and test_dpi
sys.path.insert(0, str(Path(__file__).parent.parent))

from DPI.dpi_types import RawPacket
from DPI.pcap_reader import PcapWriter
from test_dpi import _eth, _ip, _tcp, _udp, _tls_client_hello, _make_raw

# Create some packets
packets = []

# 1. Normal Google TLS traffic (should be allowed)
payload = _tls_client_hello("www.google.com")
data = _eth() + _ip(src="192.168.1.10", dst="8.8.8.8", proto=6, payload_len=20 + len(payload)) + _tcp(sport=50001, dport=443, payload=payload)
packets.append(_make_raw(data))

# 2. YouTube TLS traffic (blocked app)
payload = _tls_client_hello("www.youtube.com")
data = _eth() + _ip(src="192.168.1.10", dst="8.8.8.8", proto=6, payload_len=20 + len(payload)) + _tcp(sport=50002, dport=443, payload=payload)
packets.append(_make_raw(data))

# 3. TikTok TLS traffic (blocked domain keyword)
payload = _tls_client_hello("www.tiktok.com")
data = _eth() + _ip(src="192.168.1.10", dst="8.8.8.8", proto=6, payload_len=20 + len(payload)) + _tcp(sport=50003, dport=443, payload=payload)
packets.append(_make_raw(data))

# 4. Traffic from blocked IP (192.168.1.50)
payload = _tls_client_hello("www.google.com")
data = _eth() + _ip(src="192.168.1.50", dst="8.8.8.8", proto=6, payload_len=20 + len(payload)) + _tcp(sport=50004, dport=443, payload=payload)
packets.append(_make_raw(data))

# 5. Normal HTTP traffic to example.com (allowed)
http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
data = _eth() + _ip(src="192.168.1.10", dst="93.184.216.34", proto=6, payload_len=20 + len(http_payload)) + _tcp(sport=50005, dport=80, payload=http_payload)
packets.append(_make_raw(data))

# Write to sample.pcap
with PcapWriter("sample.pcap") as writer:
    for pkt in packets:
        writer.write_packet(pkt)

print("Generated sample.pcap containing 5 test packets.")
