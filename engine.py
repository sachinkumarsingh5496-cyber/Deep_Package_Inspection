"""
engine.py – Main DPI processing pipeline.
Mirrors dpi_mt.cpp / main_working.cpp from the C++ project.

Pipeline per packet:
  1. Parse Ethernet / IP / TCP-UDP headers
  2. Check existing flow state  →  if already DROP, skip
  3. Run DPI: extract SNI / HTTP Host, classify app
  4. Evaluate blocking rules
  5. Update flow state
  6. Write allowed packets to output pcap
"""

from __future__ import annotations
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .dpi_types import AppType, FlowAction, classify_sni
from .pcap_reader import PcapReader, PcapWriter
from .packet_parser import parse, PROTO_TCP, PROTO_UDP
from .sni_extractor import extract_sni, extract_http_host
from .rule_manager import RuleManager
from .connection_tracker import ConnectionTracker


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    total:      int = 0
    forwarded:  int = 0
    dropped:    int = 0
    tcp:        int = 0
    udp:        int = 0
    total_bytes:int = 0

    app_counts: Counter = field(default_factory=Counter)
    detected_snis: dict = field(default_factory=dict)   # sni → AppType


# ---------------------------------------------------------------------------
# DPI Engine
# ---------------------------------------------------------------------------

class DPIEngine:
    """
    Single-threaded DPI engine.
    Call run() to process a pcap file and write filtered output.
    """

    def __init__(self, rules: Optional[RuleManager] = None):
        self.rules   = rules or RuleManager()
        self.tracker = ConnectionTracker()
        self.stats   = Stats()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, input_path: str | Path,
            output_path: str | Path) -> Stats:
        """Process input pcap, write allowed packets to output pcap."""
        t0 = time.time()

        with PcapReader(input_path)  as reader, \
             PcapWriter(output_path) as writer:

            for raw in reader:
                self.stats.total      += 1
                self.stats.total_bytes+= len(raw.data)

                pkt = parse(raw)
                if pkt is None:
                    self._write(writer, raw)
                    continue

                # ---- per-protocol counters ----------------------------
                if pkt.has_tcp:
                    self.stats.tcp += 1
                elif pkt.has_udp:
                    self.stats.udp += 1

                # ---- check existing flow state -----------------------
                ft    = pkt.five_tuple
                flow  = self.tracker.get_or_create(ft)

                if flow.action == FlowAction.DROP:
                    # Flow already marked as blocked
                    pkt.app_type = flow.app_type
                    self._drop()
                    self.stats.app_counts[pkt.app_type] += 1
                    continue

                # ---- DPI: SNI / HTTP Host extraction -----------------
                if pkt.payload:
                    if pkt.has_tcp:
                        sni = extract_sni(pkt.payload)
                        if sni:
                            pkt.sni      = sni
                            pkt.app_type = classify_sni(sni)
                            # Store for reporting
                            self.stats.detected_snis[sni] = pkt.app_type
                        else:
                            # Try HTTP host
                            host = extract_http_host(pkt.payload)
                            if host:
                                pkt.http_host = host
                                pkt.app_type  = classify_sni(host)
                                self.stats.detected_snis[host] = pkt.app_type
                            elif pkt.dst_port == 443 and pkt.app_type == AppType.UNKNOWN:
                                pkt.app_type = AppType.HTTPS

                    elif pkt.has_udp and pkt.dst_port == 53:
                        pkt.app_type = AppType.DNS

                # ---- inherit flow's app type if already classified ---
                if (pkt.app_type == AppType.UNKNOWN and
                        flow.app_type != AppType.UNKNOWN):
                    pkt.app_type = flow.app_type

                # ---- blocking decision --------------------------------
                if self.rules.should_drop(pkt):
                    self.tracker.update(ft, FlowAction.DROP,
                                        pkt.app_type, pkt.sni or "")
                    self._drop()
                else:
                    self.tracker.update(ft, FlowAction.FORWARD,
                                        pkt.app_type, pkt.sni or "")
                    writer.write_packet(raw)
                    self.stats.forwarded += 1

                self.stats.app_counts[pkt.app_type] += 1

        elapsed = time.time() - t0
        print(f"[Engine] Processed {self.stats.total} packets "
              f"in {elapsed:.3f}s")
        return self.stats

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _drop(self):
        self.stats.dropped += 1

    def _write(self, writer: PcapWriter, raw):
        writer.write_packet(raw)
        self.stats.forwarded += 1


# ---------------------------------------------------------------------------
# Pretty report
# ---------------------------------------------------------------------------

def print_report(stats: Stats, rules: RuleManager):
    w = 66
    border = "═" * w

    def row(label: str, value, extra: str = "") -> str:
        val_str = str(value)
        pad = w - 4 - len(label) - len(val_str) - len(extra)
        return f"║ {label}{val_str}{' ' * max(pad, 1)}{extra}║"

    print(f"\n╔{border}╗")
    print(f"║{'DPI ENGINE – Processing Report':^{w}}║")
    print(f"╠{border}╣")
    print(row("Total Packets:   ", stats.total))
    print(row("Total Bytes:     ", stats.total_bytes))
    print(row("TCP Packets:     ", stats.tcp))
    print(row("UDP Packets:     ", stats.udp))
    print(f"╠{border}╣")
    print(row("Forwarded:       ", stats.forwarded))
    print(row("Dropped:         ", stats.dropped))

    # ---- flow stats ---------------------------------------------------
    fstats = rules  # reuse for display
    print(f"╠{border}╣")
    print(f"║{'APPLICATION BREAKDOWN':^{w}}║")
    print(f"╠{border}╣")

    total = max(stats.total, 1)
    blocked_apps = set()
    # find which apps are blocked
    for app_type, _ in stats.app_counts.items():
        # create a dummy pkt-like object
        class _Dummy:
            src_ip = ""
            sni    = None
            http_host = None
        d = _Dummy()
        d.app_type = app_type
        if rules.should_drop(d):  # type: ignore[arg-type]
            blocked_apps.add(app_type)

    for app_type, count in stats.app_counts.most_common(15):
        pct  = count / total * 100
        bar  = "#" * max(int(pct / 2), 1)
        tag  = " (BLOCKED)" if app_type in blocked_apps else ""
        line = (f"║ {app_type.name:<14}{count:>5}  {pct:>5.1f}%"
                f" {bar:<20}{tag}")
        line = line[:w + 1].ljust(w + 1) + "║"
        print(line)

    print(f"╠{border}╣")
    print(f"║{'DETECTED DOMAINS / SNIs':^{w}}║")
    print(f"╠{border}╣")
    for sni, app in list(stats.detected_snis.items())[:20]:
        line = f"║   {sni:<35} → {app.name}"
        line = line[:w + 1].ljust(w + 1) + "║"
        print(line)

    print(f"╚{border}╝\n")
