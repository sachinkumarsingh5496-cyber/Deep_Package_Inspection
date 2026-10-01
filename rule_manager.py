"""
rule_manager.py – Blocking rule storage and evaluation.
Mirrors rule_manager.h from the C++ project.
"""

from __future__ import annotations
from .dpi_types import AppType, ParsedPacket, FlowAction


class RuleManager:
    """
    Stores blocking rules and decides whether a packet should be
    FORWARD-ed or DROP-ped.

    Rule types
    ----------
    blocked_ips     – block all packets from these source IPs
    blocked_apps    – block all packets whose flow is classified as
                      one of these AppType values
    blocked_domains – block if SNI/host contains this substring
    """

    def __init__(self):
        self._blocked_ips:     set[str]     = set()
        self._blocked_apps:    set[AppType] = set()
        self._blocked_domains: list[str]    = []

    # ------------------------------------------------------------------
    # Rule registration
    # ------------------------------------------------------------------

    def block_ip(self, ip: str):
        self._blocked_ips.add(ip)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, name: str):
        """Accept AppType enum value or its name string."""
        try:
            app = AppType[name.upper()]
        except KeyError:
            print(f"[Rules] WARNING: unknown app '{name}', ignoring.")
            return
        self._blocked_apps.add(app)
        print(f"[Rules] Blocked app: {app.name}")

    def block_domain(self, keyword: str):
        self._blocked_domains.append(keyword.lower())
        print(f"[Rules] Blocked domain keyword: {keyword}")

    # ------------------------------------------------------------------
    # Decision
    # ------------------------------------------------------------------

    def should_drop(self, pkt: ParsedPacket) -> bool:
        # 1. Source IP rule
        if pkt.src_ip in self._blocked_ips:
            return True

        # 2. App type rule (set after DPI)
        if pkt.app_type in self._blocked_apps:
            return True

        # 3. Domain keyword rule
        hostname = pkt.sni or pkt.http_host or ""
        hostname_lower = hostname.lower()
        for kw in self._blocked_domains:
            if kw in hostname_lower:
                return True

        return False

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        lines = ["Active Rules:"]
        if self._blocked_ips:
            lines.append(f"  Blocked IPs:     {', '.join(sorted(self._blocked_ips))}")
        if self._blocked_apps:
            lines.append(f"  Blocked apps:    {', '.join(a.name for a in self._blocked_apps)}")
        if self._blocked_domains:
            lines.append(f"  Blocked domains: {', '.join(self._blocked_domains)}")
        if len(lines) == 1:
            lines.append("  (none)")
        return "\n".join(lines)
