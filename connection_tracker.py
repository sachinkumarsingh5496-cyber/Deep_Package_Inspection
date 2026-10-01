"""
connection_tracker.py – Stateful flow tracking.
Mirrors connection_tracker.h from the C++ project.

Once a flow is identified (e.g. YouTube), every subsequent packet
of the same five-tuple inherits the same FlowAction and AppType.
"""

from __future__ import annotations
from .dpi_types import FiveTuple, FlowState, FlowAction, AppType


class ConnectionTracker:
    """
    Maps five-tuples → FlowState.
    Flows are bidirectional: we store both (A→B) and (B→A) under
    the canonical (sorted) key.
    """

    def __init__(self):
        self._flows: dict[tuple, FlowState] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _key(ft: FiveTuple) -> tuple:
        """Canonical (sorted) key so A→B and B→A share a record."""
        a = (ft.src_ip, ft.src_port)
        b = (ft.dst_ip, ft.dst_port)
        if a <= b:
            return (ft.protocol, a, b)
        return (ft.protocol, b, a)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(self, ft: FiveTuple) -> FlowState:
        key = self._key(ft)
        if key not in self._flows:
            self._flows[key] = FlowState()
        return self._flows[key]

    def update(self, ft: FiveTuple, action: FlowAction,
               app_type: AppType, sni: str = ""):
        state = self.get_or_create(ft)
        state.action   = action
        state.app_type = app_type
        if sni:
            state.sni = sni

    def stats(self) -> dict:
        total    = len(self._flows)
        blocked  = sum(1 for s in self._flows.values()
                       if s.action == FlowAction.DROP)
        return {"total_flows": total, "blocked_flows": blocked}
