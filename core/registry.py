"""Collector registry and options context.

Defines execution scope policies for different scan modes:
- Quick mode (--quick): System info, Capabilities, Interfaces, and Routing only.
- Default mode: Baseline collection appropriate for the current phase (Interfaces, Routing, DNS, DHCP).
- Full mode (--full): Baseline + Wi-Fi + Neighbors + Sockets + future collectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class CollectorOptions:
    """Runtime options configuring which collectors run."""
    interface: str | None = None
    quick_mode: bool = False
    full_mode: bool = False
    no_internet: bool = False
    include_neighbors: bool = False
    include_sockets: bool = False
    include_wifi: bool = False
    pcap_path: Path | None = None
    pcap_filter: str | None = None
    verbose: bool = False

    def should_collect_routing(self) -> bool:
        """Routing is included in quick, default, and full modes."""
        return True

    def should_collect_dns(self) -> bool:
        """DNS is excluded in quick mode, included in default and full modes."""
        return not self.quick_mode

    def should_collect_dhcp(self) -> bool:
        """DHCP is excluded in quick mode, included in default and full modes."""
        return not self.quick_mode

    def should_collect_wifi(self) -> bool:
        """Wi-Fi is included in full mode or when explicitly requested via --wifi."""
        if self.quick_mode:
            return False
        return self.full_mode or self.include_wifi

    def should_collect_neighbors(self) -> bool:
        """Neighbors are included in full mode or when explicitly requested via --neighbors."""
        if self.quick_mode:
            return False
        return self.full_mode or self.include_neighbors

    def should_collect_sockets(self) -> bool:
        """Sockets are included in full mode or when explicitly requested via --sockets."""
        if self.quick_mode:
            return False
        return self.full_mode or self.include_sockets

    def should_collect_internet(self) -> bool:
        """Public internet queries are excluded if --no-internet or --quick."""
        if self.quick_mode:
            return False
        return not self.no_internet

    def should_collect_public_ip(self) -> bool:
        """Public IP identity is excluded in quick mode, included in standard and full modes."""
        return not self.quick_mode

    def should_collect_connectivity(self) -> bool:
        """Connectivity diagnostics are excluded in quick mode, included in standard and full modes."""
        return not self.quick_mode

    def should_analyze_pcap(self) -> bool:
        """PCAP analysis is opt-in and activates strictly when --pcap <path> is provided."""
        return self.pcap_path is not None


