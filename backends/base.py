"""Abstract Platform Backend definition.

All platform implementations (Linux/Kali, Windows, future macOS) must implement
this abstract interface, returning normalized dataclass models defined in core.models.
"""

from __future__ import annotations

import abc
from pathlib import Path

from core.capabilities import CapabilityEntry
from core.models import (
    ConnectivityInfo,
    ConnectivityTarget,
    DhcpInfo,
    DnsInfo,
    InterfaceInfo,
    NeighborEntry,
    PcapAnalysisInfo,
    PublicIpInfo,
    RoutingInfo,
    SocketEntry,
    SystemInfo,
    WifiInfo,
)


class BasePlatformBackend(abc.ABC):
    """Abstract interface for platform-specific network data collection."""

    @abc.abstractmethod
    def get_platform_name(self) -> str:
        """Return the canonical platform name, e.g. 'Windows' or 'Linux'."""
        pass

    @abc.abstractmethod
    def get_platform_info(self) -> SystemInfo:
        """Collect host operating system, version, and platform metadata."""
        pass

    @abc.abstractmethod
    def detect_capabilities(self) -> dict[str, CapabilityEntry]:
        """Detect and return the capability status for each subsystem on this platform."""
        pass

    @abc.abstractmethod
    def get_interfaces(self, target_iface: str | None = None) -> list[InterfaceInfo]:
        """Retrieve network interfaces and their configuration/statistics.

        Args:
            target_iface: Optional interface name to filter by.
        """
        pass

    @abc.abstractmethod
    def get_default_interface(self) -> InterfaceInfo | None:
        """Determine and return the primary active network interface."""
        pass

    @abc.abstractmethod
    def get_routes(self) -> RoutingInfo:
        """Retrieve routing table and default gateway information."""
        pass

    @abc.abstractmethod
    def get_dns(self) -> DnsInfo:
        """Retrieve configured DNS servers and search domains."""
        pass

    @abc.abstractmethod
    def get_dhcp(self, interface_name: str | None = None) -> DhcpInfo:
        """Retrieve DHCP lease information for the specified or default interface."""
        pass

    @abc.abstractmethod
    def get_wifi(self, interface_name: str | None = None) -> WifiInfo:
        """Retrieve Wi-Fi status and link metrics if the interface is wireless."""
        pass

    @abc.abstractmethod
    def get_neighbors(
        self,
        interface_name: str | None = None,
        routing: RoutingInfo | None = None,
    ) -> list[NeighborEntry]:
        """Retrieve local ARP / neighbor cache table."""
        pass

    @abc.abstractmethod
    def get_sockets(self) -> list[SocketEntry]:
        """Retrieve local listening and active TCP/UDP sockets."""
        pass

    @abc.abstractmethod
    def ping_host(
        self,
        target: str,
        count: int = 2,
        timeout_seconds: float = 3.0,
        interface_name: str | None = None,
    ) -> ConnectivityTarget:
        """Send ICMP echo requests to target and return normalized ConnectivityTarget."""
        pass

    def get_public_ip(
        self,
        selected_iface: InterfaceInfo | None = None,
        no_internet: bool = False,
    ) -> PublicIpInfo:
        """Retrieve observed public IP and autonomous system metadata.

        Platform-neutral collector using privacy-safe external lookups.
        """
        from core.public_ip import PublicIdentityCollector
        collector = PublicIdentityCollector()
        return collector.collect(selected_iface=selected_iface, no_internet=no_internet)

    def get_connectivity(
        self,
        selected_iface: InterfaceInfo | None = None,
        routing: RoutingInfo | None = None,
        dns: DnsInfo | None = None,
        no_internet: bool = False,
    ) -> ConnectivityInfo:
        """Measure safe host connectivity.

        Cross-platform orchestration using core.connectivity.ConnectivityCollector.
        """
        from core.connectivity import ConnectivityCollector
        collector = ConnectivityCollector(backend=self)
        return collector.collect(
            selected_iface=selected_iface,
            routing=routing,
            dns=dns,
            no_internet=no_internet,
        )

    @abc.abstractmethod

# Interface-specific DHCP lease matching

# Public internet identity get_public_ip backend integration
