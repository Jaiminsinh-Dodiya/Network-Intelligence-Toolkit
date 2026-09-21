"""Normalized, strongly typed data models for Network Intelligence Toolkit.

All platform backends populate these identical models so that the execution,
analysis, and reporting engines remain completely platform-neutral.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any


@dataclass
class SystemInfo:
    """Operating system and host platform identification."""
    os_name: str
    os_version: str
    platform_release: str
    hostname: str
    architecture: str
    python_version: str
    is_privileged: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class NetworkInfo:
    """Normalized network and subnet details for an IP address on an interface."""
    interface: str = ""
    address: str = ""
    cidr: str = ""
    network: str | None = None
    prefix_length: int | None = None
    netmask: str | None = None
    broadcast: str | None = None
    first_host: str | None = None
    last_host: str | None = None
    total_addresses: int = 0
    usable_host_count: int = 0
    ip_version: int = 4
    scope: str = "GLOBAL"
    is_prefix_known: bool = True
    # Legacy alias fields for backward compatibility
    local_ip: str = ""
    network_address: str = ""
    broadcast_address: str = ""
    cidr_prefix: int | None = None
    host_range_start: str = ""
    host_range_end: str = ""
    total_hosts: int = 0
    ipv6_network: str | None = None

    def __post_init__(self) -> None:
        if self.local_ip and not self.address:
            self.address = self.local_ip
        if not self.local_ip and self.address:
            self.local_ip = self.address
        if self.network_address and not self.network:
            self.network = self.network_address
        if not self.network_address and self.network:
            self.network_address = self.network
        if self.cidr_prefix is not None and self.prefix_length is None:
            self.prefix_length = self.cidr_prefix
        if self.cidr_prefix is None and self.prefix_length is not None:
            self.cidr_prefix = self.prefix_length
        if self.broadcast_address and not self.broadcast:
            self.broadcast = self.broadcast_address
        if not self.broadcast_address and self.broadcast:
            self.broadcast_address = self.broadcast
        if self.host_range_start and not self.first_host:
            self.first_host = self.host_range_start
        if not self.host_range_start and self.first_host:
            self.host_range_start = self.first_host
        if self.host_range_end and not self.last_host:
            self.last_host = self.host_range_end
        if not self.host_range_end and self.last_host:
            self.host_range_end = self.last_host
        if self.total_hosts and not self.usable_host_count:
            self.usable_host_count = self.total_hosts
        if not self.total_hosts and self.usable_host_count:
            self.total_hosts = self.usable_host_count
        if self.prefix_length is None:
            self.is_prefix_known = False

    @property
    def first_address(self) -> str | None:
        """Alias for first_host (commonly used in IPv6 contexts)."""
        return self.first_host

    @property
    def last_address(self) -> str | None:
        """Alias for last_host (commonly used in IPv6 contexts)."""
        return self.last_host

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "address": self.address,
            "cidr": self.cidr,
            "network": self.network,
            "prefix_length": self.prefix_length,
            "netmask": self.netmask,
            "broadcast": self.broadcast,
            "first_host": self.first_host,
            "last_host": self.last_host,
            "first_address": self.first_address,
            "last_address": self.last_address,
            "total_addresses": self.total_addresses,
            "usable_host_count": self.usable_host_count,
            "ip_version": self.ip_version,
            "scope": self.scope,
            "is_prefix_known": self.is_prefix_known,
            "local_ip": self.address,
            "network_address": self.network,
            "broadcast_address": self.broadcast or "",
            "cidr_prefix": self.prefix_length,
            "host_range_start": self.first_host or "",
            "host_range_end": self.last_host or "",
            "total_hosts": self.usable_host_count,
            "ipv6_network": self.ipv6_network,
        }


@dataclass
class InterfaceInfo:
    """Network interface configuration and traffic metrics."""
    name: str
    state: str = "UNKNOWN"
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    networks: list[NetworkInfo] = field(default_factory=list)
    mac: str = ""
    mtu: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    is_wireless: bool = False
    is_loopback: bool = False
    is_up: bool = False
    speed_mbps: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["networks"] = [net.to_dict() for net in self.networks]
        return d


@dataclass
class RouteEntry:
    """Individual routing table entry."""
    destination: str
    gateway: str | None = None
    interface: str = ""
    metric: int | None = None  # Effective metric used for route preference
    route_metric: int | None = None  # Raw route metric from OS
    interface_metric: int | None = None  # Interface metric from OS
    protocol: str | None = None
    ip_version: int = 4
    is_default: bool = False
    prefix_length: int | None = None
    network: str | None = None
    scope: str | None = None
    route_type: str | None = None
    source: str | None = None
    state: str | None = None
    policy_store: str | None = None

    def __post_init__(self) -> None:
        # Determine prefix_length and network from destination if not explicitly provided
        if not self.network and self.destination:
            self.network = self.destination
        if self.prefix_length is None and "/" in self.destination:
            try:
                self.prefix_length = int(self.destination.split("/")[1])
            except ValueError:
                pass
        # Calculate effective metric if metric not provided but components are
        if self.metric is None:
            if self.route_metric is not None and self.interface_metric is not None:
                self.metric = self.route_metric + self.interface_metric
            elif self.route_metric is not None:
                self.metric = self.route_metric
        # Determine is_default
        if self.destination in ("0.0.0.0/0", "default", "::/0"):
            self.is_default = True

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class RoutingInfo:
    """Routing table and default gateway configuration.

    Policy Routing:
        Detected policy routing rules (e.g. `ip rule`) are preserved as metadata in `rules`.
        Preferred default route selection uses the lowest metric among parsed default routes.
        Effective destination-specific kernel route selection is not fully evaluated yet.
    """
    ipv4_routes: list[RouteEntry] = field(default_factory=list)
    ipv6_routes: list[RouteEntry] = field(default_factory=list)
    default_ipv4: RouteEntry | None = None
    default_ipv6: RouteEntry | None = None
    preferred_interface: str | None = None
    selection_reason: str | None = None
    rules: list[dict[str, Any]] = field(default_factory=list)
    # Legacy backward-compatible fields
    default_gateway: str | None = None
    default_interface: str | None = None
    default_gateway_v6: str | None = None
    default_interface_v6: str | None = None
    routes: list[RouteEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Synchronize backward-compatible aliases with structured fields
        if self.default_ipv4:
            if not self.default_gateway:
                self.default_gateway = self.default_ipv4.gateway
            if not self.default_interface:
                self.default_interface = self.default_ipv4.interface
            if not self.preferred_interface:
                self.preferred_interface = self.default_ipv4.interface
        elif self.default_gateway and not self.default_ipv4:
            self.default_ipv4 = RouteEntry(
                destination="0.0.0.0/0",
                gateway=self.default_gateway,
                interface=self.default_interface or "",
                is_default=True,
                ip_version=4,
            )

        if self.default_ipv6:
            if not self.default_gateway_v6:
                self.default_gateway_v6 = self.default_ipv6.gateway
            if not self.default_interface_v6:
                self.default_interface_v6 = self.default_ipv6.interface
            if not self.preferred_interface:
                self.preferred_interface = self.default_ipv6.interface

        # Populate combined routes list and specific lists
        if not self.routes:
            self.routes = list(self.ipv4_routes) + list(self.ipv6_routes)
        else:
            if not self.ipv4_routes and not self.ipv6_routes:
                for r in self.routes:
                    if r.ip_version == 4:
                        self.ipv4_routes.append(r)
                    else:
                        self.ipv6_routes.append(r)

    @property
    def default_route(self) -> RouteEntry | None:
        """Convenience property for primary default route (IPv4 preferred over IPv6)."""
        return self.default_ipv4 or self.default_ipv6

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_gateway": self.default_gateway,
            "default_interface": self.default_interface,
            "default_gateway_v6": self.default_gateway_v6,
            "default_interface_v6": self.default_interface_v6,
            "preferred_interface": self.preferred_interface,
            "selection_reason": self.selection_reason,
            "default_ipv4": self.default_ipv4.to_dict() if self.default_ipv4 else None,
            "default_ipv6": self.default_ipv6.to_dict() if self.default_ipv6 else None,
            "ipv4_routes": [r.to_dict() for r in self.ipv4_routes],
            "ipv6_routes": [r.to_dict() for r in self.ipv6_routes],
            "routes": [r.to_dict() for r in self.routes],
            "rules": self.rules,
        }


@dataclass

class NetworkIntelligenceReport:
    """Comprehensive normalized network intelligence report."""
    system: SystemInfo
    capabilities: dict[str, dict[str, Any]] = field(default_factory=dict)
    collection_errors: dict[str, str] = field(default_factory=dict)
    selected_interface: InterfaceInfo | None = None
    all_interfaces: list[InterfaceInfo] = field(default_factory=list)
    network: NetworkInfo | None = None
    all_networks: list[NetworkInfo] = field(default_factory=list)
    routing: RoutingInfo | None = None
    dns: DnsInfo | None = None
    dhcp: DhcpInfo | None = None
    wifi: WifiInfo | None = None
    public_ip: PublicIpInfo | None = None
    connectivity: ConnectivityInfo | None = None
    neighbors: list[NeighborEntry] = field(default_factory=list)
    sockets: list[SocketEntry] = field(default_factory=list)
    pcap_analysis: PcapAnalysisInfo | None = None
    pcap: PcapSummary | None = None
    observations: list[Observation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res = dataclasses.asdict(self)
        if self.observations:
            res["observations"] = [o.to_dict() if hasattr(o, "to_dict") else o for o in self.observations]
        if self.pcap_analysis and hasattr(self.pcap_analysis, "to_dict"):
            res["pcap_analysis"] = self.pcap_analysis.to_dict()
        if self.pcap and hasattr(self.pcap, "to_dict"):
            res["pcap"] = self.pcap.to_dict()
        return res
