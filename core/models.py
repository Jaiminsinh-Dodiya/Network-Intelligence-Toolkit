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
class DnsServer:
    """Configured DNS resolver."""
    address: str
    family: int = 4  # 4 for IPv4, 6 for IPv6
    protocol: str = "UNKNOWN"  # Strictly UNKNOWN unless proven (e.g. DoH, DoT, UDP)
    port: int = 53
    interface: str | None = None
    source: str | None = None
    is_primary: bool = False  # True only when explicitly designated by OS as preferred/current; False otherwise
    role: str = "UPSTREAM_RESOLVER"  # "UPSTREAM_RESOLVER" or "LOCAL_STUB"
    doh_template: str | None = None

    def __post_init__(self) -> None:
        if ":" in self.address and self.family == 4:
            self.family = 6
        if self.address in ("127.0.0.53", "127.0.0.54"):
            self.role = "LOCAL_STUB"

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class DnsInfo:
    """Host DNS configuration."""
    servers: list[DnsServer] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    domain: str | None = None
    source: str = "system"
    status: str = "EMPTY"  # CONFIGURED, EMPTY, PARTIAL, ERROR
    is_stub: bool = False
    stub_address: str | None = None
    upstream_servers: list[DnsServer] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.servers:
            if self.status == "EMPTY":
                self.status = "CONFIGURED"
            for s in self.servers:
                if s.role == "LOCAL_STUB" or s.address in ("127.0.0.53", "127.0.0.54"):
                    self.is_stub = True
                    self.stub_address = s.address

    def to_dict(self) -> dict[str, Any]:
        return {
            "servers": [s.to_dict() for s in self.servers],
            "search_domains": self.search_domains,
            "domain": self.domain,
            "source": self.source,
            "status": self.status,
            "is_stub": self.is_stub,
            "stub_address": self.stub_address,
            "upstream_servers": [s.to_dict() for s in self.upstream_servers],
        }


@dataclass
class DhcpInfo:
    """DHCP lease and server details."""
    # Canonical fields
    enabled: bool = False
    server: str | None = None
    address: str | None = None
    lease_start: str | None = None
    lease_expiry: str | None = None
    lease_duration: int | None = None  # seconds
    interface: str | None = None
    source: str | None = None
    status: str = "UNAVAILABLE"  # CONFIGURED, PARTIAL, NOT_DHCP, UNAVAILABLE, ERROR
    router: str | None = None
    subnet_mask: str | None = None
    raw_details: dict[str, str] = field(default_factory=dict)

    # Legacy backward-compatible fields
    available: bool = False
    server_ip: str | None = None
    lease_obtained: str | None = None
    lease_expires: str | None = None
    lease_duration_seconds: int | None = None
    assigned_ip: str | None = None

    def __post_init__(self) -> None:
        # Synchronize canonical and legacy fields
        if self.server and not self.server_ip:
            self.server_ip = self.server
        elif self.server_ip and not self.server:
            self.server = self.server_ip

        if self.address and not self.assigned_ip:
            self.assigned_ip = self.address
        elif self.assigned_ip and not self.address:
            self.address = self.assigned_ip

        if self.lease_start and not self.lease_obtained:
            self.lease_obtained = self.lease_start
        elif self.lease_obtained and not self.lease_start:
            self.lease_start = self.lease_obtained

        if self.lease_expiry and not self.lease_expires:
            self.lease_expires = self.lease_expiry
        elif self.lease_expires and not self.lease_expiry:
            self.lease_expiry = self.lease_expires

        if self.lease_duration is not None and self.lease_duration_seconds is None:
            self.lease_duration_seconds = self.lease_duration
        elif self.lease_duration_seconds is not None and self.lease_duration is None:
            self.lease_duration = self.lease_duration_seconds

        if self.enabled and not self.available:
            self.available = True
        elif self.available and not self.enabled:
            self.enabled = True

        super().__setattr__("_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if not getattr(self, "_initialized", False):
            return
        if name == "server" and getattr(self, "server_ip", None) != value:
            super().__setattr__("server_ip", value)
        elif name == "server_ip" and getattr(self, "server", None) != value:
            super().__setattr__("server", value)
        elif name == "address" and getattr(self, "assigned_ip", None) != value:
            super().__setattr__("assigned_ip", value)
        elif name == "assigned_ip" and getattr(self, "address", None) != value:
            super().__setattr__("address", value)
        elif name == "lease_start" and getattr(self, "lease_obtained", None) != value:
            super().__setattr__("lease_obtained", value)
        elif name == "lease_obtained" and getattr(self, "lease_start", None) != value:
            super().__setattr__("lease_start", value)
        elif name == "lease_expiry" and getattr(self, "lease_expires", None) != value:
            super().__setattr__("lease_expires", value)
        elif name == "lease_expires" and getattr(self, "lease_expiry", None) != value:
            super().__setattr__("lease_expiry", value)
        elif name == "lease_duration" and getattr(self, "lease_duration_seconds", None) != value:
            super().__setattr__("lease_duration_seconds", value)
        elif name == "lease_duration_seconds" and getattr(self, "lease_duration", None) != value:
            super().__setattr__("lease_duration", value)
        elif name == "enabled" and getattr(self, "available", None) != value:
            super().__setattr__("available", value)
        elif name == "available" and getattr(self, "enabled", None) != value:
            super().__setattr__("enabled", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "server": self.server,
            "address": self.address,
            "lease_start": self.lease_start,
            "lease_expiry": self.lease_expiry,
            "lease_duration": self.lease_duration,
            "interface": self.interface,
            "source": self.source,
            "status": self.status,
            "router": self.router,
            "subnet_mask": self.subnet_mask,
            "raw_details": self.raw_details,
            # Legacy aliases
            "available": self.available,
            "server_ip": self.server_ip,
            "assigned_ip": self.assigned_ip,
            "lease_obtained": self.lease_obtained,
            "lease_expires": self.lease_expires,
            "lease_duration_seconds": self.lease_duration_seconds,
        }


@dataclass
class WifiInfo:
    """Wi-Fi link and radio status."""
    interface: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    state: str = "UNAVAILABLE"  # CONNECTED, DISCONNECTED, NOT_APPLICABLE, UNAVAILABLE, ERROR
    is_wireless_interface: bool | None = None
    connected: bool = False
    frequency_mhz: int | None = None
    channel: int | None = None
    signal_percent: int | None = None
    signal_dbm: int | None = None
    signal_percent_estimated: bool = False
    signal_dbm_estimated: bool = False
    rx_rate_mbps: float | None = None
    tx_rate_mbps: float | None = None
    wifi_standard: str = "UNKNOWN"  # e.g. "802.11ax", "802.11ac", "802.11n", "802.11g", "802.11a", "802.11b", "802.11be", "UNKNOWN"
    security_mode: str = "UNKNOWN"  # "OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2-ENTERPRISE", "WPA3-ENTERPRISE", "OTHER", "UNKNOWN"
    raw_security: str | None = None
    source: str | None = None
    # Legacy backward-compatible fields
    is_wifi: bool = False
    standard: str | None = None

    def __post_init__(self) -> None:
        # Synchronize canonical and legacy fields
        if self.wifi_standard != "UNKNOWN" and self.standard is None:
            self.standard = self.wifi_standard
        elif self.standard is not None and self.wifi_standard == "UNKNOWN":
            self.wifi_standard = self.standard

        if self.is_wireless_interface is not None:
            self.is_wifi = bool(self.is_wireless_interface)
        elif self.is_wifi:
            self.is_wireless_interface = True

        if self.state == "CONNECTED":
            self.connected = True
        elif self.connected and self.state in ("UNAVAILABLE", None):
            self.state = "CONNECTED"

        super().__setattr__("_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if not getattr(self, "_initialized", False):
            return
        if name == "wifi_standard" and getattr(self, "standard", None) != value:
            super().__setattr__("standard", value)
        elif name == "standard" and getattr(self, "wifi_standard", None) != value:
            super().__setattr__("wifi_standard", value or "UNKNOWN")
        elif name == "is_wireless_interface" and getattr(self, "is_wifi", None) != bool(value):
            super().__setattr__("is_wifi", bool(value))
        elif name == "is_wifi" and getattr(self, "is_wireless_interface", None) != value:
            super().__setattr__("is_wireless_interface", value)
        elif name == "state" and value == "CONNECTED" and not getattr(self, "connected", False):
            super().__setattr__("connected", True)
        elif name == "connected" and value and getattr(self, "state", None) in ("UNAVAILABLE", None):
            super().__setattr__("state", "CONNECTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "state": self.state,
            "is_wireless_interface": self.is_wireless_interface,
            "connected": self.connected,
            "frequency_mhz": self.frequency_mhz,
            "channel": self.channel,
            "signal_percent": self.signal_percent,
            "signal_dbm": self.signal_dbm,
            "signal_percent_estimated": self.signal_percent_estimated,
            "signal_dbm_estimated": self.signal_dbm_estimated,
            "rx_rate_mbps": self.rx_rate_mbps,
            "tx_rate_mbps": self.tx_rate_mbps,
            "wifi_standard": self.wifi_standard,
            "security_mode": self.security_mode,
            "raw_security": self.raw_security,
            "source": self.source,
            # Legacy aliases
            "is_wifi": self.is_wifi,
            "standard": self.standard,
        }


@dataclass
class PublicIpInfo:
    """Public internet address and autonomous system metadata.

    Semantics & Relationship Documentation:
    - `ip` and `ip_version`: The Primary Observed Public IP address returned by external discovery.
    - `ipv4`: The Observed Public IPv4 address.
    - `ipv6`: The Observed Public IPv6 address.
    - Metadata Fields (`asn`, `as_org`, `isp`, `country`, `region`, `city`, `reverse_dns`):
      These fields correspond STRICTLY to `ip` + `ip_version` (the specific public address for which
      metadata was retrieved). They do NOT imply or automatically describe both IPv4 and IPv6.
    - Local vs. External View:
      Phase 5 reports what external services observe. The local routing subsystem remains
      authoritative for default route, gateway, and interface.
    """
    available: bool = False
    ip: str | None = None
    ip_version: int | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    asn: str | None = None
    as_org: str | None = None
    isp: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    reverse_dns: str | None = None
    source: str | None = None
    sources: dict[str, str] = field(default_factory=dict)
    lookup_timestamp: str | None = None
    status: str = "AVAILABLE"  # AVAILABLE, PARTIAL, OFFLINE, ERROR, DISABLED
    reason: str | None = None
    cgnat_detected: bool = False
    cgnat_local_address: str | None = None
    cgnat_interface: str | None = None
    cgnat_details: str | None = None
    geolocation_accuracy: str = "APPROXIMATE"
    disclaimer: str = (
        "Approximate geolocation is estimated based on publicly registered IP allocations "
        "and does not represent precise physical location."
    )

    def __post_init__(self) -> None:
        if self.ip and not self.ip_version:
            try:
                self.ip_version = ipaddress.ip_address(self.ip.strip()).version
            except ValueError:
                pass

        if self.ip:
            if self.ip_version == 4 and not self.ipv4:
                self.ipv4 = self.ip
            elif self.ip_version == 6 and not self.ipv6:
                self.ipv6 = self.ip

        if not self.ip:
            if self.ipv4:
                self.ip = self.ipv4
                self.ip_version = 4
            elif self.ipv6:
                self.ip = self.ipv6
                self.ip_version = 6

        # Populate top-level source from sources dictionary if missing
        if not self.source and self.sources:
            self.source = self.sources.get("ip") or next(iter(self.sources.values()), None)

    @property
    def public_ipv4(self) -> str | None:
        """Alias for the observed public IPv4 address."""
        return self.ipv4 or (self.ip if self.ip_version == 4 else None)

    @property
    def public_ipv6(self) -> str | None:
        """Alias for the observed public IPv6 address."""
        return self.ipv6 or (self.ip if self.ip_version == 6 else None)

    @property
    def primary_source(self) -> str | None:
        """Alias for the provider that discovered the primary observed public IP."""
        return self.source

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["public_ipv4"] = self.public_ipv4
        d["public_ipv6"] = self.public_ipv6
        d["primary_source"] = self.primary_source
        return d


VALID_CONNECTIVITY_STATUSES: set[str] = {
    "SUCCESS",
    "FAILED",
    "TIMEOUT",
    "ERROR",
    "DISABLED",
    "NOT_APPLICABLE",
}


@dataclass
class ConnectivityTarget:
    """Result of an individual connectivity test."""
    name: str
    target: str
    success: bool
    latency_ms: float | None = None
    packet_loss_pct: float | None = None
    details: str | None = None
    status: str = ""
    http_status: int | None = None

    def __post_init__(self) -> None:
        if not self.status:
            self.status = "SUCCESS" if self.success else "FAILED"
        elif self.status not in VALID_CONNECTIVITY_STATUSES:
            raise ValueError(
                f"Invalid connectivity status: '{self.status}'. "
                f"Must be one of {sorted(VALID_CONNECTIVITY_STATUSES)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ConnectivityInfo:
    """Comprehensive host connectivity results."""
    local_interface: ConnectivityTarget | None = None
    gateway: ConnectivityTarget | None = None
    dns: ConnectivityTarget | None = None
    internet: ConnectivityTarget | None = None
    ipv4: ConnectivityTarget | None = None
    ipv6: ConnectivityTarget | None = None
    all_targets: list[ConnectivityTarget] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class NeighborEntry:
    """Entry in local neighbor/ARP cache."""
    ip_address: str
    mac_address: str
    interface: str
    state: str = "UNKNOWN"
    is_router: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class SocketEntry:
    """Local listening or connected socket."""
    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str = "UNKNOWN"
    pid: int | None = None
    process_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


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
