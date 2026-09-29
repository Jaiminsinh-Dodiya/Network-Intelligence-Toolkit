"""Core components of the Network Intelligence Toolkit."""

from .models import (
    InterfaceInfo,
    NetworkInfo,
    RouteEntry,
    RoutingInfo,
    DnsServer,
    DnsInfo,
    DhcpInfo,
    WifiInfo,
    PublicIpInfo,
    ConnectivityTarget,
    ConnectivityInfo,
    NeighborEntry,
    SocketEntry,
    PcapSummary,
    Observation,
    ObservationEvidence,
    VALID_OBSERVATION_CATEGORIES,
    VALID_OBSERVATION_SEVERITIES,
    VALID_OBSERVATION_CONFIDENCES,
    VALID_OBSERVATION_STATUSES,
    DiffReport,
    SystemInfo,
    NetworkIntelligenceReport,
)
from .capabilities import CapabilityStatus, CapabilityEntry, CapabilityRegistry
from .permissions import check_permissions, is_privileged
from .errors import ToolkitError
from .public_ip import PublicIdentityCollector
from .connectivity import ConnectivityCollector
from .observations import ObservationEngine

__all__ = [
    "InterfaceInfo",
    "NetworkInfo",
    "RouteEntry",
    "RoutingInfo",
    "DnsServer",
    "DnsInfo",
    "DhcpInfo",
    "WifiInfo",
    "PublicIpInfo",
    "ConnectivityTarget",
    "ConnectivityInfo",
    "NeighborEntry",
    "SocketEntry",
    "PcapSummary",
    "Observation",
    "ObservationEvidence",
    "VALID_OBSERVATION_CATEGORIES",
    "VALID_OBSERVATION_SEVERITIES",
    "VALID_OBSERVATION_CONFIDENCES",
    "VALID_OBSERVATION_STATUSES",
    "DiffReport",
    "SystemInfo",
    "NetworkIntelligenceReport",
    "CapabilityStatus",
    "CapabilityEntry",
    "CapabilityRegistry",
    "check_permissions",
    "is_privileged",
    "ToolkitError",
    "PublicIdentityCollector",
    "ConnectivityCollector",
    "ObservationEngine",
]
