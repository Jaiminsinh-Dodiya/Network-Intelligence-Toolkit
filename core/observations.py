"""Observations & Findings Engine for Network Intelligence Toolkit (Phase 9 & 9.1).

Transforms collected toolkit evidence into structured, deterministic, evidence-backed
observations with complete collection scope awareness. Strictly passive, in-memory analysis layer.

Key Guarantees:
- Zero active network activity (no socket connections, DNS queries, HTTP probes, ARP sweeps).
- Scope awareness: unrequested subsystems are never treated as empty, partial, or failed.
- Read-only analysis of existing NetworkIntelligenceReport.
- Objective, evidence-proven conclusions (no arbitrary threat scoring, no speculation).
- Deterministic observation IDs, categories, severities, and sorting.
- Automatic contradiction suppression and deduplication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import logging
from pathlib import Path
from typing import Any, Callable

from core.models import (
    NetworkIntelligenceReport,
    Observation,
    ObservationEvidence,
    VALID_OBSERVATION_CATEGORIES,
    VALID_OBSERVATION_CONFIDENCES,
    VALID_OBSERVATION_SEVERITIES,
    VALID_OBSERVATION_STATUSES,
)

logger = logging.getLogger(__name__)

# RFC 6598 Shared Address Space (Carrier-Grade NAT)
RFC6598_NET = ipaddress.ip_network("100.64.0.0/10")

# Loopback resolver addresses commonly used by local caching resolvers (e.g. systemd-resolved)
STUB_RESOLVER_IPS = {"127.0.0.53", "127.0.0.54", "127.0.0.1", "::1"}

# Mapping from capability name to canonical collected_section name
CAPABILITY_TO_SECTION = {
    "interface_info": "interfaces",
    "routing_info": "routing",
    "dns_info": "dns",
    "dhcp_info": "dhcp",
    "wifi_info": "wifi",
    "neighbor_table": "neighbors",
    "socket_summary": "sockets",
    "public_ip": "public_ip",
    "connectivity": "connectivity",
    "pcap_analysis": "pcap_analysis",
    "linux_kernel_info": "linux_kernel_info",
}


@dataclass(frozen=True)
class ObservationContext:
    """Immutable collection execution scope context for observation analysis."""

    collected_sections: frozenset[str] = field(default_factory=frozenset)
    policy_disabled_sections: frozenset[str] = field(default_factory=frozenset)

    def is_collected(self, section: str) -> bool:
        return section in self.collected_sections

    def is_policy_disabled(self, section: str) -> bool:
        return section in self.policy_disabled_sections


class ObservationEngine:
    """Deterministic, passive observations and findings engine with scope awareness."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration options and thresholds from config file if not provided."""
        if not self.config:
            config_path = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
            if config_path.is_file():
                try:
                    import yaml

                    with open(config_path, "r", encoding="utf-8") as f:
                        self.config = yaml.safe_load(f) or {}
                except Exception as err:
                    logger.debug("Failed to read config from %s: %s", config_path, err)

        obs_cfg = self.config.get("observations", {})
        self.enabled: bool = obs_cfg.get("enabled", True)

        # PCAP observation thresholds
        pcap_cfg = obs_cfg.get("pcap", {})
        self.pcap_retrans_threshold: int = int(pcap_cfg.get("retransmission_notice_threshold", 1))
        self.pcap_reset_threshold: int = int(pcap_cfg.get("tcp_reset_notice_threshold", 1))

    def analyze(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | frozenset[str] | ObservationContext | None = None,
    ) -> list[Observation]:
        """Analyze a NetworkIntelligenceReport and return deterministic observations.

        Args:
            report: The normalized NetworkIntelligenceReport to analyze.
            collected_sections: Optional explicit set of subsystems actually executed during
                the collection run. If omitted/None, scope filtering is relaxed for testing.
        """
        if not self.enabled:
            return []

        # Normalize collected_sections
        scope: set[str] | None = None
        if isinstance(collected_sections, ObservationContext):
            scope = set(collected_sections.collected_sections)
        elif isinstance(collected_sections, (set, frozenset, list, tuple)):
            scope = set(collected_sections)

        rules: list[Callable[[NetworkIntelligenceReport, set[str] | None], list[Observation]]] = [
            self.observe_default_gateway_consistency,
            self.observe_routing_state,
            self.observe_dns_consistency,
            self.observe_ipv6_state,
            self.observe_public_identity,
            self.observe_neighbor_state,
            self.observe_socket_state,
            self.observe_connectivity_state,
            self.observe_pcap_state,
            self.observe_data_quality,
        ]

        raw_observations: list[Observation] = []
        for rule in rules:
            try:
                findings = rule(report, scope)
                if findings:
                    raw_observations.extend(findings)
            except Exception as err:
                logger.error("Error executing observation rule %s: %s", rule.__name__, err)
                raw_observations.append(
                    Observation(
                        id="DATA.COLLECTION.ERROR",
                        category="DATA_QUALITY",
                        severity="WARNING",
                        title=f"Error in observation rule {rule.__name__}",
                        summary=f"Observation rule {rule.__name__} failed during analysis: {err}",
                        details=str(err),
                        confidence="HIGH",
                        source_sections=["observations"],
                        evidence=[
                            ObservationEvidence(
                                source="observations",
                                field="rule",
                                value=rule.__name__,
                                description=str(err),
                            )
                        ],
                        related_entities=[rule.__name__],
                        status="OBSERVED",
                    )
                )

        # Apply suppression rules
        suppressed_observations = self._apply_suppressions(raw_observations, report)

        # Apply deduplication
        deduplicated = self._deduplicate(suppressed_observations)

        # Sort deterministically
        return self._sort_observations(deduplicated)

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 1: Gateway / Neighbor Correlation
    # ──────────────────────────────────────────────────────────────────────────
    def observe_default_gateway_consistency(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Correlate default gateway with neighbor table entries.

        Scope-aware: A matching/missing neighbor conclusion requires actual neighbor collection.
        If neighbors were not in collected_sections, returns [].
        """
        obs: list[Observation] = []

        # Scope check: Must have collected both routing and neighbors
        if collected_sections is not None:
            if "neighbors" not in collected_sections or "routing" not in collected_sections:
                return obs

        if not report.routing or not report.routing.default_ipv4:
            return obs

        gw = report.routing.default_ipv4.gateway
        if not gw or gw == "0.0.0.0":
            return obs

        gw_iface = report.routing.default_ipv4.interface or ""

        # Check if neighbor collection occurred
        has_neighbor_cap = False
        if report.capabilities:
            cap = report.capabilities.get("neighbor_table")
            if cap:
                has_neighbor_cap = getattr(cap, "status", "") in ("AVAILABLE", "PARTIAL") or (
                    isinstance(cap, dict) and cap.get("status") in ("AVAILABLE", "PARTIAL")
                )

        # If neighbor cache has matching entry
        matching_neighbor = None
        if report.neighbors:
            for n in report.neighbors:
                if n.ip_address == gw:
                    matching_neighbor = n
                    break

        if matching_neighbor:
            obs.append(
                Observation(
                    id="NETWORK.GATEWAY.NEIGHBOR_MATCH",
                    category="NETWORK",
                    severity="INFO",
                    confidence="HIGH",
                    title="Default IPv4 gateway has matching neighbor cache entry",
                    summary=f"Default gateway {gw} is present in the neighbor cache on interface {matching_neighbor.interface} with state {matching_neighbor.state}.",
                    details=f"Default gateway {gw} was resolved in the local ARP/neighbor cache on interface {matching_neighbor.interface} with MAC {matching_neighbor.mac_address} and state {matching_neighbor.state}.",
                    source_sections=["neighbors", "routing"],
                    related_entities=[gw, matching_neighbor.interface] if matching_neighbor.interface else [gw],
                    evidence=[
                        ObservationEvidence(
                            source="routing",
                            field="default_ipv4.gateway",
                            value=gw,
                            description=f"Default gateway {gw} on interface {gw_iface}",
                        ),
                        ObservationEvidence(
                            source="neighbors",
                            field="ip_address",
                            value=matching_neighbor.ip_address,
                            description=f"Neighbor MAC: {matching_neighbor.mac_address}, state: {matching_neighbor.state}",
                        ),
                    ],
                    status="OBSERVED",
                )
            )
        elif report.neighbors and has_neighbor_cap:
            # Neighbor collection succeeded and has entries, but no entry for gateway
            obs.append(
                Observation(
                    id="NETWORK.GATEWAY.NEIGHBOR_MISSING",
                    category="NETWORK",
                    severity="NOTICE",
                    confidence="MEDIUM",
                    title="Default IPv4 gateway has no matching neighbor cache entry",
                    summary=f"Default gateway {gw} exists in routing information but no matching neighbor-cache entry was observed.",
                    details=f"The host has default gateway {gw} configured on interface '{gw_iface}', but no matching entry was found in the local ARP/neighbor cache ({len(report.neighbors)} entries observed). This may be due to cache expiration, interface inactivity, or collection timing.",
                    source_sections=["neighbors", "routing"],
                    related_entities=[gw, gw_iface] if gw_iface else [gw],
                    evidence=[
                        ObservationEvidence(
                            source="routing",
                            field="default_ipv4.gateway",
                            value=gw,
                            description=f"Configured default gateway {gw}",
                        ),
                        ObservationEvidence(
                            source="neighbors",
                            field="entries_count",
                            value=len(report.neighbors),
                            description=f"Neighbor cache contains {len(report.neighbors)} entries, none matching {gw}",
                        ),
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 2: Routing Consistency
    # ──────────────────────────────────────────────────────────────────────────
    def observe_routing_state(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect routing state for default routes and consistency."""
        obs: list[Observation] = []

        if collected_sections is not None and "routing" not in collected_sections:
            return obs

        if not report.routing or getattr(report.routing, "status", "") in ("UNAVAILABLE", "ERROR"):
            return obs

        routing = report.routing

        # Check for NO default gateway
        has_v4_default = routing.default_ipv4 is not None and bool(routing.default_ipv4.gateway)
        has_v6_default = routing.default_ipv6 is not None and bool(routing.default_ipv6.gateway)

        if not has_v4_default and not has_v6_default:
            obs.append(
                Observation(
                    id="NETWORK.ROUTING.NO_DEFAULT_GATEWAY",
                    category="NETWORK",
                    severity="NOTICE",
                    confidence="HIGH",
                    title="No default gateway route configured",
                    summary="No active default gateway route (IPv4 or IPv6) was observed in the routing table.",
                    details="The host routing table does not contain an active default route (0.0.0.0/0 or ::/0). Direct connectivity to non-local subnets or the Internet may be unavailable.",
                    source_sections=["routing"],
                    related_entities=[],
                    evidence=[
                        ObservationEvidence(
                            source="routing",
                            field="default_ipv4",
                            value=None,
                            description="No default IPv4 route present",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        # Check for multiple active default routes
        if routing.routes:
            active_v4_defaults = [
                r
                for r in routing.routes
                if r.ip_version == 4
                and r.destination in ("0.0.0.0", "0.0.0.0/0", "default")
                and r.gateway
                and r.gateway != "0.0.0.0"
            ]
            unique_defaults = {(r.gateway, r.interface) for r in active_v4_defaults}
            if len(unique_defaults) > 1:
                gw_list = [f"{gw} ({iface})" for gw, iface in sorted(unique_defaults)]
                entities = [gw for gw, _ in sorted(unique_defaults)]
                obs.append(
                    Observation(
                        id="NETWORK.ROUTING.MULTIPLE_DEFAULTS",
                        category="NETWORK",
                        severity="NOTICE",
                        confidence="HIGH",
                        title=f"Multiple active default routes observed ({len(unique_defaults)})",
                        summary=f"Multiple ({len(unique_defaults)}) active default gateway routes were observed in routing configuration: {', '.join(gw_list)}.",
                        details="Multiple active default routes are configured across one or more interfaces. The operating system selects egress routes based on interface metrics and route priorities.",
                        source_sections=["routing"],
                        related_entities=entities,
                        evidence=[
                            ObservationEvidence(
                                source="routing",
                                field="default_routes_count",
                                value=len(unique_defaults),
                                description=f"Gateways: {', '.join(gw_list)}",
                            )
                        ],
                        status="OBSERVED",
                    )
                )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 3: DNS Consistency
    # ──────────────────────────────────────────────────────────────────────────
    def observe_dns_consistency(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect DNS configuration for stub resolvers and upstream availability."""
        obs: list[Observation] = []

        if collected_sections is not None and "dns" not in collected_sections:
            return obs

        if not report.dns or report.dns.status in ("UNAVAILABLE", "ERROR"):
            return obs

        dns = report.dns

        # 1. Local stub resolver
        stub_servers = []
        if dns.servers:
            for s in dns.servers:
                addr = s.address if hasattr(s, "address") else str(s)
                is_stub = getattr(s, "is_stub", False) or addr in STUB_RESOLVER_IPS
                if is_stub or addr.startswith("127.") or addr == "::1":
                    stub_servers.append(addr)

        if stub_servers:
            unique_stubs = sorted(set(stub_servers))
            obs.append(
                Observation(
                    id="NETWORK.DNS.STUB_RESOLVER",
                    category="NETWORK",
                    severity="INFO",
                    confidence="HIGH",
                    title="Local DNS stub resolver configured",
                    summary=f"DNS queries are directed to local stub resolver ({', '.join(unique_stubs)}).",
                    details=f"The host is configured with a system-local stub resolver ({', '.join(unique_stubs)}), typically managed by systemd-resolved or a local caching daemon. Queries are resolved or cached locally before upstream forwarding.",
                    source_sections=["dns"],
                    related_entities=unique_stubs,
                    evidence=[
                        ObservationEvidence(
                            source="dns",
                            field="servers",
                            value=unique_stubs,
                            description=f"Configured stub resolver(s): {', '.join(unique_stubs)}",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        # 2. No usable upstream DNS servers
        if not dns.servers and dns.status in ("CONFIGURED", "EMPTY"):
            obs.append(
                Observation(
                    id="NETWORK.DNS.NO_UPSTREAM",
                    category="NETWORK",
                    severity="NOTICE",
                    confidence="HIGH",
                    title="No upstream DNS servers configured",
                    summary="No usable DNS nameservers were found in host DNS configuration.",
                    details="The operating system DNS client does not have any configured upstream resolver addresses. Name resolution will fail unless handled by local static hosts files.",
                    source_sections=["dns"],
                    related_entities=[],
                    evidence=[
                        ObservationEvidence(
                            source="dns",
                            field="servers",
                            value=[],
                            description="DNS resolver list is empty",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 4: IPv6 State
    # ──────────────────────────────────────────────────────────────────────────
    def observe_ipv6_state(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect IPv6 address configuration and Internet connectivity status."""
        obs: list[Observation] = []

        if collected_sections is not None and "interfaces" not in collected_sections:
            return obs

        # Find global IPv6 addresses across interfaces
        global_v6_addrs: list[tuple[str, str]] = []
        ifaces = report.all_interfaces or ([report.selected_interface] if report.selected_interface else [])
        for iface in ifaces:
            if not iface:
                continue
            for v6 in iface.ipv6:
                clean_ip = v6.split("/")[0].split("%")[0].strip()
                try:
                    ip_obj = ipaddress.ip_address(clean_ip)
                    if ip_obj.version == 6 and not ip_obj.is_link_local and not ip_obj.is_loopback:
                        global_v6_addrs.append((clean_ip, iface.name))
                except ValueError:
                    pass

        # Only evaluate unverified IPv6 Internet connectivity if connectivity probe ran
        if collected_sections is None or "connectivity" in collected_sections:
            v6_conn_status = None
            if report.connectivity and report.connectivity.ipv6:
                v6_conn_status = report.connectivity.ipv6.status

            if global_v6_addrs:
                first_addr, first_iface = global_v6_addrs[0]
                if v6_conn_status and v6_conn_status != "SUCCESS":
                    obs.append(
                        Observation(
                            id="NETWORK.IPV6.CONFIGURED_NO_CONNECTIVITY",
                            category="NETWORK",
                            severity="INFO",
                            confidence="HIGH",
                            title="Global IPv6 configured without verified Internet connectivity",
                            summary=f"Interface '{first_iface}' has global IPv6 address {first_addr} configured, but IPv6 Internet connectivity was not observed.",
                            details=f"A routable IPv6 address ({first_addr}) is assigned to interface '{first_iface}', but active IPv6 connectivity probe returned '{v6_conn_status}'. External IPv6 routing or upstream connectivity may be inactive.",
                            source_sections=["interfaces", "connectivity"],
                            related_entities=[first_addr, first_iface],
                            evidence=[
                                ObservationEvidence(
                                    source="interfaces",
                                    field="ipv6",
                                    value=first_addr,
                                    description=f"Global IPv6 address on {first_iface}",
                                ),
                                ObservationEvidence(
                                    source="connectivity",
                                    field="ipv6.status",
                                    value=v6_conn_status,
                                    description=f"IPv6 connectivity test status: {v6_conn_status}",
                                ),
                            ],
                            status="OBSERVED",
                        )
                    )

        # Check for dual-stack public identity (only if public_ip in scope)
        if collected_sections is None or "public_ip" in collected_sections:
            if report.public_ip and report.public_ip.status in ("SUCCESS", "AVAILABLE"):
                v4_pub = report.public_ip.ip
                v6_pub = getattr(report.public_ip, "ipv6", None)
                if v4_pub and v6_pub:
                    obs.append(
                        Observation(
                            id="NETWORK.PUBLIC_IDENTITY.DUAL_STACK",
                            category="PUBLIC_IDENTITY",
                            severity="INFO",
                            confidence="HIGH",
                            title="Dual-stack public Internet connectivity observed",
                            summary=f"Both public IPv4 ({v4_pub}) and IPv6 ({v6_pub}) addresses were observed.",
                            details=f"The host possesses active public egress connectivity across both IPv4 ({v4_pub}) and IPv6 ({v6_pub}) protocols.",
                            source_sections=["public_ip"],
                            related_entities=[v4_pub, v6_pub],
                            evidence=[
                                ObservationEvidence(
                                    source="public_ip",
                                    field="ip",
                                    value=v4_pub,
                                    description=f"Public IPv4 address: {v4_pub}",
                                ),
                                ObservationEvidence(
                                    source="public_ip",
                                    field="ipv6",
                                    value=v6_pub,
                                    description=f"Public IPv6 address: {v6_pub}",
                                ),
                            ],
                            status="OBSERVED",
                        )
                    )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 5: Public Identity Observations
    # ──────────────────────────────────────────────────────────────────────────
    def observe_public_identity(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect local and public IP configurations for CGNAT and address characteristics."""
        obs: list[Observation] = []

        if collected_sections is not None and "interfaces" not in collected_sections:
            return obs

        # Check for RFC 6598 Carrier-Grade NAT (CGNAT) address space (100.64.0.0/10)
        cgnat_addrs: list[tuple[str, str]] = []
        ifaces = report.all_interfaces or ([report.selected_interface] if report.selected_interface else [])
        for iface in ifaces:
            if not iface:
                continue
            for v4 in iface.ipv4:
                clean_ip = v4.split("/")[0].strip()
                try:
                    ip_obj = ipaddress.ip_address(clean_ip)
                    if ip_obj.version == 4 and ip_obj in RFC6598_NET:
                        cgnat_addrs.append((clean_ip, iface.name))
                except ValueError:
                    pass

        if cgnat_addrs:
            addr, iface_name = cgnat_addrs[0]
            obs.append(
                Observation(
                    id="NETWORK.PUBLIC_IDENTITY.CGNAT",
                    category="PUBLIC_IDENTITY",
                    severity="INFO",
                    confidence="HIGH",
                    title="Local IPv4 address is within RFC 6598 Shared Address Space",
                    summary=f"The selected local IPv4 address {addr} on interface '{iface_name}' is within RFC 6598 Shared Address Space (100.64.0.0/10).",
                    details=f"The host's interface '{iface_name}' has assigned address {addr}, which belongs to the RFC 6598 Carrier-Grade NAT (CGNAT) allocation. Upstream network address translation is performed before public Internet egress.",
                    source_sections=["interfaces", "network"],
                    related_entities=[addr, iface_name],
                    evidence=[
                        ObservationEvidence(
                            source="interfaces",
                            field="ipv4",
                            value=addr,
                            description=f"Interface {iface_name} assigned {addr} in 100.64.0.0/10",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 6: Neighbor Observations
    # ──────────────────────────────────────────────────────────────────────────
    def observe_neighbor_state(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect neighbor/ARP table for empty state, routers, and incomplete entries.

        Scope-aware: If neighbors was not in collected_sections, returns [].
        """
        obs: list[Observation] = []

        # Scope guard: Do not interpret uncollected neighbors as empty!
        if collected_sections is not None and "neighbors" not in collected_sections:
            return []

        # Check if neighbor capability is present
        has_neighbor_cap = False
        if report.capabilities:
            cap = report.capabilities.get("neighbor_table")
            if cap:
                has_neighbor_cap = getattr(cap, "status", "") in ("AVAILABLE", "PARTIAL") or (
                    isinstance(cap, dict) and cap.get("status") in ("AVAILABLE", "PARTIAL")
                )

        if not has_neighbor_cap and not report.neighbors and collected_sections is None:
            return obs

        # 1. Executed and empty neighbor table
        if not report.neighbors:
            if report.collection_errors and "neighbors" in report.collection_errors:
                return obs
            obs.append(
                Observation(
                    id="NETWORK.NEIGHBOR.EMPTY",
                    category="NETWORK",
                    severity="INFO",
                    confidence="HIGH",
                    title="Local neighbor cache is empty",
                    summary="No neighbor or ARP entries were observed in the host cache.",
                    details="The operating system neighbor table contains zero entries. This is common when an interface is newly connected, idle, or when the ARP/ND cache was recently flushed.",
                    source_sections=["neighbors"],
                    related_entities=[],
                    evidence=[
                        ObservationEvidence(
                            source="neighbors",
                            field="count",
                            value=0,
                            description="0 entries in neighbor cache",
                        )
                    ],
                    status="OBSERVED",
                )
            )
            return obs

        # 2. Router entries observed
        router_entries = [n for n in report.neighbors if getattr(n, "is_router", False)]
        if router_entries:
            for r in router_entries[:3]:
                obs.append(
                    Observation(
                        id="NETWORK.NEIGHBOR.ROUTER_OBSERVED",
                        category="NETWORK",
                        severity="INFO",
                        confidence="HIGH",
                        title=f"Neighbor router flag observed for {r.ip_address}",
                        summary=f"Neighbor entry {r.ip_address} ({r.mac_address}) is marked as a router on interface '{r.interface}'.",
                        details=f"Operating system neighbor discovery identified {r.ip_address} on interface '{r.interface}' as an active network router.",
                        source_sections=["neighbors"],
                        related_entities=[r.ip_address, r.interface] if r.interface else [r.ip_address],
                        evidence=[
                            ObservationEvidence(
                                source="neighbors",
                                field="is_router",
                                value=True,
                                description=f"Router flag True on {r.ip_address} ({r.mac_address})",
                            )
                        ],
                        status="OBSERVED",
                    )
                )

        # 3. Incomplete / Failed neighbor entries
        incomplete_entries = [
            n for n in report.neighbors if getattr(n, "state", "").upper() in ("INCOMPLETE", "FAILED")
        ]
        if incomplete_entries:
            ips = [e.ip_address for e in incomplete_entries]
            obs.append(
                Observation(
                    id="NETWORK.NEIGHBOR.INCOMPLETE",
                    category="NETWORK",
                    severity="NOTICE",
                    confidence="HIGH",
                    title=f"Incomplete neighbor cache entries observed ({len(incomplete_entries)})",
                    summary=f"Observed {len(incomplete_entries)} neighbor entry/entries with INCOMPLETE or FAILED state: {', '.join(ips[:3])}.",
                    details=f"Address resolution did not complete for {len(incomplete_entries)} target IP(s). The targets may be offline, non-responsive, or blocked by local packet filters.",
                    source_sections=["neighbors"],
                    related_entities=ips[:5],
                    evidence=[
                        ObservationEvidence(
                            source="neighbors",
                            field="incomplete_count",
                            value=len(incomplete_entries),
                            description=f"{len(incomplete_entries)} entries in INCOMPLETE/FAILED state",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 7: Socket Observations
    # ──────────────────────────────────────────────────────────────────────────
    def observe_socket_state(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect listening sockets and process visibility permissions.

        Scope-aware: If sockets was not in collected_sections, returns [].
        """
        obs: list[Observation] = []

        # Scope guard: Do not reason about uncollected sockets
        if collected_sections is not None and "sockets" not in collected_sections:
            return []

        if not report.sockets:
            return obs

        # 1. Listening sockets
        listening = [s for s in report.sockets if getattr(s, "state", "").upper() in ("LISTEN", "LISTENING")]
        if listening:
            tcp_listen = sum(1 for s in listening if getattr(s, "protocol", "").upper().startswith("TCP"))
            udp_listen = sum(1 for s in listening if getattr(s, "protocol", "").upper().startswith("UDP"))
            ports = sorted({f"{s.local_address}:{s.local_port}" for s in listening})
            obs.append(
                Observation(
                    id="HOST.SOCKET.LISTENING",
                    category="HOST",
                    severity="INFO",
                    confidence="HIGH",
                    title=f"Local listening sockets observed ({len(listening)})",
                    summary=f"Observed {len(listening)} local listening socket(s) ({tcp_listen} TCP, {udp_listen} UDP).",
                    details=f"The host has {len(listening)} listening endpoint(s) open to local or external network connections across protocols TCP ({tcp_listen}) and UDP ({udp_listen}).",
                    source_sections=["sockets"],
                    related_entities=ports[:5],
                    evidence=[
                        ObservationEvidence(
                            source="sockets",
                            field="listening_count",
                            value=len(listening),
                            description=f"{len(listening)} sockets in LISTEN state",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        # 2. Process attribution unknown / restricted
        unknown_procs = [
            s
            for s in report.sockets
            if getattr(s, "pid", None) is None and getattr(s, "process_name", None) is None
        ]
        if unknown_procs:
            entities = sorted({f"{s.local_address}:{s.local_port}" for s in unknown_procs})
            obs.append(
                Observation(
                    id="HOST.SOCKET.PROCESS_UNKNOWN",
                    category="HOST",
                    severity="NOTICE",
                    confidence="HIGH",
                    title=f"Socket process ownership unmapped ({len(unknown_procs)} sockets)",
                    summary=f"{len(unknown_procs)} socket entries do not expose process ownership under current OS permissions.",
                    details="Process attribution (PID and executable name) is restricted by operating system security policies for unprivileged users. Run with administrative or root privileges to view all socket process bindings.",
                    source_sections=["sockets"],
                    related_entities=entities[:5],
                    evidence=[
                        ObservationEvidence(
                            source="sockets",
                            field="unknown_process_count",
                            value=len(unknown_procs),
                            description=f"{len(unknown_procs)} sockets without PID or process attribution",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 8: Connectivity Observations
    # ──────────────────────────────────────────────────────────────────────────
    def observe_connectivity_state(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | None = None,
    ) -> list[Observation]:
        """Inspect connectivity diagnostic probe results."""
        obs: list[Observation] = []

        if collected_sections is not None and "connectivity" not in collected_sections:
            return obs

        if not report.connectivity:
            return obs

        conn = report.connectivity

        # 1. Gateway probe
        if conn.gateway:
            gw = conn.gateway
            if gw.status == "SUCCESS":
                latency_str = f"{gw.latency_ms:.1f} ms" if gw.latency_ms is not None else "measured"
                obs.append(
                    Observation(
                        id="CONNECTIVITY.GATEWAY_REACHABLE",
                        category="CONNECTIVITY",
                        severity="INFO",
                        confidence="HIGH",
                        title=f"Default gateway {gw.target} is reachable",
                        summary=f"ICMP ping probe to default gateway {gw.target} succeeded (latency: {latency_str}).",
                        details=f"Round-trip latency to gateway {gw.target} was measured at {latency_str} with 0% packet loss.",
                        source_sections=["connectivity"],
                        related_entities=[gw.target] if gw.target else [],
                        evidence=[
                            ObservationEvidence(
                                source="connectivity",
                                field="gateway.status",
                                value="SUCCESS",
                                description=f"Gateway latency: {latency_str}",
                            )
                        ],
                        status="OBSERVED",
                    )
                )
            elif gw.status in ("FAILED", "TIMEOUT"):
                obs.append(
                    Observation(
                        id="CONNECTIVITY.GATEWAY_UNREACHABLE",
                        category="CONNECTIVITY",
                        severity="NOTICE",
                        confidence="HIGH",
                        title=f"Default gateway {gw.target} probe failed ({gw.status})",
                        summary=f"Gateway {gw.target} did not respond to ICMP ping probe ({gw.status}).",
                        details=f"Gateway probe returned {gw.status}. ICMP echo requests may be blocked by a local firewall, gateway ACLs, or the gateway may be non-responsive.",
                        source_sections=["connectivity"],
                        related_entities=[gw.target] if gw.target else [],
                        evidence=[
                            ObservationEvidence(
                                source="connectivity",
                                field="gateway.status",
                                value=gw.status,
                                description=gw.details or "Gateway ping did not succeed",
                            )
                        ],
                        status="OBSERVED",
                    )
                )

        # 2. DNS probe
        if conn.dns:
            d = conn.dns
            if d.status == "SUCCESS":
                latency_str = f"{d.latency_ms:.1f} ms" if d.latency_ms is not None else "measured"
                obs.append(
                    Observation(
                        id="CONNECTIVITY.DNS_AVAILABLE",
                        category="CONNECTIVITY",
                        severity="INFO",
                        confidence="HIGH",
                        title="External DNS resolution succeeded",
                        summary=f"DNS query probe succeeded (latency: {latency_str}).",
                        details=f"DNS queries to configured test hosts resolved successfully in {latency_str}.",
                        source_sections=["connectivity"],
                        related_entities=[d.target] if d.target else [],
                        evidence=[
                            ObservationEvidence(
                                source="connectivity",
                                field="dns.status",
                                value="SUCCESS",
                                description=f"DNS latency: {latency_str}",
                            )
                        ],
                        status="OBSERVED",
                    )
                )

        # 3. HTTP probe
        if conn.internet:
            http_probe = conn.internet
            if http_probe.status == "SUCCESS":
                obs.append(
                    Observation(
                        id="CONNECTIVITY.HTTP_AVAILABLE",
                        category="CONNECTIVITY",
                        severity="INFO",
                        confidence="HIGH",
                        title="Internet HTTP connectivity verified",
                        summary=f"HTTP probe to {http_probe.target} succeeded (status: {http_probe.http_status or 200}).",
                        details=f"HTTP reachability check to {http_probe.target} completed successfully with HTTP status {http_probe.http_status or 200}.",
                        source_sections=["connectivity"],
                        related_entities=[http_probe.target] if http_probe.target else [],
                        evidence=[
                            ObservationEvidence(
                                source="connectivity",
                                field="internet.status",
                                value="SUCCESS",
                                description=f"HTTP status {http_probe.http_status}",
                            )
                        ],
                        status="OBSERVED",
                    )
                )

        # 4. IPv6 probe
        if conn.ipv6 and conn.ipv6.status in ("FAILED", "TIMEOUT", "UNAVAILABLE"):
            obs.append(
                Observation(
                    id="CONNECTIVITY.IPV6_NOT_OBSERVED",
                    category="CONNECTIVITY",
                    severity="INFO",
                    confidence="HIGH",
                    title="IPv6 Internet connectivity not observed",
                    summary="IPv6 connectivity test did not establish external connectivity.",
                    details=f"IPv6 connectivity test status was '{conn.ipv6.status}'. External IPv6 routing may not be enabled or supported by the local network or ISP.",
                    source_sections=["connectivity"],
                    related_entities=[],
                    evidence=[
                        ObservationEvidence(
                            source="connectivity",
                            field="ipv6.status",
                            value=conn.ipv6.status,
                            description=conn.ipv6.details or "IPv6 probe was not successful",
                        )
                    ],
                    status="OBSERVED",
                )
            )

        return obs

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 9: PCAP Observations
    # ──────────────────────────────────────────────────────────────────────────
