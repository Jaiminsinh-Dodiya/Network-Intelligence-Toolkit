"""Core Collector Coordinator.

Orchestrates data collection using the active platform backend, normalizes
results, and packages them into the final NetworkIntelligenceReport.

Execution is phase-aware: collectors whose toolkit roadmap status is PLANNED
are cleanly skipped until their respective phases are implemented.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from core.models import (
    ConnectivityInfo,
    DhcpInfo,
    DnsInfo,
    InterfaceInfo,
    NeighborEntry,
    NetworkInfo,
    NetworkIntelligenceReport,
    PcapAnalysisInfo,
    PublicIpInfo,
    RoutingInfo,
    SocketEntry,
    SystemInfo,
    WifiInfo,
)
from core.observations import ObservationEngine
from core.registry import CollectorOptions

if TYPE_CHECKING:
    from backends.base import BasePlatformBackend

logger = logging.getLogger(__name__)


class CollectorCoordinator:
    """Orchestrates multi-domain data collection across platform backends with phase-awareness."""

    def __init__(
        self,
        backend: BasePlatformBackend,
        options: CollectorOptions,
        config: dict | None = None,
    ) -> None:
        self.backend = backend
        self.options = options
        self.config = config

    def collect(self) -> NetworkIntelligenceReport:
        """Execute configured and implemented collectors with graceful degradation."""
        logger.info(
            "Starting collection on platform: %s (quick_mode=%s, full_mode=%s)",
            self.backend.get_platform_name(),
            self.options.quick_mode,
            self.options.full_mode,
        )
        collection_errors: dict[str, str] = {}
        collected_sections: set[str] = {"system", "capabilities"}

        # 1. Platform & System info (always collected)
        try:
            system_info = self.backend.get_platform_info()
        except Exception as err:
            logger.error("Failed to collect system info: %s", err)
            collection_errors["system_info"] = str(err)
            system_info = SystemInfo(
                os_name="Unknown",
                os_version="Unknown",
                platform_release="Unknown",
                hostname="localhost",
                architecture="Unknown",
                python_version="3.x",
                is_privileged=False,
            )

        # 2. Capabilities (always collected)
        capabilities_map = {}
        try:
            capabilities_map = self.backend.detect_capabilities()
            capabilities = {name: entry.to_dict() for name, entry in capabilities_map.items()}
        except Exception as err:
            logger.error("Failed to detect capabilities: %s", err)
            collection_errors["capabilities"] = str(err)
            capabilities = {}

        def is_implemented(name: str) -> bool:
            entry = capabilities_map.get(name)
            if not entry:
                return False
            # Entry can be a CapabilityEntry object or a dictionary
            if hasattr(entry, "is_implemented"):
                return entry.is_implemented()
            if isinstance(entry, dict):
                return str(entry.get("toolkit_status", "")).startswith("IMPLEMENTED")
            return False

        # 3. Routing (Phase 3: IMPLEMENTED; included in quick/default/full modes)
        routing_info: RoutingInfo | None = None
        if self.options.should_collect_routing() and is_implemented("routing_info"):
            collected_sections.add("routing")
            try:
                routing_info = self.backend.get_routes()
            except Exception as err:
                logger.error("Failed to collect routing info: %s", err)
                collection_errors["routing"] = str(err)

        # 4. Interfaces (Phase 1 & 2: IMPLEMENTED)
        all_interfaces: list[InterfaceInfo] = []
        selected_iface: InterfaceInfo | None = None
        if is_implemented("interface_info"):
            collected_sections.add("interfaces")
            try:
                all_interfaces = self.backend.get_interfaces(target_iface=self.options.interface)
                if self.options.interface:
                    for iface in all_interfaces:
                        if iface.name.lower() == self.options.interface.lower():
                            selected_iface = iface
                            break
                if not selected_iface and all_interfaces:
                    from core.network import select_default_interface
                    default_route_iface = None
                    if routing_info:
                        default_route_iface = (
                            routing_info.preferred_interface
                            or routing_info.default_interface
                            or routing_info.default_interface_v6
                        )
                    selected_iface = select_default_interface(all_interfaces, default_route_iface=default_route_iface)
            except Exception as err:
                logger.error("Failed to collect interfaces: %s", err)
                collection_errors["interfaces"] = str(err)

        # 5. DNS (Phase 3: IMPLEMENTED; excluded in quick mode)
        dns_info: DnsInfo | None = None
        if self.options.should_collect_dns() and is_implemented("dns_info"):
            collected_sections.add("dns")
            try:
                dns_info = self.backend.get_dns()
            except Exception as err:
                logger.error("Failed to collect DNS info: %s", err)
                collection_errors["dns"] = str(err)

        # 6. DHCP (Phase 4: IMPLEMENTED; excluded in quick mode)
        dhcp_info: DhcpInfo | None = None
        if self.options.should_collect_dhcp() and is_implemented("dhcp_info"):
            collected_sections.add("dhcp")
            try:
                iface_name = self.options.interface or (selected_iface.name if selected_iface else None)
                dhcp_info = self.backend.get_dhcp(interface_name=iface_name)
            except Exception as err:
                logger.error("Failed to collect DHCP info: %s", err)
                collection_errors["dhcp"] = str(err)
                dhcp_info = DhcpInfo(available=False)

        # 7. Wi-Fi (Phase 4: IMPLEMENTED; included in full mode or --wifi, excluded in quick mode)
        wifi_info: WifiInfo | None = None
        if self.options.should_collect_wifi() and is_implemented("wifi_info"):
            collected_sections.add("wifi")
            try:
                # If explicit interface was provided, it is authoritative (no replacement)
                # If no interface was specified, pass None so backend discovers the active wireless adapter
                target_wifi_iface = self.options.interface if self.options.interface else None
                wifi_info = self.backend.get_wifi(interface_name=target_wifi_iface)
            except Exception as err:
                logger.error("Failed to collect Wi-Fi info: %s", err)
                collection_errors["wifi"] = str(err)

        # 8. Neighbors (Phase 7: IMPLEMENTED; included in full mode or --neighbors, excluded in quick mode)
        neighbors: list[NeighborEntry] = []
        if self.options.should_collect_neighbors() and is_implemented("neighbor_table"):
            collected_sections.add("neighbors")
            try:
                target_iface = self.options.interface if self.options.interface else None
                neighbors = self.backend.get_neighbors(interface_name=target_iface, routing=routing_info)
            except Exception as err:
                logger.error("Failed to collect neighbor table: %s", err)
                collection_errors["neighbors"] = str(err)

        # 9. Sockets (Phase 7: IMPLEMENTED; included in full mode or --sockets, excluded in quick mode)
        sockets: list[SocketEntry] = []
        if self.options.should_collect_sockets() and is_implemented("socket_summary"):
            collected_sections.add("sockets")
            try:
                sockets = self.backend.get_sockets()
            except Exception as err:
                logger.error("Failed to collect socket summary: %s", err)
                collection_errors["sockets"] = str(err)

        # Determine primary network and aggregate all networks
        primary_network: NetworkInfo | None = None
        all_networks: list[NetworkInfo] = []
        for iface in all_interfaces:
            all_networks.extend(iface.networks)

        if selected_iface and selected_iface.networks:
            # Prefer first non-link-local IPv4 network, otherwise first network
            for net in selected_iface.networks:
                if net.ip_version == 4 and net.scope not in ("LINK_LOCAL", "LOOPBACK"):
                    primary_network = net
                    break
            if not primary_network:
                primary_network = selected_iface.networks[0]

        # 10. Public Internet Identity & ASN (Phase 5: IMPLEMENTED; excluded in quick mode, respects --no-internet)
        public_ip: PublicIpInfo | None = None
        if self.options.should_collect_public_ip() and is_implemented("public_ip"):
            collected_sections.add("public_ip")
            try:
                public_ip = self.backend.get_public_ip(
                    selected_iface=selected_iface,
                    no_internet=self.options.no_internet,
                )
            except Exception as err:
                logger.error("Failed to collect public internet identity: %s", err)
                collection_errors["public_ip"] = str(err)
                public_ip = PublicIpInfo(
                    available=False,
                    status="ERROR",
                    reason=str(err),
                )

        # 11. Safe Connectivity Probes (Phase 6: IMPLEMENTED; excluded in quick mode, respects --no-internet)
        connectivity: ConnectivityInfo | None = None
        if self.options.should_collect_connectivity() and is_implemented("connectivity"):
            collected_sections.add("connectivity")
            try:
                connectivity = self.backend.get_connectivity(
                    selected_iface=selected_iface,
                    routing=routing_info,
                    dns=dns_info,
                    no_internet=self.options.no_internet,
                )
            except Exception as err:
                logger.error("Failed to collect connectivity: %s", err)
                collection_errors["connectivity"] = str(err)
                connectivity = ConnectivityInfo()

        # 12. PCAP/PCAPNG Analysis (Phase 8: IMPLEMENTED; offline capture analysis)
        pcap_analysis: PcapAnalysisInfo | None = None
        if self.options.should_analyze_pcap() and is_implemented("pcap_analysis"):
            collected_sections.add("pcap_analysis")
            try:
                pcap_analysis = self.backend.analyze_pcap(
                    capture_path=Path(self.options.pcap_path),
                    display_filter=self.options.pcap_filter,
                    config=self.config,
                )
            except Exception as err:
                logger.error("Failed to analyze PCAP: %s", err)
                collection_errors["pcap_analysis"] = str(err)
                pcap_analysis = PcapAnalysisInfo(
                    file_path=str(self.options.pcap_path) if self.options.pcap_path else "",
                    status="ERROR",
                    reason=str(err),
                )

        # 13. Assemble report
        report = NetworkIntelligenceReport(
            system=system_info,
            capabilities=capabilities,
            collection_errors=collection_errors,
            selected_interface=selected_iface,
            all_interfaces=all_interfaces,
            network=primary_network,
            all_networks=all_networks,
            routing=routing_info,
            dns=dns_info,
            dhcp=dhcp_info,
            wifi=wifi_info,
            public_ip=public_ip,
            connectivity=connectivity,
            neighbors=neighbors,
            sockets=sockets,
            pcap=pcap_analysis,
            pcap_analysis=pcap_analysis,
            observations=[],  # Populated below
        )

        # 14. Phase 9: Observations & Findings Engine (passive in-memory analysis)
        try:
            engine = ObservationEngine(config=self.config)
            report.observations = engine.analyze(report, collected_sections=collected_sections)
        except Exception as err:
            logger.error("Failed to generate observations: %s", err)
            collection_errors["observations"] = str(err)

        return report
