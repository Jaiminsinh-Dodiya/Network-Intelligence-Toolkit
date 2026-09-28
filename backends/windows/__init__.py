"""Windows Platform Backend implementation for Network Intelligence Toolkit."""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import re
import socket
from datetime import datetime, timezone
from typing import Any

from backends.base import BasePlatformBackend
from core.capabilities import CapabilityEntry, CapabilityStatus
from core.execution import is_tool_available, run_command
from core.models import (
    ConnectivityTarget,
    DhcpInfo,
    DnsInfo,
    DnsServer,
    InterfaceInfo,
    NeighborEntry,
    RouteEntry,
    RoutingInfo,
    SocketEntry,
    SystemInfo,
    WifiInfo,
)
from core.network import (
    calculate_network_info,
    channel_to_frequency,
    deduplicate_neighbors,
    is_gateway_match,
    normalize_bssid,
    normalize_ip_string,
    normalize_wifi_security,
    normalize_wifi_standard,
    select_default_interface,
    signal_dbm_to_percent,
    signal_percent_to_dbm,
    sort_neighbors,
    sort_sockets,
)
from core.permissions import is_privileged

logger = logging.getLogger(__name__)


class WindowsBackend(BasePlatformBackend):
    """Windows 10/11 platform backend using native commands, PowerShell, and psutil."""

    def __init__(self) -> None:
        self._privileged = is_privileged()

    def get_platform_name(self) -> str:
        return "Windows"

    def get_platform_info(self) -> SystemInfo:
        return SystemInfo(
            os_name=f"Windows {platform.release()}",
            os_version=platform.version(),
            platform_release=platform.release(),
            hostname=socket.gethostname(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            is_privileged=self._privileged,
        )

    def detect_capabilities(self) -> dict[str, CapabilityEntry]:
        has_powershell = is_tool_available("powershell") or is_tool_available("pwsh")
        has_tshark = self.get_tshark_path() is not None
        has_netsh = is_tool_available("netsh")

        caps: list[CapabilityEntry] = [
            CapabilityEntry(
                name="interface_info",
                status=CapabilityStatus.AVAILABLE,
                description="Network adapter configuration and statistics",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 2)",
            ),
            CapabilityEntry(
                name="routing_info",
                status=CapabilityStatus.AVAILABLE if has_powershell else CapabilityStatus.PARTIAL,
                description="Routing table and default gateway",
                reason=None if has_powershell else "PowerShell not found; fallback routing only",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 3)",
            ),
            CapabilityEntry(
                name="dns_info",
                status=CapabilityStatus.AVAILABLE if has_powershell else CapabilityStatus.PARTIAL,
                description="DNS client server configuration",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 3)",
            ),
            CapabilityEntry(
                name="dhcp_info",
                status=CapabilityStatus.AVAILABLE if has_powershell else CapabilityStatus.PARTIAL,
                description="DHCP server and lease information",
                reason=None if has_powershell else "PowerShell not found; WMI lease query unavailable",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 4)",
            ),
            CapabilityEntry(
                name="wifi_info",
                status=CapabilityStatus.AVAILABLE if has_netsh else CapabilityStatus.UNAVAILABLE,
                description="Wi-Fi link state, SSID, BSSID, and signal metrics",
                reason=None if has_netsh else "netsh utility not found",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 4)",
            ),
            CapabilityEntry(
                name="public_ip",
                status=CapabilityStatus.AVAILABLE,
                description="Observed public IP, ASN, and geo-identity lookup with privacy-safe fallback",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 5)",
            ),
            CapabilityEntry(
                name="connectivity",
                status=CapabilityStatus.AVAILABLE,
                description="Safe connectivity diagnostic probes (gateway ping, DNS latency, HTTP reachability, IPv4/IPv6)",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 6)",
            ),
            CapabilityEntry(
                name="neighbor_table",
                status=CapabilityStatus.AVAILABLE if has_powershell else CapabilityStatus.UNAVAILABLE,
                description="ARP / neighbor cache table",
                reason=None if has_powershell else "PowerShell not found; Get-NetNeighbor unavailable",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 7)",
            ),
            CapabilityEntry(
                name="socket_summary",
                status=CapabilityStatus.AVAILABLE if self._privileged else CapabilityStatus.PARTIAL,
                description="Local TCP/UDP listening and established sockets",
                reason=None if self._privileged else "Administrator privilege required to view process names of all sockets",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 7)",
            ),
            CapabilityEntry(
                name="pcap_analysis",
                status=CapabilityStatus.AVAILABLE if has_tshark else CapabilityStatus.MISSING_DEPENDENCY,
                description="Authorized PCAP/PCAPNG packet analysis via TShark",
                reason=None if has_tshark else "TShark is not installed or not in PATH",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 8)",
            ),
            CapabilityEntry(
                name="observations",
                status=CapabilityStatus.AVAILABLE,
                description="Observations & findings engine (passive evidence correlation and analysis)",
                platform="Windows",
                toolkit_status="IMPLEMENTED (Phase 9)",
            ),
            CapabilityEntry(
                name="linux_kernel_info",
                status=CapabilityStatus.NOT_APPLICABLE,
                description="Linux kernel (/proc and /sys) metrics",
                reason="Feature is specific to Linux platforms",
                platform="Windows",
                toolkit_status="NOT_APPLICABLE",
            ),
        ]
        return {entry.name: entry for entry in caps}

    def _get_powershell_ipv6_prefixes(self) -> dict[str, int]:
        """Query PowerShell Get-NetIPAddress for accurate IPv6 prefix lengths on Windows."""
        prefixes: dict[str, int] = {}
        try:
            import json
            from core.execution import run_command
            from core.network import normalize_ip_string

            res = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    ip_str = item.get("IPAddress")
                    prefix = item.get("PrefixLength")
                    if ip_str and prefix is not None:
                        clean_ip = normalize_ip_string(str(ip_str)).lower()
                        prefixes[clean_ip] = int(prefix)
        except Exception as err:
            logger.debug("PowerShell Get-NetIPAddress query failed: %s", err)
        return prefixes

    def get_interfaces(self, target_iface: str | None = None) -> list[InterfaceInfo]:
        import psutil
        from core.network import normalize_ip_string

        results: list[InterfaceInfo] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        ipv6_prefixes = self._get_powershell_ipv6_prefixes()

        for iface_name, addr_list in addrs.items():
            if target_iface and iface_name.lower() != target_iface.lower():
                continue

            info = InterfaceInfo(name=iface_name)
            stat = stats.get(iface_name)
            if stat:
                info.is_up = stat.isup
                info.state = "UP" if stat.isup else "DOWN"
                info.mtu = stat.mtu
                info.speed_mbps = stat.speed

            io = io_counters.get(iface_name)
            if io:
                info.rx_bytes = io.bytes_recv
                info.tx_bytes = io.bytes_sent
                info.rx_packets = io.packets_recv
                info.tx_packets = io.packets_sent
                info.rx_errors = io.errin
                info.tx_errors = io.errout
                info.rx_dropped = io.dropin
                info.tx_dropped = io.dropout

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    info.ipv4.append(addr.address)
                    net_info = calculate_network_info(
                        address_str=addr.address,
                        netmask_or_prefix=addr.netmask,
                        interface_name=iface_name,
                    )
                    if net_info:
                        info.networks.append(net_info)
                elif hasattr(socket, "AF_INET6") and addr.family == socket.AF_INET6:
                    info.ipv6.append(addr.address)
                    clean_v6 = normalize_ip_string(addr.address).lower()
                    prefix_val = ipv6_prefixes.get(clean_v6)
                    if prefix_val is None and addr.netmask:
                        try:
                            # If netmask is given as hex string or prefix
                            prefix_val = int(addr.netmask)
                        except ValueError:
                            prefix_val = None
                    net_info = calculate_network_info(
                        address_str=addr.address,
                        netmask_or_prefix=prefix_val,
                        interface_name=iface_name,
                    )
                    if net_info:
                        info.networks.append(net_info)
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    info.mac = addr.address

            info.is_loopback = "loopback" in iface_name.lower() or any(a.startswith("127.") for a in info.ipv4)
            info.is_wireless = "wi-fi" in iface_name.lower() or "wireless" in iface_name.lower() or "wlan" in iface_name.lower()
            results.append(info)

        return results

    def get_default_interface(self) -> InterfaceInfo | None:
        """Determine and return the primary active network interface using Phase 2 contract."""
        interfaces = self.get_interfaces()
        return select_default_interface(interfaces)

    def get_routes(self) -> RoutingInfo:
        """Collect Windows routing table using Get-NetRoute and Get-NetIPInterface."""
        import json
        from core.execution import run_command
        from core.network import normalize_ip_string

        # 1. Collect interface metrics from Get-NetIPInterface
        iface_metrics: dict[tuple[int, int], int] = {}
        iface_metrics_by_idx: dict[int, int] = {}
        try:
            res_if = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetIPInterface -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, AddressFamily, InterfaceMetric | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_if.returncode == 0 and res_if.stdout.strip():
                data_if = json.loads(res_if.stdout)
                if isinstance(data_if, dict):
                    data_if = [data_if]
                for item in data_if:
                    idx = item.get("InterfaceIndex")
                    fam = item.get("AddressFamily")
                    m = item.get("InterfaceMetric")
                    if idx is not None and m is not None:
                        iface_metrics_by_idx[int(idx)] = int(m)
                        if fam is not None:
                            iface_metrics[(int(idx), int(fam))] = int(m)
        except Exception as err:
            logger.debug("Failed querying Get-NetIPInterface: %s", err)

        # 2. Collect routes from Get-NetRoute
        routes_v4: list[RouteEntry] = []
        routes_v6: list[RouteEntry] = []
        try:
            res_rt = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, InterfaceIndex, InterfaceAlias, RouteMetric, Protocol, @{Name='State';Expression={$_.State.ToString()}}, PolicyStore, AddressFamily | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_rt.returncode == 0 and res_rt.stdout.strip():
                data_rt = json.loads(res_rt.stdout)
                if isinstance(data_rt, dict):
                    data_rt = [data_rt]
                for item in data_rt:
                    dest = item.get("DestinationPrefix")
                    if not dest:
                        continue
                    clean_dest = normalize_ip_string(str(dest))
                    fam = item.get("AddressFamily")
                    ip_ver = 6 if fam == 23 or ":" in clean_dest else 4

                    raw_hop = item.get("NextHop")
                    gateway = None
                    if raw_hop and raw_hop not in ("0.0.0.0", "::"):
                        gateway = normalize_ip_string(str(raw_hop))

                    iface_alias = item.get("InterfaceAlias") or ""
                    idx = item.get("InterfaceIndex")
                    idx_val = int(idx) if idx is not None else None

                    route_metric = item.get("RouteMetric")
                    route_m = int(route_metric) if route_metric is not None else None

                    # Join interface metric
                    iface_m = None
                    if idx_val is not None:
                        if fam is not None and (idx_val, int(fam)) in iface_metrics:
                            iface_m = iface_metrics[(idx_val, int(fam))]
                        elif idx_val in iface_metrics_by_idx:
                            iface_m = iface_metrics_by_idx[idx_val]

                    effective_metric = None
                    if route_m is not None and iface_m is not None:
                        effective_metric = route_m + iface_m
                    elif route_m is not None:
                        effective_metric = route_m

                    proto = str(item.get("Protocol")) if item.get("Protocol") is not None else None
                    state = str(item.get("State")) if item.get("State") is not None else None
                    policy_store = str(item.get("PolicyStore")) if item.get("PolicyStore") is not None else None

                    is_default = clean_dest in ("0.0.0.0/0", "::/0", "default")

                    entry = RouteEntry(
                        destination=clean_dest,
                        gateway=gateway,
                        interface=iface_alias,
                        metric=effective_metric,
                        route_metric=route_m,
                        interface_metric=iface_m,
                        protocol=proto,
                        ip_version=ip_ver,
                        is_default=is_default,
                        source="Get-NetRoute",
                        state=state,
                        policy_store=policy_store,
                    )

                    if ip_ver == 4:
                        routes_v4.append(entry)
                    else:
                        routes_v6.append(entry)
        except Exception as err:
            logger.error("Failed querying Get-NetRoute: %s", err)

        # 3. Determine preferred default routes
        default_candidates_v4 = [r for r in routes_v4 if r.is_default]
        default_candidates_v6 = [r for r in routes_v6 if r.is_default]

        def pick_preferred_default(candidates: list[RouteEntry]) -> RouteEntry | None:
            if not candidates:
                return None
            active = [c for c in candidates if c.state is None or str(c.state).strip().lower() in ("alive", "0")]
            if not active:
                return None
            active.sort(key=lambda x: x.metric if x.metric is not None else 999999)
            return active[0]

        best_v4 = pick_preferred_default(default_candidates_v4)
        best_v6 = pick_preferred_default(default_candidates_v6)

        pref_iface = None
        sel_reason = None
        if best_v4 and best_v4.interface:
            pref_iface = best_v4.interface
            sel_reason = f"Active IPv4 default route via {best_v4.gateway or 'direct'} on {best_v4.interface} (metric={best_v4.metric})"
        elif best_v6 and best_v6.interface:
            pref_iface = best_v6.interface
            sel_reason = f"Active IPv6 default route via {best_v6.gateway or 'direct'} on {best_v6.interface} (metric={best_v6.metric})"

        return RoutingInfo(
            ipv4_routes=routes_v4,
            ipv6_routes=routes_v6,
            default_ipv4=best_v4,
            default_ipv6=best_v6,
            preferred_interface=pref_iface,
            selection_reason=sel_reason,
        )

    def get_dns(self) -> DnsInfo:
        """Collect Windows DNS client server addresses, DoH templates, and search domains."""
        import json
        from core.execution import run_command
        from core.network import normalize_ip_string

        servers: list[DnsServer] = []
        search_domains: list[str] = []
        has_error = False

        # 1. Query DoH server configurations where supported
        doh_map: dict[str, str] = {}
        try:
            res_doh = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Select-Object ServerAddress, DohTemplate | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_doh.returncode == 0 and res_doh.stdout.strip():
                data_doh = json.loads(res_doh.stdout)
                if isinstance(data_doh, dict):
                    data_doh = [data_doh]
                for item in data_doh:
                    s_addr = item.get("ServerAddress")
                    tpl = item.get("DohTemplate")
                    if s_addr:
                        clean_addr = normalize_ip_string(str(s_addr)).lower()
                        doh_map[clean_addr] = str(tpl) if tpl else ""
        except Exception as err:
            logger.debug("Get-DnsClientDohServerAddress not supported or failed: %s", err)

        # 2. Query global search domains from Get-DnsClientGlobalSetting
        try:
            res_global = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue | Select-Object SuffixSearchList | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_global.returncode == 0 and res_global.stdout.strip():
                data_glob = json.loads(res_global.stdout)
                suffixes = data_glob.get("SuffixSearchList") if isinstance(data_glob, dict) else None
                if suffixes:
                    if isinstance(suffixes, list):
                        search_domains.extend(str(s) for s in suffixes if s)
                    elif isinstance(suffixes, str) and suffixes.strip():
                        search_domains.append(suffixes.strip())
        except Exception as err:
            logger.debug("Failed querying Get-DnsClientGlobalSetting: %s", err)

        # 3. Query DNS server addresses per interface
        try:
            res_dns = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, AddressFamily, ServerAddresses | ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_dns.returncode == 0 and res_dns.stdout.strip():
                data_dns = json.loads(res_dns.stdout)
                if isinstance(data_dns, dict):
                    data_dns = [data_dns]
                for item in data_dns:
                    iface_alias = item.get("InterfaceAlias") or ""
                    fam = item.get("AddressFamily")
                    addrs = item.get("ServerAddresses")
                    if addrs:
                        if isinstance(addrs, str):
                            addrs = [addrs]
                        for addr_str in addrs:
                            clean_ip = normalize_ip_string(str(addr_str))
                            if not clean_ip:
                                continue
                            ip_ver = 6 if fam == 23 or ":" in clean_ip else 4
                            lower_clean = clean_ip.lower()
                            if lower_clean in doh_map:
                                proto = "DoH"
                                doh_tpl = doh_map[lower_clean]
                            else:
                                proto = "UNKNOWN"
                                doh_tpl = None

                            server = DnsServer(
                                address=clean_ip,
                                family=ip_ver,
                                protocol=proto,
                                port=53,
                                interface=iface_alias,
                                source="Windows DNS Client",
                                is_primary=False,
                                doh_template=doh_tpl,
                            )
                            servers.append(server)
            else:
                has_error = True
        except Exception as err:
            logger.error("Failed querying Get-DnsClientServerAddress: %s", err)
            has_error = True

        if servers:
            status = "CONFIGURED"
        elif has_error:
            status = "ERROR"
        else:
            status = "EMPTY"

        return DnsInfo(
            servers=servers,
            search_domains=search_domains,
            source="Windows DNS Client",
            status=status,
        )

    def get_dhcp(self, interface_name: str | None = None) -> DhcpInfo:
        """Retrieve DHCP lease information for the specified or default interface."""
        cim_adapters: list[dict[str, Any]] = []
        net_interfaces: list[dict[str, Any]] = []

        try:
            res_cim = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' "
                    "| Select-Object InterfaceIndex, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires, IPAddress, IPSubnet, DefaultIPGateway, Description "
                    "| ConvertTo-Json -Depth 4",
                ],
                timeout=6.0,
                check=False,
            )
            if res_cim.returncode == 0 and res_cim.stdout.strip():
                data = json.loads(res_cim.stdout)
                cim_adapters = [data] if isinstance(data, dict) else (data or [])
        except Exception as err:
            logger.debug("Failed querying Win32_NetworkAdapterConfiguration: %s", err)

        try:
            res_if = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue "
                    "| Select-Object InterfaceIndex, InterfaceAlias, Dhcp "
                    "| ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_if.returncode == 0 and res_if.stdout.strip():
                data_if = json.loads(res_if.stdout)
                net_interfaces = [data_if] if isinstance(data_if, dict) else (data_if or [])
        except Exception as err:
            logger.debug("Failed querying Get-NetIPInterface for DHCP: %s", err)

        return parse_windows_dhcp(
            cim_adapters=cim_adapters,
            net_interfaces=net_interfaces,
            target_iface=interface_name,
        )

    def get_wifi(self, interface_name: str | None = None) -> WifiInfo:
        """Retrieve Wi-Fi status and link metrics if the interface is wireless."""
        net_adapters: list[dict[str, Any]] = []
        try:
            res_na = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetAdapter -ErrorAction SilentlyContinue "
                    "| Select-Object InterfaceIndex, Name, InterfaceAlias, PhysicalMediaType, Status "
                    "| ConvertTo-Json",
                ],
                timeout=5.0,
                check=False,
            )
            if res_na.returncode == 0 and res_na.stdout.strip():
                data_na = json.loads(res_na.stdout)
                net_adapters = [data_na] if isinstance(data_na, dict) else (data_na or [])
        except Exception as err:
            logger.debug("Failed querying Get-NetAdapter for Wi-Fi: %s", err)

        netsh_output = ""
        try:
            res_netsh = run_command(
                ["netsh", "wlan", "show", "interfaces"],
                timeout=5.0,
                check=False,
            )
            if res_netsh.returncode == 0:
                netsh_output = res_netsh.stdout
        except Exception as err:
            logger.debug("Failed querying netsh wlan show interfaces: %s", err)

        return parse_windows_wifi(
            netsh_output=netsh_output,
            net_adapters=net_adapters,
            target_iface=interface_name,
        )

    def get_neighbors(
        self,
        interface_name: str | None = None,
        routing: RoutingInfo | None = None,
    ) -> list[NeighborEntry]:
        """Retrieve local ARP / neighbor cache table on Windows."""
        if not is_tool_available("powershell") and not is_tool_available("pwsh"):
            return []

        target_ifindex = None
        if interface_name:
            try:
                for iface in self.get_interfaces():
                    if iface.name.lower() == interface_name.lower():
                        break
            except Exception:
                pass

        ps_bin = "powershell" if is_tool_available("powershell") else "pwsh"
        cmd = [
            ps_bin,
            "-NoProfile",
            "-Command",
            "Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, InterfaceIndex, State, IsRouter | ConvertTo-Json -Compress",
        ]
        try:
            res = run_command(cmd, timeout=8.0, check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return []
            return parse_windows_neighbors(
                json_output=res.stdout,
                target_iface=interface_name,
                routing=routing,
                target_ifindex=target_ifindex,
            )
        except Exception as err:
            logger.debug("Failed querying Get-NetNeighbor: %s", err)
            return []

    def get_sockets(self) -> list[SocketEntry]:
        """Retrieve local listening and active TCP/UDP sockets on Windows."""
        if is_tool_available("powershell") or is_tool_available("pwsh"):
            ps_bin = "powershell" if is_tool_available("powershell") else "pwsh"
            script = """
$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess)
$pids = @($tcp | ForEach-Object { $_.OwningProcess }) + @($udp | ForEach-Object { $_.OwningProcess }) | Where-Object { $_ -gt 0 } | Select-Object -Unique
$procMap = @{}
if ($pids) {
    Get-Process -Id $pids -ErrorAction SilentlyContinue | ForEach-Object { $procMap[[string]$_.Id] = $_.ProcessName }
}
[PSCustomObject]@{ tcp = $tcp; udp = $udp; procMap = $procMap } | ConvertTo-Json -Depth 3 -Compress
"""
            cmd = [ps_bin, "-NoProfile", "-Command", script]
            try:
                res = run_command(cmd, timeout=8.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = parse_windows_sockets(res.stdout)
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("PowerShell socket query failed: %s", err)

        # Fallback to psutil if PowerShell failed or returned empty
        try:
            import psutil
            sockets: list[SocketEntry] = []
            for conn in psutil.net_connections(kind="inet"):
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                laddr = conn.laddr.ip if conn.laddr else ""
                lport = conn.laddr.port if conn.laddr else 0
                if not laddr or not lport:
                    continue

                if proto == "TCP":
                    state = conn.status if conn.status else "UNKNOWN"
                    raddr = conn.raddr.ip if conn.raddr else None
                    rport = conn.raddr.port if conn.raddr else None
                    if state == "LISTEN":
                        raddr = None
                        rport = None
                else:
                    state = "UNKNOWN"
                    raddr = None
                    rport = None

                pid = conn.pid
                pname = None
                if pid:
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pname = None

                sockets.append(
                    SocketEntry(
                        protocol=proto,
                        local_address=normalize_ip_string(laddr),
                        local_port=lport,
                        remote_address=normalize_ip_string(raddr) if raddr else None,
                        remote_port=rport,
                        state=state,
                        pid=pid,
                        process_name=pname,
                    )
                )
            return sort_sockets(sockets)
        except Exception as err:
            logger.debug("psutil socket fallback failed: %s", err)
            return []

    def get_tshark_path(self) -> str | None:
        """Find and return the path to tshark.exe on Windows."""
        import os
        import shutil
        found = shutil.which("tshark")
        if found:
            return found
        standard_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for p in standard_paths:
            if os.path.isfile(p):
                return p
        return None

    def ping_host(
        self,
        target: str,
        count: int = 2,
        timeout_seconds: float = 3.0,
        interface_name: str | None = None,
    ) -> ConnectivityTarget:
        """Send ICMP echo requests using Windows ping utility."""
        if not is_tool_available("ping"):
            return ConnectivityTarget(
                name="gateway",
                target=target,
                success=False,
                status="ERROR",
                details="Windows ping utility not found in PATH",
            )

        timeout_ms = max(100, int(timeout_seconds * 1000))
        target_arg = target

        # Handle IPv6 link-local addresses requiring interface index scope
        if "%" not in target_arg and target_arg.lower().startswith("fe80:"):
            if interface_name:
                try:
                    ifaces = self.get_interfaces(target_iface=interface_name)
                    if ifaces and ifaces[0].index is not None:
                        target_arg = f"{target_arg}%{ifaces[0].index}"
                except Exception as err:
                    logger.debug("Failed resolving ifindex for %s: %s", interface_name, err)

        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), target_arg]

        try:
            proc_timeout = (count * timeout_seconds) + 2.0
            res = run_command(cmd, timeout=proc_timeout, check=False)
        except Exception as err:
            logger.debug("Windows ping execution failed: %s", err)
            return ConnectivityTarget(
                name="gateway",
                target=target,
                success=False,
                status="ERROR",
                details=f"Ping execution error: {err}",
            )

        return parse_windows_ping_output(res.stdout, target=target)


def parse_windows_ping_output(stdout: str, target: str) -> ConnectivityTarget:
    """Parse Windows ping command output into normalized ConnectivityTarget."""
    if not stdout or not stdout.strip():
        return ConnectivityTarget(
            name="gateway",
            target=target,
            success=False,
            status="ERROR",
            details="Empty output from ping utility",
        )

    pkt_match = re.search(
        r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\(([\d\.]+)%\s*loss\)",
        stdout,
        re.IGNORECASE,
    )

    if not pkt_match:
        lower_out = stdout.lower()
        if "could not find host" in lower_out:
            return ConnectivityTarget(
                name="gateway",
                target=target,
                success=False,
                status="FAILED",
                details="Could not find host or resolve address",
            )
        if "general failure" in lower_out:
            return ConnectivityTarget(
                name="gateway",
                target=target,
                success=False,
                status="FAILED",
                details="Ping general failure",
            )
        return ConnectivityTarget(
            name="gateway",
            target=target,
            success=False,
            status="ERROR",
            details="Malformed ping output",
        )

    sent = int(pkt_match.group(1))
    received = int(pkt_match.group(2))
    lost = int(pkt_match.group(3))
    loss_pct = float(pkt_match.group(4))

    rtt_match = re.search(
        r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
        stdout,
        re.IGNORECASE,
    )

    latency_ms: float | None = None
    if rtt_match:
        latency_ms = float(rtt_match.group(3))
    elif received > 0:
        reply_times = [
            float(m) for m in re.findall(r"time[=<](\d+)ms", stdout, re.IGNORECASE)
        ]
        if reply_times:
            latency_ms = round(sum(reply_times) / len(reply_times), 2)

    if received > 0:
        status = "SUCCESS"
        details = f"{received}/{sent} packets received ({loss_pct:.0f}% loss)"
        success = True
    else:
        lower_out = stdout.lower()
        if "request timed out" in lower_out:
            status = "TIMEOUT"
            details = "Request timed out (100% packet loss)"
        elif "destination host unreachable" in lower_out:
            status = "FAILED"
            details = "Destination host unreachable (100% packet loss)"
        else:
            status = "FAILED"
            details = f"All packets lost ({loss_pct:.0f}% loss)"
        success = False

    return ConnectivityTarget(
        name="gateway",
        target=target,
        success=success,
        latency_ms=latency_ms,
        packet_loss_pct=loss_pct,
        details=details,
        status=status,
    )



def _parse_wmi_date(val: Any) -> tuple[str | None, float | None]:
    """Parse a WMI / PowerShell date into (iso_str, timestamp_seconds)."""
    if not val:
        return None, None
    if isinstance(val, (int, float)):
        ts = float(val) / 1000.0 if val > 1e11 else float(val)
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.isoformat(), ts
        except Exception:
            return None, None
    val_str = str(val).strip()
    match = re.search(r"/Date\((\d+)\)/", val_str)
    if match:
        try:
            ts = int(match.group(1)) / 1000.0
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.isoformat(), ts
        except Exception:
            pass
    # WMI format: YYYYMMDDHHMMSS.mmmmmm+UUU
    wmi_match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", val_str)
    if wmi_match:
        try:
            dt = datetime(
                int(wmi_match.group(1)),
                int(wmi_match.group(2)),
                int(wmi_match.group(3)),
                int(wmi_match.group(4)),
                int(wmi_match.group(5)),
                int(wmi_match.group(6)),
                tzinfo=timezone.utc,
            )
            return dt.isoformat(), dt.timestamp()
        except Exception:
            pass
    return val_str, None


def parse_windows_dhcp(
    cim_adapters: list[dict[str, Any]],
    net_interfaces: list[dict[str, Any]] | None = None,
    target_iface: str | None = None,
) -> DhcpInfo:
    """Parse Windows Win32_NetworkAdapterConfiguration and Get-NetIPInterface data into normalized DhcpInfo.

    Handles CONFIGURED, PARTIAL, NOT_DHCP, UNAVAILABLE, and interface-specific resolution.
    """
    if not cim_adapters:
        return DhcpInfo(
            status="UNAVAILABLE",
            interface=target_iface,
            source="Win32_NetworkAdapterConfiguration",
        )

    # Build index <-> alias mappings from net_interfaces
    alias_to_idx: dict[str, int] = {}
    idx_to_alias: dict[int, str] = {}
    if net_interfaces:
        for item in net_interfaces:
            idx = item.get("InterfaceIndex")
            alias = item.get("InterfaceAlias")
            if idx is not None and alias:
                idx_to_alias[int(idx)] = str(alias)
                alias_to_idx[str(alias).lower()] = int(idx)

    # Find target adapter
    selected_adapter: dict[str, Any] | None = None
    target_idx: int | None = None
    if target_iface:
        target_idx = alias_to_idx.get(target_iface.lower())
        for a in cim_adapters:
            a_idx = a.get("InterfaceIndex")
            if target_idx is not None and a_idx is not None and int(a_idx) == target_idx:
                selected_adapter = a
                break
            desc = str(a.get("Description", "")).lower()
            if target_iface.lower() in desc:
                selected_adapter = a
                break
        if not selected_adapter:
            return DhcpInfo(
                status="UNAVAILABLE",
                interface=target_iface,
                source="Win32_NetworkAdapterConfiguration",
            )
    else:
        # Pick best adapter: first with DefaultIPGateway, or first with DHCPEnabled, or first adapter
        for a in cim_adapters:
            gw = a.get("DefaultIPGateway")
            if gw:
                selected_adapter = a
                break
        if not selected_adapter:
            for a in cim_adapters:
                if a.get("DHCPEnabled"):
                    selected_adapter = a
                    break
        if not selected_adapter:
            selected_adapter = cim_adapters[0]

    adapter = selected_adapter
    idx = adapter.get("InterfaceIndex")
    iface_name = idx_to_alias.get(int(idx)) if idx is not None and int(idx) in idx_to_alias else target_iface

    dhcp_enabled = bool(adapter.get("DHCPEnabled", False))
    raw_server = adapter.get("DHCPServer")
    clean_server = None
    if raw_server:
        s = str(raw_server).strip()
        if s not in ("255.255.255.255", "0.0.0.0", "None"):
            clean_server = s

    raw_ips = adapter.get("IPAddress")
    ips = [raw_ips] if isinstance(raw_ips, str) else (raw_ips or [])
    assigned_ip = ips[0] if ips else None

    raw_subnets = adapter.get("IPSubnet")
    subnets = [raw_subnets] if isinstance(raw_subnets, str) else (raw_subnets or [])
    subnet_mask = subnets[0] if subnets else None

    raw_gw = adapter.get("DefaultIPGateway")
    gateways = [raw_gw] if isinstance(raw_gw, str) else (raw_gw or [])
    router = gateways[0] if gateways else None

    lease_start, ts_start = _parse_wmi_date(adapter.get("DHCPLeaseObtained"))
    lease_expiry, ts_expiry = _parse_wmi_date(adapter.get("DHCPLeaseExpires"))
    lease_duration = None
    if ts_start is not None and ts_expiry is not None and ts_expiry > ts_start:
        lease_duration = int(ts_expiry - ts_start)

    if not dhcp_enabled:
        return DhcpInfo(
            enabled=False,
            status="NOT_DHCP",
            address=assigned_ip,
            subnet_mask=subnet_mask,
            router=router,
            interface=iface_name,
            source="Win32_NetworkAdapterConfiguration",
        )

    status = "CONFIGURED" if clean_server else "PARTIAL"
    return DhcpInfo(
        enabled=True,
        status=status,
        server=clean_server,
        address=assigned_ip,
        subnet_mask=subnet_mask,
        router=router,
        lease_start=lease_start,
        lease_expiry=lease_expiry,
        lease_duration=lease_duration,
        interface=iface_name,
        source="Win32_NetworkAdapterConfiguration",
        raw_details={k: str(v) for k, v in adapter.items() if v is not None and not isinstance(v, (list, dict))},
    )


def parse_windows_wifi(
    netsh_output: str,
    net_adapters: list[dict[str, Any]] | None = None,
    target_iface: str | None = None,
) -> WifiInfo:
    """Parse netsh wlan show interfaces output and Get-NetAdapter physical media types into WifiInfo.

    Enforces:
    - NOT_APPLICABLE for non-wireless interfaces (e.g. Ethernet).
    - DISCONNECTED for disconnected wireless adapters.
    - CONNECTED with canonical BSSID, frequency, channel, rates, signal, standard, and security mode.
    - Zero credentials / passwords.
    """
    # 1. Check if target interface is explicitly non-wireless via Get-NetAdapter
    if target_iface and net_adapters:
        for na in net_adapters:
            name = na.get("Name") or na.get("InterfaceAlias")
            if name and str(name).lower() == target_iface.lower():
                pm = str(na.get("PhysicalMediaType", "")).lower()
                if "802.11" not in pm and "wireless" not in pm:
                    return WifiInfo(
                        interface=target_iface,
                        is_wireless_interface=False,
                        state="NOT_APPLICABLE",
                        source="Get-NetAdapter",
                    )

    if not netsh_output or not netsh_output.strip():
        return WifiInfo(
            interface=target_iface,
            state="UNAVAILABLE",
            source="netsh",
        )

    lower_out = netsh_output.lower()
    if "there is no wireless interface" in lower_out or ("hosted network status" in lower_out and "interface" not in lower_out):
        return WifiInfo(
            interface=target_iface,
            is_wireless_interface=False,
            state="NOT_APPLICABLE",
            source="netsh",
        )

    if "wlansvc" in lower_out or "service is not running" in lower_out:
        return WifiInfo(
            interface=target_iface,
            state="UNAVAILABLE",
            source="netsh (wlansvc stopped)",
        )

    # Parse interface blocks
    blocks: list[dict[str, str]] = []
    current_block: dict[str, str] = {}
    for line in netsh_output.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("There is") or line_s.startswith("There are"):
            continue
        if ":" in line_s:
            k, v = line_s.split(":", 1)
            k_clean = k.strip()
            v_clean = v.strip()
            if k_clean == "Name":
                if current_block:
                    blocks.append(current_block)
                current_block = {"Name": v_clean}
            else:
                current_block[k_clean] = v_clean
    if current_block:
        blocks.append(current_block)

    if not blocks:
        return WifiInfo(
            interface=target_iface,
            is_wireless_interface=False,
            state="NOT_APPLICABLE",
            source="netsh",
        )

    # Select matching block
    selected_block: dict[str, str] | None = None
    if target_iface:
        for b in blocks:
            if b.get("Name", "").lower() == target_iface.lower():
                selected_block = b
                break
        if not selected_block:
            # Target was requested but netsh has no Wi-Fi interface by this name
            return WifiInfo(
                interface=target_iface,
                is_wireless_interface=False,
                state="NOT_APPLICABLE",
                source="netsh",
            )
    else:
        # Default: pick first connected, or first block
        for b in blocks:
            if b.get("State", "").lower() == "connected":
                selected_block = b
                break
        if not selected_block:
            selected_block = blocks[0]

    block = selected_block
    iface_name = block.get("Name", target_iface)
    raw_state = block.get("State", "").lower()

    if raw_state == "connected":
        state = "CONNECTED"
        connected = True
    elif raw_state in ("disconnected", "authenticating", "associating", "associating..."):
        state = "DISCONNECTED"
        connected = False
    else:
        state = "UNAVAILABLE"
        connected = False

    if not connected:
        return WifiInfo(
            interface=iface_name,
            is_wireless_interface=True,
            state=state,
            connected=False,
            source="netsh wlan show interfaces",
        )

    ssid = block.get("SSID")
    bssid = normalize_bssid(block.get("AP BSSID"))
    band = block.get("Band")
    channel = None
    if "Channel" in block:
        try:
            channel = int(block["Channel"])
        except ValueError:
            pass

    freq = None
    if channel is not None and band:
        freq = channel_to_frequency(channel, band)

    signal_percent = None
    if "Signal" in block:
        sig_s = block["Signal"].replace("%", "").strip()
        try:
            signal_percent = int(sig_s)
        except ValueError:
            pass

    signal_dbm = None
    if "Rssi" in block:
        rssi_s = block["Rssi"].replace("dBm", "").strip()
        try:
            signal_dbm = int(rssi_s)
        except ValueError:
            pass
    signal_percent_estimated = False
    signal_dbm_estimated = False

    if signal_dbm is None and signal_percent is not None:
        signal_dbm = signal_percent_to_dbm(signal_percent)
        signal_dbm_estimated = True
    elif signal_percent is None and signal_dbm is not None:
        signal_percent = signal_dbm_to_percent(signal_dbm)
        signal_percent_estimated = True

    rx_rate = None
    if "Receive rate (Mbps)" in block:
        try:
            rx_rate = float(block["Receive rate (Mbps)"])
        except ValueError:
            pass

    tx_rate = None
    if "Transmit rate (Mbps)" in block:
        try:
            tx_rate = float(block["Transmit rate (Mbps)"])
        except ValueError:
            pass

    standard = normalize_wifi_standard(block.get("Radio type"))
    sec_mode, raw_sec = normalize_wifi_security(block.get("Authentication"))

    return WifiInfo(
        interface=iface_name,
        ssid=ssid,
        bssid=bssid,
        state=state,
        is_wireless_interface=True,
        connected=True,
        frequency_mhz=freq,
        channel=channel,
        signal_percent=signal_percent,
        signal_dbm=signal_dbm,
        signal_percent_estimated=signal_percent_estimated,
        signal_dbm_estimated=signal_dbm_estimated,
        rx_rate_mbps=rx_rate,
        tx_rate_mbps=tx_rate,
        wifi_standard=standard,
        security_mode=sec_mode,
        raw_security=raw_sec,
        source="netsh wlan show interfaces",
    )


# ==============================================================================
# Windows Neighbor & Socket Parsers (Phase 7)
# ==============================================================================

WINDOWS_NEIGHBOR_STATE_MAP: dict[Any, str] = {
    0: "UNREACHABLE",
    1: "INCOMPLETE",
    2: "PROBE",
    3: "DELAY",
    4: "STALE",
    5: "REACHABLE",
    6: "PERMANENT",
    "unreachable": "UNREACHABLE",
    "incomplete": "INCOMPLETE",
    "probe": "PROBE",
    "delay": "DELAY",
    "stale": "STALE",
    "reachable": "REACHABLE",
    "permanent": "PERMANENT",
}


def normalize_windows_neighbor_state(raw_state: Any) -> str:
    """Normalize Windows NetNeighbor State enum or string to canonical state."""
    if raw_state is None:
        return "UNKNOWN"
    if isinstance(raw_state, int):
        return WINDOWS_NEIGHBOR_STATE_MAP.get(raw_state, "UNKNOWN")
    s = str(raw_state).strip().lower()
    return WINDOWS_NEIGHBOR_STATE_MAP.get(s, str(raw_state).strip().upper() or "UNKNOWN")


def parse_windows_neighbors(
    json_output: str,
    target_iface: str | None = None,
    routing: RoutingInfo | None = None,
    target_ifindex: int | None = None,
) -> list[NeighborEntry]:
    """Parse Get-NetNeighbor JSON output into normalized NeighborEntry list."""
    if not json_output or not json_output.strip():
        return []

    try:
        data = json.loads(json_output)
    except Exception as err:
        logger.debug("Failed to parse Windows neighbor JSON: %s", err)
        return []

    # Handle PowerShell ConvertTo-Json single-item dict vs array edge case
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        return []

    raw_neighbors: list[NeighborEntry] = []

    for item in data:
        if not isinstance(item, dict):
            continue

        ip_addr = item.get("IPAddress")
        if not ip_addr:
            continue
        ip_addr_str = str(ip_addr).strip()

        iface_alias = item.get("InterfaceAlias") or "Unknown"
        iface_str = str(iface_alias).strip()
        item_ifindex = item.get("InterfaceIndex")

        # Interface filtering if target_iface was requested
        if target_iface:
            match = False
            if iface_str.lower() == target_iface.strip().lower():
                match = True
            elif target_ifindex is not None and item_ifindex is not None:
                try:
                    if int(item_ifindex) == int(target_ifindex):
                        match = True
                except (ValueError, TypeError):
                    pass
            if not match:
                continue

        # MAC normalization
        raw_mac = item.get("LinkLayerAddress")
        norm_mac = normalize_bssid(str(raw_mac)) if raw_mac else None
        if not norm_mac or norm_mac == "00:00:00:00:00:00":
            # Missing or unreachable MAC retained as UNKNOWN
            mac_address = "UNKNOWN"
        else:
            mac_address = norm_mac

        # State normalization
        state = normalize_windows_neighbor_state(item.get("State"))

        # Router correlation (requires OS flag OR matching gateway IP + family + interface)
        is_router = False
        if item.get("IsRouter") is True:
            is_router = True
        elif is_gateway_match(ip_addr_str, iface_str, routing):
            is_router = True

        raw_neighbors.append(
            NeighborEntry(
                ip_address=ip_addr_str,
                mac_address=mac_address,
                interface=iface_str,
                state=state,
                is_router=is_router,
            )
        )

    deduped = deduplicate_neighbors(raw_neighbors)
    return sort_neighbors(deduped)


WINDOWS_TCP_STATE_MAP: dict[Any, str] = {
    0: "UNKNOWN",
    1: "CLOSE",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "CLOSE",
    100: "LISTEN",  # Bound socket
    "unknown": "UNKNOWN",
    "closed": "CLOSE",
    "listen": "LISTEN",
    "synsent": "SYN_SENT",
    "synreceived": "SYN_RECEIVED",
    "established": "ESTABLISHED",
    "finwait1": "FIN_WAIT1",
    "finwait2": "FIN_WAIT2",
    "closewait": "CLOSE_WAIT",
    "closing": "CLOSING",
    "lastack": "LAST_ACK",
    "timewait": "TIME_WAIT",
    "deletetcb": "CLOSE",
    "bound": "LISTEN",
}


def normalize_windows_tcp_state(raw_state: Any) -> str:
    """Normalize Windows TCP State enum or string to canonical TCP state."""
    if raw_state is None:
        return "UNKNOWN"
    if isinstance(raw_state, int):
        return WINDOWS_TCP_STATE_MAP.get(raw_state, "UNKNOWN")
    s = str(raw_state).strip().lower()
    return WINDOWS_TCP_STATE_MAP.get(s, str(raw_state).strip().upper() or "UNKNOWN")


def parse_windows_sockets(json_output: str) -> list[SocketEntry]:
    """Parse combined PowerShell Get-NetTCPConnection and Get-NetUDPEndpoint JSON."""
    if not json_output or not json_output.strip():
        return []

    try:
        data = json.loads(json_output)
    except Exception as err:
        logger.debug("Failed to parse Windows sockets JSON: %s", err)
        return []

    if not isinstance(data, dict):
        return []

    proc_map: dict[int, str] = {}
    raw_proc = data.get("procMap", {})
    if isinstance(raw_proc, dict):
        for k, v in raw_proc.items():
            try:
                proc_map[int(k)] = str(v)
            except (ValueError, TypeError):
                pass

    sockets: list[SocketEntry] = []

    # 1. TCP Connections
    tcp_list = data.get("tcp", [])
    if isinstance(tcp_list, dict):
        tcp_list = [tcp_list]
    elif not isinstance(tcp_list, list):
        tcp_list = []

    for item in tcp_list:
        if not isinstance(item, dict):
            continue
        laddr = item.get("LocalAddress")
        lport = item.get("LocalPort")
        if laddr is None or lport is None:
            continue

        try:
            local_port = int(lport)
        except (ValueError, TypeError):
            continue

        local_addr = normalize_ip_string(str(laddr))
        state = normalize_windows_tcp_state(item.get("State"))

        # Remote endpoint
        raddr = item.get("RemoteAddress")
        rport = item.get("RemotePort")
        remote_addr = None
        remote_port = None

        if state == "LISTEN":
            remote_addr = None
            remote_port = None
        elif raddr is not None and rport is not None:
            try:
                rp = int(rport)
                ra = normalize_ip_string(str(raddr))
                if ra in ("0.0.0.0", "::", "") and rp == 0:
                    remote_addr = None
                    remote_port = None
                else:
                    remote_addr = ra
                    remote_port = rp
            except (ValueError, TypeError):
                remote_addr = None
                remote_port = None

        pid = None
        owning_proc = item.get("OwningProcess")
        if owning_proc is not None:
            try:
                p = int(owning_proc)
                if p > 0:
                    pid = p
            except (ValueError, TypeError):
                pid = None

        pname = proc_map.get(pid) if pid else None

        sockets.append(
            SocketEntry(
                protocol="TCP",
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=pname,
            )
        )

    # 2. UDP Endpoints
    udp_list = data.get("udp", [])
    if isinstance(udp_list, dict):
        udp_list = [udp_list]
    elif not isinstance(udp_list, list):
        udp_list = []

    for item in udp_list:
        if not isinstance(item, dict):
            continue
        laddr = item.get("LocalAddress")
        lport = item.get("LocalPort")
        if laddr is None or lport is None:
            continue

        try:
            local_port = int(lport)
        except (ValueError, TypeError):
            continue

        local_addr = normalize_ip_string(str(laddr))

        pid = None
        owning_proc = item.get("OwningProcess")
        if owning_proc is not None:
            try:
                p = int(owning_proc)
                if p > 0:
                    pid = p
            except (ValueError, TypeError):
                pid = None

        pname = proc_map.get(pid) if pid else None

        sockets.append(
            SocketEntry(
                protocol="UDP",
                local_address=local_addr,
                local_port=local_port,
                remote_address=None,
                remote_port=None,
                state="UNKNOWN",  # Do not fabricate LISTENING for UDP
                pid=pid,
                process_name=pname,
            )
        )

    return sort_sockets(sockets)

