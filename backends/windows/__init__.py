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

# Network math adapter normalization integration

# Windows Get-NetRoute route table collection

# Windows route metric prioritization and default route discovery

# Windows DNS client server discovery via Get-DnsClientServerAddress
