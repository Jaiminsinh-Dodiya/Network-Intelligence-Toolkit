from __future__ import annotations

import glob
import json
import logging
import os
import platform
import re
import socket
from pathlib import Path
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
    frequency_to_channel,
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


def get_interface_by_ifindex(ifindex: str | int) -> str | None:
    """Find the network interface name corresponding to a kernel ifindex."""
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return None
    try:
        target_idx = str(ifindex).strip()
        for iface_dir in net_path.iterdir():
            idx_file = iface_dir / "ifindex"
            if idx_file.is_file():
                try:
                    if idx_file.read_text(encoding="utf-8").strip() == target_idx:
                        return iface_dir.name
                except Exception:
                    continue
    except Exception:
        pass
    return None


def is_interface_up(iface: str) -> bool:
    """Check if a network interface is UP in the Linux kernel."""
    oper = Path(f"/sys/class/net/{iface}/operstate")
    if oper.exists():
        try:
            if oper.read_text(encoding="utf-8").strip().lower() == "up":
                return True
        except Exception:
            pass
    flags = Path(f"/sys/class/net/{iface}/flags")
    if flags.exists():
        try:
            val = int(flags.read_text(encoding="utf-8").strip(), 16)
            return bool(val & 1)  # IFF_UP = 0x1
        except Exception:
            pass
    return False


class LinuxBackend(BasePlatformBackend):
    """Linux and Kali Linux platform backend using native Linux tools (/proc, /sys, ip, ss, iw)."""

    def __init__(self) -> None:
        self._privileged = is_privileged()

    def get_platform_name(self) -> str:
        return "Linux"

    def _get_distro_name(self) -> str:
        """Inspect /etc/os-release or fallback for distribution name."""
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                content = os_release.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip('"\'')
                    if line.startswith("NAME=") and "distro" not in locals():
                        distro = line.split("=", 1)[1].strip('"\'')
                if "distro" in locals():
                    return distro
            except Exception:
                pass
        return f"Linux {platform.release()}"

    def get_platform_info(self) -> SystemInfo:
        return SystemInfo(
            os_name=self._get_distro_name(),
            os_version=platform.version(),
            platform_release=platform.release(),
            hostname=socket.gethostname(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            is_privileged=self._privileged,
        )

    def detect_capabilities(self) -> dict[str, CapabilityEntry]:
        has_ip = is_tool_available("ip")
        has_ss = is_tool_available("ss")
        has_iw = is_tool_available("iw")
        has_nmcli = is_tool_available("nmcli")
        has_resolvectl = is_tool_available("resolvectl") or is_tool_available("systemd-resolve")
        has_tshark = self.get_tshark_path() is not None
        has_proc = os.path.isdir("/proc/net")
        has_sys = os.path.isdir("/sys/class/net")

        caps: list[CapabilityEntry] = [
            CapabilityEntry(
                name="interface_info",
                status=CapabilityStatus.AVAILABLE if (has_ip or has_sys) else CapabilityStatus.PARTIAL,
                description="Network interface configuration and statistics (/sys, ip)",
                reason=None if (has_ip or has_sys) else "ip or /sys/class/net not found",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 2)",
            ),
            CapabilityEntry(
                name="routing_info",
                status=CapabilityStatus.AVAILABLE if has_ip else CapabilityStatus.PARTIAL,
                description="Routing table and default gateway (ip route, /proc/net/route)",
                reason=None if has_ip else "ip command not found; using /proc/net/route fallback",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 3)",
            ),
            CapabilityEntry(
                name="dns_info",
                status=CapabilityStatus.AVAILABLE if (has_resolvectl or os.path.exists("/etc/resolv.conf")) else CapabilityStatus.UNAVAILABLE,
                description="DNS resolution configuration (/etc/resolv.conf, systemd-resolved)",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 3)",
            ),
            CapabilityEntry(
                name="dhcp_info",
                status=CapabilityStatus.AVAILABLE if self._privileged else CapabilityStatus.PARTIAL,
                description="DHCP lease information (/var/lib/dhcp, NetworkManager)",
                reason=None if self._privileged else "Full lease inspection may require root privileges",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 4)",
            ),
            CapabilityEntry(
                name="wifi_info",
                status=CapabilityStatus.AVAILABLE if (has_iw or has_nmcli) else CapabilityStatus.UNAVAILABLE,
                description="Wi-Fi link state, SSID, BSSID, and metrics (iw, nmcli)",
                reason=None if (has_iw or has_nmcli) else "iw and nmcli utilities not found",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 4)",
            ),
            CapabilityEntry(
                name="public_ip",
                status=CapabilityStatus.AVAILABLE,
                description="Observed public IP, ASN, and geo-identity lookup with privacy-safe fallback",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 5)",
            ),
            CapabilityEntry(
                name="connectivity",
                status=CapabilityStatus.AVAILABLE if (is_tool_available("ping") or is_tool_available("ping6")) else CapabilityStatus.PARTIAL,
                description="Safe connectivity diagnostic probes (gateway ping, DNS latency, HTTP reachability, IPv4/IPv6)",
                reason=None if (is_tool_available("ping") or is_tool_available("ping6")) else "ping utility not found; non-ICMP probes remain functional",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 6)",
            ),
            CapabilityEntry(
                name="neighbor_table",
                status=CapabilityStatus.AVAILABLE if (has_ip or os.path.exists("/proc/net/arp")) else CapabilityStatus.UNAVAILABLE,
                description="ARP / neighbor cache table (ip neigh, /proc/net/arp)",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 7)",
            ),
            CapabilityEntry(
                name="socket_summary",
                status=CapabilityStatus.AVAILABLE if (has_ss and self._privileged) else CapabilityStatus.PARTIAL,
                description="Local TCP/UDP listening and active sockets (ss, /proc/net)",
                reason=None if (has_ss and self._privileged) else "ss command or root privilege required to view all process names",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 7)",
            ),
            CapabilityEntry(
                name="pcap_analysis",
                status=CapabilityStatus.AVAILABLE if has_tshark else CapabilityStatus.MISSING_DEPENDENCY,
                description="Authorized PCAP/PCAPNG packet analysis via TShark",
                reason=None if has_tshark else "TShark is not installed (install with: sudo apt install tshark)",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 8)",
            ),
            CapabilityEntry(
                name="observations",
                status=CapabilityStatus.AVAILABLE,
                description="Observations & findings engine (passive evidence correlation and analysis)",
                platform="Linux",
                toolkit_status="IMPLEMENTED (Phase 9)",
            ),
            CapabilityEntry(
                name="linux_kernel_info",
                status=CapabilityStatus.AVAILABLE if (has_proc and has_sys) else CapabilityStatus.PARTIAL,
                description="Linux kernel (/proc and /sys) metrics",
                platform="Linux",
                toolkit_status="PLANNED",
            ),
        ]
        return {entry.name: entry for entry in caps}

    def _get_linux_ipv6_prefixes(self) -> dict[str, int]:
        """Discover IPv6 prefixes using /proc/net/if_inet6 and/or ip -6 addr show."""
        prefixes: dict[str, int] = {}

        # 1. Try reading /proc/net/if_inet6 (fast path without subprocess)
        proc_file = Path("/proc/net/if_inet6")
        if proc_file.exists():
            try:
                import ipaddress
                lines = proc_file.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        hex_ip, _, hex_prefix, _, _, _ = parts[:6]
                        chunks = [hex_ip[i:i+4] for i in range(0, 32, 4)]
                        full_ip = ":".join(chunks)
                        canonical_ip = str(ipaddress.IPv6Address(full_ip)).lower()
                        prefixes[canonical_ip] = int(hex_prefix, 16)
            except Exception as err:
                logger.debug("Failed parsing /proc/net/if_inet6: %s", err)

        # 2. Try ip -6 addr show if ip tool is available and /proc was empty or absent
        if not prefixes and is_tool_available("ip"):
            try:
                from core.execution import run_command
                from core.network import normalize_ip_string
                res = run_command(["ip", "-6", "addr", "show"], timeout=3.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    for line in res.stdout.splitlines():
                        sline = line.strip()
                        if sline.startswith("inet6 "):
                            parts = sline.split()
                            if len(parts) >= 2 and "/" in parts[1]:
                                ip_part, prefix_part = parts[1].split("/", 1)
                                clean_ip = normalize_ip_string(ip_part).lower()
                                try:
                                    prefixes[clean_ip] = int(prefix_part)
                                except ValueError:
                                    pass
            except Exception as err:
                logger.debug("Failed running ip -6 addr show: %s", err)

        return prefixes

    def get_interfaces(self, target_iface: str | None = None) -> list[InterfaceInfo]:
        import psutil
        from core.network import normalize_ip_string

        results: list[InterfaceInfo] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        ipv6_prefixes = self._get_linux_ipv6_prefixes()

        for iface_name, addr_list in addrs.items():
            if target_iface and iface_name != target_iface:
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

            info.is_loopback = iface_name == "lo" or any(a.startswith("127.") for a in info.ipv4)
            wireless_sys = Path(f"/sys/class/net/{iface_name}/wireless")
            info.is_wireless = wireless_sys.exists() or iface_name.startswith("wl")
            results.append(info)

        return results

    def get_default_interface(self) -> InterfaceInfo | None:
        """Determine and return the primary active network interface using Phase 2 contract."""
        interfaces = self.get_interfaces()
        return select_default_interface(interfaces)

    def get_routes(self) -> RoutingInfo:
        """Collect Linux routing table using ip -j route or text fallback, plus ip rule metadata.

        Policy routing limitation:
            - Policy routing: Detected and preserved as metadata in RoutingInfo.rules.
            - Preferred default route: Lowest-metric parsed default route.
            - Effective destination-specific route: Not fully evaluated yet.
        """
        import json
        from core.execution import run_command
        from core.network import normalize_ip_string

        routes_v4: list[RouteEntry] = []
        routes_v6: list[RouteEntry] = []
        rules: list[dict[str, Any]] = []

        # 1. Collect policy rules (ip -j rule or ip rule show)
        if is_tool_available("ip"):
            try:
                res_rule = run_command(["ip", "-j", "rule"], timeout=3.0, check=False)
                if res_rule.returncode == 0 and res_rule.stdout.strip():
                    rules_data = json.loads(res_rule.stdout)
                    if isinstance(rules_data, list):
                        rules = rules_data
                else:
                    res_rule_txt = run_command(["ip", "rule", "show"], timeout=3.0, check=False)
                    if res_rule_txt.returncode == 0 and res_rule_txt.stdout.strip():
                        for line in res_rule_txt.stdout.splitlines():
                            sline = line.strip()
                            if sline:
                                rules.append({"raw": sline})
            except Exception as err:
                logger.debug("Failed querying ip rule: %s", err)

        # 2. Collect routes via ip -j route (or fallback)
        def parse_json_routes(json_str: str, default_family: int) -> list[RouteEntry]:
            parsed = []
            try:
                data = json.loads(json_str)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    dst = item.get("dst")
                    if not dst:
                        continue
                    clean_dst = normalize_ip_string(str(dst))
                    if clean_dst == "default":
                        clean_dst = "::/0" if default_family == 6 else "0.0.0.0/0"

                    gw = item.get("gateway")
                    if not gw and item.get("via"):
                        gw = item.get("via")
                    clean_gw = normalize_ip_string(str(gw)) if gw else None

                    dev = item.get("dev") or ""
                    metric_raw = item.get("metric")
                    metric = int(metric_raw) if metric_raw is not None else None
                    scope = item.get("scope")
                    proto = item.get("protocol")
                    rtype = item.get("type")
                    is_default = clean_dst in ("0.0.0.0/0", "::/0", "default")

                    ip_ver = default_family
                    if ":" in clean_dst:
                        ip_ver = 6
                    elif "." in clean_dst:
                        ip_ver = 4

                    parsed.append(
                        RouteEntry(
                            destination=clean_dst,
                            gateway=clean_gw,
                            interface=dev,
                            metric=metric,
                            route_metric=metric,
                            scope=scope,
                            route_type=rtype,
                            source="iproute2",
                            protocol=proto,
                            ip_version=ip_ver,
                            is_default=is_default,
                        )
                    )
            except Exception as e:
                logger.debug("Failed parsing json routes: %s", e)
            return parsed

        def parse_text_routes(output: str, default_family: int) -> list[RouteEntry]:
            parsed = []
            for line in output.splitlines():
                sline = line.strip()
                if not sline:
                    continue
                tokens = sline.split()
                if not tokens:
                    continue
                dst = tokens[0]
                clean_dst = normalize_ip_string(dst)
                if clean_dst == "default":
                    clean_dst = "::/0" if default_family == 6 else "0.0.0.0/0"

                gw = None
                dev = ""
                metric = None
                proto = None
                scope = None

                i = 1
                while i < len(tokens):
                    tok = tokens[i]
                    if tok in ("via", "gateway") and i + 1 < len(tokens):
                        gw = normalize_ip_string(tokens[i + 1])
                        i += 2
                    elif tok == "dev" and i + 1 < len(tokens):
                        dev = tokens[i + 1]
                        i += 2
                    elif tok == "metric" and i + 1 < len(tokens):
                        try:
                            metric = int(tokens[i + 1])
                        except ValueError:
                            pass
                        i += 2
                    elif tok in ("proto", "protocol") and i + 1 < len(tokens):
                        proto = tokens[i + 1]
                        i += 2
                    elif tok == "scope" and i + 1 < len(tokens):
                        scope = tokens[i + 1]
                        i += 2
                    else:
                        i += 1

                ip_ver = default_family
                if ":" in clean_dst:
                    ip_ver = 6
                elif "." in clean_dst:
                    ip_ver = 4

                is_default = clean_dst in ("0.0.0.0/0", "::/0", "default")
                parsed.append(
                    RouteEntry(
                        destination=clean_dst,
                        gateway=gw,
                        interface=dev,
                        metric=metric,
                        route_metric=metric,
                        scope=scope,
                        source="iproute2_text",
                        protocol=proto,
                        ip_version=ip_ver,
                        is_default=is_default,
                    )
                )
            return parsed

        if is_tool_available("ip"):
            # Try IPv4 json
            try:
                res_v4 = run_command(["ip", "-j", "route"], timeout=3.0, check=False)
                if res_v4.returncode == 0 and res_v4.stdout.strip():
                    routes_v4 = parse_json_routes(res_v4.stdout, 4)
                else:
                    res_v4_txt = run_command(["ip", "route", "show"], timeout=3.0, check=False)
                    if res_v4_txt.returncode == 0 and res_v4_txt.stdout.strip():
                        routes_v4 = parse_text_routes(res_v4_txt.stdout, 4)
            except Exception as err:
                logger.error("Failed querying IPv4 routes: %s", err)

            # Try IPv6 json
            try:
                res_v6 = run_command(["ip", "-j", "-6", "route"], timeout=3.0, check=False)
                if res_v6.returncode == 0 and res_v6.stdout.strip():
                    routes_v6 = parse_json_routes(res_v6.stdout, 6)
                else:
                    res_v6_txt = run_command(["ip", "-6", "route", "show"], timeout=3.0, check=False)
                    if res_v6_txt.returncode == 0 and res_v6_txt.stdout.strip():
                        routes_v6 = parse_text_routes(res_v6_txt.stdout, 6)
            except Exception as err:
                logger.error("Failed querying IPv6 routes: %s", err)

        # 3. Fallback to /proc/net/route if IPv4 routes still empty
        if not routes_v4:
            proc_route = Path("/proc/net/route")
            if proc_route.exists():
                try:
                    lines = proc_route.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in lines[1:]:  # skip header
                        cols = line.strip().split()
                        if len(cols) >= 8:
                            dev, dest_hex, gw_hex, flags_hex, _, _, metric_str, mask_hex = cols[:8]
                            import ipaddress
                            def hex_to_ip(h: str) -> str:
                                val = int(h, 16)
                                return str(ipaddress.IPv4Address(val.to_bytes(4, byteorder="little")))

                            dest_ip = hex_to_ip(dest_hex)
                            gw_ip = hex_to_ip(gw_hex)
                            mask_ip = hex_to_ip(mask_hex)
                            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask_ip}").prefixlen
                            dst_cidr = f"{dest_ip}/{prefix}"
                            clean_gw = gw_ip if gw_ip != "0.0.0.0" else None
                            m = int(metric_str) if metric_str.isdigit() else None
                            is_default = dst_cidr == "0.0.0.0/0" or dest_ip == "0.0.0.0"
                            routes_v4.append(
                                RouteEntry(
                                    destination=dst_cidr,
                                    gateway=clean_gw,
                                    interface=dev,
                                    metric=m,
                                    route_metric=m,
                                    source="/proc/net/route",
                                    ip_version=4,
                                    is_default=is_default,
                                )
                            )
                except Exception as err:
                    logger.debug("Failed parsing /proc/net/route: %s", err)

        # 4. Determine preferred default routes
        default_candidates_v4 = [r for r in routes_v4 if r.is_default]
        default_candidates_v6 = [r for r in routes_v6 if r.is_default]

        def pick_preferred_default(candidates: list[RouteEntry]) -> RouteEntry | None:
            if not candidates:
                return None
            pool = list(candidates)
            pool.sort(key=lambda x: x.metric if x.metric is not None else 999999)
            return pool[0]

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

        if rules and len(rules) > 3:
            policy_note = f"Policy routing detected ({len(rules)} rules configured; preserved as metadata; effective destination-specific routes not evaluated)"
            sel_reason = f"{sel_reason}; {policy_note}" if sel_reason else policy_note

        return RoutingInfo(
            ipv4_routes=routes_v4,
            ipv6_routes=routes_v6,
            default_ipv4=best_v4,
            default_ipv6=best_v6,
            preferred_interface=pref_iface,
            selection_reason=sel_reason,
            rules=rules,
        )

    def get_dns(self) -> DnsInfo:
        """Collect Linux DNS configuration via systemd-resolved, /etc/resolv.conf, or nmcli."""
        from core.execution import run_command
        from core.network import normalize_ip_string

        servers: list[DnsServer] = []
        upstream_servers: list[DnsServer] = []
        search_domains: list[str] = []
        primary_source = "resolv.conf"
        is_stub = False
        stub_address = None

        # 1. Preferred source: systemd-resolved (resolvectl status)
        if is_tool_available("resolvectl") or is_tool_available("systemd-resolve"):
            cmd = ["resolvectl", "status"] if is_tool_available("resolvectl") else ["systemd-resolve", "--status"]
            try:
                res = run_command(cmd, timeout=3.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    primary_source = "systemd-resolved"
                    current_link: str | None = None
                    dot_enabled: bool = False
                    current_dns_for_link: str | None = None
                    seen_servers: set[tuple[str, str | None]] = set()

                    for line in res.stdout.splitlines():
                        sline = line.strip()
                        if sline.startswith("Link ") and "(" in sline and ")" in sline:
                            current_link = sline.split("(")[1].split(")")[0].strip()
                            dot_enabled = False  # Reset protocol state for new link scope
                            current_dns_for_link = None
                        elif sline.startswith("Global"):
                            current_link = None
                            dot_enabled = False  # Reset protocol state for global scope
                            current_dns_for_link = None
                        elif "Protocols:" in sline:
                            if "+DNSOverTLS" in sline:
                                dot_enabled = True
                            elif "-DNSOverTLS" in sline:
                                dot_enabled = False
                        elif sline.startswith("Current DNS Server:"):
                            parts = sline.split(":", 1)[1].split()
                            if parts:
                                current_dns_for_link = normalize_ip_string(parts[0])
                                for s in servers:
                                    if s.interface == current_link and s.address == current_dns_for_link:
                                        s.is_primary = True
                        elif sline.startswith("DNS Servers:"):
                            parts = sline.split(":", 1)[1].split()
                            for p in parts:
                                clean_ip = normalize_ip_string(p)
                                if clean_ip and (clean_ip, current_link) not in seen_servers:
                                    seen_servers.add((clean_ip, current_link))
                                    ip_ver = 6 if ":" in clean_ip else 4
                                    proto = "DoT" if dot_enabled else "UNKNOWN"
                                    role = "LOCAL_STUB" if clean_ip in ("127.0.0.53", "127.0.0.54") else "UPSTREAM_RESOLVER"
                                    is_primary = (clean_ip == current_dns_for_link)
                                    srv = DnsServer(
                                        address=clean_ip,
                                        family=ip_ver,
                                        protocol=proto,
                                        interface=current_link,
                                        source="systemd-resolved",
                                        role=role,
                                        is_primary=is_primary,
                                    )
                                    if role == "LOCAL_STUB":
                                        is_stub = True
                                        stub_address = clean_ip
                                        servers.append(srv)
                                    else:
                                        servers.append(srv)
                                        upstream_servers.append(srv)
                        elif "DNS Domain:" in sline or "DNS Search Domains:" in sline:
                            domains = sline.split(":", 1)[1].split()
                            for d in domains:
                                clean_d = d.strip()
                                if clean_d and not clean_d.startswith("~") and clean_d not in search_domains:
                                    search_domains.append(clean_d)
            except Exception as err:
                logger.debug("Failed running %s: %s", cmd, err)

        # 2. Traditional fallback: /etc/resolv.conf
        if not servers:
            resolv_conf = Path("/etc/resolv.conf")
            if resolv_conf.exists():
                try:
                    primary_source = "resolv.conf"
                    lines = resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in lines:
                        sline = line.strip()
                        if sline.startswith("nameserver "):
                            parts = sline.split()
                            if len(parts) >= 2:
                                clean_ip = normalize_ip_string(parts[1])
                                ip_ver = 6 if ":" in clean_ip else 4
                                role = "LOCAL_STUB" if clean_ip in ("127.0.0.53", "127.0.0.54") else "UPSTREAM_RESOLVER"
                                if role == "LOCAL_STUB":
                                    is_stub = True
                                    stub_address = clean_ip
                                srv = DnsServer(
                                    address=clean_ip,
                                    family=ip_ver,
                                    protocol="UNKNOWN",
                                    source="resolv.conf",
                                    role=role,
                                    is_primary=False,
                                )
                                servers.append(srv)
                        elif sline.startswith("search ") or sline.startswith("domain "):
                            parts = sline.split()[1:]
                            for p in parts:
                                if p not in search_domains:
                                    search_domains.append(p)
                except Exception as err:
                    logger.debug("Failed reading /etc/resolv.conf: %s", err)

        # 3. NetworkManager fallback: nmcli dev show
        if not servers and is_tool_available("nmcli"):
            try:
                res_nm = run_command(["nmcli", "dev", "show"], timeout=3.0, check=False)
                if res_nm.returncode == 0 and res_nm.stdout.strip():
                    primary_source = "NetworkManager"
                    current_dev = None
                    for line in res_nm.stdout.splitlines():
                        sline = line.strip()
                        if sline.startswith("GENERAL.DEVICE:"):
                            current_dev = sline.split(":", 1)[1].strip()
                        elif "IP4.DNS" in sline or "IP6.DNS" in sline:
                            clean_ip = normalize_ip_string(sline.split(":", 1)[1].strip())
                            if clean_ip:
                                ip_ver = 6 if ":" in clean_ip else 4
                                srv = DnsServer(
                                    address=clean_ip,
                                    family=ip_ver,
                                    protocol="UNKNOWN",
                                    interface=current_dev,
                                    source="NetworkManager",
                                    is_primary=False,
                                )
                                servers.append(srv)
                        elif "IP4.DOMAIN" in sline or "IP6.DOMAIN" in sline:
                            dom = sline.split(":", 1)[1].strip()
                            if dom and dom not in search_domains:
                                search_domains.append(dom)
            except Exception as err:
                logger.debug("Failed querying nmcli: %s", err)

        status = "CONFIGURED" if servers else "EMPTY"

        return DnsInfo(
            servers=servers,
            search_domains=search_domains,
            source=primary_source,
            status=status,
            is_stub=is_stub,
            stub_address=stub_address,
            upstream_servers=upstream_servers,
        )

    def get_dhcp(self, interface_name: str | None = None) -> DhcpInfo:
        """Retrieve DHCP lease information for the specified or default interface."""
        target_iface = interface_name
        if not target_iface:
            def_if = self.get_default_interface()
            if def_if:
                target_iface = def_if.name

        # 1. Check systemd-networkd lease files (/run/systemd/netif/leases/<ifindex>)
        if target_iface:
            ifindex_path = Path(f"/sys/class/net/{target_iface}/ifindex")
            if ifindex_path.exists():
                try:
                    ifindex = ifindex_path.read_text(encoding="utf-8").strip()
                    lease_file = Path(f"/run/systemd/netif/leases/{ifindex}")
                    if lease_file.exists():
                        parsed = parse_systemd_lease(lease_file.read_text(encoding="utf-8", errors="replace"), target_iface)
                        if parsed:
                            return parsed
                except Exception as err:
                    logger.debug("Failed checking systemd lease: %s", err)
            # When target_iface is explicitly supplied, DO NOT fall back to arbitrary lease files.
        else:
            # When target_iface is None, check any files in /run/systemd/netif/leases/
            # but assign each lease to the actual interface matching its ifindex.
            for lpath in glob.glob("/run/systemd/netif/leases/*"):
                try:
                    p = Path(lpath)
                    if p.is_file() and p.name.isdigit():
                        actual_iface = get_interface_by_ifindex(p.name)
                        if actual_iface:
                            parsed = parse_systemd_lease(p.read_text(encoding="utf-8", errors="replace"), actual_iface)
                            if parsed:
                                return parsed
                except Exception:
                    pass

        # 2. Check dhclient lease files (/var/lib/dhcp/dhclient*.leases, /var/lib/dhclient/dhclient*.leases)
        dhclient_paths = glob.glob("/var/lib/dhcp/dhclient*.lease*") + glob.glob("/var/lib/dhclient/dhclient*.lease*")
        for dpath in dhclient_paths:
            try:
                p = Path(dpath)
                if p.is_file():
                    parsed = parse_dhclient_leases(p.read_text(encoding="utf-8", errors="replace"), target_iface)
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Failed checking dhclient lease: %s", err)

        # 3. Check NetworkManager lease files (/var/lib/NetworkManager/*.lease)
        nm_paths = glob.glob("/var/lib/NetworkManager/*.lease")
        for nm_path in nm_paths:
            try:
                p = Path(nm_path)
                if p.is_file():
                    parsed = parse_dhclient_leases(p.read_text(encoding="utf-8", errors="replace"), target_iface)
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Failed checking NetworkManager lease file: %s", err)

        # 4. Check nmcli if tool is available
        if is_tool_available("nmcli") and target_iface:
            try:
                res_nm = run_command(["nmcli", "-f", "DHCP4", "dev", "show", target_iface], timeout=3.0, check=False)
                if res_nm.returncode == 0 and res_nm.stdout.strip():
                    parsed = parse_nmcli_dhcp(res_nm.stdout, target_iface)
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Failed querying nmcli DHCP: %s", err)

        # 5. Fallback: inspect default routing table for proto dhcp
        try:
            routing_info = self.get_routes()
            routes = routing_info.ipv4_routes or routing_info.routes
            fallback_dhcp = parse_linux_dhcp_route_fallback(routes, target_iface)
            if fallback_dhcp:
                return fallback_dhcp
        except Exception as err:
            logger.debug("Failed checking routing table for DHCP fallback: %s", err)

        return DhcpInfo(
            status="UNAVAILABLE",
            interface=target_iface,
            source="Linux",
        )

    def _find_wireless_interfaces(self) -> list[str]:
        """Find all wireless interfaces on the system in discovery order."""
        candidates: list[str] = []
        for wpath in glob.glob("/sys/class/net/*/wireless") + glob.glob("/sys/class/net/*/phy80211"):
            p = Path(wpath)
            iface = p.parent.name
            if iface not in candidates:
                candidates.append(iface)

        if is_tool_available("iw"):
            try:
                res_dev = run_command(["iw", "dev"], timeout=3.0, check=False)
                if res_dev.returncode == 0:
                    for line in res_dev.stdout.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("Interface "):
                            parts = line_s.split()
                            if len(parts) >= 2:
                                iface = parts[1]
                                if iface not in candidates:
                                    candidates.append(iface)
            except Exception:
                pass
        return candidates

    def get_wifi(self, interface_name: str | None = None) -> WifiInfo:
        """Retrieve Wi-Fi status and link metrics if the interface is wireless."""
        target_iface = interface_name

        # If interface was requested, check if it is wireless
        if target_iface:
            is_wireless = False
            sys_wireless = Path(f"/sys/class/net/{target_iface}/wireless")
            sys_phy = Path(f"/sys/class/net/{target_iface}/phy80211")
            if sys_wireless.exists() or sys_phy.exists():
                is_wireless = True
            elif is_tool_available("iw"):
                try:
                    res_info = run_command(["iw", "dev", target_iface, "info"], timeout=3.0, check=False)
                    if res_info.returncode == 0 and "type" in res_info.stdout.lower():
                        is_wireless = True
                except Exception:
                    pass

            if not is_wireless:
                return WifiInfo(
                    interface=target_iface,
                    is_wireless_interface=False,
                    state="NOT_APPLICABLE",
                    source="/sys/class/net",
                )
        else:
            # Precedence for automatic selection when interface_name is None:
            # 1. Connected wireless interface
            # 2. Wireless interface that is UP
            # 3. First available wireless interface
            # 4. No wireless interface
            candidates = self._find_wireless_interfaces()
            if not candidates:
                return WifiInfo(
                    is_wireless_interface=False,
                    state="NOT_APPLICABLE",
                    source="/sys/class/net",
                )

            selected_iface: str | None = None
            cached_link_info: dict[str, WifiInfo] = {}

            # 1. Connected wireless interface
            for cand in candidates:
                if is_tool_available("iw"):
                    try:
                        res_link = run_command(["iw", "dev", cand, "link"], timeout=3.0, check=False)
                        if res_link.returncode == 0 and res_link.stdout.strip():
                            parsed = parse_iw_link(res_link.stdout, cand)
                            cached_link_info[cand] = parsed
                            if parsed.connected:
                                selected_iface = cand
                                break
                    except Exception as err:
                        logger.debug("Failed querying iw dev %s link: %s", cand, err)

            # 2. Wireless interface that is UP
            if not selected_iface:
                for cand in candidates:
                    if is_interface_up(cand):
                        selected_iface = cand
                        break

            # 3. First available wireless interface
            if not selected_iface:
                selected_iface = candidates[0]

            target_iface = selected_iface

        # Query link metrics via `iw dev <iface> link`
        wifi_info: WifiInfo | None = cached_link_info.get(target_iface) if not interface_name else None
        if not wifi_info and is_tool_available("iw"):
            try:
                res_link = run_command(["iw", "dev", target_iface, "link"], timeout=3.0, check=False)
                if res_link.returncode == 0:
                    wifi_info = parse_iw_link(res_link.stdout, target_iface)
            except Exception as err:
                logger.debug("Failed querying iw dev link: %s", err)

        if not wifi_info:
            wifi_info = WifiInfo(
                interface=target_iface,
                is_wireless_interface=True,
                state="UNAVAILABLE",
                source="Linux",
            )

        # Enrich security and standard via nmcli if available
        if wifi_info.connected and is_tool_available("nmcli"):
            try:
                res_nm = run_command(
                    ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY", "dev", "wifi"],
                    timeout=3.0,
                    check=False,
                )
                if res_nm.returncode == 0 and res_nm.stdout.strip():
                    sec_mode, raw_sec, std = parse_nmcli_wifi_detail(res_nm.stdout, target_iface)
                    if sec_mode != "UNKNOWN":
                        wifi_info.security_mode = sec_mode
                        wifi_info.raw_security = raw_sec
                    if std != "UNKNOWN" and wifi_info.wifi_standard == "UNKNOWN":
                        wifi_info.wifi_standard = std
            except Exception as err:
                logger.debug("Failed querying nmcli dev wifi for security: %s", err)

        return wifi_info

    def get_neighbors(
        self,
        interface_name: str | None = None,
        routing: RoutingInfo | None = None,
    ) -> list[NeighborEntry]:
        """Retrieve local ARP / neighbor cache table on Linux.

        Tries:
        1. `ip -j neigh` (structured JSON from iproute2)
        2. `ip neigh` (text output)
        3. `/proc/net/arp` (kernel ARP table fallback for IPv4)
        """
        # 1. Try ip -j neigh
        if is_tool_available("ip"):
            try:
                cmd = ["ip", "-j", "neigh"]
                res = run_command(cmd, timeout=5.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = parse_linux_ip_neigh_json(
                        json_output=res.stdout,
                        target_iface=interface_name,
                        routing=routing,
                    )
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Linux ip -j neigh failed: %s", err)

            # 2. Try ip neigh (text output)
            try:
                cmd = ["ip", "neigh"]
                res = run_command(cmd, timeout=5.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = parse_linux_ip_neigh_text(
                        text_output=res.stdout,
                        target_iface=interface_name,
                        routing=routing,
                    )
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Linux ip neigh text failed: %s", err)

        # 3. Fallback to /proc/net/arp
        arp_path = Path("/proc/net/arp")
        if arp_path.exists():
            try:
                content = arp_path.read_text(encoding="utf-8", errors="replace")
                return parse_linux_proc_arp(
                    proc_output=content,
                    target_iface=interface_name,
                    routing=routing,
                )
            except Exception as err:
                logger.debug("Linux /proc/net/arp failed: %s", err)

        return []

    def get_sockets(self) -> list[SocketEntry]:
        """Retrieve local listening and active TCP/UDP sockets on Linux using ss -tunapn -H."""
        if is_tool_available("ss"):
            try:
                cmd = ["ss", "-tunapn", "-H"]
                res = run_command(cmd, timeout=5.0, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    parsed = parse_linux_ss(res.stdout)
                    if parsed:
                        return parsed
            except Exception as err:
                logger.debug("Linux ss command failed: %s", err)

        # Fallback to psutil
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
            logger.debug("Linux psutil socket fallback failed: %s", err)
            return []

# Linux ip-addr network math normalization integration

# Linux ip -j route parser

# Linux policy routing rules and route metrics

# systemd-resolved resolvectl status DNS parser

# NetworkManager nmcli and resolv.conf DNS fallback

# Local stub resolver 127.0.0.53 identification

# Linux DHCP lease discovery via systemd-networkd and dhclient

# Linux wireless telemetry via iw dev link
