"""Safe Connectivity Engine for the Network Intelligence Toolkit.

Performs bounded, read-only diagnostic probes across:
1. Default gateway ICMP echo latency and packet loss.
2. DNS resolution latency of configured test domains.
3. HTTP/HTTPS reachability of configured connectivity URLs.
4. Fixed IPv4 TCP connectivity (port 443) against configured targets.
5. Fixed IPv6 TCP connectivity (port 443) against configured targets.

Security Boundary:
    Strictly diagnostic and non-intrusive. Never scans subnets, ports, or arbitrary hosts.
    Never crafts raw packets, modifies routes, or tampers with DNS.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
from pathlib import Path
import socket
import time
from typing import TYPE_CHECKING, Any
import urllib.error
import urllib.request

from core.models import ConnectivityInfo, ConnectivityTarget, DnsInfo, InterfaceInfo, RoutingInfo

if TYPE_CHECKING:
    from backends.base import BasePlatformBackend

logger = logging.getLogger(__name__)

USER_AGENT = "NetworkIntelligenceToolkit/1.0"

DEFAULT_PING_TIMEOUT: float = 3.0
DEFAULT_DNS_TIMEOUT: float = 3.0
DEFAULT_HTTP_TIMEOUT: float = 4.0
DEFAULT_TCP_TIMEOUT: float = 4.0

MIN_TIMEOUT_SECONDS: float = 0.05
MAX_TIMEOUT_SECONDS: float = 60.0


def parse_bounded_timeout(
    val: Any,
    default: float,
    min_val: float = MIN_TIMEOUT_SECONDS,
    max_val: float = MAX_TIMEOUT_SECONDS,
) -> float:
    """Validate and clamp configured timeout values.

    Rules:
        - Rejects boolean types (which are int subclasses in Python).
        - Rejects non-numeric types (strings that cannot be parsed as float, dicts, None, etc.).
        - Rejects non-positive values (<= 0).
        - Clamps excessively large values (> max_val) to max_val.
        - Returns default on rejection.
    """
    if val is None:
        return default
    if isinstance(val, bool):
        logger.warning("Invalid boolean timeout %r; using default %.1fs", val, default)
        return default
    try:
        f = float(val)
    except (ValueError, TypeError):
        logger.warning("Non-numeric timeout %r; using default %.1fs", val, default)
        return default

    if f <= 0:
        logger.warning("Non-positive timeout %r; using default %.1fs", val, default)
        return default

    if f > max_val:
        logger.warning("Excessive timeout %.1fs clamped to upper bound %.1fs", f, max_val)
        return max_val

    return max(min_val, f)


def is_local_gateway(gateway_str: str | None, selected_iface: InterfaceInfo | None = None) -> bool:
    """Verify whether a gateway address is demonstrably local/internal.

    Authorization Criteria for --no-internet:
        1. Link-local address (169.254.0.0/16 or fe80::/10)
        2. Private IPv4 address (RFC 1918) or ULA IPv6 address (fc00::/7)
        3. Address belonging to the selected interface's directly connected network subnet.
    """
    if not gateway_str or gateway_str in ("0.0.0.0", "::", "None"):
        return False

    # Strip zone identifier if present (e.g. fe80::1%10)
    clean_addr = gateway_str.split("%")[0]

    try:
        addr = ipaddress.ip_address(clean_addr)
    except ValueError:
        return False

    # 1. Link-local
    if addr.is_link_local:
        return True

    # 2. RFC 1918 Private or ULA Private
    if addr.is_private:
        return True

    # 3. Directly connected subnet on the selected interface
    if selected_iface and selected_iface.networks:
        for net_info in selected_iface.networks:
            try:
                if net_info.network:
                    ip_net = ipaddress.ip_network(net_info.network, strict=False)
                    if addr in ip_net:
                        return True
                elif net_info.address and net_info.prefix_length is not None:
                    ip_net = ipaddress.ip_network(f"{net_info.address}/{net_info.prefix_length}", strict=False)
                    if addr in ip_net:
                        return True
            except Exception:
                continue

    return False


class BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTP redirect handler strictly bounded to at most a specified number of redirects."""

    def __init__(self, max_redirects: int = 1) -> None:
        super().__init__()
        self.max_redirects = max_redirects
        self._redirect_count = 0

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if self._redirect_count >= self.max_redirects:
            logger.debug("Max redirect limit (%d) reached for %s", self.max_redirects, newurl)
            return None
        self._redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ConnectivityCollector:
    """Coordinates cross-platform diagnostic connectivity measurement."""

    def __init__(
        self,
        backend: BasePlatformBackend,
        config_path: Path | None = None,
    ) -> None:
        self.backend = backend
        self.config_path = config_path
        self._load_configuration(config_path)

    def _load_configuration(self, config_path: Path | None = None) -> None:
        """Load data-driven configuration from config/config.yaml or apply safe defaults."""
        config_data: dict[str, Any] = {}
        timeouts_data: dict[str, Any] = {}

        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent / "config" / "config.yaml"

        if config_path.is_file():
            try:
                import yaml
                with open(config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        config_data = loaded.get("connectivity", {})
                        timeouts_data = loaded.get("timeouts", {})
            except Exception as err:
                logger.debug("Failed to read connectivity config from %s: %s", config_path, err)

        # 1. Gateway Ping Count
        raw_count = config_data.get("gateway_ping_count", 2)
        try:
            self.gateway_ping_count = max(1, min(int(raw_count), 10))
        except (ValueError, TypeError):
            self.gateway_ping_count = 2

        # 2. DNS Test Hosts
        raw_dns = config_data.get("dns_test_hosts", ["one.one.one.one", "dns.google"])
        if isinstance(raw_dns, list) and raw_dns:
            self.dns_test_hosts = [str(h).strip() for h in raw_dns if str(h).strip()][:10]
        else:
            self.dns_test_hosts = ["one.one.one.one", "dns.google"]

        # 3. HTTP Probe URLs
        raw_http = config_data.get(
            "http_probe_urls",
            [
                "http://connectivitycheck.gstatic.com/generate_204",
                "https://one.one.one.one",
            ],
        )
        if isinstance(raw_http, list) and raw_http:
            valid_urls: list[str] = []
            for u in raw_http:
                s = str(u).strip()
                if s.startswith("http://") or s.startswith("https://"):
                    valid_urls.append(s)
            self.http_probe_urls = valid_urls[:10]
        else:
            self.http_probe_urls = [
                "http://connectivitycheck.gstatic.com/generate_204",
                "https://one.one.one.one",
            ]

        # 4. TCP Probe Port
        self.tcp_probe_port = 443

        # 5. Timeouts (validated and bounded)
        self.ping_timeout = parse_bounded_timeout(
            timeouts_data.get("ping_seconds"),
            default=DEFAULT_PING_TIMEOUT,
        )
        self.dns_timeout = parse_bounded_timeout(
            timeouts_data.get("dns_lookup_seconds"),
            default=DEFAULT_DNS_TIMEOUT,
        )
        self.http_timeout = parse_bounded_timeout(
            timeouts_data.get("http_probe_seconds"),
            default=DEFAULT_HTTP_TIMEOUT,
        )
        self.tcp_timeout = parse_bounded_timeout(
            timeouts_data.get("tcp_probe_seconds"),
            default=DEFAULT_TCP_TIMEOUT,
        )

    def collect(
        self,
        selected_iface: InterfaceInfo | None = None,
        routing: RoutingInfo | None = None,
        dns: DnsInfo | None = None,
        no_internet: bool = False,
    ) -> ConnectivityInfo:
        """Execute safe diagnostic probes and return normalized ConnectivityInfo."""
        all_targets: list[ConnectivityTarget] = []

        # ----------------------------------------------------------------------
        # Probe 1: Default Gateway Ping
        # ----------------------------------------------------------------------
        gateway_target = self._probe_gateway(selected_iface, routing, no_internet)
        all_targets.append(gateway_target)

        # ----------------------------------------------------------------------
        # Probe 2: DNS Resolution Latency
        # ----------------------------------------------------------------------
        dns_targets, dns_aggregate = self._probe_dns(no_internet)
        all_targets.extend(dns_targets)

        # ----------------------------------------------------------------------
        # Probe 3: HTTP/HTTPS Connectivity
        # ----------------------------------------------------------------------
        http_targets, http_aggregate = self._probe_http(no_internet)
        all_targets.extend(http_targets)

        # ----------------------------------------------------------------------
        # Probe 4: Fixed IPv4 TCP Probe (Port 443)
        # ----------------------------------------------------------------------
        ipv4_target = self._probe_tcp_family(version=4, no_internet=no_internet)
        all_targets.append(ipv4_target)

        # ----------------------------------------------------------------------
        # Probe 5: Fixed IPv6 TCP Probe (Port 443)
        # ----------------------------------------------------------------------
        ipv6_target = self._probe_tcp_family(version=6, no_internet=no_internet)
        all_targets.append(ipv6_target)

        return ConnectivityInfo(
            local_interface=None,
            gateway=gateway_target,
            dns=dns_aggregate,
            internet=http_aggregate,
            ipv4=ipv4_target,
            ipv6=ipv6_target,
            all_targets=all_targets,
        )

    # --------------------------------------------------------------------------
    # Probe Implementations
    # --------------------------------------------------------------------------

    def _probe_gateway(
        self,
        selected_iface: InterfaceInfo | None,
        routing: RoutingInfo | None,
        no_internet: bool,
    ) -> ConnectivityTarget:
        """Select and ping the authoritative default gateway."""
        if not routing:
            return ConnectivityTarget(
                name="gateway",
                target="None",
                success=False,
                status="NOT_APPLICABLE",
                details="Routing table information unavailable",
            )

        candidate_gw: str | None = None
        candidate_iface: str | None = None

        if selected_iface:
            iface_name = selected_iface.name
            if routing.default_ipv4 and routing.default_ipv4.interface == iface_name and routing.default_ipv4.gateway:
                candidate_gw = routing.default_ipv4.gateway
                candidate_iface = iface_name
            elif routing.default_ipv6 and routing.default_ipv6.interface == iface_name and routing.default_ipv6.gateway:
                candidate_gw = routing.default_ipv6.gateway
                candidate_iface = iface_name
            else:
                return ConnectivityTarget(
                    name="gateway",
                    target="None",
                    success=False,
                    status="NOT_APPLICABLE",
                    details=f"No default gateway configured on selected interface '{iface_name}'",
                )
        else:
            if routing.default_ipv4 and routing.default_ipv4.gateway:
                candidate_gw = routing.default_ipv4.gateway
                candidate_iface = routing.default_ipv4.interface
            elif routing.default_ipv6 and routing.default_ipv6.gateway:
                candidate_gw = routing.default_ipv6.gateway
                candidate_iface = routing.default_ipv6.interface

        if not candidate_gw:
            return ConnectivityTarget(
                name="gateway",
                target="None",
                success=False,
                status="NOT_APPLICABLE",
                details="No default gateway discovered in routing table",
            )

        # Gateway authorization under --no-internet
        if no_internet and not is_local_gateway(candidate_gw, selected_iface):
            logger.debug(
                "Gateway '%s' rejected under --no-internet: not verified as local/internal address.",
                candidate_gw,
            )
            return ConnectivityTarget(
                name="gateway",
                target=candidate_gw,
                success=False,
                status="NOT_APPLICABLE",
                details="Gateway address is not verified as local/internal under --no-internet",
            )

        # Dispatch ping to platform backend
        try:
            return self.backend.ping_host(
                target=candidate_gw,
                count=self.gateway_ping_count,
                timeout_seconds=self.ping_timeout,
                interface_name=candidate_iface,
            )
        except Exception as err:
            logger.debug("Gateway ping execution failed: %s", err)
            return ConnectivityTarget(
                name="gateway",
                target=candidate_gw,
                success=False,
                status="ERROR",
                details=f"Ping execution failure: {err}",
            )
