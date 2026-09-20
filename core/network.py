"""Cross-Platform Subnet and Network Engine.

Performs normalized network calculations for IPv4 and IPv6 using Python's ipaddress library.
Provides address classification, subnet boundaries, usable host calculations,
and interface selection groundwork.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from core.models import InterfaceInfo, NetworkInfo, NeighborEntry, RoutingInfo, SocketEntry

logger = logging.getLogger(__name__)


def normalize_ip_string(address_str: str) -> str:
    """Normalize an IP address string by stripping whitespace and IPv6 zone identifiers."""
    cleaned = address_str.strip()
    if "/" in cleaned:
        addr_part, prefix_part = cleaned.split("/", 1)
        if "%" in addr_part:
            addr_part = addr_part.split("%")[0]
        return f"{addr_part}/{prefix_part}"
    elif "%" in cleaned:
        cleaned = cleaned.split("%")[0]
    return cleaned


def classify_address_scope(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an IP address into standard architectural reachability scopes.

    Scopes:
        LOOPBACK: Host loopback (127.0.0.0/8, ::1/128)
        LINK_LOCAL: Non-routable link-local (169.254.0.0/16, fe80::/10)
        PRIVATE: RFC 1918 / RFC 4193 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        MULTICAST: Multicast group (224.0.0.0/4, ff00::/8)
        UNSPECIFIED: All-zeros unassigned (0.0.0.0, ::)
        GLOBAL: Public Internet routable address
        OTHER: Reserved / benchmarking / carrier-grade NAT space
    """
    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_link_local:
        return "LINK_LOCAL"
    if ip.is_multicast:
        return "MULTICAST"
    if ip.is_unspecified:
        return "UNSPECIFIED"
    if ip.is_private:
        return "PRIVATE"
    if ip.is_global:
        return "GLOBAL"
    return "OTHER"


def calculate_ipv4_network(
    address_str: str,
    netmask_or_prefix: str | int | None = None,
    interface_name: str = "",
) -> NetworkInfo:
    """Calculate IPv4 network boundaries, broadcast, and usable host range.

    Special prefix semantics:
        /32: Single host. Total=1, Usable=1, First=Last=Address, Broadcast=None.
        /31: Point-to-point link (RFC 3021). Total=2, Usable=2, First=net[0], Last=net[1], Broadcast=None.
        /30: Small subnet. Total=4, Usable=2, First=net[1], Last=net[2], Broadcast=net[3].
        /1 - /29: Standard subnets. Total=2^(32-p), Usable=Total-2, Broadcast=net.broadcast_address.
    When prefix/netmask is unavailable, reports is_prefix_known=False, prefix_length=None, network=None.
    """
    clean_addr = normalize_ip_string(address_str)
    if "/" in clean_addr:
        addr_part, slash_prefix = clean_addr.split("/", 1)
        clean_addr = addr_part
        if netmask_or_prefix is None:
            netmask_or_prefix = slash_prefix

    if netmask_or_prefix is None:
        ip = ipaddress.IPv4Address(clean_addr)
        scope = classify_address_scope(ip)
        return NetworkInfo(
            interface=interface_name,
            address=str(ip),
            cidr=str(ip),
            network=None,
            prefix_length=None,
            netmask=None,
            broadcast=None,
            first_host=None,
            last_host=None,
            total_addresses=0,
            usable_host_count=0,
            ip_version=4,
            scope=scope,
            is_prefix_known=False,
        )

    if isinstance(netmask_or_prefix, int):
        iface_str = f"{clean_addr}/{netmask_or_prefix}"
    else:
        iface_str = f"{clean_addr}/{normalize_ip_string(str(netmask_or_prefix))}"

    iface = ipaddress.IPv4Interface(iface_str)
    net = iface.network
    prefix = net.prefixlen
    total_addresses = net.num_addresses

    broadcast: str | None = None
    first_host: str | None = None
    last_host: str | None = None
    usable_hosts: int = 0

    if prefix == 32:
        total_addresses = 1
        usable_hosts = 1
        first_host = str(net.network_address)
        last_host = str(net.network_address)
        broadcast = None
    elif prefix == 31:
        # RFC 3021 Point-to-Point Links: both endpoints are usable
        total_addresses = 2
        usable_hosts = 2
        first_host = str(net[0])
        last_host = str(net[1])
        broadcast = None
    elif prefix == 30:
        total_addresses = 4
        usable_hosts = 2
        first_host = str(net[1])
        last_host = str(net[2])
        broadcast = str(net[3])
    else:
        # Standard subnets /1 to /29
        usable_hosts = max(0, total_addresses - 2)
        first_host = str(net[1])
        last_host = str(net[-2])
        broadcast = str(net.broadcast_address)

    scope = classify_address_scope(iface.ip)

    return NetworkInfo(
        interface=interface_name,
        address=str(iface.ip),
        cidr=f"{iface.ip}/{prefix}",
        network=str(net),
        prefix_length=prefix,
        netmask=str(net.netmask),
        broadcast=broadcast,
        first_host=first_host,
        last_host=last_host,
        total_addresses=total_addresses,
        usable_host_count=usable_hosts,
        ip_version=4,
        scope=scope,
        is_prefix_known=True,
    )


def calculate_ipv6_network(
    address_str: str,
    prefix: int | None = None,
    interface_name: str = "",
) -> NetworkInfo:
    """Calculate IPv6 network boundaries and address characteristics.

    IPv6 does not use broadcast addresses (multicast and anycast are used instead).
    Special prefix semantics:
        /128: Host address / loopback. Total=1, Usable=1, First=Last=Address.
        /127: Point-to-point link (RFC 6164). Total=2, Usable=2.
        < 127: Subnets (e.g. /64, /56, /48).
    When prefix is unavailable (None), does NOT silently assume /64.
    Reports is_prefix_known=False, prefix_length=None, network=None.
    """
    clean_addr = normalize_ip_string(address_str)
    if "/" in clean_addr:
        addr_part, slash_prefix = clean_addr.split("/", 1)
        clean_addr = addr_part
        if prefix is None:
            try:
                prefix = int(slash_prefix)
            except ValueError:
                prefix = None

    if prefix is None:
        ip = ipaddress.IPv6Address(clean_addr)
        scope = classify_address_scope(ip)
        return NetworkInfo(
            interface=interface_name,
            address=str(ip),
            cidr=str(ip),
            network=None,
            prefix_length=None,
            netmask=None,
            broadcast=None,
            first_host=None,
            last_host=None,
            total_addresses=0,
            usable_host_count=0,
            ip_version=6,
            scope=scope,
            is_prefix_known=False,
        )

    iface = ipaddress.IPv6Interface(f"{clean_addr}/{prefix}")
    net = iface.network
    prefix_len = net.prefixlen
    total_addresses = net.num_addresses

    broadcast: str | None = None  # IPv6 has no broadcast address

    if prefix_len == 128:
        usable_hosts = 1
        first_host = str(net.network_address)
        last_host = str(net.network_address)
    elif prefix_len == 127:
        # RFC 6164
        usable_hosts = 2
        first_host = str(net[0])
        last_host = str(net[1])
    else:
        usable_hosts = total_addresses
        first_host = str(net[0])
        last_host = str(net[-1])

    scope = classify_address_scope(iface.ip)

    return NetworkInfo(
        interface=interface_name,
        address=str(iface.ip),
        cidr=f"{iface.ip}/{prefix_len}",
        network=str(net),
        prefix_length=prefix_len,
        netmask=str(net.netmask),
        broadcast=broadcast,
        first_host=first_host,
        last_host=last_host,
        total_addresses=total_addresses,
        usable_host_count=usable_hosts,
        ip_version=6,
        scope=scope,
        is_prefix_known=True,
    )


def calculate_network_info(
    address_str: str,
    netmask_or_prefix: str | int | None = None,
    interface_name: str = "",
) -> NetworkInfo | None:
    """Safe dispatcher calculating normalized NetworkInfo for IPv4 or IPv6.

    Returns None if input is invalid or malformed without raising exceptions.
    """
    if not address_str or not isinstance(address_str, str):
        return None

    clean_addr = normalize_ip_string(address_str)

    # Determine IP version
    addr_part = clean_addr.split("/")[0]

    try:
        ip = ipaddress.ip_address(addr_part)
    except ValueError:
        return None

    try:
        if ip.version == 4:
            return calculate_ipv4_network(clean_addr, netmask_or_prefix, interface_name)
        elif ip.version == 6:
            prefix_val = None
            if isinstance(netmask_or_prefix, int):
                prefix_val = netmask_or_prefix
            elif isinstance(netmask_or_prefix, str) and netmask_or_prefix.strip():
                stripped = netmask_or_prefix.strip()
                if stripped.isdigit():
                    prefix_val = int(stripped)
                else:
                    try:
                        mask_net = ipaddress.IPv6Network(f"::/{stripped}")
                        prefix_val = mask_net.prefixlen
                    except Exception:
                        prefix_val = None
            elif "/" in clean_addr:
                try:
                    prefix_val = int(clean_addr.split("/")[1])
                except ValueError:
                    prefix_val = None
            return calculate_ipv6_network(clean_addr, prefix_val, interface_name)
    except (ValueError, TypeError, ipaddress.NetmaskValueError) as err:
        logger.debug("Failed network calculation for '%s': %s", address_str, err)
        return None

    return None


def select_default_interface(
    interfaces: list[InterfaceInfo],
    default_route_iface: str | None = None,
) -> InterfaceInfo | None:
    """Select the primary active network interface according to the Phase 2 contract:

    1. Interface associated with the active default route (when provided/resolved).
    2. Active UP non-loopback interface with a usable (non-link-local) IPv4 address.
    3. Active UP non-loopback interface with any IP address.
    4. First non-loopback interface.
    5. First interface or None.
    """
    if not interfaces:
        return None

    # 1. Default route interface
    if default_route_iface:
        for iface in interfaces:
            if iface.name.lower() == default_route_iface.lower() and iface.is_up:
                return iface
        for iface in interfaces:
            if iface.name.lower() == default_route_iface.lower():
                return iface

    # 2. Active non-loopback with non-link-local IPv4 (prioritize active traffic and non-virtual adapters)
    candidates: list[tuple[int, InterfaceInfo]] = []
    for iface in interfaces:
        if iface.is_up and not iface.is_loopback:
            has_usable_ipv4 = False
            for net in iface.networks:
                if net.ip_version == 4 and net.scope not in ("LINK_LOCAL", "LOOPBACK"):
                    has_usable_ipv4 = True
                    break
            if not has_usable_ipv4:
                for ip in iface.ipv4:
                    clean = ip.split("/")[0]
                    if not clean.startswith("169.254.") and not clean.startswith("127."):
                        has_usable_ipv4 = True
                        break

            if has_usable_ipv4:
                score = 0
                lower_name = iface.name.lower()
                # Deprioritize virtual adapter names
                if not any(v in lower_name for v in ("virtual", "vbox", "vmware", "hyper-v", "wsl")):
                    score += 10
                # Prioritize interfaces with active traffic
                if iface.rx_bytes > 0 or iface.tx_bytes > 0:
                    score += 10
                candidates.append((score, iface))

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    # 3. Active non-loopback with any IP
    for iface in interfaces:
        if iface.is_up and not iface.is_loopback and (iface.ipv4 or iface.ipv6):
            return iface

    # 4. Any non-loopback interface
    for iface in interfaces:
        if not iface.is_loopback:
            return iface

    return interfaces[0]
