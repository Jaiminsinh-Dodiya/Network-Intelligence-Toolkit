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


def frequency_to_channel(freq_mhz: int) -> int | None:
    """Map a frequency in MHz to its standard 802.11 channel number.

    Supports 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7).
    Returns None if unmapped or unrecognized.
    """
    try:
        freq = int(freq_mhz)
    except (ValueError, TypeError):
        return None

    # 2.4 GHz band (channels 1-13: 2412-2472 MHz; channel 14: 2484 MHz)
    if 2412 <= freq <= 2472 and (freq - 2407) % 5 == 0:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14

    # 5 GHz band (channels 32-177: 5160-5885 MHz)
    if 5000 <= freq <= 5900 and (freq - 5000) % 5 == 0:
        ch = (freq - 5000) // 5
        if 32 <= ch <= 177:
            return ch

    # 6 GHz band (Wi-Fi 6E/7: channel 2 = 5935 MHz, channels 1-233 = 5955-7115 MHz)
    if freq == 5935:
        return 2
    if 5955 <= freq <= 7115 and (freq - 5950) % 5 == 0:
        ch = (freq - 5950) // 5
        if 1 <= ch <= 233:
            return ch

    return None


def channel_to_frequency(channel: int, band: str | None = None) -> int | None:
    """Map a channel number to its center frequency in MHz given the frequency band.

    Requires an explicit band string (e.g. '2.4GHz', '5GHz', '6GHz').
    Returns None if band is None or channel is ambiguous/invalid.
    """
    if band is None:
        # Ambiguous across bands (e.g. Channel 1 in 2.4 GHz vs 6 GHz)
        return None

    try:
        ch = int(channel)
    except (ValueError, TypeError):
        return None

    b = band.lower().replace(" ", "").replace("-", "")

    if "2.4" in b:
        if 1 <= ch <= 13:
            return 2407 + (ch * 5)
        if ch == 14:
            return 2484
        return None

    if "5" in b and "2.4" not in b and "6" not in b:
        if 32 <= ch <= 177:
            return 5000 + (ch * 5)
        return None

    if "6" in b:
        if ch == 2:
            return 5935
        if 1 <= ch <= 233:
            return 5950 + (ch * 5)
        return None

    return None


def normalize_bssid(bssid_str: str | None) -> str | None:
    """Normalize a MAC/BSSID string to canonical lowercase colon-delimited format (aa:bb:cc:dd:ee:ff).

    Returns None if input is invalid or missing.
    """
    if not bssid_str:
        return None

    cleaned = bssid_str.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return cleaned

    return None


def normalize_wifi_security(auth_str: str | None) -> tuple[str, str | None]:
    """Classify Wi-Fi security mode into canonical categories:
    OPEN, WEP, WPA, WPA2, WPA3, WPA2-ENTERPRISE, WPA3-ENTERPRISE, OTHER, UNKNOWN.

    Never maps enterprise modes to WPA2.
    Returns (security_mode, raw_security).
    """
    if not auth_str:
        return ("UNKNOWN", None)

    raw = auth_str.strip()
    lower = raw.lower()

    if "wpa3" in lower and ("enterprise" in lower or "802.1x" in lower):
        return ("WPA3-ENTERPRISE", raw)
    if "wpa2" in lower and ("enterprise" in lower or "802.1x" in lower):
        return ("WPA2-ENTERPRISE", raw)
    if "enterprise" in lower or "802.1x" in lower:
        return ("OTHER", raw)
    if "wpa3" in lower:
        return ("WPA3", raw)
    if "wpa2" in lower:
        return ("WPA2", raw)
    if "wpa" in lower:
        return ("WPA", raw)
    if "wep" in lower:
        return ("WEP", raw)
    if "open" in lower or lower in ("none", "no authentication"):
        return ("OPEN", raw)
    if any(k in lower for k in ("owe", "eap", "psk", "sae")):
        return ("OTHER", raw)

    return ("UNKNOWN", raw)


def normalize_wifi_standard(radio_str: str | None) -> str:
    """Normalize Wi-Fi radio type / standard string into canonical notation (e.g. 802.11ax, 802.11ac, etc.).

    Strictly returns 'UNKNOWN' unless explicitly exposed by the OS.
    Never infers standard from SSID, frequency, or bitrate.
    """
    if not radio_str:
        return "UNKNOWN"

    r = radio_str.strip().lower()
    if "802.11be" in r or "wi-fi 7" in r or "wifi 7" in r:
        return "802.11be"
    if "802.11ax" in r or "wi-fi 6" in r or "wifi 6" in r:
        return "802.11ax"
    if "802.11ac" in r or "wi-fi 5" in r or "wifi 5" in r:
        return "802.11ac"
    if "802.11n" in r or "wi-fi 4" in r or "wifi 4" in r:
        return "802.11n"
    if "802.11g" in r:
        return "802.11g"
    if "802.11a" in r:
        return "802.11a"
    if "802.11b" in r:
        return "802.11b"

    if r.startswith("802.11"):
        return radio_str.strip()

    return "UNKNOWN"


def signal_percent_to_dbm(percent: int | float | None) -> int | None:
    """Approximate/heuristic conversion of signal quality percentage (0-100%) to RSSI in dBm.

    Note: This is a linear approximation heuristic, not a direct RF measurement or logarithmic curve.
    """
    if percent is None:
        return None
    try:
        p = max(0, min(100, float(percent)))
        return int((p / 2.0) - 100.0)
    except (ValueError, TypeError):
        return None


def signal_dbm_to_percent(dbm: int | float | None) -> int | None:
    """Approximate/heuristic conversion of RSSI in dBm to signal quality percentage (0-100%).

    Note: This is a linear approximation heuristic, not a direct RF measurement or logarithmic curve.
    """
    if dbm is None:
        return None
    try:
        d = float(dbm)
        p = 2.0 * (d + 100.0)
        return int(max(0, min(100, round(p))))
    except (ValueError, TypeError):
        return None


NEIGHBOR_STATE_PRIORITY: dict[str, int] = {
    "REACHABLE": 6,
    "PERMANENT": 5,
    "STALE": 4,
    "DELAY": 3,
    "PROBE": 2,
    "INCOMPLETE": 1,
    "UNREACHABLE": 1,
    "FAILED": 1,
    "NOARP": 1,
    "NONE": 0,
    "UNKNOWN": 0,
}
