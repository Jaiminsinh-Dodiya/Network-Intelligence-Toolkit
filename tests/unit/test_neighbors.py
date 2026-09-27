"""Unit tests for Phase 7: Neighbor / ARP Table Collector."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from backends.linux import (
    parse_linux_ip_neigh_json,
    parse_linux_ip_neigh_text,
    parse_linux_proc_arp,
)
from backends.windows import (
    WINDOWS_NEIGHBOR_STATE_MAP,
    normalize_windows_neighbor_state,
    parse_windows_neighbors,
)
from core.models import NeighborEntry, RouteEntry, RoutingInfo
from core.network import (
    deduplicate_neighbors,
    is_gateway_match,
    sort_neighbors,
)


# ==============================================================================
# Windows Neighbor Parsing Tests
# ==============================================================================

def test_windows_neighbor_state_normalization() -> None:
    """Verify Windows neighbor state enum integer and string mapping."""
    assert normalize_windows_neighbor_state(0) == "UNREACHABLE"
    assert normalize_windows_neighbor_state(1) == "INCOMPLETE"
    assert normalize_windows_neighbor_state(2) == "PROBE"
    assert normalize_windows_neighbor_state(3) == "DELAY"
    assert normalize_windows_neighbor_state(4) == "STALE"
    assert normalize_windows_neighbor_state(5) == "REACHABLE"
    assert normalize_windows_neighbor_state(6) == "PERMANENT"
    assert normalize_windows_neighbor_state("Reachable") == "REACHABLE"
    assert normalize_windows_neighbor_state("stale") == "STALE"
    assert normalize_windows_neighbor_state("Permanent") == "PERMANENT"
    assert normalize_windows_neighbor_state(None) == "UNKNOWN"
    assert normalize_windows_neighbor_state("nonexistent") == "NONEXISTENT"


def test_windows_neighbor_json_parsing() -> None:
    """Verify parsing typical Windows Get-NetNeighbor JSON array."""
    data = [
        {
            "IPAddress": "192.168.1.1",
            "LinkLayerAddress": "00-11-22-33-44-55",
            "InterfaceAlias": "Wi-Fi",
            "InterfaceIndex": 12,
            "State": 5,
            "IsRouter": True,
        },
        {
            "IPAddress": "192.168.1.50",
            "LinkLayerAddress": "00-00-00-00-00-00",
            "InterfaceAlias": "Wi-Fi",
            "InterfaceIndex": 12,
            "State": 1,
            "IsRouter": False,
        },
        {
            "IPAddress": "fe80::1",
            "LinkLayerAddress": "00-11-22-33-44-66",
            "InterfaceAlias": "Ethernet",
            "InterfaceIndex": 5,
            "State": 4,
            "IsRouter": False,
        },
    ]
    parsed = parse_windows_neighbors(json.dumps(data))
    assert len(parsed) == 3

    # Check Ethernet entry (sorted first by interface)
    eth = [n for n in parsed if n.interface == "Ethernet"][0]
    assert eth.ip_address == "fe80::1"
    assert eth.mac_address == "00:11:22:33:44:66"
    assert eth.state == "STALE"
    assert eth.is_router is False

    # Check Wi-Fi entries
    wifi_entries = [n for n in parsed if n.interface == "Wi-Fi"]
    assert len(wifi_entries) == 2
    gw = [n for n in wifi_entries if n.ip_address == "192.168.1.1"][0]
    assert gw.mac_address == "00:11:22:33:44:55"
    assert gw.state == "REACHABLE"
    assert gw.is_router is True

    incomplete = [n for n in wifi_entries if n.ip_address == "192.168.1.50"][0]
    assert incomplete.mac_address == "UNKNOWN"
    assert incomplete.state == "INCOMPLETE"
    assert incomplete.is_router is False


def test_windows_neighbor_single_item_dict_edge_case() -> None:
    """Verify PowerShell ConvertTo-Json single-item dict normalization."""
    single_item = {
        "IPAddress": "192.168.1.1",
        "LinkLayerAddress": "00-11-22-33-44-55",
        "InterfaceAlias": "Wi-Fi",
        "InterfaceIndex": 12,
        "State": 5,
        "IsRouter": True,
    }
    parsed = parse_windows_neighbors(json.dumps(single_item))
    assert len(parsed) == 1
    assert parsed[0].ip_address == "192.168.1.1"
    assert parsed[0].mac_address == "00:11:22:33:44:55"
    assert parsed[0].interface == "Wi-Fi"
    assert parsed[0].state == "REACHABLE"
    assert parsed[0].is_router is True


def test_windows_neighbor_interface_filtering() -> None:
    """Verify filtering neighbors by target interface name and index."""
    data = [
        {
            "IPAddress": "192.168.1.1",
            "LinkLayerAddress": "00-11-22-33-44-55",
            "InterfaceAlias": "Wi-Fi",
            "InterfaceIndex": 12,
            "State": 5,
        },
        {
            "IPAddress": "10.0.0.1",
            "LinkLayerAddress": "00-11-22-33-44-66",
            "InterfaceAlias": "Ethernet",
            "InterfaceIndex": 5,
            "State": 5,
        },
    ]
    raw_json = json.dumps(data)

    # Filter by name
    res_wifi = parse_windows_neighbors(raw_json, target_iface="Wi-Fi")
    assert len(res_wifi) == 1
    assert res_wifi[0].ip_address == "192.168.1.1"

    # Filter by index
    res_eth = parse_windows_neighbors(raw_json, target_iface="eth-other", target_ifindex=5)
    assert len(res_eth) == 1
    assert res_eth[0].ip_address == "10.0.0.1"


def test_windows_neighbor_router_correlation_with_routing_info() -> None:
    """Verify router correlation against authoritative RoutingInfo."""
    routing = RoutingInfo(
        default_ipv4=RouteEntry(
            destination="0.0.0.0/0",
            gateway="192.168.1.1",
            interface="Wi-Fi",
            ip_version=4,
            is_default=True,
        ),
        default_ipv6=RouteEntry(
            destination="::/0",
            gateway="fe80::1",
            interface="Wi-Fi",
            ip_version=6,
            is_default=True,
        ),
    )

    data = [
        {
            "IPAddress": "192.168.1.1",
            "LinkLayerAddress": "00-11-22-33-44-55",
            "InterfaceAlias": "Wi-Fi",
            "State": 5,
            "IsRouter": False,  # OS flag is False, but matches routing table gateway
        },
        {
            "IPAddress": "192.168.1.1",
            "LinkLayerAddress": "00-11-22-33-44-55",
            "InterfaceAlias": "Ethernet",  # Different interface -> should NOT be router
            "State": 5,
            "IsRouter": False,
        },
        {
            "IPAddress": "192.168.1.200",
            "LinkLayerAddress": "00-11-22-33-44-88",
            "InterfaceAlias": "Wi-Fi",
            "State": 5,
            "IsRouter": False,
        },
    ]
    parsed = parse_windows_neighbors(json.dumps(data), routing=routing)
    wifi_gw = [n for n in parsed if n.interface == "Wi-Fi" and n.ip_address == "192.168.1.1"][0]
    assert wifi_gw.is_router is True

    eth_gw = [n for n in parsed if n.interface == "Ethernet" and n.ip_address == "192.168.1.1"][0]
    assert eth_gw.is_router is False

    wifi_other = [n for n in parsed if n.interface == "Wi-Fi" and n.ip_address == "192.168.1.200"][0]
    assert wifi_other.is_router is False


# ==============================================================================
# Linux Neighbor Parsing Tests
# ==============================================================================

def test_linux_ip_neigh_json_array_and_string_states() -> None:
    """Verify Linux ip -j neigh parser handles state as array or string."""
    data = [
        {
            "dst": "192.168.1.1",
            "dev": "eth0",
            "lladdr": "00:11:22:33:44:55",
            "router": True,
            "state": ["REACHABLE"],
        },
        {
            "dst": "192.168.1.2",
            "dev": "eth0",
            "lladdr": "00:11:22:33:44:66",
            "state": "STALE",
        },
        {
            "dst": "192.168.1.3",
            "dev": "eth0",
            "state": ["FAILED"],  # No lladdr, state in array
        },
        {
            "dst": "fe80::1",
            "dev": "eth0",
            "lladdr": "00:11:22:33:44:77",
            "state": ["STALE", "ROUTER"],  # ROUTER inside state list
        },
    ]
    parsed = parse_linux_ip_neigh_json(json.dumps(data))
    assert len(parsed) == 4

    p1 = [n for n in parsed if n.ip_address == "192.168.1.1"][0]
    assert p1.state == "REACHABLE"
    assert p1.is_router is True
    assert p1.mac_address == "00:11:22:33:44:55"

    p2 = [n for n in parsed if n.ip_address == "192.168.1.2"][0]
    assert p2.state == "STALE"
    assert p2.is_router is False

    p3 = [n for n in parsed if n.ip_address == "192.168.1.3"][0]
    assert p3.state == "FAILED"
    assert p3.mac_address == "UNKNOWN"

    p4 = [n for n in parsed if n.ip_address == "fe80::1"][0]
    assert p4.state == "STALE"
    assert p4.is_router is True


def test_linux_ip_neigh_text_parsing() -> None:
    """Verify parsing Linux ip neigh plain text output."""
    text = """
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.2 dev eth0 lladdr 00:11:22:33:44:66 router STALE
192.168.1.50 dev eth0  FAILED
192.168.1.51 dev eth0  INCOMPLETE
fe80::1 dev eth0 lladdr 00:11:22:33:44:77 router REACHABLE
10.0.0.1 dev wlan0 lladdr 00:11:22:33:44:88 PERMANENT
"""
    parsed = parse_linux_ip_neigh_text(text)
    assert len(parsed) == 6

    # Test interface filtering
    wlan = parse_linux_ip_neigh_text(text, target_iface="wlan0")
    assert len(wlan) == 1
    assert wlan[0].ip_address == "10.0.0.1"
    assert wlan[0].state == "PERMANENT"

    eth_entries = parse_linux_ip_neigh_text(text, target_iface="eth0")
    assert len(eth_entries) == 5

    failed_entry = [n for n in eth_entries if n.ip_address == "192.168.1.50"][0]
    assert failed_entry.state == "FAILED"
    assert failed_entry.mac_address == "UNKNOWN"


def test_linux_proc_arp_parsing() -> None:
    """Verify parsing /proc/net/arp table output."""
    content = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
192.168.1.2      0x1         0x6         00:11:22:33:44:66     *        eth0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.1         0x1         0x2         00:11:22:33:44:77     *        wlan0
"""
    routing = RoutingInfo(
        default_ipv4=RouteEntry(
            destination="0.0.0.0/0",
            gateway="192.168.1.1",
            interface="eth0",
            ip_version=4,
            is_default=True,
        )
    )
    parsed = parse_linux_proc_arp(content, routing=routing)
    assert len(parsed) == 4

    gw = [n for n in parsed if n.ip_address == "192.168.1.1"][0]
    assert gw.state == "REACHABLE"
    assert gw.is_router is True
    assert gw.mac_address == "00:11:22:33:44:55"

    perm = [n for n in parsed if n.ip_address == "192.168.1.2"][0]
    assert perm.state == "PERMANENT"
    assert perm.is_router is False

    incomp = [n for n in parsed if n.ip_address == "192.168.1.50"][0]
    assert incomp.state == "INCOMPLETE"
    assert incomp.mac_address == "UNKNOWN"


# ==============================================================================
# Router Correlation & Deduplication Tests
# ==============================================================================

def test_is_gateway_match_rules() -> None:
    """Verify is_gateway_match requires matching IP, family, and interface."""
    routing = RoutingInfo(
        default_ipv4=RouteEntry(
            destination="0.0.0.0/0",
            gateway="192.168.1.1",
            interface="eth0",
            ip_version=4,
            is_default=True,
        ),
        default_ipv6=RouteEntry(
            destination="::/0",
            gateway="fe80::1",
            interface="eth0",
            ip_version=6,
            is_default=True,
        ),
    )

    # Exact match
    assert is_gateway_match("192.168.1.1", "eth0", routing) is True
    assert is_gateway_match("fe80::1", "eth0", routing) is True

    # Interface mismatch
    assert is_gateway_match("192.168.1.1", "wlan0", routing) is False
    assert is_gateway_match("fe80::1", "wlan0", routing) is False

    # IP mismatch
    assert is_gateway_match("192.168.1.2", "eth0", routing) is False

    # Routing is None
    assert is_gateway_match("192.168.1.1", "eth0", None) is False


def test_deduplicate_neighbors_priority_and_merging() -> None:
    """Verify deduplication keeps higher priority state and merges router flag."""
    n1 = NeighborEntry(
        ip_address="192.168.1.1",
        mac_address="UNKNOWN",
        interface="eth0",
        state="STALE",
        is_router=False,
    )
    n2 = NeighborEntry(
        ip_address="192.168.1.1",
        mac_address="00:11:22:33:44:55",
        interface="eth0",
        state="REACHABLE",
        is_router=True,
    )
    deduped = deduplicate_neighbors([n1, n2])
    assert len(deduped) == 1
    assert deduped[0].state == "REACHABLE"
    assert deduped[0].mac_address == "00:11:22:33:44:55"
    assert deduped[0].is_router is True

    # Test reverse order preserves highest priority
    deduped_rev = deduplicate_neighbors([n2, n1])
    assert len(deduped_rev) == 1
    assert deduped_rev[0].state == "REACHABLE"
    assert deduped_rev[0].mac_address == "00:11:22:33:44:55"
    assert deduped_rev[0].is_router is True


def test_sort_neighbors_deterministic() -> None:
    """Verify sorting order: interface, IP version (4 before 6), numerical IP, MAC, state."""
    entries = [
        NeighborEntry(ip_address="fe80::1", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE"),
        NeighborEntry(ip_address="192.168.1.10", mac_address="00:11:22:33:44:66", interface="eth0", state="REACHABLE"),
        NeighborEntry(ip_address="192.168.1.2", mac_address="00:11:22:33:44:77", interface="eth0", state="REACHABLE"),
        NeighborEntry(ip_address="10.0.0.1", mac_address="00:11:22:33:44:88", interface="wlan0", state="REACHABLE"),
    ]
    sorted_entries = sort_neighbors(entries)

    # eth0 entries should be first (alphabetical)
    assert sorted_entries[0].interface == "eth0"
    assert sorted_entries[1].interface == "eth0"
    assert sorted_entries[2].interface == "eth0"
    assert sorted_entries[3].interface == "wlan0"

    # Within eth0, IPv4 comes before IPv6, and 192.168.1.2 before 192.168.1.10
    assert sorted_entries[0].ip_address == "192.168.1.2"
    assert sorted_entries[1].ip_address == "192.168.1.10"
    assert sorted_entries[2].ip_address == "fe80::1"


def test_empty_and_malformed_inputs() -> None:
    """Verify empty or malformed inputs return empty lists without crashing."""
    assert parse_windows_neighbors("") == []
    assert parse_windows_neighbors("invalid json") == []
    assert parse_windows_neighbors("[]") == []
    assert parse_linux_ip_neigh_json("") == []
    assert parse_linux_ip_neigh_json("invalid json") == []
    assert parse_linux_ip_neigh_text("") == []
    assert parse_linux_proc_arp("") == []
