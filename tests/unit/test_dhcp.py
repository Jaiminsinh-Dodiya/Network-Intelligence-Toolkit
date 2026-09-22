"""Unit tests for DHCP data models, Windows parser, and Linux parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.models import DhcpInfo, RouteEntry, RoutingInfo
from backends.windows import parse_windows_dhcp
from backends.linux import (
    parse_systemd_lease,
    parse_dhclient_leases,
    parse_nmcli_dhcp,
    parse_linux_dhcp_route_fallback,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestDhcpModels:
    def test_dhcp_info_defaults(self) -> None:
        info = DhcpInfo()
        assert info.enabled is False
        assert info.available is False
        assert info.status == "UNAVAILABLE"
        assert info.server is None
        assert info.server_ip is None
        assert info.address is None
        assert info.assigned_ip is None
        assert info.lease_duration is None
        assert info.lease_duration_seconds is None

    def test_dhcp_info_bidirectional_synchronization(self) -> None:
        # Canonical initialization sets legacy aliases
        info1 = DhcpInfo(
            enabled=True,
            server="192.168.1.1",
            address="192.168.1.50",
            lease_start="2026-09-20T00:00:00Z",
            lease_expiry="2026-09-21T00:00:00Z",
            lease_duration=86400,
        )
        assert info1.available is True
        assert info1.server_ip == "192.168.1.1"
        assert info1.assigned_ip == "192.168.1.50"
        assert info1.lease_obtained == "2026-09-20T00:00:00Z"
        assert info1.lease_expires == "2026-09-21T00:00:00Z"
        assert info1.lease_duration_seconds == 86400

        # Legacy initialization sets canonical fields
        info2 = DhcpInfo(
            available=True,
            server_ip="10.0.0.1",
            assigned_ip="10.0.0.5",
            lease_obtained="2026-09-20T01:00:00Z",
            lease_expires="2026-09-21T01:00:00Z",
            lease_duration_seconds=7200,
        )
        assert info2.enabled is True
        assert info2.server == "10.0.0.1"
        assert info2.address == "10.0.0.5"
        assert info2.lease_start == "2026-09-20T01:00:00Z"
        assert info2.lease_expiry == "2026-09-21T01:00:00Z"
        assert info2.lease_duration == 7200

        # Dynamic attribute mutation synchronizes both sides
        info1.server = "192.168.1.254"
        assert info1.server_ip == "192.168.1.254"
        info1.server_ip = "192.168.1.2"
        assert info1.server == "192.168.1.2"

        info1.lease_duration = 3600
        assert info1.lease_duration_seconds == 3600

    def test_dhcp_info_serialization(self) -> None:
        info = DhcpInfo(
            enabled=True,
            server="192.168.1.1",
            address="192.168.1.50",
            status="CONFIGURED",
            lease_duration=86400,
        )
        d = info.to_dict()
        assert d["enabled"] is True
        assert d["available"] is True
        assert d["server"] == "192.168.1.1"
        assert d["server_ip"] == "192.168.1.1"
        assert d["address"] == "192.168.1.50"
        assert d["assigned_ip"] == "192.168.1.50"
        assert d["status"] == "CONFIGURED"
        assert d["lease_duration"] == 86400
        assert d["lease_duration_seconds"] == 86400

    def test_independent_lease_duration_support(self) -> None:
        """Engineering Correction #5: support duration without fabricating timestamps."""
        info = DhcpInfo(lease_duration=3600)
        assert info.lease_duration == 3600
        assert info.lease_duration_seconds == 3600
        assert info.lease_start is None
        assert info.lease_expiry is None


class TestWindowsDhcpParser:
    @pytest.fixture
    def cim_adapters(self) -> list[dict]:
        path = FIXTURES_DIR / "windows" / "dhcp" / "cim_dhcp_enabled.json"
        return json.loads(path.read_text(encoding="utf-8"))

    @pytest.fixture
    def net_interfaces(self) -> list[dict]:
        path = FIXTURES_DIR / "windows" / "dhcp" / "net_ip_interface.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_windows_dhcp_active_lease_parsing(self, cim_adapters, net_interfaces) -> None:
        info = parse_windows_dhcp(cim_adapters, net_interfaces, target_iface="Wi-Fi")
        assert info.enabled is True
        assert info.status == "CONFIGURED"
        assert info.server == "192.168.1.1"
        assert info.address == "192.168.1.150"
        assert info.subnet_mask == "255.255.255.0"
        assert info.router == "192.168.1.1"
        assert info.interface == "Wi-Fi"
        assert info.lease_duration == 3599
        assert info.lease_start is not None
        assert info.lease_expiry is not None

    def test_windows_dhcp_static_adapter(self, cim_adapters, net_interfaces) -> None:
        info = parse_windows_dhcp(cim_adapters, net_interfaces, target_iface="Ethernet 2")
        assert info.enabled is False
        assert info.status == "NOT_DHCP"
        assert info.server is None
        assert info.address == "192.168.56.1"
        assert info.interface == "Ethernet 2"

    def test_windows_dhcp_unknown_interface(self, cim_adapters, net_interfaces) -> None:
        info = parse_windows_dhcp(cim_adapters, net_interfaces, target_iface="NonExistentAdapter")
        assert info.status == "UNAVAILABLE"
        assert info.interface == "NonExistentAdapter"

    def test_windows_dhcp_empty_adapters(self) -> None:
        info = parse_windows_dhcp([], [], target_iface="Wi-Fi")
        assert info.status == "UNAVAILABLE"


class TestLinuxDhcpParser:
    def test_systemd_lease_parsing(self) -> None:
        path = FIXTURES_DIR / "linux" / "dhcp" / "systemd_lease_100.txt"
        content = path.read_text(encoding="utf-8")
        info = parse_systemd_lease(content, iface_name="eth0")
        assert info is not None
        assert info.enabled is True
        assert info.status == "CONFIGURED"
        assert info.server == "192.168.10.1"
        assert info.address == "192.168.10.55"
        assert info.subnet_mask == "255.255.255.0"
        assert info.router == "192.168.10.1"
        assert info.lease_duration == 86400
        assert info.interface == "eth0"

    def test_dhclient_multi_interface_isolation(self) -> None:
        """Engineering Correction #3: match requested interface, preventing cross-interface contamination."""
        path = FIXTURES_DIR / "linux" / "dhcp" / "dhclient_multi_interface.leases"
        content = path.read_text(encoding="utf-8")

        # Parse wlan0 lease
        wlan_info = parse_dhclient_leases(content, iface_name="wlan0")
        assert wlan_info is not None
        assert wlan_info.server == "192.168.1.254"
        assert wlan_info.address == "192.168.1.77"
        assert wlan_info.router == "192.168.1.254"
        assert wlan_info.lease_duration == 86400
        assert wlan_info.interface == "wlan0"

        # Parse eth0 lease
        eth_info = parse_dhclient_leases(content, iface_name="eth0")
        assert eth_info is not None
        assert eth_info.server == "10.0.0.1"
        assert eth_info.address == "10.0.0.99"
        assert eth_info.router == "10.0.0.1"
        assert eth_info.lease_duration == 7200
        assert eth_info.interface == "eth0"

        # Requesting an interface without a lease returns None
        assert parse_dhclient_leases(content, iface_name="eth1") is None

    def test_nmcli_dhcp_parsing(self) -> None:
        nmcli_output = """
DHCP4.OPTION[1]: requested_domain_name = lan
DHCP4.OPTION[2]: dhcp_server_identifier = 192.168.2.1
DHCP4.OPTION[3]: ip_address = 192.168.2.100
DHCP4.OPTION[4]: subnet_mask = 255.255.255.0
DHCP4.OPTION[5]: routers = 192.168.2.1
DHCP4.OPTION[6]: lease_time = 43200
"""
        info = parse_nmcli_dhcp(nmcli_output, iface_name="wlan0")
        assert info is not None
        assert info.server == "192.168.2.1"
        assert info.address == "192.168.2.100"
        assert info.subnet_mask == "255.255.255.0"
        assert info.router == "192.168.2.1"
        assert info.lease_duration == 43200
        assert info.status == "CONFIGURED"

    def test_linux_dhcp_route_fallback_gateway_never_copied_to_server(self) -> None:
        """Engineering Correction #1: Default route proto dhcp -> status=PARTIAL, server=None, router=gateway."""
        routes = [
            RouteEntry(
                destination="0.0.0.0/0",
                gateway="192.168.1.1",
                interface="eth0",
                protocol="dhcp",
                is_default=True,
            )
        ]
        info = parse_linux_dhcp_route_fallback(routes, iface_name="eth0")
        assert info is not None
        assert info.status == "PARTIAL"
        assert info.server is None  # Gateway MUST NEVER be copied into server
        assert info.router == "192.168.1.1"
        assert info.interface == "eth0"
        assert "evidence" in info.raw_details

    def test_linux_dhcp_route_fallback_proto_static_does_not_infer_not_dhcp(self) -> None:
        """Engineering Correction #2: Do not infer NOT_DHCP solely from proto static."""
        routes = [
            RouteEntry(
                destination="0.0.0.0/0",
                gateway="192.168.1.1",
                interface="eth0",
                protocol="static",
                is_default=True,
            )
        ]
        info = parse_linux_dhcp_route_fallback(routes, iface_name="eth0")
        assert info is not None
        assert info.status == "UNAVAILABLE"  # Must NOT be NOT_DHCP

    def test_linux_systemd_dhcp_isolation_rejects_other_interface_lease(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Phase 4.1: If target=wlan0 and wlan0 lease is absent, eth0 lease must NOT be returned as wlan0."""
        from typing import Any
        from backends.linux import LinuxBackend

        backend = LinuxBackend()

        def mock_exists(self: Path) -> bool:
            p_str = str(self).replace("\\", "/")
            if p_str == "/sys/class/net/wlan0/ifindex":
                return True
            if p_str == "/run/systemd/netif/leases/3":
                return False  # wlan0 lease does not exist
            if p_str == "/run/systemd/netif/leases/2":
                return True   # eth0 lease exists
            return False

        def mock_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
            p_str = str(self).replace("\\", "/")
            if p_str == "/sys/class/net/wlan0/ifindex":
                return "3\n"
            if p_str == "/run/systemd/netif/leases/2":
                return "ADDRESS=10.0.0.99\nSERVER_ADDRESS=10.0.0.1\n"
            return ""

        monkeypatch.setattr(Path, "exists", mock_exists)
        monkeypatch.setattr(Path, "read_text", mock_read_text)
        monkeypatch.setattr("glob.glob", lambda pattern: ["/run/systemd/netif/leases/2"] if "leases" in pattern else [])
        monkeypatch.setattr(backend, "get_routes", lambda: RoutingInfo())

        info = backend.get_dhcp("wlan0")
        assert info.interface == "wlan0"
        # eth0 lease (10.0.0.1) must NOT be returned as wlan0!
        assert info.server is None
        assert info.address is None
        assert info.status == "UNAVAILABLE"

    def test_linux_dhclient_lease_without_interface_rejected(self) -> None:
        """Phase 4.1: Reject dhclient lease without interface field when target iface is requested."""
        lease_content = """
lease {
  interface "eth0";
  fixed-address 10.0.0.1;
  option dhcp-server-identifier 10.0.0.254;
}
lease {
  fixed-address 192.168.1.50;
  option dhcp-server-identifier 192.168.1.1;
  option subnet-mask 255.255.255.0;
}
"""
        # When target is wlan0, block with no interface must be rejected -> returns None
        result_wlan0 = parse_dhclient_leases(lease_content, iface_name="wlan0")
        assert result_wlan0 is None

        # When target is eth0, explicit eth0 block matches
        result_eth0 = parse_dhclient_leases(lease_content, iface_name="eth0")
        assert result_eth0 is not None
        assert result_eth0.interface == "eth0"
        assert result_eth0.address == "10.0.0.1"
        assert result_eth0.server == "10.0.0.254"
