"""Unit tests for Phase 3 routing models and parsers (Windows and Linux)."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend
from core.execution import CommandResult
from core.models import RouteEntry, RoutingInfo


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class TestRoutingModels:
    """Test RouteEntry and RoutingInfo normalization and behaviors."""

    def test_route_entry_ipv4_default(self):
        entry = RouteEntry(
            destination="0.0.0.0/0",
            gateway="192.168.1.1",
            interface="eth0",
            metric=100,
            route_metric=10,
            interface_metric=90,
            ip_version=4,
            is_default=True,
            protocol="dhcp",
            source="iproute2",
        )
        assert entry.is_default is True
        assert entry.metric == 100
        assert entry.route_metric == 10
        assert entry.interface_metric == 90
        assert entry.gateway == "192.168.1.1"
        assert entry.destination == "0.0.0.0/0"
        d = entry.to_dict()
        assert d["destination"] == "0.0.0.0/0"
        assert d["metric"] == 100
        assert d["interface_metric"] == 90

    def test_route_entry_ipv6_default(self):
        entry = RouteEntry(
            destination="::/0",
            gateway="fe80::1",
            interface="wlan0",
            metric=1024,
            ip_version=6,
            is_default=True,
        )
        assert entry.is_default is True
        assert entry.ip_version == 6
        assert entry.gateway == "fe80::1"

    def test_routing_info_properties_and_backward_compatibility(self):
        v4_def = RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", metric=100, ip_version=4, is_default=True)
        v4_local = RouteEntry(destination="192.168.1.0/24", gateway=None, interface="eth0", metric=100, ip_version=4)
        v6_def = RouteEntry(destination="::/0", gateway="fe80::1", interface="eth0", metric=1024, ip_version=6, is_default=True)

        info = RoutingInfo(
            ipv4_routes=[v4_def, v4_local],
            ipv6_routes=[v6_def],
            default_ipv4=v4_def,
            default_ipv6=v6_def,
            preferred_interface="eth0",
            selection_reason="Active IPv4 default route via 192.168.1.1 on eth0 (metric=100)",
        )

        assert info.default_route == v4_def
        assert len(info.routes) == 3
        assert info.preferred_interface == "eth0"
        assert "metric=100" in info.selection_reason

        d = info.to_dict()
        assert len(d["ipv4_routes"]) == 2
        assert len(d["ipv6_routes"]) == 1
        assert d["default_ipv4"]["gateway"] == "192.168.1.1"
        assert d["default_ipv6"]["gateway"] == "fe80::1"
        assert d["preferred_interface"] == "eth0"


class TestWindowsRoutingParser:
    """Test Windows routing parser with mocked PowerShell output."""

    @pytest.fixture
    def windows_routes_json(self):
        fixture_path = FIXTURES_DIR / "windows" / "routing" / "get_netroute.json"
        return fixture_path.read_text(encoding="utf-8")

    @pytest.fixture
    def windows_ifaces_json(self):
        fixture_path = FIXTURES_DIR / "windows" / "routing" / "get_netipinterface.json"
        return fixture_path.read_text(encoding="utf-8")

    def test_windows_route_and_interface_metric_combination(self, windows_routes_json, windows_ifaces_json):
        backend = WindowsBackend()

        def mock_run_cmd(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "Get-NetIPInterface" in cmd_str:
                return CommandResult(command=cmd, stdout=windows_ifaces_json, stderr="", returncode=0)
            if "Get-NetRoute" in cmd_str:
                return CommandResult(command=cmd, stdout=windows_routes_json, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            routing = backend.get_routes()

            # Check IPv4 and IPv6 routes separated
            assert len(routing.ipv4_routes) >= 2
            assert len(routing.ipv6_routes) >= 2

            # Wi-Fi default route: RouteMetric=10, InterfaceMetric=20 -> effective metric=30
            wifi_v4 = [r for r in routing.ipv4_routes if r.is_default and r.interface == "Wi-Fi"][0]
            assert wifi_v4.route_metric == 10
            assert wifi_v4.interface_metric == 20
            assert wifi_v4.metric == 30
            assert wifi_v4.gateway == "192.168.1.1"

            # Ethernet default route: RouteMetric=20, InterfaceMetric=25 -> effective metric=45
            eth_v4 = [r for r in routing.ipv4_routes if r.is_default and r.interface == "Ethernet"][0]
            assert eth_v4.route_metric == 20
            assert eth_v4.interface_metric == 25
            assert eth_v4.metric == 45
            assert eth_v4.gateway == "10.0.0.1"

            # Preferred default IPv4 route should be Wi-Fi because 30 < 45
            assert routing.default_ipv4 is not None
            assert routing.default_ipv4.interface == "Wi-Fi"
            assert routing.default_ipv4.metric == 30
            assert routing.preferred_interface == "Wi-Fi"

            # IPv6 default route: ::/0 on Wi-Fi, RouteMetric=15, InterfaceMetric=20 -> 35
            assert routing.default_ipv6 is not None
            assert routing.default_ipv6.destination == "::/0"
            assert routing.default_ipv6.metric == 35
            assert routing.default_ipv6.gateway == "fe80::1"

    def test_windows_inactive_routes_filtering(self):
        """Routes that are not Alive should not be preferred as active default route."""
        backend = WindowsBackend()
        dead_route = [
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "192.168.1.1",
                "InterfaceIndex": 12,
                "InterfaceAlias": "Wi-Fi",
                "RouteMetric": 5,
                "State": "Dead",
                "AddressFamily": 2,
            },
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "10.0.0.1",
                "InterfaceIndex": 15,
                "InterfaceAlias": "Ethernet",
                "RouteMetric": 50,
                "State": "Alive",
                "AddressFamily": 2,
            },
        ]
        iface_data = [
            {"InterfaceIndex": 12, "AddressFamily": 2, "InterfaceMetric": 10},
            {"InterfaceIndex": 15, "AddressFamily": 2, "InterfaceMetric": 10},
        ]

        def mock_run_cmd(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "Get-NetIPInterface" in cmd_str:
                return CommandResult(command=cmd, stdout=json.dumps(iface_data), stderr="", returncode=0)
            if "Get-NetRoute" in cmd_str:
                return CommandResult(command=cmd, stdout=json.dumps(dead_route), stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            routing = backend.get_routes()
            # Ethernet should be picked despite higher metric (60 vs 15) because Wi-Fi is Dead
            assert routing.default_ipv4 is not None
            assert routing.default_ipv4.interface == "Ethernet"
            assert routing.default_ipv4.metric == 60

    def test_windows_all_default_routes_inactive(self):
        """When all default routes have State != Alive, default_ipv4 must be None, but routes preserved."""
        backend = WindowsBackend()
        all_dead_routes = [
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "192.168.1.1",
                "InterfaceIndex": 12,
                "InterfaceAlias": "Wi-Fi",
                "RouteMetric": 5,
                "State": "Dead",
                "AddressFamily": 2,
            },
            {
                "DestinationPrefix": "0.0.0.0/0",
                "NextHop": "10.0.0.1",
                "InterfaceIndex": 15,
                "InterfaceAlias": "Ethernet",
                "RouteMetric": 10,
                "State": "Disconnected",
                "AddressFamily": 2,
            },
        ]
        iface_data = [
            {"InterfaceIndex": 12, "AddressFamily": 2, "InterfaceMetric": 10},
            {"InterfaceIndex": 15, "AddressFamily": 2, "InterfaceMetric": 10},
        ]

        def mock_run_cmd(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "Get-NetIPInterface" in cmd_str:
                return CommandResult(command=cmd, stdout=json.dumps(iface_data), stderr="", returncode=0)
            if "Get-NetRoute" in cmd_str:
                return CommandResult(command=cmd, stdout=json.dumps(all_dead_routes), stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            routing = backend.get_routes()
            # default_ipv4 must be None because no default route is Alive
            assert routing.default_ipv4 is None
            # All inactive routes must remain preserved in ipv4_routes
            assert len(routing.ipv4_routes) == 2
            assert all(r.is_default for r in routing.ipv4_routes)
            assert routing.preferred_interface is None


class TestLinuxRoutingParser:
    """Test Linux routing parser with mocked iproute2 and /proc outputs."""

    @pytest.fixture
    def linux_v4_json(self):
        return (FIXTURES_DIR / "linux" / "routing" / "ip_route_json.json").read_text(encoding="utf-8")

    @pytest.fixture
    def linux_v6_json(self):
        return (FIXTURES_DIR / "linux" / "routing" / "ip_route_v6_json.json").read_text(encoding="utf-8")

    @pytest.fixture
    def linux_v4_text(self):
        return (FIXTURES_DIR / "linux" / "routing" / "ip_route_text.txt").read_text(encoding="utf-8")

    @pytest.fixture
    def linux_rules_json(self):
        return (FIXTURES_DIR / "linux" / "routing" / "ip_rule_json.json").read_text(encoding="utf-8")

    def test_linux_json_routes_parsing(self, linux_v4_json, linux_v6_json, linux_rules_json):
        backend = LinuxBackend()

        def mock_run_cmd(cmd, **kwargs):
            if cmd == ["ip", "-j", "rule"]:
                return CommandResult(command=cmd, stdout=linux_rules_json, stderr="", returncode=0)
            if cmd == ["ip", "-j", "route"]:
                return CommandResult(command=cmd, stdout=linux_v4_json, stderr="", returncode=0)
            if cmd == ["ip", "-j", "-6", "route"]:
                return CommandResult(command=cmd, stdout=linux_v6_json, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("backends.linux.is_tool_available", return_value=True), \
             patch("core.execution.run_command", side_effect=mock_run_cmd):
            routing = backend.get_routes()

            assert len(routing.ipv4_routes) == 3
            assert len(routing.ipv6_routes) == 2

            # IPv4 default selected by lowest metric (100 on eth0 vs 200 on eth1)
            assert routing.default_ipv4 is not None
            assert routing.default_ipv4.interface == "eth0"
            assert routing.default_ipv4.metric == 100
            assert routing.default_ipv4.gateway == "192.168.1.1"

            # IPv6 default
            assert routing.default_ipv6 is not None
            assert routing.default_ipv6.interface == "eth0"
            assert routing.default_ipv6.gateway == "fe80::1"
            assert routing.default_ipv6.metric == 1024

            assert routing.preferred_interface == "eth0"
            assert len(routing.rules) == 3

    def test_linux_text_fallback_parsing(self, linux_v4_text):
        backend = LinuxBackend()

        def mock_run_cmd(cmd, **kwargs):
            if cmd == ["ip", "-j", "rule"]:
                return CommandResult(command=cmd, stdout="", stderr="", returncode=1)
            if cmd == ["ip", "rule", "show"]:
                return CommandResult(command=cmd, stdout="", stderr="", returncode=1)
            if cmd == ["ip", "-j", "route"]:
                return CommandResult(command=cmd, stdout="", stderr="", returncode=1)
            if cmd == ["ip", "route", "show"]:
                return CommandResult(command=cmd, stdout=linux_v4_text, stderr="", returncode=0)
            if cmd == ["ip", "-j", "-6", "route"]:
                return CommandResult(command=cmd, stdout="", stderr="", returncode=1)
            if cmd == ["ip", "-6", "route", "show"]:
                return CommandResult(command=cmd, stdout="", stderr="", returncode=1)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("backends.linux.is_tool_available", return_value=True), \
             patch("core.execution.run_command", side_effect=mock_run_cmd):
            routing = backend.get_routes()

            assert len(routing.ipv4_routes) == 4
            # Lowest metric default is 100 on eth0 (vs 300 on eth1)
            assert routing.default_ipv4 is not None
            assert routing.default_ipv4.interface == "eth0"
            assert routing.default_ipv4.metric == 100
            assert routing.default_ipv4.gateway == "192.168.1.1"
            assert routing.preferred_interface == "eth0"

    def test_linux_proc_net_route_fallback(self):
        backend = LinuxBackend()

        # Simulated /proc/net/route with little-endian hex addresses
        # Destination 00000000 = 0.0.0.0, Gateway 0101A8C0 = 192.168.1.1, Mask 00000000 = 0.0.0.0
        proc_content = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        )

        with patch("backends.linux.is_tool_available", return_value=False), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=proc_content):
            routing = backend.get_routes()

            assert len(routing.ipv4_routes) == 2
            assert routing.default_ipv4 is not None
            assert routing.default_ipv4.destination == "0.0.0.0/0"
            assert routing.default_ipv4.gateway == "192.168.1.1"
            assert routing.default_ipv4.interface == "eth0"
            assert routing.default_ipv4.metric == 100
            assert routing.default_ipv4.source == "/proc/net/route"
