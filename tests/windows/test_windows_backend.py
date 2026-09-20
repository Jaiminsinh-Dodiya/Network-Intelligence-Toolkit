"""Windows live integration tests on current host."""

import platform
import pytest
from backends.windows import WindowsBackend
from core.models import SystemInfo, InterfaceInfo, RoutingInfo, DnsInfo, DhcpInfo, WifiInfo


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_platform_info_live():
    backend = WindowsBackend()
    info = backend.get_platform_info()
    assert isinstance(info, SystemInfo)
    assert "Windows" in info.os_name
    assert info.hostname != ""
    assert info.architecture != ""
    assert info.python_version.startswith("3.")


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_capabilities_live():
    backend = WindowsBackend()
    caps = backend.detect_capabilities()
    assert len(caps) >= 8
    assert "interface_info" in caps
    assert "routing_info" in caps
    assert "dns_info" in caps
    assert caps["routing_info"].toolkit_status == "IMPLEMENTED (Phase 3)"
    assert caps["dns_info"].toolkit_status == "IMPLEMENTED (Phase 3)"
    assert caps["dhcp_info"].toolkit_status == "IMPLEMENTED (Phase 4)"
    assert caps["wifi_info"].toolkit_status == "IMPLEMENTED (Phase 4)"
    assert "public_ip" in caps
    assert caps["public_ip"].toolkit_status == "IMPLEMENTED (Phase 5)"
    assert caps["linux_kernel_info"].status.value == "NOT_APPLICABLE"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_interfaces_live():
    backend = WindowsBackend()
    interfaces = backend.get_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    for iface in interfaces:
        assert isinstance(iface, InterfaceInfo)
        assert iface.name != ""

    default_iface = backend.get_default_interface()
    if default_iface:
        assert isinstance(default_iface, InterfaceInfo)
        assert default_iface.name != ""


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_ipv6_prefix_discovery_live():
    backend = WindowsBackend()
    interfaces = backend.get_interfaces()
    for iface in interfaces:
        for net in iface.networks:
            if net.ip_version == 6:
                if net.is_prefix_known:
                    assert net.prefix_length is not None
                    assert 0 <= net.prefix_length <= 128
                    assert net.network is not None
                else:
                    assert net.prefix_length is None
                    assert net.network is None


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_routing_live():
    backend = WindowsBackend()
    routing = backend.get_routes()
    assert isinstance(routing, RoutingInfo)
    assert isinstance(routing.ipv4_routes, list)
    assert isinstance(routing.ipv6_routes, list)
    assert len(routing.routes) == len(routing.ipv4_routes) + len(routing.ipv6_routes)

    if routing.default_ipv4:
        assert routing.default_ipv4.is_default is True
        assert routing.default_ipv4.destination in ("0.0.0.0/0", "default")
        assert routing.preferred_interface is not None
        assert routing.selection_reason is not None
        if routing.default_ipv4.route_metric is not None and routing.default_ipv4.interface_metric is not None:
            assert routing.default_ipv4.metric == routing.default_ipv4.route_metric + routing.default_ipv4.interface_metric


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_dns_live():
    backend = WindowsBackend()
    dns = backend.get_dns()
    assert isinstance(dns, DnsInfo)
    assert isinstance(dns.servers, list)
    assert isinstance(dns.search_domains, list)
    assert dns.status in ("CONFIGURED", "EMPTY", "ERROR")

    for server in dns.servers:
        assert server.protocol in ("UNKNOWN", "DoH", "DoT")
        assert server.family in (4, 6)
        assert server.address != ""


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_dhcp_live():
    backend = WindowsBackend()
    dhcp = backend.get_dhcp()
    assert isinstance(dhcp, DhcpInfo)
    assert dhcp.status in ("CONFIGURED", "PARTIAL", "NOT_DHCP", "UNAVAILABLE", "ERROR")
    if dhcp.enabled:
        assert dhcp.available is True
        if dhcp.server:
            assert dhcp.server_ip == dhcp.server
        if dhcp.address:
            assert dhcp.assigned_ip == dhcp.address


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows host integration test")
def test_windows_wifi_live():
    backend = WindowsBackend()
    wifi = backend.get_wifi()
    assert isinstance(wifi, WifiInfo)
    assert wifi.state in ("CONNECTED", "DISCONNECTED", "NOT_APPLICABLE", "UNAVAILABLE", "ERROR")
    if wifi.state == "CONNECTED":
        assert wifi.connected is True
        assert wifi.is_wireless_interface is True
        assert wifi.is_wifi is True
        assert wifi.bssid is not None
        assert wifi.security_mode in ("OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2-ENTERPRISE", "WPA3-ENTERPRISE", "OTHER", "UNKNOWN")


