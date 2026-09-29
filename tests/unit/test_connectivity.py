"""Unit tests for Phase 6 Safe Connectivity Engine."""

from __future__ import annotations

import concurrent.futures
import json
import socket
import time
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from backends.base import BasePlatformBackend
from backends.linux import LinuxBackend, parse_linux_ping_output
from backends.windows import WindowsBackend, parse_windows_ping_output
from core.collector import CollectorCoordinator
from core.connectivity import (
    USER_AGENT,
    BoundedRedirectHandler,
    ConnectivityCollector,
    is_local_gateway,
    parse_bounded_timeout,
)
from core.models import (
    ConnectivityInfo,
    ConnectivityTarget,
    InterfaceInfo,
    NetworkInfo,
    NetworkIntelligenceReport,
    RouteEntry,
    RoutingInfo,
    SystemInfo,
)
from core.registry import CollectorOptions


# ==============================================================================
# 1. Model & Serialization Tests
# ==============================================================================

def test_connectivity_target_status_defaults():
    """Verify ConnectivityTarget default status and validation."""
    # Defaults from success boolean
    t1 = ConnectivityTarget(name="ping", target="1.1.1.1", success=True)
    assert t1.status == "SUCCESS"

    t2 = ConnectivityTarget(name="ping", target="1.1.1.1", success=False)
    assert t2.status == "FAILED"

    # Explicit valid statuses
    for status in ("SUCCESS", "FAILED", "TIMEOUT", "ERROR", "DISABLED", "NOT_APPLICABLE"):
        t = ConnectivityTarget(name="test", target="1.1.1.1", success=True, status=status)
        assert t.status == status

    # Invalid status rejection
    with pytest.raises(ValueError, match="Invalid connectivity status"):
        ConnectivityTarget(name="test", target="1.1.1.1", success=True, status="UNREACHABLE")


def test_connectivity_models_serialization():
    """Verify ConnectivityTarget and ConnectivityInfo JSON serialization."""
    target = ConnectivityTarget(
        name="internet_http",
        target="http://connectivitycheck.gstatic.com/generate_204",
        success=True,
        latency_ms=45.2,
        status="SUCCESS",
        http_status=204,
        details="HTTP 204 No Content",
    )
    d = target.to_dict()
    assert d["name"] == "internet_http"
    assert d["http_status"] == 204
    assert d["status"] == "SUCCESS"
    assert d["packet_loss_pct"] is None

    info = ConnectivityInfo(
        local_interface=None,
        gateway=ConnectivityTarget(name="gateway", target="192.168.1.1", success=True, latency_ms=1.5, packet_loss_pct=0.0),
        dns=ConnectivityTarget(name="dns_aggregate", target="configured_dns_hosts", success=True, latency_ms=12.0),
        internet=target,
        ipv4=ConnectivityTarget(name="ipv4_connectivity", target="one.one.one.one (1.1.1.1:443)", success=True, latency_ms=50.0),
        ipv6=ConnectivityTarget(name="ipv6_connectivity", target="None", success=False, status="NOT_APPLICABLE", details="No IPv6 destination"),
        all_targets=[target],
    )
    info_dict = info.to_dict()
    assert info_dict["local_interface"] is None
    assert info_dict["gateway"]["packet_loss_pct"] == 0.0
    assert info_dict["ipv6"]["status"] == "NOT_APPLICABLE"

    # Ensure full JSON serialization succeeds
    json_str = json.dumps(info_dict)
    loaded = json.loads(json_str)
    assert loaded["internet"]["http_status"] == 204


# ==============================================================================
# 2. Windows Ping Parser Tests
# ==============================================================================

def test_windows_ping_parsing_success():
    """Verify Windows ping output parsing with 0% loss and RTT statistics."""
    stdout = """
Pinging 10.197.32.217 with 32 bytes of data:
Reply from 10.197.32.217: bytes=32 time=104ms TTL=64
Reply from 10.197.32.217: bytes=32 time=2ms TTL=64

Ping statistics for 10.197.32.217:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 2ms, Maximum = 104ms, Average = 53ms
"""
    res = parse_windows_ping_output(stdout, target="10.197.32.217")
    assert res.success is True
    assert res.status == "SUCCESS"
    assert res.latency_ms == 53.0
    assert res.packet_loss_pct == 0.0
    assert "2/2 packets received" in res.details


def test_windows_ping_parsing_timeout():
    """Verify Windows ping output parsing with 100% loss / Request timed out."""
    stdout = """
Pinging 192.0.2.1 with 32 bytes of data:
Request timed out.
Request timed out.

Ping statistics for 192.0.2.1:
    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),
"""
    res = parse_windows_ping_output(stdout, target="192.0.2.1")
    assert res.success is False
    assert res.status == "TIMEOUT"
    assert res.latency_ms is None
    assert res.packet_loss_pct == 100.0


def test_windows_ping_parsing_partial_loss():
    """Verify Windows ping output parsing with partial packet loss."""
    stdout = """
Pinging 10.0.0.1 with 32 bytes of data:
Reply from 10.0.0.1: bytes=32 time=12ms TTL=64
Request timed out.

Ping statistics for 10.0.0.1:
    Packets: Sent = 2, Received = 1, Lost = 1 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 12ms, Maximum = 12ms, Average = 12ms
"""
    res = parse_windows_ping_output(stdout, target="10.0.0.1")
    assert res.success is True
    assert res.status == "SUCCESS"
    assert res.latency_ms == 12.0
    assert res.packet_loss_pct == 50.0


def test_windows_ping_missing_binary():
    """Verify graceful handling when Windows ping binary is missing."""
    backend = WindowsBackend()
    with patch("backends.windows.is_tool_available", return_value=False):
        res = backend.ping_host("192.168.1.1")
        assert res.success is False
        assert res.status == "ERROR"
        assert "not found" in res.details


# ==============================================================================
# 3. Linux Ping Parser Tests
# ==============================================================================

def test_linux_ping_parsing_success():
    """Verify Linux ping output parsing with 0% loss and RTT statistics."""
    stdout = """
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.45 ms

--- 192.168.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 1.230/1.340/1.450/0.110 ms
"""
    res = parse_linux_ping_output(stdout, target="192.168.1.1")
    assert res.success is True
    assert res.status == "SUCCESS"
    assert res.latency_ms == 1.34
    assert res.packet_loss_pct == 0.0
    assert "2/2 packets received" in res.details


def test_linux_ping_parsing_timeout():
    """Verify Linux ping output parsing with 100% loss."""
    stdout = """
PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.

--- 192.0.2.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1005ms
"""
    res = parse_linux_ping_output(stdout, target="192.0.2.1")
    assert res.success is False
    assert res.status == "TIMEOUT"
    assert res.latency_ms is None
    assert res.packet_loss_pct == 100.0


def test_linux_ping_missing_binary():
    """Verify graceful handling when Linux ping and ping6 binaries are missing."""
    backend = LinuxBackend()
    with patch("backends.linux.is_tool_available", return_value=False):
        res = backend.ping_host("192.168.1.1")
        assert res.success is False
        assert res.status == "ERROR"
        assert "not found" in res.details


# ==============================================================================
# 4. Gateway Selection & Authorization Tests
# ==============================================================================

def test_is_local_gateway_authorization():
    """Verify local-target authorization logic for --no-internet."""
    iface = InterfaceInfo(
        name="eth0",
        state="UP",
        networks=[
            NetworkInfo(address="192.168.1.100", prefix_length=24, network="192.168.1.0/24", ip_version=4),
            NetworkInfo(address="2001:db8::10", prefix_length=64, network="2001:db8::/64", ip_version=6),
        ],
    )

    # 1. Link-local addresses are local
    assert is_local_gateway("fe80::1", iface) is True
    assert is_local_gateway("fe80::c010:a7ff:fe97:ad48%10", iface) is True
    assert is_local_gateway("169.254.1.1", iface) is True

    # 2. RFC 1918 Private and ULA IPv6 are local
    assert is_local_gateway("192.168.1.1", iface) is True
    assert is_local_gateway("10.0.0.1", iface) is True
    assert is_local_gateway("172.16.0.1", iface) is True
    assert is_local_gateway("fd00::1", iface) is True

    # 3. Directly connected subnet address is local
    assert is_local_gateway("2001:db8::1", iface) is True

    # 4. Public addresses NOT directly connected are NOT local
    assert is_local_gateway("8.8.8.8", iface) is False
    assert is_local_gateway("1.1.1.1", iface) is False
    assert is_local_gateway("2606:4700:4700::1111", iface) is False
    assert is_local_gateway("None", iface) is False
    assert is_local_gateway("", iface) is False


def test_gateway_unauthorized_under_no_internet_returns_not_applicable():
    """Verify that an unauthorized (public) gateway under --no-internet returns NOT_APPLICABLE without pinging."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    # Routing with a public gateway (e.g. cloud VPS default route)
    routing = RoutingInfo(
        default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="8.8.8.8", interface="eth0", ip_version=4),
    )
    iface = InterfaceInfo(name="eth0", state="UP", networks=[])

    target = collector._probe_gateway(selected_iface=iface, routing=routing, no_internet=True)
    assert target.success is False
    assert target.status == "NOT_APPLICABLE"
    assert "not verified as local/internal" in target.details
    mock_backend.ping_host.assert_not_called()


def test_gateway_selection_explicit_interface():
    """Verify explicit interface restriction: wrong interface gateway is rejected."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    routing = RoutingInfo(
        default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="Ethernet", ip_version=4),
    )
    selected_iface = InterfaceInfo(name="Wi-Fi", state="UP", networks=[])

    target = collector._probe_gateway(selected_iface=selected_iface, routing=routing, no_internet=False)
    assert target.success is False
    assert target.status == "NOT_APPLICABLE"
    assert "No default gateway configured on selected interface 'Wi-Fi'" in target.details
    mock_backend.ping_host.assert_not_called()


# ==============================================================================
# 5. DNS Resolution Latency Tests
# ==============================================================================

def test_dns_probe_success():
    """Verify DNS latency probe measures wall-clock time and records resolved IPs."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)
    collector.dns_test_hosts = ["one.one.one.one"]

    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.0.0.1", 0)),
    ]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        targets, aggregate = collector._probe_dns(no_internet=False)

    assert len(targets) == 1
    assert targets[0].success is True
    assert targets[0].status == "SUCCESS"
    assert targets[0].latency_ms is not None
    assert targets[0].latency_ms >= 0.0
    assert "1.0.0.1, 1.1.1.1" in targets[0].details
    assert aggregate.status == "SUCCESS"


def test_dns_probe_does_not_mutate_global_socket_timeout():
    """Verify DNS probe preserves global socket default timeout without mutation."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    original_timeout = socket.getdefaulttimeout()
    try:
        collector._probe_dns(no_internet=False)
        assert socket.getdefaulttimeout() == original_timeout
    finally:
        socket.setdefaulttimeout(original_timeout)


def test_dns_probe_returns_within_timeout_bound(monkeypatch):
    """Verify DNS probe returns promptly on timeout without waiting for blocked resolver."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)
    collector.dns_timeout = 0.1
    collector.dns_test_hosts = ["slow.resolver.test"]

    def slow_resolver(host, port, *args, **kwargs):
        time.sleep(0.6)
        return []

    original_default_timeout = socket.getdefaulttimeout()
    monkeypatch.setattr(socket, "getaddrinfo", slow_resolver)

    start_time = time.perf_counter()
    targets, aggregate = collector._probe_dns(no_internet=False)
    elapsed = time.perf_counter() - start_time

    assert len(targets) == 1
    assert targets[0].status == "TIMEOUT"
    assert "timed out after 0.1s" in targets[0].details
    assert aggregate.status == "TIMEOUT"

    # Must return promptly within bounded overhead rather than waiting for 0.6s mock sleep
    assert elapsed < 0.4, f"DNS probe took {elapsed:.3f}s, expected prompt return under 0.4s"

    # Global socket default timeout must remain unmutated
    assert socket.getdefaulttimeout() == original_default_timeout


def test_dns_probe_disabled_under_no_internet():
    """Verify DNS probe returns DISABLED under --no-internet with 0 network lookups."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    with patch("socket.getaddrinfo") as mock_dns:
        targets, aggregate = collector._probe_dns(no_internet=True)
        mock_dns.assert_not_called()

    assert all(t.status == "DISABLED" for t in targets)
    assert aggregate.status == "DISABLED"


# ==============================================================================
# 6. HTTP / HTTPS Reachability Tests
# ==============================================================================

@patch("urllib.request.build_opener")
def test_http_probe_204_success(mock_build_opener):
    """Verify HTTP 204 No Content is recognized as expected connectivity-check success."""
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 204
    mock_resp.read.return_value = b""

    mock_opener = MagicMock()
    mock_opener.open.return_value.__enter__.return_value = mock_resp
    mock_build_opener.return_value = mock_opener

    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)
    collector.http_probe_urls = ["http://connectivitycheck.gstatic.com/generate_204"]

    targets, aggregate = collector._probe_http(no_internet=False)
    assert len(targets) == 1
    assert targets[0].success is True
    assert targets[0].status == "SUCCESS"
    assert targets[0].http_status == 204
    assert "HTTP 204 No Content" in targets[0].details
    assert aggregate.status == "SUCCESS"
    assert aggregate.http_status == 204


@patch("urllib.request.build_opener")
def test_http_probe_200_and_error(mock_build_opener):
    """Verify HTTP probe records status codes for 200 and HTTP errors."""
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b"OK"

    mock_opener = MagicMock()
    mock_opener.open.return_value.__enter__.return_value = mock_resp
    mock_build_opener.return_value = mock_opener

    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)
    collector.http_probe_urls = ["https://one.one.one.one"]

    targets, aggregate = collector._probe_http(no_internet=False)
    assert len(targets) == 1
    assert targets[0].success is True
    assert targets[0].http_status == 200
    assert aggregate.status == "SUCCESS"


def test_http_probe_disabled_under_no_internet():
    """Verify HTTP probe executes zero network requests under --no-internet."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    with patch("urllib.request.build_opener") as mock_opener:
        targets, aggregate = collector._probe_http(no_internet=True)
        mock_opener.assert_not_called()

    assert all(t.status == "DISABLED" for t in targets)
    assert aggregate.status == "DISABLED"


# ==============================================================================
# 7. IPv4 & IPv6 TCP Probe Tests
# ==============================================================================

@patch("socket.getaddrinfo")
@patch("socket.socket")
def test_tcp_family_probes_success(mock_socket_cls, mock_getaddrinfo):
    """Verify IPv4 and IPv6 TCP probes connect to port 443 with measured latency."""
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
    ]
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)
    collector.dns_test_hosts = ["one.one.one.one"]

    t4 = collector._probe_tcp_family(version=4, no_internet=False)
    assert t4.success is True
    assert t4.status == "SUCCESS"
    assert "one.one.one.one (1.1.1.1:443)" in t4.target
    assert t4.latency_ms is not None
    mock_sock.connect.assert_called_once_with(("1.1.1.1", 443))


@patch("socket.getaddrinfo", return_value=[])
def test_tcp_family_probes_unavailable_returns_not_applicable(mock_getaddrinfo):
    """Verify missing IPv6 destinations return NOT_APPLICABLE rather than FAILED."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    t6 = collector._probe_tcp_family(version=6, no_internet=False)
    assert t6.success is False
    assert t6.status == "NOT_APPLICABLE"
    assert "No IPv6 destination available" in t6.details


# ==============================================================================
# 8. Mode & Hard Isolation Tests
# ==============================================================================

def test_quick_mode_excludes_connectivity():
    """Verify --quick mode completely excludes Phase 6 connectivity collection."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    options = CollectorOptions(quick_mode=True)
    coordinator = CollectorCoordinator(backend=mock_backend, options=options)

    with patch.object(mock_backend, "get_connectivity") as mock_conn:
        report = coordinator.collect()
        mock_conn.assert_not_called()
        assert report.connectivity is None


@patch("socket.getaddrinfo")
@patch("urllib.request.build_opener")
@patch("socket.socket")
def test_no_internet_hard_isolation(mock_sock, mock_opener, mock_dns):
    """Verify that under --no-internet, exactly 0 external calls are made."""
    mock_backend = MagicMock(spec=BasePlatformBackend)
    mock_backend.ping_host.return_value = ConnectivityTarget(
        name="gateway", target="192.168.1.1", success=True, latency_ms=1.0, packet_loss_pct=0.0
    )

    collector = ConnectivityCollector(backend=mock_backend)
    iface = InterfaceInfo(
        name="eth0",
        state="UP",
        networks=[NetworkInfo(address="192.168.1.10", prefix_length=24, network="192.168.1.0/24", ip_version=4)],
    )
    routing = RoutingInfo(
        default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4)
    )

    info = collector.collect(selected_iface=iface, routing=routing, no_internet=True)

    # 1. Local gateway ping was executed
    mock_backend.ping_host.assert_called_once()
    assert info.gateway.status == "SUCCESS"

    # 2. Zero external calls
    mock_dns.assert_not_called()
    mock_opener.assert_not_called()
    mock_sock.assert_not_called()

    # 3. All external probes report DISABLED
    assert info.dns.status == "DISABLED"
    assert info.internet.status == "DISABLED"
    assert info.ipv4.status == "DISABLED"
    assert info.ipv6.status == "DISABLED"


# ==============================================================================
# 9. Privacy Audit
# ==============================================================================

@patch("urllib.request.build_opener")
@patch("socket.getaddrinfo")
def test_privacy_audit_no_local_artifacts_transmitted(mock_dns, mock_build_opener):
    """Verify that local network artifacts are never transmitted in external connectivity queries."""
    local_artifacts = [
        "192.168.1.100",
        "fe80::1ff:fe00:3a60",
        "fd00::dead:beef",
        "00:1A:2B:3C:4D:5E",
        "Corporate-Guest-WiFi",
        "aa:bb:cc:dd:ee:ff",
        "secret-corp-workstation",
        "10.0.0.0/8",
    ]

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b""
    mock_opener = MagicMock()
    mock_opener.open.return_value.__enter__.return_value = mock_resp
    mock_build_opener.return_value = mock_opener

    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend)

    # Trigger HTTP probes
    collector._probe_http(no_internet=False)

    for call_item in mock_opener.open.call_args_list:
        req = call_item[0][0]
        # Verify URL
        for art in local_artifacts:
            assert art not in req.full_url
        # Verify Headers
        for h_val in req.headers.values():
            for art in local_artifacts:
                assert art not in str(h_val)
        # Verify clean User-Agent
        assert req.headers.get("User-agent") == USER_AGENT


# ==============================================================================
# 10. Timeout Validation Tests
# ==============================================================================

def test_parse_bounded_timeout_validation():
    """Verify parse_bounded_timeout rejects non-numeric, booleans, <= 0, and clamps excessive values."""
    default = 3.0

    # Non-numeric
    assert parse_bounded_timeout("not-a-number", default=default) == default
    assert parse_bounded_timeout(None, default=default) == default
    assert parse_bounded_timeout({}, default=default) == default
    assert parse_bounded_timeout([], default=default) == default

    # Booleans (subclass of int in Python)
    assert parse_bounded_timeout(True, default=default) == default
    assert parse_bounded_timeout(False, default=default) == default

    # Non-positive (<= 0)
    assert parse_bounded_timeout(0, default=default) == default
    assert parse_bounded_timeout(0.0, default=default) == default
    assert parse_bounded_timeout(-1, default=default) == default
    assert parse_bounded_timeout(-5.5, default=default) == default

    # Excessively large (> 60.0) clamped to 60.0
    assert parse_bounded_timeout(120.0, default=default) == 60.0
    assert parse_bounded_timeout(999, default=default) == 60.0

    # Valid values
    assert parse_bounded_timeout(2.5, default=default) == 2.5
    assert parse_bounded_timeout("4.5", default=default) == 4.5
    assert parse_bounded_timeout(0.2, default=default) == 0.2


def test_collector_configuration_timeout_validation(tmp_path):
    """Verify ConnectivityCollector._load_configuration applies validation to all timeouts."""
    yaml_content = """
connectivity:
  gateway_ping_count: 2
timeouts:
  ping_seconds: -1
  dns_lookup_seconds: "invalid"
  http_probe_seconds: 0
  tcp_probe_seconds: 120.0
"""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml_content, encoding="utf-8")

    mock_backend = MagicMock(spec=BasePlatformBackend)
    collector = ConnectivityCollector(backend=mock_backend, config_path=cfg_file)

    assert collector.ping_timeout == 3.0      # rejected -1, used default
    assert collector.dns_timeout == 3.0       # rejected "invalid", used default
    assert collector.http_timeout == 4.0      # rejected 0, used default
    assert collector.tcp_timeout == 60.0      # clamped 120.0 to 60.0 upper bound

