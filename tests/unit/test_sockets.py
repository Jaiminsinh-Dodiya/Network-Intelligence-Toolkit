"""Unit tests for Phase 7: Socket & Port Summary Collector."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from backends.linux import (
    LINUX_TCP_STATE_MAP,
    normalize_linux_tcp_state,
    parse_linux_ss,
)
from backends.windows import (
    WINDOWS_TCP_STATE_MAP,
    normalize_windows_tcp_state,
    parse_windows_sockets,
)
from core.collector import CollectorCoordinator, CollectorOptions
from core.models import InterfaceInfo, NeighborEntry, SocketEntry
from core.network import sort_sockets


# ==============================================================================
# Windows Sockets Parsing Tests
# ==============================================================================

def test_windows_tcp_state_normalization() -> None:
    """Verify Windows TCP state integer and string mappings match System.Net.NetworkInformation.TcpState."""
    # Integer enum mappings
    assert normalize_windows_tcp_state(0) == "UNKNOWN"
    assert normalize_windows_tcp_state(1) == "CLOSE"
    assert normalize_windows_tcp_state(2) == "LISTEN"
    assert normalize_windows_tcp_state(3) == "SYN_SENT"
    assert normalize_windows_tcp_state(4) == "SYN_RECEIVED"
    assert normalize_windows_tcp_state(5) == "ESTABLISHED"
    assert normalize_windows_tcp_state(6) == "FIN_WAIT1"
    assert normalize_windows_tcp_state(7) == "FIN_WAIT2"
    assert normalize_windows_tcp_state(8) == "CLOSE_WAIT"
    assert normalize_windows_tcp_state(9) == "CLOSING"
    assert normalize_windows_tcp_state(10) == "LAST_ACK"
    assert normalize_windows_tcp_state(11) == "TIME_WAIT"
    assert normalize_windows_tcp_state(12) == "CLOSE"
    assert normalize_windows_tcp_state(100) == "LISTEN"  # Bound

    # String mappings
    assert normalize_windows_tcp_state("Listen") == "LISTEN"
    assert normalize_windows_tcp_state("Established") == "ESTABLISHED"
    assert normalize_windows_tcp_state("TimeWait") == "TIME_WAIT"
    assert normalize_windows_tcp_state("CloseWait") == "CLOSE_WAIT"
    assert normalize_windows_tcp_state("Bound") == "LISTEN"
    assert normalize_windows_tcp_state(None) == "UNKNOWN"


def test_windows_sockets_json_parsing() -> None:
    """Verify parsing combined PowerShell Get-NetTCPConnection and Get-NetUDPEndpoint JSON."""
    data = {
        "tcp": [
            {
                "LocalAddress": "0.0.0.0",
                "LocalPort": 22,
                "RemoteAddress": "0.0.0.0",
                "RemotePort": 0,
                "State": 2,  # LISTEN
                "OwningProcess": 1234,
            },
            {
                "LocalAddress": "192.168.1.10",
                "LocalPort": 54321,
                "RemoteAddress": "93.184.216.34",
                "RemotePort": 443,
                "State": 5,  # ESTABLISHED
                "OwningProcess": 5678,
            },
        ],
        "udp": [
            {
                "LocalAddress": "0.0.0.0",
                "LocalPort": 68,
                "OwningProcess": 9999,
            }
        ],
        "procMap": {
            "1234": "sshd",
            "5678": "curl",
            "9999": "dhclient",
        },
    }

    parsed = parse_windows_sockets(json.dumps(data))
    assert len(parsed) == 3

    # Sockets are sorted: TCP before UDP
    tcp_listen = parsed[0]
    assert tcp_listen.protocol == "TCP"
    assert tcp_listen.local_address == "0.0.0.0"
    assert tcp_listen.local_port == 22
    assert tcp_listen.remote_address is None
    assert tcp_listen.remote_port is None
    assert tcp_listen.state == "LISTEN"
    assert tcp_listen.pid == 1234
    assert tcp_listen.process_name == "sshd"

    tcp_estab = parsed[1]
    assert tcp_estab.protocol == "TCP"
    assert tcp_estab.local_address == "192.168.1.10"
    assert tcp_estab.local_port == 54321
    assert tcp_estab.remote_address == "93.184.216.34"
    assert tcp_estab.remote_port == 443
    assert tcp_estab.state == "ESTABLISHED"
    assert tcp_estab.pid == 5678
    assert tcp_estab.process_name == "curl"

    udp_sock = parsed[2]
    assert udp_sock.protocol == "UDP"
    assert udp_sock.local_address == "0.0.0.0"
    assert udp_sock.local_port == 68
    assert udp_sock.remote_address is None
    assert udp_sock.remote_port is None
    # Crucial requirement: UDP state must be UNKNOWN, never fabricated LISTENING
    assert udp_sock.state == "UNKNOWN"
    assert udp_sock.pid == 9999
    assert udp_sock.process_name == "dhclient"


def test_windows_sockets_single_item_dict_normalization() -> None:
    """Verify single-item dict for tcp or udp is normalized to a list."""
    data = {
        "tcp": {
            "LocalAddress": "127.0.0.1",
            "LocalPort": 8080,
            "RemoteAddress": "0.0.0.0",
            "RemotePort": 0,
            "State": 2,
            "OwningProcess": 4321,
        },
        "udp": {
            "LocalAddress": "127.0.0.1",
            "LocalPort": 5353,
            "OwningProcess": 4321,
        },
        "procMap": {
            "4321": "node",
        },
    }

    parsed = parse_windows_sockets(json.dumps(data))
    assert len(parsed) == 2
    assert parsed[0].protocol == "TCP"
    assert parsed[0].process_name == "node"
    assert parsed[1].protocol == "UDP"
    assert parsed[1].process_name == "node"


# ==============================================================================
# Linux Sockets (ss) Parsing Tests
# ==============================================================================

def test_linux_ss_parsing() -> None:
    """Verify parsing ss -tunapn -H output with processes, IPv4, IPv6, and UDP."""
    ss_output = """
tcp   LISTEN  0   128   0.0.0.0:22         0.0.0.0:*       users:(("sshd",pid=1234,fd=3))
tcp   LISTEN  0   4096  [::]:80            [::]:*          users:(("nginx",pid=5678,fd=6))
tcp   ESTAB   0   0     192.168.1.10:45678 93.184.216.34:443  users:(("curl",pid=9999,fd=3))
udp   UNCONN  0   0     0.0.0.0:68         0.0.0.0:*       users:(("dhclient",pid=4321,fd=5))
udp   UNCONN  0   0     [::]:5353          [::]:*          users:(("avahi-daemon",pid=888,fd=12))
"""
    parsed = parse_linux_ss(ss_output)
    assert len(parsed) == 5

    # Check TCP Listen v4
    ssh = [s for s in parsed if s.local_port == 22][0]
    assert ssh.protocol == "TCP"
    assert ssh.local_address == "0.0.0.0"
    assert ssh.state == "LISTEN"
    assert ssh.remote_address is None
    assert ssh.remote_port is None
    assert ssh.pid == 1234
    assert ssh.process_name == "sshd"

    # Check TCP Listen v6
    nginx = [s for s in parsed if s.local_port == 80][0]
    assert nginx.protocol == "TCP"
    assert nginx.local_address == "::"
    assert nginx.state == "LISTEN"
    assert nginx.remote_address is None
    assert nginx.pid == 5678
    assert nginx.process_name == "nginx"

    # Check TCP Established
    curl = [s for s in parsed if s.local_port == 45678][0]
    assert curl.protocol == "TCP"
    assert curl.state == "ESTABLISHED"
    assert curl.remote_address == "93.184.216.34"
    assert curl.remote_port == 443
    assert curl.pid == 9999
    assert curl.process_name == "curl"

    # Check UDP v4
    dhcp = [s for s in parsed if s.local_port == 68][0]
    assert dhcp.protocol == "UDP"
    assert dhcp.state == "UNKNOWN"  # Do not fabricate LISTENING
    assert dhcp.remote_address is None
    assert dhcp.pid == 4321
    assert dhcp.process_name == "dhclient"

    # Check UDP v6
    avahi = [s for s in parsed if s.local_port == 5353][0]
    assert avahi.protocol == "UDP"
    assert avahi.local_address == "::"
    assert avahi.state == "UNKNOWN"
    assert avahi.pid == 888
    assert avahi.process_name == "avahi-daemon"


def test_linux_ss_unprivileged_without_process_column() -> None:
    """Verify parsing ss output when process/PID is unavailable (unprivileged user)."""
    ss_output = """
tcp   LISTEN  0   128   0.0.0.0:22   0.0.0.0:*
udp   UNCONN  0   0     0.0.0.0:68   0.0.0.0:*
"""
    parsed = parse_linux_ss(ss_output)
    assert len(parsed) == 2
    assert parsed[0].local_port == 22
    assert parsed[0].pid is None
    assert parsed[0].process_name is None
    assert parsed[1].local_port == 68
    assert parsed[1].pid is None
    assert parsed[1].process_name is None


def test_sort_sockets_deterministic() -> None:
    """Verify sorting order: protocol (TCP before UDP), local_address, local_port, remote_address, remote_port, state, pid."""
    s1 = SocketEntry(protocol="UDP", local_address="0.0.0.0", local_port=53, state="UNKNOWN")
    s2 = SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=80, state="LISTEN")
    s3 = SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=22, state="LISTEN")
    s4 = SocketEntry(protocol="TCP", local_address="127.0.0.1", local_port=22, state="LISTEN")

    sorted_sockets = sort_sockets([s1, s2, s3, s4])
    assert sorted_sockets[0] == s3  # TCP 0.0.0.0:22
    assert sorted_sockets[1] == s2  # TCP 0.0.0.0:80
    assert sorted_sockets[2] == s4  # TCP 127.0.0.1:22
    assert sorted_sockets[3] == s1  # UDP 0.0.0.0:53


# ==============================================================================
# Scope Control & Passive Guarantee Tests
# ==============================================================================

def test_scope_flags_control() -> None:
    """Verify CollectorOptions correctly determines whether neighbors and sockets are collected."""
    # 1. Quick mode: excludes both
    opt_quick = CollectorOptions(quick_mode=True, include_neighbors=True, include_sockets=True)
    assert opt_quick.should_collect_neighbors() is False
    assert opt_quick.should_collect_sockets() is False

    # 2. Default mode: excludes both
    opt_default = CollectorOptions()
    assert opt_default.should_collect_neighbors() is False
    assert opt_default.should_collect_sockets() is False

    # 3. Full mode: includes both
    opt_full = CollectorOptions(full_mode=True)
    assert opt_full.should_collect_neighbors() is True
    assert opt_full.should_collect_sockets() is True

    # 4. Explicit --neighbors: includes neighbors, excludes sockets
    opt_neigh = CollectorOptions(include_neighbors=True)
    assert opt_neigh.should_collect_neighbors() is True
    assert opt_neigh.should_collect_sockets() is False

    # 5. Explicit --sockets: includes sockets, excludes neighbors
    opt_sock = CollectorOptions(include_sockets=True)
    assert opt_sock.should_collect_neighbors() is False
    assert opt_sock.should_collect_sockets() is True

    # 6. --no-internet does NOT disable local neighbors or sockets
    opt_no_net = CollectorOptions(full_mode=True, no_internet=True)
    assert opt_no_net.should_collect_neighbors() is True
    assert opt_no_net.should_collect_sockets() is True


def test_passive_collection_guarantee() -> None:
    """Verify that collecting neighbors and sockets performs ZERO network I/O.

    Strict boundary verification:
    - 0 socket connects
    - 0 HTTP requests
    - 0 DNS resolutions
    """
    from unittest.mock import MagicMock
    import socket
    import urllib.request

    mock_backend = MagicMock()
    mock_backend.get_platform_info.return_value = MagicMock(
        os_name="Windows",
        os_version="11",
        platform_release="10.0.26100",
        hostname="localhost",
        architecture="AMD64",
        python_version="3.12",
        is_privileged=False,
    )
    mock_backend.detect_capabilities.return_value = {
        "neighbor_table": MagicMock(
            is_implemented=lambda: True,
            to_dict=lambda: {"status": "AVAILABLE", "toolkit_status": "IMPLEMENTED (Phase 7)"},
        ),
        "socket_summary": MagicMock(
            is_implemented=lambda: True,
            to_dict=lambda: {"status": "AVAILABLE", "toolkit_status": "IMPLEMENTED (Phase 7)"},
        ),
    }
    mock_backend.get_interfaces.return_value = []
    mock_backend.get_neighbors.return_value = [
        NeighborEntry(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE")
    ]
    mock_backend.get_sockets.return_value = [
        SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=22, state="LISTEN")
    ]

    options = CollectorOptions(full_mode=True, no_internet=True)
    coordinator = CollectorCoordinator(backend=mock_backend, options=options)

    with patch("socket.socket.connect") as mock_connect, \
         patch("socket.create_connection") as mock_create_conn, \
         patch("urllib.request.urlopen") as mock_urlopen, \
         patch("socket.getaddrinfo") as mock_getaddrinfo:

        report = coordinator.collect()

        assert len(report.neighbors) == 1
        assert len(report.sockets) == 1

        # Assert ZERO network calls occurred
        assert mock_connect.call_count == 0
        assert mock_create_conn.call_count == 0
        assert mock_urlopen.call_count == 0
        assert mock_getaddrinfo.call_count == 0
