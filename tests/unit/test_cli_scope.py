"""Tests for CLI scan mode execution scope, mutual exclusion, and phase awareness."""

import subprocess
import sys
from unittest.mock import MagicMock

from backends.base import BasePlatformBackend
from core.capabilities import CapabilityEntry, CapabilityStatus
from core.collector import CollectorCoordinator
from core.models import InterfaceInfo, RoutingInfo, SystemInfo
from core.registry import CollectorOptions


def create_mock_backend(all_implemented: bool = True) -> MagicMock:
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_platform_name.return_value = "MockOS"
    backend.get_platform_info.return_value = SystemInfo(
        os_name="MockOS",
        os_version="1.0",
        platform_release="1.0",
        hostname="mockhost",
        architecture="x86_64",
        python_version="3.12.0",
        is_privileged=False,
    )

    status_str = "IMPLEMENTED (Phase 1)" if all_implemented else "PLANNED (Phase 3)"
    backend.detect_capabilities.return_value = {
        "interface_info": CapabilityEntry(
            name="interface_info",
            status=CapabilityStatus.AVAILABLE,
            description="Interface info",
            toolkit_status="IMPLEMENTED (Phase 1)",
        ),
        "routing_info": CapabilityEntry(
            name="routing_info",
            status=CapabilityStatus.AVAILABLE,
            description="Routing info",
            toolkit_status=status_str,
        ),
        "dns_info": CapabilityEntry(
            name="dns_info",
            status=CapabilityStatus.AVAILABLE,
            description="DNS info",
            toolkit_status=status_str,
        ),
        "dhcp_info": CapabilityEntry(
            name="dhcp_info",
            status=CapabilityStatus.AVAILABLE,
            description="DHCP info",
            toolkit_status=status_str,
        ),
        "wifi_info": CapabilityEntry(
            name="wifi_info",
            status=CapabilityStatus.AVAILABLE,
            description="Wi-Fi info",
            toolkit_status=status_str,
        ),
        "neighbor_table": CapabilityEntry(
            name="neighbor_table",
            status=CapabilityStatus.AVAILABLE,
            description="Neighbor table",
            toolkit_status=status_str,
        ),
        "socket_summary": CapabilityEntry(
            name="socket_summary",
            status=CapabilityStatus.AVAILABLE,
            description="Socket summary",
            toolkit_status=status_str,
        ),
        "pcap_analysis": CapabilityEntry(
            name="pcap_analysis",
            status=CapabilityStatus.AVAILABLE,
            description="PCAP analysis",
            toolkit_status=status_str,
        ),
        "observations": CapabilityEntry(
            name="observations",
            status=CapabilityStatus.AVAILABLE,
            description="Observations & findings engine",
            toolkit_status="IMPLEMENTED (Phase 9)",
        ),
    }

    backend.get_interfaces.return_value = [InterfaceInfo(name="eth0", state="UP", ipv4=["192.168.1.10"])]
    backend.get_default_interface.return_value = InterfaceInfo(name="eth0", state="UP", ipv4=["192.168.1.10"])
    backend.get_routes.return_value = RoutingInfo(default_gateway="192.168.1.1")
    return backend


def test_quick_mode_scope():
    """Verify that --quick only executes system info, capabilities, interfaces, and routing."""
    backend = create_mock_backend(all_implemented=True)
    options = CollectorOptions(quick_mode=True)
    coordinator = CollectorCoordinator(backend=backend, options=options)

    report = coordinator.collect()

    # Included in quick mode
    backend.get_platform_info.assert_called_once()
    backend.detect_capabilities.assert_called_once()
    backend.get_interfaces.assert_called_once()
    backend.get_routes.assert_called_once()

    # Excluded in quick mode
    backend.get_dns.assert_not_called()
    backend.get_dhcp.assert_not_called()
    backend.get_wifi.assert_not_called()
    backend.get_neighbors.assert_not_called()
    backend.get_sockets.assert_not_called()

    # Report assertions
    assert report.dns is None
    assert report.dhcp is None
    assert report.wifi is None
    assert report.neighbors == []
    assert report.sockets == []


def test_full_mode_scope():
    """Verify that --full enables Wi-Fi, neighbor cache, and socket summary collectors when implemented."""
    backend = create_mock_backend(all_implemented=True)
    options = CollectorOptions(full_mode=True)
    coordinator = CollectorCoordinator(backend=backend, options=options)

    coordinator.collect()

    backend.get_platform_info.assert_called_once()
    backend.detect_capabilities.assert_called_once()
    backend.get_interfaces.assert_called_once()
    backend.get_routes.assert_called_once()
    backend.get_dns.assert_called_once()
    backend.get_dhcp.assert_called_once()
    backend.get_wifi.assert_called_once()
    backend.get_neighbors.assert_called_once()
    backend.get_sockets.assert_called_once()


def test_default_mode_scope():
    """Verify that default mode runs baseline collectors (interfaces, routes, dns, dhcp) without full extras."""
    backend = create_mock_backend(all_implemented=True)
    options = CollectorOptions(quick_mode=False, full_mode=False)
    coordinator = CollectorCoordinator(backend=backend, options=options)

    coordinator.collect()

    backend.get_interfaces.assert_called_once()
    backend.get_routes.assert_called_once()
    backend.get_dns.assert_called_once()
    backend.get_dhcp.assert_called_once()

    # Extras not called in default mode
    backend.get_wifi.assert_not_called()
    backend.get_neighbors.assert_not_called()
    backend.get_sockets.assert_not_called()


def test_phase_awareness_skips_planned_collectors():
    """Verify that collectors marked PLANNED are cleanly skipped and not treated as implemented."""
    backend = create_mock_backend(all_implemented=False)
    options = CollectorOptions(full_mode=True)
    coordinator = CollectorCoordinator(backend=backend, options=options)

    report = coordinator.collect()

    # Interface is marked IMPLEMENTED, so it runs
    backend.get_interfaces.assert_called_once()

    # All others are marked PLANNED, so they are cleanly skipped
    backend.get_routes.assert_not_called()
    backend.get_dns.assert_not_called()
    backend.get_dhcp.assert_not_called()
    backend.get_wifi.assert_not_called()
    backend.get_neighbors.assert_not_called()
    backend.get_sockets.assert_not_called()

    # Check report fields are cleanly None / empty
    assert report.routing is None
    assert report.dns is None
    assert report.dhcp is None
    assert report.wifi is None
    assert report.neighbors == []
    assert report.sockets == []


def test_quick_and_full_mutually_exclusive():
    """Verify that specifying both --quick and --full exits with code 2."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--quick", "--full"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "not allowed with argument --quick" in proc.stderr or "not allowed with argument --full" in proc.stderr


def test_output_without_json_rejected():
    """Verify that specifying --output without --json exits with code 2."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--output", "test.json"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "Error: --output currently requires --json" in proc.stderr


def test_pcap_filter_without_pcap_fails():
    """Verify that specifying --pcap-filter without --pcap exits with code 2."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--pcap-filter", "tcp.port == 80"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "Error: --pcap-filter requires --pcap to be specified." in proc.stderr


def test_future_option_snapshot_fails_cleanly():
    """Verify that --snapshot exits with code 2 and explicit not-implemented message."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--snapshot", "baseline.json"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "not implemented yet" in proc.stderr
    assert "Phase 10" in proc.stderr


def test_future_option_html_fails_cleanly():
    """Verify that --html exits with code 2 and explicit not-implemented message."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--html"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "not implemented yet" in proc.stderr
    assert "Phase 11" in proc.stderr
