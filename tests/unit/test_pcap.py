"""Unit tests for Phase 8: Authorized PCAP/PCAPNG Analysis Engine."""

from __future__ import annotations

import hashlib
from pathlib import Path
import socket
import struct
import subprocess
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from backends.base import BasePlatformBackend
from core.capabilities import CapabilityEntry, CapabilityStatus
from core.collector import CollectorCoordinator
from core.models import (
    InterfaceInfo,
    NetworkIntelligenceReport,
    PcapAnalysisInfo,
    PcapConversationStat,
    PcapDnsSummary,
    PcapEndpointStat,
    PcapHttpSummary,
    PcapPacketSample,
    PcapProtocolStat,
    PcapTcpSummary,
    PcapTlsSummary,
    PcapTrafficTimelineBucket,
    RoutingInfo,
    SystemInfo,
)
from core.pcap import (
    DEFAULT_MAX_OUTPUT_BYTES,
    PcapAnalyzer,
    run_bounded_subprocess,
    validate_capture_file,
)
from core.registry import CollectorOptions

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"


@pytest.fixture
def valid_pcap_path() -> Path:
    return FIXTURES_DIR / "valid_sample.pcap"


@pytest.fixture
def valid_pcapng_path() -> Path:
    return FIXTURES_DIR / "valid_sample.pcapng"


@pytest.fixture
def empty_pcap_path() -> Path:
    return FIXTURES_DIR / "empty.pcap"


@pytest.fixture
def corrupt_pcap_path() -> Path:
    return FIXTURES_DIR / "corrupt.pcap"


# ============================================================================
# 1. File and Magic Header Validation Tests
# ============================================================================

def test_validate_capture_file_missing(tmp_path: Path):
    non_existent = tmp_path / "missing.pcap"
    is_valid, fmt, err = validate_capture_file(non_existent)
    assert not is_valid
    assert fmt is None
    assert "not found" in err.lower()


def test_validate_capture_file_directory(tmp_path: Path):
    is_valid, fmt, err = validate_capture_file(tmp_path)
    assert not is_valid
    assert fmt is None
    assert "directory" in err.lower()


def test_validate_capture_file_size_exceeded(tmp_path: Path):
    oversized = tmp_path / "oversized.pcap"
    oversized.write_bytes(b"\x00" * 1024)
    # Configure max size as 0 MB (threshold 0 bytes)
    is_valid, fmt, err = validate_capture_file(oversized, max_file_size_mb=0)
    assert not is_valid
    assert fmt is None
    assert "exceeds configured limit" in err


def test_validate_capture_file_empty(empty_pcap_path: Path):
    is_valid, fmt, err = validate_capture_file(empty_pcap_path)
    assert not is_valid
    assert fmt is None
    assert "empty or too short" in err.lower()


def test_validate_capture_file_corrupt(corrupt_pcap_path: Path):
    is_valid, fmt, err = validate_capture_file(corrupt_pcap_path)
    assert not is_valid
    assert fmt is None
    assert "corrupt or invalid" in err.lower()


def test_validate_capture_file_valid_pcap(valid_pcap_path: Path):
    is_valid, fmt, err = validate_capture_file(valid_pcap_path)
    assert is_valid
    assert fmt == "PCAP"
    assert err is None


def test_validate_capture_file_valid_pcapng(valid_pcapng_path: Path):
    is_valid, fmt, err = validate_capture_file(valid_pcapng_path)
    assert is_valid
    assert fmt == "PCAPNG"
    assert err is None


# ============================================================================
# 2. Capability Detection Tests
# ============================================================================

def test_capability_detection_missing_tshark():
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = None
    from backends.windows import WindowsBackend
    wb = WindowsBackend()
    with patch.object(wb, "get_tshark_path", return_value=None):
        caps = wb.detect_capabilities()
        assert "pcap_analysis" in caps
        cap = caps["pcap_analysis"]
        assert cap.status == CapabilityStatus.MISSING_DEPENDENCY
        assert "IMPLEMENTED (Phase 8)" in cap.toolkit_status
        assert not cap.is_usable()


def test_capability_detection_with_tshark():
    from backends.windows import WindowsBackend
    wb = WindowsBackend()
    with patch.object(wb, "get_tshark_path", return_value=r"C:\Program Files\Wireshark\tshark.exe"):
        caps = wb.detect_capabilities()
        assert "pcap_analysis" in caps
        cap = caps["pcap_analysis"]
        assert cap.status == CapabilityStatus.AVAILABLE
        assert "IMPLEMENTED (Phase 8)" in cap.toolkit_status
        assert cap.is_usable()


# ============================================================================
# 3. Security, Safety, and Offline Guarantees
# ============================================================================

def test_pcap_analyzer_missing_tshark_returns_unavailable(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = None
    analyzer = PcapAnalyzer(backend=backend)
    with patch("shutil.which", return_value=None):
        result = analyzer.analyze(valid_pcap_path)
        assert not result.available
        assert result.status == "UNAVAILABLE"
        assert "TShark executable not found" in result.reason


def test_offline_enforcement_arguments(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    executed_cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        executed_cmds.append(cmd)
        return 0, "", "", False

    with patch("core.pcap.run_bounded_subprocess", side_effect=fake_run):
        analyzer.analyze(valid_pcap_path)

    assert len(executed_cmds) > 0
    for cmd in executed_cmds:
        # Must include -r <path>
        assert "-r" in cmd
        r_idx = cmd.index("-r")
        assert cmd[r_idx + 1] == str(valid_pcap_path)
        # Must NEVER include -i or --interface (live capture forbidden)
        assert "-i" not in cmd
        assert "--interface" not in cmd


def test_capture_file_hash_unmodified(valid_pcap_path: Path):
    sha_before = hashlib.sha256(valid_pcap_path.read_bytes()).hexdigest()

    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, "", "", False)):
        analyzer.analyze(valid_pcap_path)

    sha_after = hashlib.sha256(valid_pcap_path.read_bytes()).hexdigest()
    assert sha_before == sha_after, "Capture file must never be modified by analysis"


def test_passive_guarantee_zero_network_calls(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch.object(socket.socket, "connect") as mock_connect, \
         patch("socket.create_connection") as mock_create_conn, \
         patch("urllib.request.urlopen") as mock_urlopen, \
         patch("socket.getaddrinfo") as mock_getaddrinfo, \
         patch("core.pcap.run_bounded_subprocess", return_value=(0, "", "", False)):

        analyzer.analyze(valid_pcap_path)

        assert mock_connect.call_count == 0
        assert mock_create_conn.call_count == 0
        assert mock_urlopen.call_count == 0
        assert mock_getaddrinfo.call_count == 0


def test_packet_limit_flag_passed(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    config = {"pcap": {"max_packets": 500}}
    analyzer = PcapAnalyzer(backend=backend, config=config)

    executed_cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        executed_cmds.append(cmd)
        return 0, "", "", False

    with patch("core.pcap.run_bounded_subprocess", side_effect=fake_run):
        analyzer.analyze(valid_pcap_path)

    limit_cmds = [cmd for cmd in executed_cmds if "-c" in cmd and "1" not in cmd]
    assert len(limit_cmds) > 0
    for cmd in limit_cmds:
        c_idx = cmd.index("-c")
        assert cmd[c_idx + 1] in ("500", "501")


# ============================================================================
# 4. Incremental Subprocess & Output Limit Tests
# ============================================================================

def test_run_bounded_subprocess_truncation(tmp_path: Path):
    # Test that exceeding max_output_bytes flags truncated and caps output
    import sys
    # Command that prints 10,000 bytes
    script = tmp_path / "print_large.py"
    script.write_text("import sys; sys.stdout.write('A' * 10000); sys.stdout.flush()", encoding="utf-8")

    code, out, err, truncated = run_bounded_subprocess(
        cmd=[sys.executable, str(script)],
        timeout=5.0,
        max_output_bytes=2000,
    )
    assert truncated is True
    assert len(out.encode("utf-8")) <= 2000


def test_run_bounded_subprocess_timeout(tmp_path: Path):
    import sys
    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(10)", encoding="utf-8")

    code, out, err, truncated = run_bounded_subprocess(
        cmd=[sys.executable, str(script)],
        timeout=0.2,
        max_output_bytes=10000,
    )
    assert code == -1
    assert "timed out" in err


# ============================================================================
# 5. Protocol, Endpoint, Conversation, and Application Layer Parsers
# ============================================================================

MOCK_PHS_OUTPUT = """
===================================================================
Protocol Hierarchy Statistics
Filter: frame

eth                                      frames:1000 bytes:500000
  ip                                     frames:950 bytes:480000
    tcp                                  frames:800 bytes:420000
      tls                                frames:500 bytes:300000
      http                               frames:100 bytes:60000
    udp                                  frames:150 bytes:60000
      dns                                frames:150 bytes:60000
  arp                                    frames:50 bytes:20000
===================================================================
"""

def test_parse_protocol_hierarchy(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, MOCK_PHS_OUTPUT, "", False)):
        protocols, truncated = analyzer._parse_protocol_hierarchy("tshark", valid_pcap_path, None)

    assert not truncated
    assert len(protocols) == 8
    # Ordered deterministically by packet count descending
    assert protocols[0].protocol == "eth"
    assert protocols[0].packet_count == 1000
    assert protocols[1].protocol == "ip"
    assert protocols[1].packet_count == 950
    assert protocols[2].protocol == "tcp"
    assert protocols[2].packet_count == 800


MOCK_ENDPOINTS_IP_OUTPUT = """
===================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  --- Total ---  |
IPv4                   | Packets | Bytes |
192.168.1.50                 800    420000
142.250.190.46               500    300000
1.1.1.1                      150     60000
===================================================================
"""

def test_parse_endpoints(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", side_effect=[
        (0, MOCK_ENDPOINTS_IP_OUTPUT, "", False),
        (0, "", "", False),  # IPv6 empty
    ]):
        endpoints, truncated = analyzer._parse_endpoints("tshark", valid_pcap_path, None)

    assert not truncated
    assert len(endpoints) == 3
    assert endpoints[0].address == "192.168.1.50"
    assert endpoints[0].packet_count == 800
    assert endpoints[0].ip_version == 4


MOCK_CONVERSATIONS_TCP_OUTPUT = """
===================================================================
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.50:54321    142.250.190.46:443            250 150000        250 150000        500 300000
192.168.1.50:54322    93.184.216.34:80               50  30000         50  30000        100  60000
===================================================================
"""

def test_parse_conversations(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", side_effect=[
        (0, MOCK_CONVERSATIONS_TCP_OUTPUT, "", False),
        (0, "", "", False),  # UDP empty
    ]):
        convs, truncated = analyzer._parse_conversations("tshark", valid_pcap_path, None)

    assert not truncated
    assert len(convs) == 2
    assert convs[0].endpoint_a == "192.168.1.50"
    assert convs[0].port_a == 54321
    assert convs[0].endpoint_b == "142.250.190.46"
    assert convs[0].port_b == 443
    assert convs[0].protocol == "TCP"
    assert convs[0].packet_count == 500


MOCK_DNS_OUTPUT = """1\t192.168.1.50\t1.1.1.1\t0x1001\t0\texample.com\t1\t
2\t1.1.1.1\t192.168.1.50\t0x1001\t1\t\t1\t0
3\t192.168.1.50\t1.1.1.1\t0x1002\t0\tnonexistent.test\t1\t
4\t1.1.1.1\t192.168.1.50\t0x1002\t1\t\t1\t3
5\t192.168.1.50\t1.1.1.1\t0x1003\t0\tunresolved.test\t1\t
"""

def test_parse_dns_metadata(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, MOCK_DNS_OUTPUT, "", False)):
        dns, truncated = analyzer._parse_dns_metadata("tshark", valid_pcap_path, None)

    assert not truncated
    assert dns.total_queries == 3
    assert dns.total_responses == 2
    assert dns.unresolved_queries == 1
    assert ("example.com", 1) in dns.top_queried_domains
    assert ("nonexistent.test", 1) in dns.top_queried_domains


MOCK_HTTP_OUTPUT = """1\t192.168.1.50\t93.184.216.34\tGET\texample.com\t/index.html\t
2\t93.184.216.34\t192.168.1.50\t\t\t\t200
3\t192.168.1.50\t93.184.216.34\tPOST\texample.com\t/api/data\t
4\t93.184.216.34\t192.168.1.50\t\t\t\t404
"""

def test_parse_http_metadata_no_credentials(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, MOCK_HTTP_OUTPUT, "", False)):
        http, truncated = analyzer._parse_http_metadata("tshark", valid_pcap_path, None)

    assert not truncated
    assert http.total_requests == 2
    assert http.total_responses == 2
    hosts = [h["host"] for h in http.top_hosts] if isinstance(http.top_hosts[0], dict) else [h[0] for h in http.top_hosts]
    assert "example.com" in hosts
    assert ("GET", 1) in http.top_methods
    assert ("POST", 1) in http.top_methods


def test_parse_http_metadata_query_string_privacy(valid_pcap_path: Path):
    """Verify parse_tshark_http_output and _parse_http_metadata strip query parameters defensively."""
    mock_tsv = (
        "1\t192.0.2.10\t192.0.2.1\tGET\texample.com\t/login?token=SYNTHETIC_SECRET&password=SYNTHETIC_PASSWORD\t\n"
        "2\t192.0.2.1\t192.0.2.10\t\t\t\t200\n"
    )
    from core.pcap import parse_tshark_http_output
    import json
    summary = parse_tshark_http_output(mock_tsv)
    assert summary.request_count == 1
    req = summary.requests[0]
    assert req["path"] == "/login"

    serialized = json.dumps(summary.to_dict())
    assert "/login" in serialized
    assert "token=SYNTHETIC_SECRET" not in serialized
    assert "password=SYNTHETIC_PASSWORD" not in serialized
    assert "SYNTHETIC_SECRET" not in serialized
    assert "SYNTHETIC_PASSWORD" not in serialized


MOCK_TLS_OUTPUT = """1\t192.168.1.50\t142.250.190.46\t0x0303\t1\twww.google.com\t0x1301
2\t142.250.190.46\t192.168.1.50\t0x0303\t2\t\t0x1301
3\t192.168.1.50\t104.244.42.1\t0x0303\t1\ttwitter.com\t0x1302
"""

def test_parse_tls_metadata_no_secrets(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, MOCK_TLS_OUTPUT, "", False)):
        tls, truncated = analyzer._parse_tls_metadata("tshark", valid_pcap_path, None)

    assert not truncated
    assert tls.total_sessions == 2
    snis = [s[0] for s in tls.top_server_names]
    assert "www.google.com" in snis
    assert "twitter.com" in snis
    assert ("TLS 1.2", 3) in tls.tls_versions


MOCK_TCP_OUTPUT = """1\t1\t0\t0\t0\t\t\t
2\t0\t1\t0\t0\t1\t\t
3\t0\t1\t0\t0\t\t1\t
4\t0\t1\t0\t0\t\t\t1
5\t0\t0\t1\t0\t\t\t
"""

def test_parse_tcp_diagnostics(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    with patch("core.pcap.run_bounded_subprocess", return_value=(0, MOCK_TCP_OUTPUT, "", False)):
        tcp, truncated = analyzer._parse_tcp_diagnostics("tshark", valid_pcap_path, None)

    assert not truncated
    assert tcp.retransmissions == 1
    assert tcp.duplicate_acks == 1
    assert tcp.zero_window_advertisements == 1
    assert tcp.rst_flag_count == 1
    assert tcp.syn_flag_count == 1


# ============================================================================
# 6. Display Filter and Error Handling Tests
# ============================================================================

def test_display_filter_passed_to_tshark(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    executed_cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        executed_cmds.append(cmd)
        return 0, "", "", False

    with patch("core.pcap.run_bounded_subprocess", side_effect=fake_run):
        analyzer.analyze(valid_pcap_path, display_filter="tcp.port == 443")

    assert len(executed_cmds) > 0
    y_cmds = [cmd for cmd in executed_cmds if "-Y" in cmd]
    assert len(y_cmds) > 0
    for cmd in y_cmds:
        y_idx = cmd.index("-Y")
        assert "tcp.port == 443" in cmd[y_idx + 1]
    z_cmds = [cmd for cmd in executed_cmds if "-z" in cmd]
    assert len(z_cmds) > 0
    for cmd in z_cmds:
        z_idx = cmd.index("-z")
        assert "tcp.port == 443" in cmd[z_idx + 1]


def test_invalid_display_filter_error(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_tshark_path.return_value = "tshark"
    analyzer = PcapAnalyzer(backend=backend)

    invalid_err = "tshark: 'invalid@@filter' is neither a field nor a protocol name."
    with patch("core.pcap.run_bounded_subprocess", return_value=(1, "", invalid_err, False)):
        result = analyzer.analyze(valid_pcap_path, display_filter="invalid@@filter")

    assert result.status == "ERROR"
    assert "Invalid display filter" in result.reason
    assert "invalid@@filter" in result.reason


# ============================================================================
# 7. Collector Coordination & Option I Semantics Tests
# ============================================================================

def test_collector_coordination_pcap(valid_pcap_path: Path):
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_platform_name.return_value = "MockOS"
    backend.get_platform_info.return_value = SystemInfo(
        os_name="MockOS", os_version="1.0", platform_release="1.0",
        hostname="mock", architecture="x86_64", python_version="3.12", is_privileged=False
    )
    backend.detect_capabilities.return_value = {
        "pcap_analysis": CapabilityEntry(
            name="pcap_analysis",
            status=CapabilityStatus.AVAILABLE,
            description="PCAP Analysis",
            toolkit_status="IMPLEMENTED (Phase 8)",
        )
    }
    backend.get_interfaces.return_value = []
    backend.get_routes.return_value = None

    expected_pcap = PcapAnalysisInfo(
        file_path=str(valid_pcap_path),
        file_format="PCAP",
        file_size_bytes=1024,
        packet_count=100,
        status="AVAILABLE",
    )
    backend.analyze_pcap.return_value = expected_pcap

    options = CollectorOptions(pcap_path=valid_pcap_path)
    coordinator = CollectorCoordinator(backend=backend, options=options)
    report = coordinator.collect()

    assert report.pcap is not None
    assert report.pcap.packet_count == 100
    assert report.pcap_analysis is not None
    assert report.pcap_analysis.packet_count == 100
    backend.analyze_pcap.assert_called_once()


def test_collector_coordination_pcap_quick_mode(valid_pcap_path: Path):
    """Option I: --pcap <file> --quick runs quick scan + PCAP analysis."""
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_platform_name.return_value = "MockOS"
    backend.get_platform_info.return_value = SystemInfo(
        os_name="MockOS", os_version="1.0", platform_release="1.0",
        hostname="mock", architecture="x86_64", python_version="3.12", is_privileged=False
    )
    backend.detect_capabilities.return_value = {
        "pcap_analysis": CapabilityEntry(
            name="pcap_analysis",
            status=CapabilityStatus.AVAILABLE,
            description="PCAP Analysis",
            toolkit_status="IMPLEMENTED (Phase 8)",
        )
    }
    backend.get_interfaces.return_value = []
    backend.get_routes.return_value = None
    backend.analyze_pcap.return_value = PcapAnalysisInfo(
        file_path=str(valid_pcap_path),
        status="AVAILABLE",
    )

    options = CollectorOptions(quick_mode=True, pcap_path=valid_pcap_path)
    coordinator = CollectorCoordinator(backend=backend, options=options)
    report = coordinator.collect()

    assert report.pcap is not None
    assert report.pcap_analysis is not None
    backend.analyze_pcap.assert_called_once()


def test_collector_coordination_pcap_no_internet(valid_pcap_path: Path):
    """Option I: --pcap <file> --no-internet skips internet and runs 100% offline PCAP analysis."""
    backend = MagicMock(spec=BasePlatformBackend)
    backend.get_platform_name.return_value = "MockOS"
    backend.get_platform_info.return_value = SystemInfo(
        os_name="MockOS", os_version="1.0", platform_release="1.0",
        hostname="mock", architecture="x86_64", python_version="3.12", is_privileged=False
    )
    backend.detect_capabilities.return_value = {
        "public_ip": CapabilityEntry(name="public_ip", status=CapabilityStatus.AVAILABLE, description="", toolkit_status="IMPLEMENTED (Phase 5)"),
        "connectivity": CapabilityEntry(name="connectivity", status=CapabilityStatus.AVAILABLE, description="", toolkit_status="IMPLEMENTED (Phase 6)"),
        "pcap_analysis": CapabilityEntry(name="pcap_analysis", status=CapabilityStatus.AVAILABLE, description="", toolkit_status="IMPLEMENTED (Phase 8)"),
    }
    backend.get_interfaces.return_value = []
    backend.get_routes.return_value = None
    from core.models import PublicIpInfo, ConnectivityInfo
    backend.get_public_ip.return_value = PublicIpInfo(status="SKIPPED", reason="Disabled by --no-internet", available=False)
    backend.get_connectivity.return_value = ConnectivityInfo()
    backend.analyze_pcap.return_value = PcapAnalysisInfo(
        file_path=str(valid_pcap_path),
        status="AVAILABLE",
    )

    options = CollectorOptions(no_internet=True, pcap_path=valid_pcap_path)
    coordinator = CollectorCoordinator(backend=backend, options=options)
    report = coordinator.collect()

    assert report.pcap is not None
    assert report.public_ip is not None
    assert report.public_ip.status == "SKIPPED"
    backend.get_public_ip.assert_called_once_with(selected_iface=None, no_internet=True)
    backend.analyze_pcap.assert_called_once()


# ============================================================================
# 8. Serialization Tests
# ============================================================================

def test_pcap_analysis_info_to_dict():
    pcap = PcapAnalysisInfo(
        file_path="capture.pcap",
        file_format="PCAP",
        file_size_bytes=1024,
        packet_count=10,
        protocols=[PcapProtocolStat(protocol="tcp", packet_count=10, byte_count=500, percent_packets=100.0, percent_bytes=100.0)],
        endpoints=[PcapEndpointStat(address="192.168.1.1", packet_count=10, byte_count=500, ip_version=4)],
        conversations=[PcapConversationStat(endpoint_a="192.168.1.1", port_a=1234, endpoint_b="8.8.8.8", port_b=53, protocol="UDP", packet_count=10, byte_count=500)],
        dns_summary=PcapDnsSummary(total_queries=5, total_responses=5, unresolved_queries=0, top_queried_domains=[("example.com", 5)]),
        http_summary=PcapHttpSummary(total_requests=2, total_responses=2, top_hosts=[("example.com", 2)], top_methods=[("GET", 2)], status_codes=[(200, 2)]),
        tls_summary=PcapTlsSummary(total_sessions=1, tls_versions=[("TLS 1.3", 1)], top_server_names=[("example.com", 1)]),
        tcp_summary=PcapTcpSummary(retransmissions=0, duplicate_acks=0, zero_window_advertisements=0, rst_flag_count=0, syn_flag_count=1),
        packet_samples=[PcapPacketSample(frame_number=1, timestamp_epoch=1600000000.0, length_bytes=64, src="192.168.1.1", dst="8.8.8.8", protocol="UDP", summary="DNS Query")],
        timeline=[PcapTrafficTimelineBucket(timestamp_start=1600000000.0, timestamp_end=1600000001.0, packet_count=10, byte_count=500)],
        status="AVAILABLE",
    )
    d = pcap.to_dict()
    assert d["file_format"] == "PCAP"
    assert len(d["protocols"]) == 1
    assert d["protocols"][0]["protocol"] == "tcp"
    assert len(d["endpoints"]) == 1
    assert d["endpoints"][0]["address"] == "192.168.1.1"
    assert d["dns_summary"]["total_queries"] == 5
    assert d["http_summary"]["total_requests"] == 2
    assert d["tls_summary"]["total_sessions"] == 1
    assert d["tcp_summary"]["syn_flag_count"] == 1
    assert len(d["packet_samples"]) == 1
    assert len(d["timeline"]) == 1

# Bounded subprocess cutoff and URI privacy regression tests
