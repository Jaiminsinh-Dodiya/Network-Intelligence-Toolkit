"""Integration tests for Phase 8: Authorized PCAP/PCAPNG Analysis Engine using real TShark.

Verifies:
- Real TShark detection and execution (tshark -r <capture> -n)
- PCAP and PCAPNG compatibility
- Complete protocol hierarchy, endpoints, conversations, and application layer parsing
- Strict security boundaries:
  - Zero live capture (-i / --interface forbidden)
  - Zero external network calls (socket.connect, urlopen, getaddrinfo all 0)
  - Zero sensitive payload/credential leakage (no cookies, auth headers, passwords, keys)
  - File immutability (SHA-256 byte-identical before and after)
- Bounded limits (packet limit truncation, output byte limit, execution timeout, empty valid capture)
- JSON serialization
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from core.models import PcapAnalysisInfo
from core.pcap import PcapAnalyzer

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"
VALID_PCAP = FIXTURES_DIR / "valid_sample.pcap"
VALID_PCAPNG = FIXTURES_DIR / "valid_sample.pcapng"
EMPTY_VALID_PCAP = FIXTURES_DIR / "empty_valid.pcap"
CORRUPT_PCAP = FIXTURES_DIR / "corrupt.pcap"

# Platform-aware TShark detection
def _find_real_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    if os.name == "nt":
        for p in (
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ):
            if os.path.isfile(p):
                return p
    else:
        for p in ("/usr/bin/tshark", "/usr/local/bin/tshark"):
            if os.path.isfile(p):
                return p
    return None

REAL_TSHARK_PATH = _find_real_tshark()
HAS_TSHARK = REAL_TSHARK_PATH is not None

pytestmark = pytest.mark.skipif(
    not HAS_TSHARK,
    reason="Real TShark integration: SKIPPED — dependency unavailable",
)


@pytest.fixture
def analyzer() -> PcapAnalyzer:
    return PcapAnalyzer()


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


# ============================================================================
# 1. Real PCAP & PCAPNG Analysis Tests
# ============================================================================

def test_real_tshark_opens_pcap(analyzer: PcapAnalyzer):
    """Verify real TShark opens and fully analyzes valid_sample.pcap."""
    assert VALID_PCAP.is_file(), f"Fixture missing: {VALID_PCAP}"
    sha_before = sha256_of_file(VALID_PCAP)

    result = analyzer.analyze(VALID_PCAP)

    sha_after = sha256_of_file(VALID_PCAP)
    assert sha_before == sha_after, "Capture file was modified during analysis"

    assert result.status == "AVAILABLE"
    assert result.file_format == "PCAP"
    assert result.analyzed_packets == 17
    assert result.total_packets == 17
    assert not result.truncated

    # Protocol hierarchy
    assert len(result.protocols) > 0
    proto_names = [p["protocol"].lower() for p in result.protocols]
    assert any("eth" in p or "ip" in p for p in proto_names)

    # Endpoints: both IPv4 and IPv6
    assert len(result.endpoints) >= 4
    ep_addrs = [e["address"] for e in result.endpoints]
    assert "192.0.2.10" in ep_addrs
    assert "192.0.2.1" in ep_addrs
    assert "2001:db8::10" in ep_addrs or "2001:db8::1" in ep_addrs

    # Conversations: both TCP and UDP
    assert len(result.conversations) >= 3
    conv_protos = [c["protocol"] for c in result.conversations]
    assert "TCP" in conv_protos
    assert "UDP" in conv_protos

    # DNS metadata
    assert result.dns is not None
    assert result.dns["query_count"] >= 1
    assert result.dns["response_count"] >= 1
    assert any(q["name"] == "example.com" for q in result.dns["top_queries"])

    # HTTP metadata
    assert result.http is not None
    assert result.http["request_count"] >= 1
    assert result.http["response_count"] >= 1
    assert "GET" in result.http["methods"]
    assert 200 in result.http["status_codes"] or "200" in result.http["status_codes"]

    # TLS metadata
    assert result.tls is not None
    assert result.tls["session_count"] >= 1
    assert "example.com" in result.tls["sni_list"]

    # TCP diagnostics
    assert result.tcp is not None
    assert result.tcp["syn_count"] >= 1
    assert result.tcp["rst_count"] >= 1

    # Samples and timeline
    assert len(result.packet_samples) > 0
    assert len(result.timeline) > 0

    # JSON serialization
    serialized = json.dumps(result.to_dict())
    assert "example.com" in serialized
    assert "192.0.2.10" in serialized


def test_real_tshark_opens_pcapng(analyzer: PcapAnalyzer):
    """Verify real TShark opens and analyzes valid_sample.pcapng."""
    assert VALID_PCAPNG.is_file(), f"Fixture missing: {VALID_PCAPNG}"
    sha_before = sha256_of_file(VALID_PCAPNG)

    result = analyzer.analyze(VALID_PCAPNG)

    sha_after = sha256_of_file(VALID_PCAPNG)
    assert sha_before == sha_after, "Capture file was modified during analysis"

    assert result.status != "ERROR"
    assert result.file_format == "PCAPNG"
    assert result.analyzed_packets == 17
    assert len(result.protocols) > 0
    assert len(result.endpoints) > 0

    # JSON serialization
    d = result.to_dict()
    assert d["file_format"] == "PCAPNG"
    assert json.dumps(d)


# ============================================================================
# 2. Security & Command Boundary Tests
# ============================================================================

def test_real_tshark_command_boundaries(analyzer: PcapAnalyzer):
    """Verify that all commands executed by real TShark use -r and -n, and NEVER -i or --interface."""
    executed_commands: list[list[str]] = []
    real_popen = subprocess.Popen

    def mock_popen(cmd, *args, **kwargs):
        if isinstance(cmd, list):
            executed_commands.append(cmd)
        return real_popen(cmd, *args, **kwargs)

    with patch("subprocess.Popen", side_effect=mock_popen):
        result = analyzer.analyze(VALID_PCAP)

    assert result.status == "AVAILABLE"
    assert len(executed_commands) > 0

    for cmd in executed_commands:
        cmd_str = " ".join(cmd)
        # Must contain -r and -n
        assert "-r" in cmd, f"Missing -r flag in command: {cmd_str}"
        assert "-n" in cmd, f"Missing -n flag in command: {cmd_str}"
        # Never live interface
        assert "-i" not in cmd, f"Forbidden -i flag found in command: {cmd_str}"
        assert "--interface" not in cmd, f"Forbidden --interface flag found in command: {cmd_str}"


def test_real_tshark_offline_privacy_guarantee(analyzer: PcapAnalyzer):
    """Verify zero external networking during real TShark analysis."""
    with (
        patch("socket.socket.connect") as mock_connect,
        patch("socket.create_connection") as mock_create_conn,
        patch("urllib.request.urlopen") as mock_urlopen,
        patch("socket.getaddrinfo") as mock_getaddrinfo,
    ):
        result = analyzer.analyze(VALID_PCAP)

        assert result.status == "AVAILABLE"
        mock_connect.assert_not_called()
        mock_create_conn.assert_not_called()
        mock_urlopen.assert_not_called()
        mock_getaddrinfo.assert_not_called()


def test_real_tshark_http_metadata_boundary(analyzer: PcapAnalyzer):
    """Verify HTTP summary contains only allowed metadata and zero sensitive headers/bodies."""
    result = analyzer.analyze(VALID_PCAP)
    assert result.status == "AVAILABLE"
    assert result.http is not None

    http_dict = result.http
    serialized_http = json.dumps(http_dict).lower()

    # Forbidden sensitive tokens
    forbidden_tokens = [
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "token",
        "api key",
        "apikey",
        "secret",
        "session",
        "bearer",
    ]
    for token in forbidden_tokens:
        assert token not in serialized_http, f"Forbidden sensitive token '{token}' leaked in HTTP summary"


def test_real_tshark_http_query_string_privacy_boundary(analyzer: PcapAnalyzer):
    """Verify HTTP summary extracts URI path /login and strictly excludes query string parameters."""
    result = analyzer.analyze(VALID_PCAP)
    assert result.status == "AVAILABLE"
    assert result.http is not None

    http_dict = result.http
    serialized_http = json.dumps(http_dict)

    # Must contain the clean URI path
    assert "/login" in serialized_http

    # Must NOT contain query string or credentials/secrets
    assert "token=SYNTHETIC_SECRET" not in serialized_http
    assert "password=SYNTHETIC_PASSWORD" not in serialized_http
    assert "SYNTHETIC_SECRET" not in serialized_http
    assert "SYNTHETIC_PASSWORD" not in serialized_http

    # Verify requests list explicitly
    requests = http_dict.get("requests", [])
    assert len(requests) >= 1
    req = requests[0]
    assert req["method"] == "GET"
    assert req["host"] == "example.com"
    assert req["path"] == "/login"


def test_real_tshark_tls_metadata_boundary(analyzer: PcapAnalyzer):
    """Verify TLS summary contains only allowed metadata and zero cryptographic secrets."""
    result = analyzer.analyze(VALID_PCAP)
    assert result.status == "AVAILABLE"
    assert result.tls is not None

    tls_dict = result.tls
    serialized_tls = json.dumps(tls_dict).lower()

    forbidden_tls = [
        "private key",
        "session key",
        "master key",
        "pre-master",
        "keylog",
        "tls secret",
    ]
    for token in forbidden_tls:
        assert token not in serialized_tls, f"Forbidden cryptographic secret '{token}' found in TLS summary"


# ============================================================================
# 3. Display Filter & Preflight Tests
# ============================================================================

def test_real_tshark_valid_display_filter(analyzer: PcapAnalyzer):
    """Verify display filter 'tcp' filters packets down to TCP only."""
    result = analyzer.analyze(VALID_PCAP, display_filter="tcp")

    assert result.status == "AVAILABLE"
    assert result.analyzed_packets == 13
    assert result.filters_applied == ["tcp"]

    # DNS (which was UDP in our fixture) should have 0 queries in TCP filter
    if result.dns:
        assert result.dns["query_count"] == 0


def test_real_tshark_invalid_display_filter(analyzer: PcapAnalyzer):
    """Verify invalid display filter produces status=ERROR with sanitized reason."""
    result = analyzer.analyze(VALID_PCAP, display_filter="invalid..syntax&&&")

    assert result.status == "ERROR"
    assert result.reason is not None
    assert "invalid display filter" in result.reason.lower()


# ============================================================================
# 4. Resource Limits & Edge Case Tests
# ============================================================================

def test_real_tshark_packet_limit_truncation():
    """Verify capture exceeding max_packets sets status=PARTIAL and truncated=True."""
    custom_analyzer = PcapAnalyzer(config={"pcap": {"max_packets": 5}})
    result = custom_analyzer.analyze(VALID_PCAP)

    assert result.status == "PARTIAL"
    assert result.truncated is True
    assert result.reason is not None
    assert "packet limit" in result.reason.lower() or "limit" in result.reason.lower()
    assert result.analyzed_packets == 5


def test_real_tshark_empty_valid_capture(analyzer: PcapAnalyzer):
    """Verify valid empty capture (24-byte PCAP with 0 packets) reports AVAILABLE with 0 packets."""
    assert EMPTY_VALID_PCAP.is_file(), f"Fixture missing: {EMPTY_VALID_PCAP}"
    result = analyzer.analyze(EMPTY_VALID_PCAP)

    assert result.status == "AVAILABLE"
    assert result.total_packets == 0
    assert result.analyzed_packets == 0
    assert not result.truncated
    assert result.reason is None


def test_real_tshark_corrupt_capture(analyzer: PcapAnalyzer):
    """Verify corrupted capture file is rejected with ERROR status."""
    assert CORRUPT_PCAP.is_file(), f"Fixture missing: {CORRUPT_PCAP}"
    result = analyzer.analyze(CORRUPT_PCAP)

    assert result.status == "ERROR"
    assert result.reason is not None
    assert "corrupt or invalid" in result.reason.lower()


def test_real_tshark_output_overflow_bounded_termination():
    """Verify output limit exceeding max_output_bytes terminates boundedly and reports PARTIAL."""
    tiny_output_analyzer = PcapAnalyzer(config={"pcap": {"max_output_bytes": 100}})
    result = tiny_output_analyzer.analyze(VALID_PCAP)

    assert result.status == "PARTIAL"
    assert result.truncated is True
    assert result.reason is not None
    assert "output" in result.reason.lower() or "limit" in result.reason.lower()


def test_real_tshark_timeout_classification():
    """Verify execution timeout reports ERROR with sanitized timeout reason."""
    timeout_analyzer = PcapAnalyzer(config={"pcap": {"tshark_timeout_seconds": 0.0001}})
    result = timeout_analyzer.analyze(VALID_PCAP)

    assert result.status in ("ERROR", "PARTIAL")
    assert result.reason is not None
    assert "timed out" in result.reason.lower()
