"""Integration tests for Phase 9 Observations & Findings Engine CLI behavior."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

FIXTURE_PCAP = Path("tests/fixtures/pcap/valid_sample.pcap")


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Helper to execute main.py with explicit UTF-8 encoding across platforms."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "main.py"] + args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def test_cli_json_observations_schema():
    """Verify that --json produces valid JSON containing structured observations."""
    proc = _run_cli(["--json", "--quick"])
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert "observations" in data
    assert isinstance(data["observations"], list)

    for obs in data["observations"]:
        assert "id" in obs
        assert "category" in obs
        assert "severity" in obs
        assert "confidence" in obs
        assert "summary" in obs
        assert "details" in obs
        assert "evidence" in obs
        assert "status" in obs
        assert obs["category"] in (
            "NETWORK",
            "HOST",
            "CONNECTIVITY",
            "PUBLIC_IDENTITY",
            "PCAP",
            "DATA_QUALITY",
        )
        assert obs["severity"] in ("INFO", "NOTICE", "WARNING")
        assert obs["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert obs["status"] in ("OBSERVED", "INFORMATIONAL", "UNAVAILABLE", "SUPPRESSED")


def test_cli_quick_mode_observations():
    """Verify that --quick completes with exit code 0 and renders observations."""
    proc = _run_cli(["--quick"])
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr
    assert "Traceback" not in proc.stdout


def test_cli_quick_mode_scope_awareness():
    """Verify that --quick does NOT emit unrequested neighbor/socket/partial observations."""
    proc = _run_cli(["--quick", "--json"])
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    obs_ids = [o["id"] for o in data.get("observations", [])]

    # Quick mode must NEVER produce false empty neighbor or process unknown findings
    assert "NETWORK.NEIGHBOR.EMPTY" not in obs_ids
    assert "HOST.SOCKET.PROCESS_UNKNOWN" not in obs_ids

    # Quick mode must NEVER produce DATA.COLLECTION.PARTIAL for unrequested socket_summary
    for obs in data.get("observations", []):
        if obs["id"] == "DATA.COLLECTION.PARTIAL":
            assert "socket_summary" not in obs.get("related_entities", [])
            assert "neighbor_table" not in obs.get("related_entities", [])


def test_cli_neighbors_mode_scope():
    """Verify that --neighbors --no-internet does not report unrequested socket findings."""
    proc = _run_cli(["--neighbors", "--no-internet", "--json"])
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    obs_ids = [o["id"] for o in data.get("observations", [])]
    assert "HOST.SOCKET.PROCESS_UNKNOWN" not in obs_ids
    assert "HOST.SOCKET.LISTENING" not in obs_ids


def test_cli_sockets_mode_scope():
    """Verify that --sockets --no-internet does not report unrequested neighbor findings."""
    proc = _run_cli(["--sockets", "--no-internet", "--json"])
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    obs_ids = [o["id"] for o in data.get("observations", [])]
    assert "NETWORK.NEIGHBOR.EMPTY" not in obs_ids
    assert "NETWORK.GATEWAY.NEIGHBOR_MATCH" not in obs_ids
    assert "NETWORK.GATEWAY.NEIGHBOR_MISSING" not in obs_ids


def test_cli_full_mode_no_internet():
    """Verify that --full --no-internet completes with exit code 0."""
    proc = _run_cli(["--full", "--no-internet"])
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr


def test_cli_neighbors_mode():
    """Verify that --neighbors --no-internet completes cleanly."""
    proc = _run_cli(["--neighbors", "--no-internet"])
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr


def test_cli_sockets_mode():
    """Verify that --sockets --no-internet completes cleanly."""
    proc = _run_cli(["--sockets", "--no-internet"])
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr


def test_cli_pcap_observations():
    """Verify that --pcap generates PCAP-derived observations."""
    if not FIXTURE_PCAP.is_file():
        pytest.skip(f"PCAP fixture {FIXTURE_PCAP} not found")

    proc = _run_cli(["--pcap", str(FIXTURE_PCAP), "--quick", "--json"])
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert "observations" in data
    obs_ids = [o["id"] for o in data["observations"]]
    assert any(oid.startswith("PCAP.") for oid in obs_ids)
    assert "PCAP.ANALYSIS.AVAILABLE" in obs_ids


def test_cli_pcap_no_internet_observations():
    """Verify that --pcap with --no-internet operates cleanly offline."""
    if not FIXTURE_PCAP.is_file():
        pytest.skip(f"PCAP fixture {FIXTURE_PCAP} not found")

    proc = _run_cli(["--pcap", str(FIXTURE_PCAP), "--no-internet", "--quick"])
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr
    assert "Observations" in proc.stdout
    assert "PCAP.ANALYSIS.AVAILABLE" in proc.stdout


def test_observations_engine_zero_network_activity():
    """Verify that ObservationEngine.analyze performs zero active network I/O."""
    from unittest.mock import patch
    from core.observations import ObservationEngine
    from core.models import NetworkIntelligenceReport, SystemInfo

    sys_info = SystemInfo(
        os_name="TestOS",
        os_version="1.0",
        platform_release="1.0",
        hostname="testhost",
        architecture="x86_64",
        python_version="3.12.0",
        is_privileged=False,
    )
    report = NetworkIntelligenceReport(
        system=sys_info,
        capabilities={},
        collection_errors={},
    )

    engine = ObservationEngine()

    with patch("socket.socket") as mock_sock, \
         patch("urllib.request.urlopen") as mock_url, \
         patch("subprocess.run") as mock_sub:
        obs = engine.analyze(report)

        mock_sock.assert_not_called()
        mock_url.assert_not_called()
        mock_sub.assert_not_called()

    assert isinstance(obs, list)
