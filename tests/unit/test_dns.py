"""Unit tests for Phase 3 DNS models and parsers (Windows and Linux)."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend
from core.execution import CommandResult
from core.models import DnsInfo, DnsServer


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class TestDnsModels:
    """Test DnsServer and DnsInfo models, conservative transport detection, and roles."""

    def test_dns_server_defaults_to_unknown_protocol(self):
        """DNS protocol must strictly default to UNKNOWN and never be assumed UDP."""
        server = DnsServer(address="192.168.1.1")
        assert server.protocol == "UNKNOWN"
        assert server.family == 4
        assert server.port == 53
        assert server.role == "UPSTREAM_RESOLVER"

    def test_dns_server_ipv6(self):
        server = DnsServer(address="2001:4860:4860::8888", family=6, protocol="DoH", doh_template="https://dns.google/dns-query")
        assert server.family == 6
        assert server.protocol == "DoH"
        assert server.doh_template == "https://dns.google/dns-query"

    def test_dns_server_local_stub_role(self):
        server = DnsServer(address="127.0.0.53", role="LOCAL_STUB")
        assert server.role == "LOCAL_STUB"

    def test_dns_info_serialization(self):
        s1 = DnsServer(address="1.1.1.1", protocol="DoH", doh_template="https://cloudflare-dns.com/dns-query")
        s2 = DnsServer(address="127.0.0.53", role="LOCAL_STUB")
        info = DnsInfo(
            servers=[s1, s2],
            search_domains=["corp.example"],
            source="systemd-resolved",
            status="CONFIGURED",
            is_stub=True,
            stub_address="127.0.0.53",
            upstream_servers=[s1],
        )

        d = info.to_dict()
        assert d["status"] == "CONFIGURED"
        assert d["source"] == "systemd-resolved"
        assert d["is_stub"] is True
        assert d["stub_address"] == "127.0.0.53"
        assert len(d["servers"]) == 2
        assert len(d["upstream_servers"]) == 1
        assert d["servers"][0]["protocol"] == "DoH"
        assert d["servers"][1]["role"] == "LOCAL_STUB"


class TestWindowsDnsParser:
    """Test Windows DNS parser with mocked PowerShell fixtures."""

    @pytest.fixture
    def windows_server_addr_json(self):
        return (FIXTURES_DIR / "windows" / "dns" / "get_dnsclientserveraddress.json").read_text(encoding="utf-8")

    @pytest.fixture
    def windows_global_json(self):
        return (FIXTURES_DIR / "windows" / "dns" / "get_dnsclientglobalsetting.json").read_text(encoding="utf-8")

    @pytest.fixture
    def windows_doh_json(self):
        return (FIXTURES_DIR / "windows" / "dns" / "get_dnsclientdohserveraddress.json").read_text(encoding="utf-8")

    def test_windows_dns_parsing_with_doh(self, windows_server_addr_json, windows_global_json, windows_doh_json):
        backend = WindowsBackend()

        def mock_run_cmd(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            if "Get-DnsClientDohServerAddress" in cmd_str:
                return CommandResult(command=cmd, stdout=windows_doh_json, stderr="", returncode=0)
            if "Get-DnsClientGlobalSetting" in cmd_str:
                return CommandResult(command=cmd, stdout=windows_global_json, stderr="", returncode=0)
            if "Get-DnsClientServerAddress" in cmd_str:
                return CommandResult(command=cmd, stdout=windows_server_addr_json, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()

            assert dns_info.status == "CONFIGURED"
            assert dns_info.source == "Windows DNS Client"
            assert dns_info.search_domains == ["corp.local", "internal.net"]
            assert len(dns_info.servers) == 4

            # 1.1.1.1 has verified DoH template configured
            s_doh = [s for s in dns_info.servers if s.address == "1.1.1.1"][0]
            assert s_doh.protocol == "DoH"
            assert s_doh.doh_template == "https://cloudflare-dns.com/dns-query"
            assert s_doh.interface == "Wi-Fi"

            # 192.168.1.1 has NO DoH configured -> must remain UNKNOWN
            s_gw = [s for s in dns_info.servers if s.address == "192.168.1.1"][0]
            assert s_gw.protocol == "UNKNOWN"
            assert s_gw.doh_template is None

            # IPv6 server 2606:4700:4700::1111
            s_v6 = [s for s in dns_info.servers if s.address == "2606:4700:4700::1111"][0]
            assert s_v6.family == 6
            assert s_v6.protocol == "UNKNOWN"

            # Windows does not designate an explicit preferred resolver -> is_primary must be False
            assert all(s.is_primary is False for s in dns_info.servers)

    def test_windows_dns_empty_handling(self):
        backend = WindowsBackend()

        def mock_run_cmd(cmd, **kwargs):
            return CommandResult(command=cmd, stdout="[]", stderr="", returncode=0)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()
            assert dns_info.status == "EMPTY"
            assert len(dns_info.servers) == 0
            assert dns_info.search_domains == []

    def test_windows_dns_error_handling(self):
        backend = WindowsBackend()

        def mock_run_cmd(cmd, **kwargs):
            return CommandResult(command=cmd, stdout="", stderr="Access denied", returncode=1)

        with patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()
            assert dns_info.status == "ERROR"
            assert len(dns_info.servers) == 0


class TestLinuxDnsParser:
    """Test Linux DNS parser with mocked systemd-resolved, resolv.conf, and nmcli."""

    @pytest.fixture
    def resolvectl_output(self):
        return (FIXTURES_DIR / "linux" / "dns" / "resolvectl_status.txt").read_text(encoding="utf-8")

    @pytest.fixture
    def resolv_conf_output(self):
        return (FIXTURES_DIR / "linux" / "dns" / "resolv_conf.txt").read_text(encoding="utf-8")

    @pytest.fixture
    def nmcli_output(self):
        return (FIXTURES_DIR / "linux" / "dns" / "nmcli_dev_show.txt").read_text(encoding="utf-8")

    def test_linux_systemd_resolved_dot_detection(self, resolvectl_output):
        backend = LinuxBackend()

        def mock_is_tool(name):
            return name == "resolvectl"

        def mock_run_cmd(cmd, **kwargs):
            if cmd == ["resolvectl", "status"]:
                return CommandResult(command=cmd, stdout=resolvectl_output, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("backends.linux.is_tool_available", side_effect=mock_is_tool), \
             patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()

            assert dns_info.status == "CONFIGURED"
            assert dns_info.source == "systemd-resolved"
            assert "corp.example" in dns_info.search_domains
            assert "lan" in dns_info.search_domains
            assert "~." not in dns_info.search_domains  # Routing indicator excluded

            # Resolvers found: 192.168.1.1 and 1.1.1.1
            assert len(dns_info.servers) >= 2
            # Notice in fixture +DNSOverTLS was enabled on Link eth0
            for s in dns_info.servers:
                assert s.protocol == "DoT"
                assert s.role == "UPSTREAM_RESOLVER"

            # 192.168.1.1 was designated as Current DNS Server, while 1.1.1.1 was not
            s_cur = [s for s in dns_info.servers if s.address == "192.168.1.1"][0]
            assert s_cur.is_primary is True
            s_other = [s for s in dns_info.servers if s.address == "1.1.1.1"][0]
            assert s_other.is_primary is False

    def test_linux_systemd_resolved_dot_per_link_scope(self):
        backend = LinuxBackend()
        multilink_fixture = (FIXTURES_DIR / "linux" / "dns" / "resolvectl_multilink.txt").read_text(encoding="utf-8")

        def mock_is_tool(name):
            return name == "resolvectl"

        def mock_run_cmd(cmd, **kwargs):
            if cmd == ["resolvectl", "status"]:
                return CommandResult(command=cmd, stdout=multilink_fixture, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("backends.linux.is_tool_available", side_effect=mock_is_tool), \
             patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()

            assert dns_info.status == "CONFIGURED"
            assert dns_info.source == "systemd-resolved"

            # eth0 link had +DNSOverTLS enabled -> 1.1.1.1 and 1.0.0.1 must be DoT
            eth0_servers = [s for s in dns_info.servers if s.interface == "eth0"]
            assert len(eth0_servers) == 2
            for s in eth0_servers:
                assert s.protocol == "DoT"

            # wlan0 link had -DNSOverTLS -> 8.8.8.8 and 8.8.4.4 must be UNKNOWN (NOT affected by eth0's +DNSOverTLS)
            wlan0_servers = [s for s in dns_info.servers if s.interface == "wlan0"]
            assert len(wlan0_servers) == 2
            for s in wlan0_servers:
                assert s.protocol == "UNKNOWN"

            # Primary flag checks: 1.1.1.1 is Current on eth0, 8.8.8.8 is Current on wlan0
            s_1111 = [s for s in dns_info.servers if s.address == "1.1.1.1"][0]
            assert s_1111.is_primary is True
            s_1001 = [s for s in dns_info.servers if s.address == "1.0.0.1"][0]
            assert s_1001.is_primary is False

            s_8888 = [s for s in dns_info.servers if s.address == "8.8.8.8"][0]
            assert s_8888.is_primary is True
            s_8844 = [s for s in dns_info.servers if s.address == "8.8.4.4"][0]
            assert s_8844.is_primary is False

    def test_linux_resolv_conf_stub_detection(self, resolv_conf_output):
        backend = LinuxBackend()

        with patch("backends.linux.is_tool_available", return_value=False), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=resolv_conf_output):
            dns_info = backend.get_dns()

            assert dns_info.status == "CONFIGURED"
            assert dns_info.source == "resolv.conf"
            assert dns_info.is_stub is True
            assert dns_info.stub_address == "127.0.0.53"
            assert "corp.example" in dns_info.search_domains
            assert "localdomain" in dns_info.search_domains

            assert len(dns_info.servers) == 1
            assert dns_info.servers[0].address == "127.0.0.53"
            assert dns_info.servers[0].role == "LOCAL_STUB"
            assert dns_info.servers[0].protocol == "UNKNOWN"
            assert dns_info.servers[0].is_primary is False

    def test_linux_nmcli_fallback(self, nmcli_output):
        backend = LinuxBackend()

        def mock_is_tool(name):
            return name == "nmcli"

        def mock_run_cmd(cmd, **kwargs):
            if cmd == ["nmcli", "dev", "show"]:
                return CommandResult(command=cmd, stdout=nmcli_output, stderr="", returncode=0)
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        with patch("backends.linux.is_tool_available", side_effect=mock_is_tool), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("core.execution.run_command", side_effect=mock_run_cmd):
            dns_info = backend.get_dns()

            assert dns_info.status == "CONFIGURED"
            assert dns_info.source == "NetworkManager"
            assert "corp.example" in dns_info.search_domains

            addresses = [s.address for s in dns_info.servers]
            assert "192.168.1.1" in addresses
            assert "8.8.8.8" in addresses
            assert "2001:4860:4860::8888" in addresses

            # IPv6 family check
            v6_server = [s for s in dns_info.servers if s.address == "2001:4860:4860::8888"][0]
            assert v6_server.family == 6
            assert v6_server.protocol == "UNKNOWN"
            assert all(s.is_primary is False for s in dns_info.servers)
