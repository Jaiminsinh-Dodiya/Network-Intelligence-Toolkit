"""Unit tests for Wi-Fi data models, normalization functions, Windows parser, and Linux parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.models import WifiInfo
from core.network import (
    channel_to_frequency,
    frequency_to_channel,
    normalize_bssid,
    normalize_wifi_security,
    normalize_wifi_standard,
    signal_dbm_to_percent,
    signal_percent_to_dbm,
)
from backends.windows import parse_windows_wifi
from backends.linux import parse_iw_link, parse_nmcli_wifi_detail

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestWifiModels:
    def test_wifi_info_defaults(self) -> None:
        info = WifiInfo()
        assert info.state == "UNAVAILABLE"
        assert info.connected is False
        assert info.is_wireless_interface is None
        assert info.is_wifi is False
        assert info.wifi_standard == "UNKNOWN"
        assert info.standard is None
        assert info.security_mode == "UNKNOWN"

    def test_wifi_info_bidirectional_synchronization(self) -> None:
        info1 = WifiInfo(
            is_wireless_interface=True,
            wifi_standard="802.11ax",
            state="CONNECTED",
        )
        assert info1.is_wifi is True
        assert info1.standard == "802.11ax"
        assert info1.connected is True

        info2 = WifiInfo(
            is_wifi=True,
            standard="802.11ac",
            connected=True,
        )
        assert info2.is_wireless_interface is True
        assert info2.wifi_standard == "802.11ac"
        assert info2.state == "CONNECTED"

        # Dynamic attribute mutation
        info1.wifi_standard = "802.11be"
        assert info1.standard == "802.11be"
        info1.standard = "802.11n"
        assert info1.wifi_standard == "802.11n"

    def test_wifi_info_serialization(self) -> None:
        info = WifiInfo(
            interface="wlan0",
            ssid="OfficeNet",
            bssid="00:11:22:33:44:55",
            state="CONNECTED",
            wifi_standard="802.11ax",
            security_mode="WPA2",
        )
        d = info.to_dict()
        assert d["interface"] == "wlan0"
        assert d["ssid"] == "OfficeNet"
        assert d["bssid"] == "00:11:22:33:44:55"
        assert d["state"] == "CONNECTED"
        assert d["wifi_standard"] == "802.11ax"
        assert d["standard"] == "802.11ax"
        assert d["security_mode"] == "WPA2"

    def test_wifi_info_signal_provenance_serialization(self) -> None:
        """Phase 4.1: Verify signal estimation flags exist and serialize to JSON dict."""
        w = WifiInfo(
            signal_percent=88,
            signal_dbm=-56,
            signal_percent_estimated=False,
            signal_dbm_estimated=True,
        )
        d = w.to_dict()
        assert d["signal_percent"] == 88
        assert d["signal_dbm"] == -56
        assert d["signal_percent_estimated"] is False
        assert d["signal_dbm_estimated"] is True


class TestWifiHelpers:
    def test_frequency_to_channel(self) -> None:
        # 2.4 GHz
        assert frequency_to_channel(2412) == 1
        assert frequency_to_channel(2437) == 6
        assert frequency_to_channel(2472) == 13
        assert frequency_to_channel(2484) == 14
        # 5 GHz
        assert frequency_to_channel(5180) == 36
        assert frequency_to_channel(5200) == 40
        assert frequency_to_channel(5745) == 149
        assert frequency_to_channel(5825) == 165
        # 6 GHz
        assert frequency_to_channel(5935) == 2
        assert frequency_to_channel(5955) == 1
        assert frequency_to_channel(7115) == 233
        # Invalid
        assert frequency_to_channel(1234) is None
        assert frequency_to_channel(99999) is None

    def test_channel_to_frequency(self) -> None:
        # Known band
        assert channel_to_frequency(1, band="2.4 GHz") == 2412
        assert channel_to_frequency(6, band="2.4GHz") == 2437
        assert channel_to_frequency(14, band="2.4 GHz") == 2484
        assert channel_to_frequency(36, band="5 GHz") == 5180
        assert channel_to_frequency(149, band="5GHz") == 5745
        assert channel_to_frequency(2, band="6 GHz") == 5935
        assert channel_to_frequency(1, band="6 GHz") == 5955

        # Engineering Correction #6: channel without band returns None (ambiguous across bands)
        assert channel_to_frequency(1, band=None) is None
        assert channel_to_frequency(36, band=None) is None

    def test_normalize_bssid(self) -> None:
        assert normalize_bssid("00-11-22-AA-BB-CC") == "00:11:22:aa:bb:cc"
        assert normalize_bssid("  c2:10:a7:97:ad:48  ") == "c2:10:a7:97:ad:48"
        assert normalize_bssid("invalid-mac") is None
        assert normalize_bssid("") is None
        assert normalize_bssid(None) is None

    def test_normalize_wifi_security(self) -> None:
        """Engineering Correction #4: Never map enterprise modes to WPA2."""
        mode, raw = normalize_wifi_security("WPA2-Enterprise")
        assert mode == "WPA2-ENTERPRISE"
        assert raw == "WPA2-Enterprise"

        mode, raw = normalize_wifi_security("WPA3-Enterprise")
        assert mode == "WPA3-ENTERPRISE"

        mode, raw = normalize_wifi_security("WPA2 802.1X")
        assert mode == "WPA2-ENTERPRISE"

        mode, raw = normalize_wifi_security("WPA2-Personal")
        assert mode == "WPA2"

        mode, raw = normalize_wifi_security("WPA3-Personal")
        assert mode == "WPA3"

        mode, raw = normalize_wifi_security("Open")
        assert mode == "OPEN"

        assert normalize_wifi_security(None) == ("UNKNOWN", None)

    def test_normalize_wifi_security_generic_enterprise(self) -> None:
        """Phase 4.1: Generic 'Enterprise' without WPA2/WPA3 must NOT map to WPA2-ENTERPRISE."""
        mode, raw = normalize_wifi_security("Enterprise")
        assert mode == "OTHER"
        assert raw == "Enterprise"
        assert mode != "WPA2-ENTERPRISE"

        mode, raw = normalize_wifi_security("802.1X")
        assert mode == "OTHER"
        assert raw == "802.1X"
        assert mode != "WPA2-ENTERPRISE"

        # Explicit WPA2/WPA3 enterprise remain recognized
        assert normalize_wifi_security("WPA2-Enterprise")[0] == "WPA2-ENTERPRISE"
        assert normalize_wifi_security("WPA3-Enterprise")[0] == "WPA3-ENTERPRISE"

    def test_normalize_wifi_standard(self) -> None:
        """Engineering Correction #4: Strictly report standard when exposed; never infer."""
        assert normalize_wifi_standard("802.11ax") == "802.11ax"
        assert normalize_wifi_standard("Wi-Fi 6") == "802.11ax"
        assert normalize_wifi_standard("802.11ac") == "802.11ac"
        assert normalize_wifi_standard("Wi-Fi 5") == "802.11ac"
        assert normalize_wifi_standard("802.11g") == "802.11g"
        assert normalize_wifi_standard(None) == "UNKNOWN"
        assert normalize_wifi_standard("custom-radio") == "UNKNOWN"

    def test_signal_conversions(self) -> None:
        assert signal_percent_to_dbm(100) == -50
        assert signal_percent_to_dbm(50) == -75
        assert signal_percent_to_dbm(0) == -100

        assert signal_dbm_to_percent(-50) == 100
        assert signal_dbm_to_percent(-75) == 50
        assert signal_dbm_to_percent(-100) == 0


class TestWindowsWifiParser:
    @pytest.fixture
    def net_adapters(self) -> list[dict]:
        path = FIXTURES_DIR / "windows" / "wifi" / "net_adapters.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_windows_wifi_connected_wpa2(self, net_adapters) -> None:
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_connected_wpa2.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters, target_iface="Wi-Fi")
        assert info.state == "CONNECTED"
        assert info.connected is True
        assert info.is_wireless_interface is True
        assert info.ssid == "OfficeNetwork"
        assert info.bssid == "00:11:22:aa:bb:cc"
        assert info.channel == 6
        assert info.frequency_mhz == 2437
        assert info.signal_percent == 85
        assert info.signal_dbm == -57
        assert info.rx_rate_mbps == 300.0
        assert info.tx_rate_mbps == 300.0
        assert info.wifi_standard == "802.11ax"
        assert info.security_mode == "WPA2"
        assert info.raw_security == "WPA2-Personal"

    def test_windows_wifi_connected_enterprise(self, net_adapters) -> None:
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_connected_enterprise.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters, target_iface="Wi-Fi")
        assert info.state == "CONNECTED"
        assert info.security_mode == "WPA2-ENTERPRISE"
        assert info.channel == 36
        assert info.frequency_mhz == 5180

    def test_windows_wifi_disconnected(self, net_adapters) -> None:
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_disconnected.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters, target_iface="Wi-Fi")
        assert info.state == "DISCONNECTED"
        assert info.connected is False
        assert info.is_wireless_interface is True
        assert info.ssid is None

    def test_windows_wifi_non_wireless_adapter_not_applicable(self, net_adapters) -> None:
        """Engineering Correction #7: --interface Ethernet --wifi returns NOT_APPLICABLE without replacement."""
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_connected_wpa2.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters, target_iface="Ethernet")
        assert info.state == "NOT_APPLICABLE"
        assert info.is_wireless_interface is False
        assert info.interface == "Ethernet"

    def test_windows_wifi_no_wireless_on_system(self, net_adapters) -> None:
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_no_wireless.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters)
        assert info.state == "NOT_APPLICABLE"
        assert info.is_wireless_interface is False

    def test_windows_wifi_signal_provenance(self, net_adapters) -> None:
        """Phase 4.1: Netsh reports percentage directly; dBm RSSI is estimated unless explicit Rssi field present."""
        # 1. Measured RSSI present in fixture
        path = FIXTURES_DIR / "windows" / "wifi" / "netsh_connected_wpa2.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_windows_wifi(output, net_adapters, target_iface="Wi-Fi")
        assert info.signal_percent == 85
        assert info.signal_percent_estimated is False
        assert info.signal_dbm == -57
        assert info.signal_dbm_estimated is False

        # 2. Output without Rssi field -> dBm is estimated
        output_no_rssi = """
Name                   : Wi-Fi
State                  : connected
SSID                   : OfficeNetwork
AP BSSID               : 00:11:22:aa:bb:cc
Band                   : 2.4 GHz
Channel                : 6
Radio type             : 802.11ax
Authentication         : WPA2-Personal
Signal                 : 88%
"""
        info_est = parse_windows_wifi(output_no_rssi, net_adapters, target_iface="Wi-Fi")
        assert info_est.signal_percent == 88
        assert info_est.signal_percent_estimated is False
        assert info_est.signal_dbm == -56
        assert info_est.signal_dbm_estimated is True


class TestLinuxWifiParser:
    def test_linux_iw_link_connected(self) -> None:
        path = FIXTURES_DIR / "linux" / "wifi" / "iw_link_connected.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_iw_link(output, iface_name="wlan0")
        assert info.state == "CONNECTED"
        assert info.connected is True
        assert info.is_wireless_interface is True
        assert info.ssid == "LinuxOffice"
        assert info.bssid == "00:11:22:33:44:55"
        assert info.frequency_mhz == 5180
        assert info.channel == 36
        assert info.signal_dbm == -54
        assert info.signal_percent == 92
        assert info.rx_rate_mbps == 866.7
        assert info.tx_rate_mbps == 866.7

    def test_linux_iw_link_disconnected(self) -> None:
        path = FIXTURES_DIR / "linux" / "wifi" / "iw_link_disconnected.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_iw_link(output, iface_name="wlan0")
        assert info.state == "DISCONNECTED"
        assert info.connected is False
        assert info.is_wireless_interface is True
        assert info.ssid == None

    def test_linux_nmcli_wifi_detail_parsing(self) -> None:
        path = FIXTURES_DIR / "linux" / "wifi" / "nmcli_wifi_detail.txt"
        output = path.read_text(encoding="utf-8")
        sec_mode, raw_sec, std = parse_nmcli_wifi_detail(output, iface_name="wlan0")
        assert sec_mode == "WPA2"
        assert raw_sec == "WPA2"

    def test_linux_wifi_signal_provenance(self) -> None:
        """Phase 4.1: iw dev link reports dBm RSSI directly; percentage is estimated."""
        path = FIXTURES_DIR / "linux" / "wifi" / "iw_link_connected.txt"
        output = path.read_text(encoding="utf-8")
        info = parse_iw_link(output, iface_name="wlan0")
        assert info.signal_dbm == -54
        assert info.signal_dbm_estimated is False
        assert info.signal_percent == 92
        assert info.signal_percent_estimated is True

    def test_linux_wifi_selection_prefers_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Phase 4.1: Multiple wireless interfaces where only the second is connected -> select second."""
        from backends.linux import LinuxBackend
        from core.execution import CommandResult

        backend = LinuxBackend()

        # Mock candidate discovery to return ["wlan0", "wlan1"]
        monkeypatch.setattr(backend, "_find_wireless_interfaces", lambda: ["wlan0", "wlan1"])

        # Mock run_command for `iw dev <iface> link`
        def mock_run_command(cmd: list[str], *args, **kwargs) -> CommandResult:
            if "iw" in cmd and "dev" in cmd and "link" in cmd:
                if "wlan0" in cmd:
                    return CommandResult(
                        command=cmd,
                        stdout="Not connected.\n",
                        stderr="",
                        returncode=0,
                    )
                if "wlan1" in cmd:
                    path = FIXTURES_DIR / "linux" / "wifi" / "iw_link_connected.txt"
                    return CommandResult(
                        command=cmd,
                        stdout=path.read_text(encoding="utf-8"),
                        stderr="",
                        returncode=0,
                    )
            return CommandResult(command=cmd, stdout="", stderr="", returncode=1)

        monkeypatch.setattr("backends.linux.run_command", mock_run_command)
        monkeypatch.setattr("backends.linux.is_tool_available", lambda tool: True)

        info = backend.get_wifi(interface_name=None)
        assert info.interface == "wlan1"
        assert info.state == "CONNECTED"
        assert info.connected is True
        assert info.ssid == "LinuxOffice"

    def test_linux_wifi_explicit_interface_authoritative(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Phase 4.1: Explicit --interface eth0 --wifi must return NOT_APPLICABLE and never switch."""
        from backends.linux import LinuxBackend

        backend = LinuxBackend()
        monkeypatch.setattr(backend, "_find_wireless_interfaces", lambda: ["wlan0", "wlan1"])

        info = backend.get_wifi(interface_name="eth0")
        assert info.interface == "eth0"
        assert info.state == "NOT_APPLICABLE"
        assert info.is_wireless_interface is False
