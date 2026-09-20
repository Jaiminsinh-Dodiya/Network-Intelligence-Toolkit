"""Unit tests for cross-platform interface normalization, multiple addresses, and selection."""

import json
from pathlib import Path
from core.models import InterfaceInfo, NetworkInfo
from core.network import calculate_network_info, select_default_interface


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_interface_multiple_addresses_preservation():
    """Verify that multiple IPv4 and IPv6 addresses on an interface are all preserved."""
    iface = InterfaceInfo(name="eth0", state="UP", is_up=True)

    addrs = [
        ("192.168.1.10", "255.255.255.0"),
        ("10.0.2.15", "255.255.255.0"),
        ("2606:4700:4700::1111", 64),
        ("fe80::a00:27ff:febc:5433", 64),
    ]

    for addr, mask in addrs:
        net = calculate_network_info(addr, mask, interface_name="eth0")
        assert net is not None
        iface.networks.append(net)
        if net.ip_version == 4:
            iface.ipv4.append(net.address)
        else:
            iface.ipv6.append(net.address)

    assert len(iface.networks) == 4
    assert len(iface.ipv4) == 2
    assert len(iface.ipv6) == 2

    # Check scopes
    scopes = [n.scope for n in iface.networks]
    assert "PRIVATE" in scopes
    assert "LINK_LOCAL" in scopes
    assert "GLOBAL" in scopes


def test_interface_selection_with_default_route():
    """Verify that default route interface is selected first."""
    eth0 = InterfaceInfo(name="eth0", is_up=True)
    wlan0 = InterfaceInfo(name="wlan0", is_up=True)
    selected = select_default_interface([eth0, wlan0], default_route_iface="wlan0")
    assert selected is not None
    assert selected.name == "wlan0"


def test_interface_selection_prefers_active_non_virtual_traffic():
    """Verify selection prefers non-virtual adapter with usable IP over virtual host-only adapter."""
    vbox = InterfaceInfo(
        name="VirtualBox Host-Only Network",
        is_up=True,
        is_loopback=False,
        rx_bytes=0,
        tx_bytes=0,
    )
    vbox_net = calculate_network_info("192.168.56.1", "255.255.255.0", interface_name="VirtualBox")
    assert vbox_net is not None
    vbox.networks.append(vbox_net)

    wifi = InterfaceInfo(
        name="Wi-Fi",
        is_up=True,
        is_loopback=False,
        rx_bytes=1000000,
        tx_bytes=500000,
    )
    wifi_net = calculate_network_info("192.168.1.100", "255.255.255.0", interface_name="Wi-Fi")
    assert wifi_net is not None
    wifi.networks.append(wifi_net)

    selected = select_default_interface([vbox, wifi])
    assert selected is not None
    assert selected.name == "Wi-Fi"


def test_interface_selection_skips_link_local_only():
    """Verify selection prefers interface with private/global IPv4 over link-local (169.254.x.x) only."""
    eth_unconf = InterfaceInfo(name="eth1", is_up=True, is_loopback=False)
    ll_net = calculate_network_info("169.254.10.5", "255.255.0.0", interface_name="eth1")
    assert ll_net is not None
    eth_unconf.networks.append(ll_net)

    eth_priv = InterfaceInfo(name="eth0", is_up=True, is_loopback=False)
    priv_net = calculate_network_info("10.0.0.15", "255.255.255.0", interface_name="eth0")
    assert priv_net is not None
    eth_priv.networks.append(priv_net)

    selected = select_default_interface([eth_unconf, eth_priv])
    assert selected is not None
    assert selected.name == "eth0"


def test_interface_selection_fallback_to_any_non_loopback():
    """Verify fallback when no usable IPv4 is configured."""
    lo = InterfaceInfo(name="lo", is_up=True, is_loopback=True)
    eth0 = InterfaceInfo(name="eth0", is_up=False, is_loopback=False)
    selected = select_default_interface([lo, eth0])
    assert selected is not None
    assert selected.name == "eth0"


def test_interface_without_ip_has_empty_networks():
    """Verify interface without IP addresses is handled cleanly."""
    iface = InterfaceInfo(name="eth2", state="DOWN", is_up=False)
    assert iface.networks == []
    assert iface.ipv4 == []
    assert iface.ipv6 == []


def test_linux_fixture_parsing_simulated():
    """Parse simulated Linux ip addr fixture."""
    fixture_path = FIXTURES_DIR / "linux" / "ip_addr_basic.txt"
    assert fixture_path.exists()
    content = fixture_path.read_text(encoding="utf-8")

    # Verify expected fixture contents
    assert "192.168.1.105/24" in content
    assert "2001:db8:85a3::8a2e:370:7334/64" in content

    # Calculate networks from fixture IP tokens
    net_v4 = calculate_network_info("192.168.1.105/24", interface_name="eth0")
    assert net_v4 is not None
    assert net_v4.network == "192.168.1.0/24"
    assert net_v4.broadcast == "192.168.1.255"

    net_v6 = calculate_network_info("2001:db8:85a3::8a2e:370:7334/64", interface_name="eth0")
    assert net_v6 is not None
    assert net_v6.network == "2001:db8:85a3::/64"
    assert net_v6.broadcast is None


def test_windows_fixture_parsing_simulated():
    """Parse simulated Windows Get-NetIPAddress fixture."""
    fixture_path = FIXTURES_DIR / "windows" / "interface_samples" / "get_netipaddress.json"
    assert fixture_path.exists()
    entries = json.loads(fixture_path.read_text(encoding="utf-8"))

    networks = []
    for entry in entries:
        ip = entry["IPAddress"]
        prefix = entry["PrefixLength"]
        iface = entry["InterfaceAlias"]
        net = calculate_network_info(ip, prefix, interface_name=iface)
        if net:
            networks.append(net)

    assert len(networks) == 5
    wifi_nets = [n for n in networks if n.interface == "Wi-Fi"]
    assert len(wifi_nets) == 2
    v4_wifi = next(n for n in wifi_nets if n.ip_version == 4)
    assert v4_wifi.network == "192.168.43.0/24"
    assert v4_wifi.usable_host_count == 254
