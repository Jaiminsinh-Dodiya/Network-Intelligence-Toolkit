"""Unit tests for normalized dataclass models."""

import json
from core.models import (
    SystemInfo,
    InterfaceInfo,
    NetworkInfo,
    RouteEntry,
    RoutingInfo,
    DnsServer,
    DnsInfo,
    DhcpInfo,
    WifiInfo,
    PublicIpInfo,
    ConnectivityTarget,
    ConnectivityInfo,
    NeighborEntry,
    SocketEntry,
    TcpConversation,
    PcapSummary,
    Observation,
    DiffItem,
    DiffReport,
    NetworkIntelligenceReport,
)


def test_system_info_serialization():
    sys_info = SystemInfo(
        os_name="Kali GNU/Linux Rolling",
        os_version="2024.1",
        platform_release="6.6.9-kali1-amd64",
        hostname="kali-pentest",
        architecture="x86_64",
        python_version="3.12.1",
        is_privileged=True,
    )
    d = sys_info.to_dict()
    assert d["os_name"] == "Kali GNU/Linux Rolling"
    assert d["is_privileged"] is True
    assert "timestamp" in d


def test_interface_info_defaults():
    iface = InterfaceInfo(name="eth0")
    assert iface.name == "eth0"
    assert iface.state == "UNKNOWN"
    assert iface.ipv4 == []
    assert iface.ipv6 == []
    assert iface.rx_bytes == 0
    assert iface.is_wireless is False
    assert iface.is_up is False


def test_network_info_serialization():
    net = NetworkInfo(
        local_ip="192.168.1.100",
        network_address="192.168.1.0",
        broadcast_address="192.168.1.255",
        cidr_prefix=24,
        netmask="255.255.255.0",
        host_range_start="192.168.1.1",
        host_range_end="192.168.1.254",
        total_hosts=254,
    )
    d = net.to_dict()
    assert d["cidr_prefix"] == 24
    assert d["total_hosts"] == 254


def test_routing_info_serialization():
    route = RouteEntry(
        destination="0.0.0.0/0",
        gateway="192.168.1.1",
        interface="eth0",
        metric=100,
        is_default=True,
    )
    routing = RoutingInfo(
        default_gateway="192.168.1.1",
        default_interface="eth0",
        routes=[route],
    )
    d = routing.to_dict()
    assert d["default_gateway"] == "192.168.1.1"
    assert len(d["routes"]) == 1
    assert d["routes"][0]["is_default"] is True


def test_tcp_conversation_serialization():
    flow = TcpConversation(
        client_ip="192.168.1.50",
        client_port=54321,
        server_ip="93.184.216.34",
        server_port=80,
        packets=6,
        bytes_sent=450,
        syn_count=1,
        syn_ack_count=1,
        ack_count=1,
        handshake_status="COMPLETE",
    )
    d = flow.to_dict()
    assert d["handshake_status"] == "COMPLETE"
    assert d["server_port"] == 80


def test_observation_serialization():
    obs = Observation(
        category="Protocols",
        title="Unencrypted HTTP Traffic Observed",
        evidence="Observed 12 HTTP GET requests in PCAP.",
        interpretation="Traffic can be read in transit by any observer on the network path.",
        severity="MEDIUM",
        confidence="HIGH",
    )
    d = obs.to_dict()
    assert d["severity"] == "MEDIUM"
    assert d["confidence"] == "HIGH"


def test_full_report_json_serializable():
    sys_info = SystemInfo(
        os_name="Windows 11",
        os_version="10.0.22631",
        platform_release="11",
        hostname="DESKTOP-TEST",
        architecture="AMD64",
        python_version="3.12.0",
        is_privileged=False,
    )
    report = NetworkIntelligenceReport(
        system=sys_info,
        capabilities={"test_cap": {"status": "AVAILABLE"}},
        selected_interface=InterfaceInfo(name="Wi-Fi", state="UP", ipv4=["192.168.1.15"]),
        all_interfaces=[InterfaceInfo(name="Wi-Fi", state="UP")],
        observations=[
            Observation(
                category="General",
                title="Test Observation",
                evidence="Evidence text",
                interpretation="Interpretation text",
            )
        ],
    )
    report_dict = report.to_dict()
    json_str = json.dumps(report_dict)
    assert json_str is not None
    loaded = json.loads(json_str)
    assert loaded["system"]["os_name"] == "Windows 11"
    assert len(loaded["observations"]) == 1
