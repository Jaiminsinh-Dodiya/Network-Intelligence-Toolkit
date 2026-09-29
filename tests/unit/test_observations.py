"""Unit tests for Phase 9 Observations & Findings Engine."""

from __future__ import annotations

import json
import pytest

from core.capabilities import CapabilityEntry, CapabilityStatus
from core.models import (
    ConnectivityInfo,
    ConnectivityTarget,
    DhcpInfo,
    DnsInfo,
    DnsServer,
    InterfaceInfo,
    NeighborEntry,
    NetworkInfo,
    NetworkIntelligenceReport,
    Observation,
    ObservationEvidence,
    PcapAnalysisInfo,
    PcapDnsSummary,
    PcapHttpSummary,
    PcapTcpSummary,
    PcapTlsSummary,
    PublicIpInfo,
    RouteEntry,
    RoutingInfo,
    SocketEntry,
    SystemInfo,
    VALID_OBSERVATION_CATEGORIES,
    VALID_OBSERVATION_CONFIDENCES,
    VALID_OBSERVATION_SEVERITIES,
    VALID_OBSERVATION_STATUSES,
)
from core.observations import ObservationEngine


def create_minimal_report(**kwargs) -> NetworkIntelligenceReport:
    """Helper to create a deterministic baseline report."""
    sys_info = SystemInfo(
        os_name="TestOS",
        os_version="1.0",
        platform_release="1.0",
        hostname="testhost",
        architecture="x86_64",
        python_version="3.12.0",
        is_privileged=False,
    )
    defaults = {
        "system": sys_info,
        "capabilities": {},
        "collection_errors": {},
        "selected_interface": None,
        "all_interfaces": [],
        "network": None,
        "all_networks": [],
        "routing": None,
        "dns": None,
        "dhcp": None,
        "wifi": None,
        "public_ip": None,
        "connectivity": None,
        "neighbors": [],
        "sockets": [],
        "pcap_analysis": None,
        "observations": [],
    }
    defaults.update(kwargs)
    return NetworkIntelligenceReport(**defaults)


# ==============================================================================
# 1. Model Validation & Serialization Tests
# ==============================================================================
def test_observation_model_validations():
    """Verify valid and invalid category, severity, confidence, and status."""
    # Valid observation
    obs = Observation(
        id="NETWORK.GATEWAY.NEIGHBOR_MATCH",
        category="NETWORK",
        severity="INFO",
        title="Gateway Match",
        summary="Summary text",
        details="Detail text",
        confidence="HIGH",
        status="OBSERVED",
    )
    assert obs.category == "NETWORK"
    assert obs.severity == "INFO"
    assert obs.confidence == "HIGH"
    assert obs.status == "OBSERVED"

    # Invalid category
    with pytest.raises(ValueError, match="Invalid observation category"):
        Observation(id="TEST.1", category="MALWARE", severity="INFO", confidence="HIGH", status="OBSERVED")

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid observation severity"):
        Observation(id="TEST.2", category="NETWORK", severity="EXTREME", confidence="HIGH", status="OBSERVED")

    # Invalid confidence
    with pytest.raises(ValueError, match="Invalid observation confidence"):
        Observation(id="TEST.3", category="NETWORK", severity="INFO", confidence="CERTAIN", status="OBSERVED")

    # Invalid status
    with pytest.raises(ValueError, match="Invalid observation status"):
        Observation(id="TEST.4", category="NETWORK", severity="INFO", confidence="HIGH", status="DELETED")


def test_observation_json_serialization():
    """Verify observation serialization and deterministic sorting of internal collections."""
    ev1 = ObservationEvidence(source="routing", field="default_ipv4.gateway", value="192.168.1.1", description="Default gw")
    ev2 = ObservationEvidence(source="neighbors", field="ip_address", value="192.168.1.1", description="Neighbor IP")

    obs = Observation(
        id="NETWORK.GATEWAY.NEIGHBOR_MATCH",
        category="NETWORK",
        severity="INFO",
        title="Gateway Match",
        summary="Summary text",
        details="Detail text",
        confidence="HIGH",
        evidence=[ev2, ev1],  # Unsorted input
        source_sections=["routing", "neighbors"],
        related_entities=["eth0", "192.168.1.1"],
        status="OBSERVED",
    )

    d = obs.to_dict()
    assert d["id"] == "NETWORK.GATEWAY.NEIGHBOR_MATCH"
    assert d["source_sections"] == ["neighbors", "routing"]  # Sorted deterministically
    assert d["related_entities"] == ["192.168.1.1", "eth0"]  # Sorted deterministically
    # Evidence sorted by source, field
    assert d["evidence"][0]["source"] == "neighbors"
    assert d["evidence"][1]["source"] == "routing"

    json_str = json.dumps(d)
    assert "NETWORK.GATEWAY.NEIGHBOR_MATCH" in json_str
    loaded = json.loads(json_str)
    assert loaded["severity"] == "INFO"


# ==============================================================================
# 2. Gateway / Neighbor Correlation Tests
# ==============================================================================
def test_gateway_neighbor_match():
    """Verify NETWORK.GATEWAY.NEIGHBOR_MATCH when gateway is in neighbor cache."""
    report = create_minimal_report(
        capabilities={"neighbor_table": CapabilityEntry(name="neighbor_table", status=CapabilityStatus.AVAILABLE, description="Neighbors")},
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
        ),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE")
        ],
    )
    engine = ObservationEngine()
    obs = engine.observe_default_gateway_consistency(report)
    assert len(obs) == 1
    assert obs[0].id == "NETWORK.GATEWAY.NEIGHBOR_MATCH"
    assert obs[0].severity == "INFO"
    assert obs[0].confidence == "HIGH"
    assert "192.168.1.1" in obs[0].summary


def test_gateway_neighbor_missing():
    """Verify NETWORK.GATEWAY.NEIGHBOR_MISSING when gateway is absent from non-empty cache."""
    report = create_minimal_report(
        capabilities={"neighbor_table": CapabilityEntry(name="neighbor_table", status=CapabilityStatus.AVAILABLE, description="Neighbors")},
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
        ),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.50", mac_address="00:11:22:33:44:99", interface="eth0", state="REACHABLE")
        ],
    )
    engine = ObservationEngine()
    obs = engine.observe_default_gateway_consistency(report)
    assert len(obs) == 1
    assert obs[0].id == "NETWORK.GATEWAY.NEIGHBOR_MISSING"
    assert obs[0].severity == "NOTICE"
    assert obs[0].confidence == "MEDIUM"


def test_gateway_neighbor_no_gateway():
    """Verify no gateway correlation observation when no default route exists."""
    report = create_minimal_report(
        capabilities={"neighbor_table": CapabilityEntry(name="neighbor_table", status=CapabilityStatus.AVAILABLE, description="Neighbors")},
        routing=RoutingInfo(default_ipv4=None),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.50", mac_address="00:11:22:33:44:99", interface="eth0", state="REACHABLE")
        ],
    )
    engine = ObservationEngine()
    obs = engine.observe_default_gateway_consistency(report)
    assert len(obs) == 0


# ==============================================================================
# 3. Routing Tests
# ==============================================================================
def test_routing_no_default_gateway():
    """Verify NETWORK.ROUTING.NO_DEFAULT_GATEWAY when no default gateway exists."""
    report = create_minimal_report(
        routing=RoutingInfo(default_ipv4=None, default_ipv6=None)
    )
    engine = ObservationEngine()
    obs = engine.observe_routing_state(report)
    assert any(o.id == "NETWORK.ROUTING.NO_DEFAULT_GATEWAY" for o in obs)


def test_routing_multiple_defaults():
    """Verify NETWORK.ROUTING.MULTIPLE_DEFAULTS when multiple active default routes exist."""
    report = create_minimal_report(
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
            routes=[
                RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4, metric=10),
                RouteEntry(destination="0.0.0.0/0", gateway="10.0.0.1", interface="wlan0", ip_version=4, metric=20),
            ],
        )
    )
    engine = ObservationEngine()
    obs = engine.observe_routing_state(report)
    assert any(o.id == "NETWORK.ROUTING.MULTIPLE_DEFAULTS" for o in obs)


# ==============================================================================
# 4. DNS Tests
# ==============================================================================
def test_dns_stub_resolver():
    """Verify NETWORK.DNS.STUB_RESOLVER for 127.0.0.53 / loopback resolver."""
    report = create_minimal_report(
        dns=DnsInfo(
            servers=[DnsServer(address="127.0.0.53")],
            status="CONFIGURED",
        )
    )
    engine = ObservationEngine()
    obs = engine.observe_dns_consistency(report)
    assert len(obs) == 1
    assert obs[0].id == "NETWORK.DNS.STUB_RESOLVER"
    assert obs[0].severity == "INFO"


def test_dns_no_upstream():
    """Verify NETWORK.DNS.NO_UPSTREAM when resolver list is empty."""
    report = create_minimal_report(
        dns=DnsInfo(servers=[], status="CONFIGURED")
    )
    engine = ObservationEngine()
    obs = engine.observe_dns_consistency(report)
    assert len(obs) == 1
    assert obs[0].id == "NETWORK.DNS.NO_UPSTREAM"
    assert obs[0].severity == "NOTICE"


# ==============================================================================
# 5. IPv6 Tests
# ==============================================================================
def test_ipv6_configured_no_connectivity():
    """Verify NETWORK.IPV6.CONFIGURED_NO_CONNECTIVITY when global IPv6 exists but probe fails."""
    report = create_minimal_report(
        selected_interface=InterfaceInfo(
            name="eth0",
            state="UP",
            ipv4=["192.168.1.10"],
            ipv6=["2001:db8::1/64", "fe80::1/64"],
        ),
        connectivity=ConnectivityInfo(
            ipv6=ConnectivityTarget(name="ipv6", target="2606:4700:4700::1111", success=False, status="FAILED")
        ),
    )
    engine = ObservationEngine()
    obs = engine.observe_ipv6_state(report)
    assert any(o.id == "NETWORK.IPV6.CONFIGURED_NO_CONNECTIVITY" for o in obs)


def test_ipv6_dual_stack():
    """Verify NETWORK.PUBLIC_IDENTITY.DUAL_STACK when both v4 and v6 public addresses exist."""
    report = create_minimal_report(
        public_ip=PublicIpInfo(
            ip="203.0.113.5",
            ipv6="2001:db8::cafe",
            status="SUCCESS",
            available=True,
        )
    )
    engine = ObservationEngine()
    obs = engine.observe_ipv6_state(report)
    assert any(o.id == "NETWORK.PUBLIC_IDENTITY.DUAL_STACK" for o in obs)


# ==============================================================================
# 6. Public Identity & CGNAT Tests
# ==============================================================================
def test_public_identity_cgnat():
    """Verify NETWORK.PUBLIC_IDENTITY.CGNAT for RFC6598 100.64.0.0/10 address."""
    report = create_minimal_report(
        selected_interface=InterfaceInfo(
            name="eth0",
            state="UP",
            ipv4=["100.64.12.34/24"],
        )
    )
    engine = ObservationEngine()
    obs = engine.observe_public_identity(report)
    assert len(obs) == 1
    assert obs[0].id == "NETWORK.PUBLIC_IDENTITY.CGNAT"
    assert obs[0].severity == "INFO"
    assert "100.64.12.34" in obs[0].summary


# ==============================================================================
# 7. Neighbor Tests
# ==============================================================================
def test_neighbor_empty_and_router():
    """Verify NETWORK.NEIGHBOR.EMPTY and NETWORK.NEIGHBOR.ROUTER_OBSERVED."""
    engine = ObservationEngine()

    # Empty
    rep_empty = create_minimal_report(
        capabilities={"neighbor_table": CapabilityEntry(name="neighbor_table", status=CapabilityStatus.AVAILABLE, description="Neighbors")},
        neighbors=[],
    )
    obs_empty = engine.observe_neighbor_state(rep_empty)
    assert len(obs_empty) == 1
    assert obs_empty[0].id == "NETWORK.NEIGHBOR.EMPTY"

    # Router & Incomplete
    rep_nodes = create_minimal_report(
        neighbors=[
            NeighborEntry(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", interface="eth0", is_router=True, state="REACHABLE"),
            NeighborEntry(ip_address="192.168.1.99", mac_address="", interface="eth0", is_router=False, state="INCOMPLETE"),
        ]
    )
    obs_nodes = engine.observe_neighbor_state(rep_nodes)
    obs_ids = {o.id for o in obs_nodes}
    assert "NETWORK.NEIGHBOR.ROUTER_OBSERVED" in obs_ids
    assert "NETWORK.NEIGHBOR.INCOMPLETE" in obs_ids


# ==============================================================================
# 8. Socket Tests
# ==============================================================================
def test_socket_listening_and_unknown_process():
    """Verify HOST.SOCKET.LISTENING and HOST.SOCKET.PROCESS_UNKNOWN."""
    report = create_minimal_report(
        sockets=[
            SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=80, state="LISTEN", pid=1234, process_name="nginx.exe"),
            SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=443, state="LISTEN", pid=None, process_name=None),
            SocketEntry(protocol="UDP", local_address="0.0.0.0", local_port=53, state="LISTEN", pid=None, process_name=None),
        ]
    )
    engine = ObservationEngine()
    obs = engine.observe_socket_state(report)
    obs_ids = {o.id for o in obs}
    assert "HOST.SOCKET.LISTENING" in obs_ids
    assert "HOST.SOCKET.PROCESS_UNKNOWN" in obs_ids


# ==============================================================================
# 9. Connectivity Tests
# ==============================================================================
def test_connectivity_observations():
    """Verify CONNECTIVITY.GATEWAY_REACHABLE, DNS_AVAILABLE, HTTP_AVAILABLE, IPV6_NOT_OBSERVED."""
    report = create_minimal_report(
        connectivity=ConnectivityInfo(
            gateway=ConnectivityTarget(name="gateway", target="192.168.1.1", success=True, status="SUCCESS", latency_ms=1.5),
            dns=ConnectivityTarget(name="dns", target="dns.google", success=True, status="SUCCESS", latency_ms=12.4),
            internet=ConnectivityTarget(name="internet", target="http://example.com", success=True, status="SUCCESS", http_status=200),
            ipv6=ConnectivityTarget(name="ipv6", target="2606:4700::1", success=False, status="FAILED"),
        )
    )
    engine = ObservationEngine()
    obs = engine.observe_connectivity_state(report)
    obs_ids = {o.id for o in obs}
    assert "CONNECTIVITY.GATEWAY_REACHABLE" in obs_ids
    assert "CONNECTIVITY.DNS_AVAILABLE" in obs_ids
    assert "CONNECTIVITY.HTTP_AVAILABLE" in obs_ids
    assert "CONNECTIVITY.IPV6_NOT_OBSERVED" in obs_ids


# ==============================================================================
# 10. PCAP Tests
# ==============================================================================
def test_pcap_observations():
    """Verify PCAP observations: AVAILABLE, TRUNCATED, RETRANSMISSIONS, RESETS, DNS, HTTP, TLS."""
    pcap_info = PcapAnalysisInfo(
        file_path="capture.pcap",
        status="PARTIAL",
        truncated=True,
        reason="Packet limit reached",
        total_packets=500,
        analyzed_packets=500,
        protocols=[{"protocol": "tcp", "frames": 400, "bytes": 50000, "percentage": 80.0}],
        tcp_summary=PcapTcpSummary(retransmissions=15, rst_flag_count=3),
        dns_summary=PcapDnsSummary(query_count=10, response_count=8, unresolved_queries=2),
        http_summary=PcapHttpSummary(request_count=5, response_count=5, top_hosts=[("example.com", 5)]),
        tls_summary=PcapTlsSummary(session_count=4, top_server_names=[("secure.example.com", 4)]),
    )
    report = create_minimal_report(pcap_analysis=pcap_info)
    engine = ObservationEngine()
    obs = engine.observe_pcap_state(report)
    obs_ids = {o.id for o in obs}

    assert "PCAP.ANALYSIS.AVAILABLE" in obs_ids
    assert "PCAP.ANALYSIS.TRUNCATED" in obs_ids
    assert "PCAP.TCP.RETRANSMISSIONS" in obs_ids
    assert "PCAP.TCP.RESETS" in obs_ids
    assert "PCAP.DNS.UNRESOLVED" in obs_ids
    assert "PCAP.HTTP.OBSERVED" in obs_ids
    assert "PCAP.TLS.OBSERVED" in obs_ids


def test_pcap_absent_produces_no_pcap_observations():
    """Verify that absent PCAP analysis produces zero PCAP observations."""
    report = create_minimal_report(pcap_analysis=None)
    engine = ObservationEngine()
    obs = engine.observe_pcap_state(report)
    assert len(obs) == 0


# ==============================================================================
# 11. Data Quality Tests
# ==============================================================================
def test_data_quality_observations():
    """Verify DATA.COLLECTION.ERROR and DATA.COLLECTION.PARTIAL."""
    report = create_minimal_report(
        collection_errors={"wifi": "Command timed out"},
        public_ip=PublicIpInfo(status="DISABLED"),
        capabilities={
            "socket_summary": CapabilityEntry(name="socket_summary", status=CapabilityStatus.PARTIAL, description="Sockets", reason="Admin required")
        },
    )
    engine = ObservationEngine()
    obs = engine.observe_data_quality(report)
    obs_ids = [o.id for o in obs]

    assert "DATA.COLLECTION.ERROR" in obs_ids
    assert "DATA.COLLECTION.PARTIAL" in obs_ids


# ==============================================================================
# 12. Suppression & Deduplication Tests
# ==============================================================================
def test_suppression_of_contradictory_rules():
    """Verify contradictory rules are suppressed."""
    engine = ObservationEngine()

    # 1. Gateway match suppresses missing neighbor
    rep = create_minimal_report(
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
        ),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE")
        ],
        connectivity=ConnectivityInfo(
            gateway=ConnectivityTarget(name="gateway", target="192.168.1.1", success=True, status="SUCCESS"),
            ipv6=ConnectivityTarget(name="ipv6", target="2606::1", success=True, status="SUCCESS"),
        ),
        selected_interface=InterfaceInfo(name="eth0", state="UP", ipv4=["192.168.1.10"], ipv6=["2001:db8::1/64"]),
    )

    all_obs = engine.analyze(rep)
    obs_ids = {o.id for o in all_obs}

    # Gateway match exists, missing neighbor must NOT exist
    assert "NETWORK.GATEWAY.NEIGHBOR_MATCH" in obs_ids
    assert "NETWORK.GATEWAY.NEIGHBOR_MISSING" not in obs_ids

    # IPv6 connectivity succeeded, so configured_no_connectivity must NOT exist
    assert "NETWORK.IPV6.CONFIGURED_NO_CONNECTIVITY" not in obs_ids


def test_deduplication():
    """Verify deduplication of observations with identical (id, related_entities)."""
    engine = ObservationEngine()
    obs1 = Observation(id="HOST.SOCKET.LISTENING", category="HOST", severity="INFO", title="Listening 1", summary="S1", details="D1", confidence="HIGH", related_entities=["80", "443"])
    obs2 = Observation(id="HOST.SOCKET.LISTENING", category="HOST", severity="NOTICE", title="Listening 2", summary="S2", details="D2", confidence="HIGH", related_entities=["443", "80"])

    deduped = engine._deduplicate([obs1, obs2])
    assert len(deduped) == 1
    # Retains higher severity (NOTICE > INFO)
    assert deduped[0].severity == "NOTICE"


# ==============================================================================
# 13. Determinism Tests
# ==============================================================================
def test_observation_engine_determinism():
    """Verify identical report produces byte-identical observations and JSON output."""
    report = create_minimal_report(
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
        ),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.1", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE"),
            NeighborEntry(ip_address="192.168.1.200", mac_address="00:11:22:33:44:66", interface="eth0", is_router=True, state="REACHABLE"),
        ],
        dns=DnsInfo(servers=[DnsServer(address="127.0.0.53")], status="CONFIGURED"),
        sockets=[
            SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=22, state="LISTEN", pid=None, process_name=None)
        ],
        connectivity=ConnectivityInfo(
            gateway=ConnectivityTarget(name="gateway", target="192.168.1.1", success=True, status="SUCCESS", latency_ms=2.1),
            dns=ConnectivityTarget(name="dns", target="dns.google", success=True, status="SUCCESS", latency_ms=10.5),
        ),
    )

    engine1 = ObservationEngine()
    engine2 = ObservationEngine()

    obs_run1 = engine1.analyze(report)
    obs_run2 = engine2.analyze(report)

    # 1. Lengths match
    assert len(obs_run1) == len(obs_run2)

    # 2. JSON representations match byte-for-byte
    json1 = json.dumps([o.to_dict() for o in obs_run1], sort_keys=True)
    json2 = json.dumps([o.to_dict() for o in obs_run2], sort_keys=True)
    assert json1 == json2

    # 3. Order is deterministic
    for o1, o2 in zip(obs_run1, obs_run2):
        assert o1.id == o2.id
        assert o1.severity == o2.severity
        assert o1.category == o2.category


# ==============================================================================
# 14. Collection Scope Awareness Tests (Phase 9.1 Hardening)
# ==============================================================================
def test_scope_quick_mode_excludes_unrequested_observations():
    """Verify that quick mode scope suppresses neighbor, socket, and unrequested partial observations."""
    engine = ObservationEngine()
    rep = create_minimal_report(
        neighbors=[],
        sockets=[],
        capabilities={
            "socket_summary": CapabilityEntry(
                name="socket_summary",
                description="Socket mapping",
                status="PARTIAL",
                reason="Process mapping restricted",
            ),
            "neighbor_table": CapabilityEntry(
                name="neighbor_table",
                description="ARP table",
                status="AVAILABLE",
            ),
        },
    )

    quick_scope = {"system", "capabilities", "interfaces", "routing"}
    obs = engine.analyze(rep, collected_sections=quick_scope)
    obs_ids = {o.id for o in obs}

    # Must NOT report empty neighbors or unknown socket processes
    assert "NETWORK.NEIGHBOR.EMPTY" not in obs_ids
    assert "HOST.SOCKET.PROCESS_UNKNOWN" not in obs_ids

    # Must NOT report DATA.COLLECTION.PARTIAL for socket_summary because sockets was unrequested
    partial_entities = [ent for o in obs if o.id == "DATA.COLLECTION.PARTIAL" for ent in o.related_entities]
    assert "socket_summary" not in partial_entities


def test_scope_explicit_neighbor_collection_allows_empty_observation():
    """Verify that when neighbors subsystem is explicitly in scope, empty table is reported."""
    engine = ObservationEngine()
    rep = create_minimal_report(
        neighbors=[],
        capabilities={
            "neighbor_table": CapabilityEntry(
                name="neighbor_table",
                description="ARP table",
                status="AVAILABLE",
            ),
        },
    )

    scope_with_neighbors = {"system", "capabilities", "interfaces", "routing", "neighbors"}
    obs = engine.analyze(rep, collected_sections=scope_with_neighbors)
    obs_ids = {o.id for o in obs}

    assert "NETWORK.NEIGHBOR.EMPTY" in obs_ids


def test_scope_explicit_socket_collection_allows_socket_observations():
    """Verify that when sockets subsystem is in scope, socket observations are produced."""
    engine = ObservationEngine()
    rep = create_minimal_report(
        sockets=[
            SocketEntry(protocol="TCP", local_address="0.0.0.0", local_port=80, state="LISTEN", pid=None, process_name=None),
        ],
        capabilities={
            "socket_summary": CapabilityEntry(
                name="socket_summary",
                description="Socket mapping",
                status="PARTIAL",
                reason="Process mapping restricted",
            ),
        },
    )

    scope_with_sockets = {"system", "capabilities", "interfaces", "routing", "sockets"}
    obs = engine.analyze(rep, collected_sections=scope_with_sockets)
    obs_ids = {o.id for o in obs}

    assert "HOST.SOCKET.LISTENING" in obs_ids
    assert "HOST.SOCKET.PROCESS_UNKNOWN" in obs_ids

    # socket_summary PARTIAL is reported because sockets was in scope
    partial_entities = [ent for o in obs if o.id == "DATA.COLLECTION.PARTIAL" for ent in o.related_entities]
    assert "socket_summary" in partial_entities


def test_scope_gateway_consistency_requires_neighbor_scope():
    """Verify NETWORK.GATEWAY.NEIGHBOR_MISSING is suppressed if neighbors was uncollected."""
    engine = ObservationEngine()
    rep = create_minimal_report(
        routing=RoutingInfo(
            default_ipv4=RouteEntry(destination="0.0.0.0/0", gateway="192.168.1.1", interface="eth0", ip_version=4),
        ),
        neighbors=[
            NeighborEntry(ip_address="192.168.1.50", mac_address="00:11:22:33:44:55", interface="eth0", state="REACHABLE"),
        ],
        capabilities={
            "neighbor_table": CapabilityEntry(name="neighbor_table", description="ARP", status="AVAILABLE"),
        },
    )

    # 1. Without neighbors in scope -> Suppressed
    scope_no_neighbors = {"system", "capabilities", "interfaces", "routing"}
    obs1 = engine.analyze(rep, collected_sections=scope_no_neighbors)
    obs_ids1 = {o.id for o in obs1}
    assert "NETWORK.GATEWAY.NEIGHBOR_MISSING" not in obs_ids1

    # 2. With neighbors in scope -> Reported
    scope_with_neighbors = {"system", "capabilities", "interfaces", "routing", "neighbors"}
    obs2 = engine.analyze(rep, collected_sections=scope_with_neighbors)
    obs_ids2 = {o.id for o in obs2}
    assert "NETWORK.GATEWAY.NEIGHBOR_MISSING" in obs_ids2


def test_scope_failed_collection_does_not_emit_empty_observation():
    """Verify that a collection error is reported as DATA.COLLECTION.ERROR, not NETWORK.NEIGHBOR.EMPTY."""
    engine = ObservationEngine()
    rep = create_minimal_report(
        neighbors=[],
        collection_errors={"neighbors": "Command ip neigh failed with exit code 1"},
        capabilities={
            "neighbor_table": CapabilityEntry(name="neighbor_table", description="ARP", status="AVAILABLE"),
        },
    )

    scope = {"system", "capabilities", "interfaces", "routing", "neighbors"}
    obs = engine.analyze(rep, collected_sections=scope)
    obs_ids = {o.id for o in obs}

    assert "NETWORK.NEIGHBOR.EMPTY" not in obs_ids
    assert "DATA.COLLECTION.ERROR" in obs_ids


def test_observation_context_dataclass_input():
    """Verify ObservationContext dataclass works seamlessly as input to engine.analyze()."""
    from core.observations import ObservationContext

    engine = ObservationEngine()
    rep = create_minimal_report(
        neighbors=[],
        capabilities={
            "neighbor_table": CapabilityEntry(name="neighbor_table", description="ARP", status="AVAILABLE"),
        },
    )

    ctx = ObservationContext(
        collected_sections=frozenset({"system", "capabilities", "interfaces", "routing"}),
        policy_disabled_sections=frozenset(),
    )
    obs = engine.analyze(rep, collected_sections=ctx)
    obs_ids = {o.id for o in obs}

    assert "NETWORK.NEIGHBOR.EMPTY" not in obs_ids

