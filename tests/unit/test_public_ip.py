"""Unit tests for Phase 5 Public Internet Identity & ASN Intelligence."""

from __future__ import annotations

import json
import socket
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from core.collector import CollectorCoordinator
from core.models import InterfaceInfo, NetworkInfo, PublicIpInfo, SystemInfo
from core.public_ip import (
    BasePublicIpProvider,
    ICanHazIpProvider,
    IPApiProvider,
    IPWhoisProvider,
    IpifyProvider,
    ProviderCapability,
    ProviderResult,
    PublicIdentityCollector,
    detect_cgnat,
    is_valid_public_ip,
    lookup_system_ptr,
    normalize_asn,
)
from core.registry import CollectorOptions


# ==============================================================================
# 1. Validation & ASN Normalization Tests
# ==============================================================================

def test_is_valid_public_ip():
    """Verify strict validation accepts public/global IPs and rejects private/reserved/malformed IPs."""
    # Valid globally routable addresses
    assert is_valid_public_ip("8.8.8.8") is True
    assert is_valid_public_ip("1.1.1.1") is True
    assert is_valid_public_ip("203.0.113.1") is False  # 203.0.113.0/24 is TEST-NET-3 (reserved)
    assert is_valid_public_ip("198.51.100.1") is False  # TEST-NET-2 (reserved)
    assert is_valid_public_ip("104.26.10.228") is True
    assert is_valid_public_ip("2606:4700:4700::1111") is True

    # Private addresses
    assert is_valid_public_ip("192.168.1.1") is False
    assert is_valid_public_ip("10.0.0.1") is False
    assert is_valid_public_ip("172.16.0.1") is False
    assert is_valid_public_ip("fc00::1") is False

    # Loopback
    assert is_valid_public_ip("127.0.0.1") is False
    assert is_valid_public_ip("::1") is False

    # Link-local
    assert is_valid_public_ip("169.254.1.1") is False
    assert is_valid_public_ip("fe80::1") is False

    # Multicast
    assert is_valid_public_ip("224.0.0.1") is False
    assert is_valid_public_ip("ff02::1") is False

    # Unspecified
    assert is_valid_public_ip("0.0.0.0") is False
    assert is_valid_public_ip("::") is False

    # RFC 6598 Carrier-Grade NAT (Shared Address Space)
    assert is_valid_public_ip("100.64.0.1") is False
    assert is_valid_public_ip("100.127.255.254") is False

    # Malformed / empty / non-string
    assert is_valid_public_ip("") is False
    assert is_valid_public_ip(None) is False
    assert is_valid_public_ip("not_an_ip") is False
    assert is_valid_public_ip("999.999.999.999") is False


def test_normalize_asn():
    """Verify ASN normalization to standard 'AS<number>' format."""
    assert normalize_asn(13335) == "AS13335"
    assert normalize_asn("13335") == "AS13335"
    assert normalize_asn("AS13335") == "AS13335"
    assert normalize_asn("as13335") == "AS13335"
    assert normalize_asn("AS 15169") == "AS15169"
    assert normalize_asn(None) is None
    assert normalize_asn("") is None
    assert normalize_asn("invalid") is None


# ==============================================================================
# 2. Provider Unit Tests (Mocked Network)
# ==============================================================================

@patch("core.public_ip.providers._fetch_url")
def test_provider_ipapi_success(mock_fetch):
    """Verify IPApiProvider parses IP, ASN, Org, and Geolocation accurately."""
    mock_payload = {
        "ip": "104.26.10.228",
        "version": "IPv4",
        "city": "San Francisco",
        "region": "California",
        "country_name": "United States",
        "asn": "AS13335",
        "org": "Cloudflare, Inc.",
    }
    mock_fetch.return_value = (200, json.dumps(mock_payload).encode("utf-8"))

    provider = IPApiProvider()
    res = provider.lookup_identity()

    assert res.ip == "104.26.10.228"
    assert res.ip_version == 4
    assert res.ipv4 == "104.26.10.228"
    assert res.asn == "AS13335"
    assert res.as_org == "Cloudflare, Inc."
    assert res.country == "United States"
    assert res.region == "California"
    assert res.city == "San Francisco"
    assert res.isp is None  # ipapi does not provide independent ISP
    assert res.sources["ip"] == "ipapi"
    assert res.sources["asn"] == "ipapi"
    assert res.sources["as_org"] == "ipapi"


@patch("core.public_ip.providers._fetch_url")
def test_provider_ipwhois_success(mock_fetch):
    """Verify IPWhoisProvider preserves distinct as_org and isp."""
    mock_payload = {
        "ip": "1.1.1.1",
        "success": True,
        "type": "IPv4",
        "country": "Australia",
        "region": "Queensland",
        "city": "Brisbane",
        "asn": "AS13335",
        "org": "APNIC and Cloudflare DNS Resolver Project",
        "isp": "Cloudflare, Inc.",
    }
    mock_fetch.return_value = (200, json.dumps(mock_payload).encode("utf-8"))

    provider = IPWhoisProvider()
    res = provider.lookup_identity()

    assert res.ip == "1.1.1.1"
    assert res.asn == "AS13335"
    assert res.as_org == "APNIC and Cloudflare DNS Resolver Project"
    assert res.isp == "Cloudflare, Inc."
    assert res.as_org != res.isp  # Strict separation
    assert res.sources["isp"] == "ipwhois"


@patch("core.public_ip.providers._fetch_url")
def test_provider_partial_success(mock_fetch):
    """Verify provider with partial data does not fail or discard valid fields."""
    mock_payload = {
        "ip": "8.8.8.8",
        "version": "IPv4",
        "country_name": "United States",
        # asn, org, city, region missing
    }
    mock_fetch.return_value = (200, json.dumps(mock_payload).encode("utf-8"))

    provider = IPApiProvider()
    res = provider.lookup_identity()

    assert res.ip == "8.8.8.8"
    assert res.country == "United States"
    assert res.asn is None
    assert res.as_org is None
    assert res.has_ip() is True


@patch("core.public_ip.providers._fetch_url")
def test_provider_http_errors_and_malformed_json(mock_fetch):
    """Verify provider gracefully handles HTTP 429, 500, and malformed HTML responses."""
    # HTTP Error 429
    mock_fetch.side_effect = urllib.error.HTTPError("https://ipapi.co/json/", 429, "Too Many Requests", {}, None)
    provider = IPApiProvider()
    res = provider.lookup_identity()
    assert res.has_ip() is False
    assert len(res.errors) > 0

    # Malformed HTML error page
    mock_fetch.side_effect = None
    mock_fetch.return_value = (200, b"<html><head><title>502 Bad Gateway</title></head></html>")
    res2 = provider.lookup_identity()
    assert res2.has_ip() is False
    assert any("error" in e.lower() or "json" in e.lower() for e in res2.errors)


@patch("core.public_ip.providers._fetch_url")
def test_reject_private_ip_in_metadata_query(mock_fetch):
    """Verify metadata lookups reject private IPs without initiating network requests."""
    provider = IPApiProvider()
    res = provider.lookup_identity(requested_ip="192.168.1.100")
    assert res.has_ip() is False
    assert mock_fetch.call_count == 0
    assert any("Invalid public IP" in e for e in res.errors)


# ==============================================================================
# 3. Collector Fallback & Dual-Stack Tests
# ==============================================================================

def test_collector_sequential_fallback():
    """Verify collector fails over sequentially from Provider 1 to Provider 2."""
    p1 = MagicMock(spec=BasePublicIpProvider)
    p1.name = "failing_provider"
    p1.enabled = True
    p1.capabilities = {ProviderCapability.PUBLIC_IP}
    p1.has_capability.side_effect = lambda cap: cap in p1.capabilities
    # Provider 1 returns empty result with error
    p1.lookup_identity.return_value = ProviderResult(errors=["Timeout contacting failing_provider"])

    p2 = MagicMock(spec=BasePublicIpProvider)
    p2.name = "fallback_provider"
    p2.enabled = True
    p2.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.ASN}
    p2.has_capability.side_effect = lambda cap: cap in p2.capabilities
    p2.lookup_identity.return_value = ProviderResult(
        ip="1.1.1.1",
        ip_version=4,
        asn="AS13335",
        as_org="Cloudflare, Inc.",
        sources={"ip": "fallback_provider", "asn": "fallback_provider", "as_org": "fallback_provider"},
    )

    collector = PublicIdentityCollector(providers=[p1, p2])
    info = collector.collect()

    assert p1.lookup_identity.called
    assert p2.lookup_identity.called
    assert info.available is True
    assert info.ip == "1.1.1.1"
    assert info.sources["ip"] == "fallback_provider"
    assert info.asn == "AS13335"


def test_collector_dual_stack_independent_discovery():
    """Verify independent discovery of IPv4 and IPv6 addresses."""
    p1 = MagicMock(spec=BasePublicIpProvider)
    p1.name = "p1"
    p1.enabled = True
    p1.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.IPV4, ProviderCapability.IPV6}
    p1.has_capability.side_effect = lambda cap: cap in p1.capabilities
    # Primary returns IPv4
    p1.lookup_identity.return_value = ProviderResult(
        ip="8.8.8.8",
        ip_version=4,
        ipv4="8.8.8.8",
        sources={"ip": "p1", "ipv4": "p1"},
    )
    # Secondary IPv6 lookup returns valid IPv6
    p1.lookup_ip.return_value = "2001:4860:4860::8888"

    collector = PublicIdentityCollector(providers=[p1])
    info = collector.collect()

    assert info.available is True
    assert info.ip == "8.8.8.8"
    assert info.ipv4 == "8.8.8.8"
    assert info.ipv6 == "2001:4860:4860::8888"
    assert info.public_ipv4 == "8.8.8.8"
    assert info.public_ipv6 == "2001:4860:4860::8888"
    assert info.sources["ipv6"] == "p1"


def test_collector_ipv6_unavailable_is_normal():
    """Verify that when IPv6 is unavailable, ipv6 remains cleanly None without error."""
    p1 = MagicMock(spec=BasePublicIpProvider)
    p1.name = "p1"
    p1.enabled = True
    p1.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.IPV4, ProviderCapability.IPV6}
    p1.has_capability.side_effect = lambda cap: cap in p1.capabilities
    p1.lookup_identity.return_value = ProviderResult(
        ip="8.8.8.8",
        ip_version=4,
        ipv4="8.8.8.8",
        sources={"ip": "p1", "ipv4": "p1"},
    )
    # IPv6 lookup returns None (normal condition)
    p1.lookup_ip.return_value = None

    collector = PublicIdentityCollector(providers=[p1])
    info = collector.collect()

    assert info.available is True
    assert info.ipv4 == "8.8.8.8"
    assert info.ipv6 is None
    assert info.public_ipv6 is None


# ==============================================================================
# 4. Reverse DNS (System-Resolver PTR) & Timeout Scoping Tests
# ==============================================================================

@patch("socket.gethostbyaddr")
def test_system_ptr_lookup_success(mock_gethostbyaddr):
    """Verify system-resolver PTR lookup returns hostname."""
    mock_gethostbyaddr.return_value = ("one.one.one.one", [], ["1.1.1.1"])
    hostname = lookup_system_ptr("1.1.1.1")
    assert hostname == "one.one.one.one"


@patch("socket.gethostbyaddr")
def test_system_ptr_lookup_failure_handled_cleanly(mock_gethostbyaddr):
    """Verify PTR failure (NXDOMAIN / timeout) returns None without raising."""
    mock_gethostbyaddr.side_effect = socket.herror(1, "Unknown host")
    hostname = lookup_system_ptr("1.1.1.1")
    assert hostname is None


def test_socket_timeout_safely_restored():
    """Verify that lookup_system_ptr does not leave socket default timeout permanently modified."""
    original_timeout = 12.34
    socket.setdefaulttimeout(original_timeout)
    try:
        lookup_system_ptr("8.8.8.8", timeout_seconds=1.0)
        assert socket.getdefaulttimeout() == original_timeout
    finally:
        socket.setdefaulttimeout(None)


# ==============================================================================
# 5. CGNAT Detection Tests
# ==============================================================================

def test_cgnat_detection_active_interface():
    """Verify detection of RFC 6598 Shared Address Space (100.64.0.0/10) on active interface."""
    # CGNAT address
    cgnat_iface = InterfaceInfo(
        name="eth0",
        state="UP",
        networks=[NetworkInfo(interface="eth0", address="100.64.1.5", ip_version=4)],
    )
    detected, addr, iface_name, details = detect_cgnat(cgnat_iface)
    assert detected is True
    assert addr == "100.64.1.5"
    assert iface_name == "eth0"
    assert "RFC 6598 Shared Address Space" in details

    # Standard private RFC 1918 address
    private_iface = InterfaceInfo(
        name="eth0",
        state="UP",
        networks=[NetworkInfo(interface="eth0", address="192.168.1.5", ip_version=4)],
    )
    detected2, addr2, iface_name2, _ = detect_cgnat(private_iface)
    assert detected2 is False
    assert addr2 is None

    # None interface
    detected3, _, _, _ = detect_cgnat(None)
    assert detected3 is False


# ==============================================================================
# 6. Privacy & Isolation Tests (--no-internet and Privacy Audit)
# ==============================================================================

@patch("urllib.request.urlopen")
@patch("socket.gethostbyaddr")
def test_no_internet_hard_isolation(mock_ptr, mock_urlopen):
    """Verify --no-internet executes zero HTTP requests and zero PTR lookups."""
    collector = PublicIdentityCollector()
    info = collector.collect(no_internet=True)

    assert mock_urlopen.call_count == 0
    assert mock_ptr.call_count == 0
    assert info.available is False
    assert info.status == "DISABLED"
    assert info.reason == "--no-internet flag specified"


@patch("core.public_ip.providers._fetch_url")
def test_privacy_audit_no_local_info_transmitted(mock_fetch):
    """Verify that requests made to providers never contain local IPs, MACs, or hostnames."""
    mock_payload = {"ip": "1.1.1.1", "version": "IPv4"}
    mock_fetch.return_value = (200, json.dumps(mock_payload).encode("utf-8"))

    local_ip = "192.168.1.50"
    local_mac = "00:11:22:33:44:55"
    local_hostname = "my-secret-laptop"

    provider = IPApiProvider()
    provider.lookup_identity()

    assert mock_fetch.called
    called_url = mock_fetch.call_args[0][0]
    assert local_ip not in called_url
    assert local_mac not in called_url
    assert local_hostname not in called_url


# ==============================================================================
# 7. Quick Mode & Scope Integration Tests
# ==============================================================================

def test_quick_mode_excludes_public_ip():
    """Verify that running CollectorCoordinator with quick_mode=True skips public IP collection."""
    mock_backend = MagicMock()
    mock_backend.get_platform_info.return_value = SystemInfo(
        os_name="MockOS",
        os_version="1.0",
        platform_release="1.0",
        hostname="mockhost",
        architecture="x86_64",
        python_version="3.12.0",
        is_privileged=False,
    )
    mock_backend.detect_capabilities.return_value = {
        "public_ip": MagicMock(is_implemented=lambda: True),
        "interface_info": MagicMock(is_implemented=lambda: True),
        "routing_info": MagicMock(is_implemented=lambda: True),
    }
    mock_backend.get_interfaces.return_value = []
    mock_backend.get_default_interface.return_value = None
    mock_backend.get_routes.return_value = None

    options = CollectorOptions(quick_mode=True)
    coordinator = CollectorCoordinator(backend=mock_backend, options=options)
    report = coordinator.collect()

    assert report.public_ip is None
    mock_backend.get_public_ip.assert_not_called()


def test_public_ip_offline_status():
    """Verify that when all external providers fail, status is OFFLINE."""
    p1 = MagicMock(spec=BasePublicIpProvider)
    p1.name = "p1"
    p1.enabled = True
    p1.capabilities = {ProviderCapability.PUBLIC_IP}
    p1.has_capability.side_effect = lambda cap: cap in p1.capabilities
    p1.lookup_identity.return_value = ProviderResult(errors=["Connection refused"])

    collector = PublicIdentityCollector(providers=[p1])
    info = collector.collect()

    assert info.available is False
    assert info.status == "OFFLINE"
    assert "offline" in info.reason.lower() or "blocked" in info.reason.lower()


def test_public_ip_model_serialization_and_metadata_binding():
    """Verify PublicIpInfo serialization and metadata binding to primary IP."""
    info = PublicIpInfo(
        available=True,
        ip="1.1.1.1",
        ip_version=4,
        asn="AS13335",
        as_org="Cloudflare, Inc.",
        isp="Cloudflare, Inc.",
        country="United States",
        region="California",
        city="San Francisco",
        reverse_dns="one.one.one.one",
        sources={
            "ip": "ipapi",
            "asn": "ipapi",
            "as_org": "ipapi",
            "isp": "ipwhois",
            "reverse_dns": "system_resolver",
        },
    )

    d = info.to_dict()
    assert d["available"] is True
    assert d["ip"] == "1.1.1.1"
    assert d["public_ipv4"] == "1.1.1.1"
    assert d["public_ipv6"] is None
    assert d["primary_source"] == "ipapi"
    assert d["asn"] == "AS13335"
    assert d["sources"]["reverse_dns"] == "system_resolver"
    assert d["geolocation_accuracy"] == "APPROXIMATE"
    assert "physical location" in d["disclaimer"]


# ==============================================================================
# 8. Phase 5.1 Fidelity Regression Tests
# ==============================================================================

@patch("core.public_ip.providers._fetch_url")
def test_custom_metadata_url_template(mock_fetch):
    """Verify custom metadata URL template from configuration is honored."""
    mock_payload = {
        "ip": "104.26.10.228",
        "asn": "AS13335",
        "org": "Cloudflare",
    }
    mock_fetch.return_value = (200, json.dumps(mock_payload).encode("utf-8"))

    provider = IPApiProvider(
        metadata_url_template="https://custom-proxy.enterprise.corp/lookup/{ip}/v2"
    )
    res = provider.lookup_identity(requested_ip="104.26.10.228")

    assert mock_fetch.called
    called_url = mock_fetch.call_args[0][0]
    assert called_url == "https://custom-proxy.enterprise.corp/lookup/104.26.10.228/v2"
    assert res.asn == "AS13335"


def test_provider_family_capability_behavior():
    """Verify that only providers with dedicated family endpoints advertise family capabilities."""
    # Generic identity providers do not advertise IPV4 or IPV6 capabilities
    ipapi = IPApiProvider()
    assert ProviderCapability.IPV4 not in ipapi.capabilities
    assert ProviderCapability.IPV6 not in ipapi.capabilities
    assert ipapi.lookup_ip(4) is None
    assert ipapi.lookup_ip(6) is None

    ipwhois = IPWhoisProvider()
    assert ProviderCapability.IPV4 not in ipwhois.capabilities
    assert ProviderCapability.IPV6 not in ipwhois.capabilities
    assert ipwhois.lookup_ip(4) is None
    assert ipwhois.lookup_ip(6) is None

    # Family-specific discovery providers advertise IPV4 and IPV6
    ipify = IpifyProvider()
    assert ProviderCapability.IPV4 in ipify.capabilities
    assert ProviderCapability.IPV6 in ipify.capabilities

    icanhazip = ICanHazIpProvider()
    assert ProviderCapability.IPV4 in icanhazip.capabilities
    assert ProviderCapability.IPV6 in icanhazip.capabilities


def test_metadata_fallback_error_recording():
    """Verify metadata fallback errors are recorded in collector reason when partial success occurs."""
    p1 = MagicMock(spec=BasePublicIpProvider)
    p1.name = "ipify"
    p1.enabled = True
    p1.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.IPV4}
    p1.has_capability.side_effect = lambda cap: cap in p1.capabilities
    p1.lookup_identity.return_value = ProviderResult(ip="1.1.1.1", ip_version=4, sources={"ip": "ipify"})

    p_meta = MagicMock(spec=BasePublicIpProvider)
    p_meta.name = "failing_metadata"
    p_meta.enabled = True
    p_meta.capabilities = {ProviderCapability.ASN, ProviderCapability.GEOLOCATION}
    p_meta.has_capability.side_effect = lambda cap: cap in p_meta.capabilities
    p_meta.lookup_identity.side_effect = RuntimeError("HTTP 429 Rate Limit Exceeded")

    collector = PublicIdentityCollector(providers=[p1, p_meta])
    info = collector.collect()

    assert info.available is True
    assert info.status == "PARTIAL"
    assert info.ip == "1.1.1.1"
    assert "failing_metadata metadata lookup failed" in info.reason
    assert "HTTP 429" in info.reason


def test_top_level_source_and_primary_source():
    """Verify top-level source identifies primary observed IP provider and primary_source property matches."""
    info = PublicIpInfo(
        available=True,
        ip="8.8.8.8",
        ip_version=4,
        sources={"ip": "ipify", "asn": "ipapi", "isp": "ipwhois"},
    )
    assert info.source == "ipify"
    assert info.primary_source == "ipify"


def test_clean_user_agent():
    """Verify User-Agent header does not contain placeholder repository URL."""
    from core.public_ip.providers import USER_AGENT
    assert USER_AGENT == "NetworkIntelligenceToolkit/1.0"
    assert "github" not in USER_AGENT.lower()


@patch("urllib.request.urlopen")
def test_comprehensive_privacy_audit(mock_urlopen):
    """Verify no local network data appears in request URL or headers for generic or targeted requests."""
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b'{"ip": "104.26.10.228", "asn": "AS13335"}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    local_artifacts = [
        "192.168.1.100",           # local IPv4
        "fe80::1ff:fe00:3a60",      # local link-local IPv6
        "fd00::dead:beef",          # ULA IPv6
        "00:1A:2B:3C:4D:5E",        # MAC address
        "Corporate-Guest-WiFi",     # SSID
        "aa:bb:cc:dd:ee:ff",        # BSSID
        "192.168.1.1",              # Gateway
        "192.168.1.254",            # DNS Server
        "secret-corp-workstation",  # Hostname
        "10.0.0.0/8",               # Routing Info
    ]

    provider = IPApiProvider()

    # 1. Generic identity query
    provider.lookup_identity()
    assert mock_urlopen.called
    req1 = mock_urlopen.call_args[0][0]
    for artifact in local_artifacts:
        assert artifact not in req1.full_url
        for h_val in req1.headers.values():
            assert artifact not in str(h_val)

    # 2. Targeted metadata query
    provider.lookup_identity(requested_ip="104.26.10.228")
    req2 = mock_urlopen.call_args[0][0]
    for artifact in local_artifacts:
        assert artifact not in req2.full_url
        for h_val in req2.headers.values():
            assert artifact not in str(h_val)

    # Confirm only the validated public IP appears in targeted URL
    assert "104.26.10.228" in req2.full_url


# ==============================================================================
# 9. Phase 5.1 Final Fidelity Regression Tests
# ==============================================================================

def test_metadata_fallback_triggers_when_only_ipv4_or_ipv6_set():
    """Verify that when a provider returns only ipv4 or ipv6 without generic ip,
    it is normalized before metadata fallback, triggering metadata discovery
    and preserving field provenance.
    """
    # 1. Primary provider returning only ipv4
    p_v4 = MagicMock(spec=BasePublicIpProvider)
    p_v4.name = "ipv4_only_provider"
    p_v4.enabled = True
    p_v4.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.IPV4}
    p_v4.has_capability.side_effect = lambda cap: cap in p_v4.capabilities
    p_v4.lookup_identity.return_value = ProviderResult(
        ipv4="8.8.8.8",
        ip_version=4,
        sources={"ipv4": "ipv4_only_provider"},
    )

    # Metadata provider
    p_meta = MagicMock(spec=BasePublicIpProvider)
    p_meta.name = "meta_provider"
    p_meta.enabled = True
    p_meta.capabilities = {ProviderCapability.ASN, ProviderCapability.AS_ORG, ProviderCapability.GEOLOCATION}
    p_meta.has_capability.side_effect = lambda cap: cap in p_meta.capabilities
    p_meta.lookup_identity.return_value = ProviderResult(
        asn="AS15169",
        as_org="Google LLC",
        country="United States",
        city="Mountain View",
        sources={"asn": "meta_provider", "as_org": "meta_provider", "country": "meta_provider", "city": "meta_provider"},
    )

    collector = PublicIdentityCollector(providers=[p_v4, p_meta])
    info = collector.collect()

    assert info.available is True
    assert info.status == "AVAILABLE"
    assert info.ip == "8.8.8.8"
    assert info.ip_version == 4
    assert info.ipv4 == "8.8.8.8"
    assert info.asn == "AS15169"
    assert info.as_org == "Google LLC"
    assert info.country == "United States"
    assert info.city == "Mountain View"
    assert info.source == "ipv4_only_provider"
    assert info.primary_source == "ipv4_only_provider"
    assert info.sources["ip"] == "ipv4_only_provider"
    assert info.sources["asn"] == "meta_provider"
    p_meta.lookup_identity.assert_called_once_with(requested_ip="8.8.8.8")


def test_metadata_fallback_triggers_when_only_ipv6_set():
    """Verify that when a provider returns only ipv6 without generic ip,
    it is normalized before metadata fallback, triggering metadata discovery.
    """
    p_v6 = MagicMock(spec=BasePublicIpProvider)
    p_v6.name = "ipv6_only_provider"
    p_v6.enabled = True
    p_v6.capabilities = {ProviderCapability.PUBLIC_IP, ProviderCapability.IPV6}
    p_v6.has_capability.side_effect = lambda cap: cap in p_v6.capabilities
    p_v6.lookup_identity.return_value = ProviderResult(
        ipv6="2606:4700:4700::1111",
        ip_version=6,
        sources={"ipv6": "ipv6_only_provider"},
    )

    p_meta = MagicMock(spec=BasePublicIpProvider)
    p_meta.name = "meta_provider"
    p_meta.enabled = True
    p_meta.capabilities = {ProviderCapability.ASN, ProviderCapability.AS_ORG, ProviderCapability.GEOLOCATION}
    p_meta.has_capability.side_effect = lambda cap: cap in p_meta.capabilities
    p_meta.lookup_identity.return_value = ProviderResult(
        asn="AS13335",
        as_org="Cloudflare, Inc.",
        country="United States",
        sources={"asn": "meta_provider", "as_org": "meta_provider", "country": "meta_provider"},
    )

    collector = PublicIdentityCollector(providers=[p_v6, p_meta])
    info = collector.collect()

    assert info.available is True
    assert info.ip == "2606:4700:4700::1111"
    assert info.ip_version == 6
    assert info.ipv6 == "2606:4700:4700::1111"
    assert info.asn == "AS13335"
    assert info.sources["ip"] == "ipv6_only_provider"
    p_meta.lookup_identity.assert_called_once_with(requested_ip="2606:4700:4700::1111")


@patch("core.public_ip.providers._fetch_url")
def test_invalid_provider_response_records_error_and_classifies_status_error(mock_fetch):
    """Verify that when providers return unusable or non-public IPs (e.g. 192.168.1.1),
    a structured error is recorded and the collector classifies the result as ERROR (not OFFLINE).
    """
    # 1. IPApiProvider returns RFC 1918 private IP
    mock_fetch.return_value = (200, b'{"ip": "192.168.1.1", "version": "IPv4"}')
    ipapi = IPApiProvider()
    res = ipapi.lookup_identity()
    assert res.ip is None
    assert res.ipv4 is None
    assert any("unusable or non-public IP address" in err for err in res.errors)

    # 2. Collector with this provider classifies as ERROR
    collector = PublicIdentityCollector(providers=[ipapi])
    info = collector.collect()
    assert info.available is False
    assert info.status == "ERROR"
    assert "invalid or unusable data" in info.reason.lower()

    # 3. ICanHazIpProvider returns malformed string
    mock_fetch.return_value = (200, b'invalid_ip_string_here\\n')
    icanhaz = ICanHazIpProvider()
    res2 = icanhaz.lookup_identity()
    assert res2.ip is None
    assert any("unusable or non-public IP address" in err for err in res2.errors)

    collector2 = PublicIdentityCollector(providers=[icanhaz])
    info2 = collector2.collect()
    assert info2.available is False
    assert info2.status == "ERROR"
    assert "invalid or unusable data" in info2.reason.lower()


def test_public_ip_timeout_single_source_of_truth():
    """Verify config/config.yaml enforces public_ip.timeout_seconds as single source of truth."""
    from pathlib import Path
    import yaml

    config_path = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"
    assert config_path.is_file()

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    # 1. Top-level timeouts section must NOT contain public_ip_seconds
    timeouts_section = cfg.get("timeouts", {})
    assert "public_ip_seconds" not in timeouts_section, "timeouts.public_ip_seconds must be removed in favor of public_ip.timeout_seconds"

    # 2. public_ip section must specify timeout_seconds
    public_ip_section = cfg.get("public_ip", {})
    assert "timeout_seconds" in public_ip_section
    assert public_ip_section["timeout_seconds"] == 3.0

    # 3. PublicIdentityCollector loads this timeout
    collector = PublicIdentityCollector()
    assert len(collector.providers) > 0
    for prov in collector.providers:
        assert prov.timeout_seconds == 3.0

