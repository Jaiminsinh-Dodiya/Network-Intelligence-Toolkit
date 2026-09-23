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
