"""Unit tests for subnet mathematics and IP normalization engine."""

import pytest
from core.network import (
    calculate_ipv4_network,
    calculate_ipv6_network,
    calculate_network_info,
    classify_address_scope,
    normalize_ip_string,
)
import ipaddress


class TestIPv4SubnetMath:
    def test_standard_class_c(self):
        net = calculate_ipv4_network("192.168.1.10/24")
        assert net.network == "192.168.1.0/24"
        assert net.netmask == "255.255.255.0"
        assert net.broadcast == "192.168.1.255"
        assert net.first_host == "192.168.1.1"
        assert net.last_host == "192.168.1.254"
        assert net.total_addresses == 256
        assert net.usable_host_count == 254
        assert net.prefix_length == 24
        assert net.scope == "PRIVATE"

    def test_separate_ip_and_netmask(self):
        net = calculate_ipv4_network("192.168.1.20", "255.255.255.0")
        assert net.network == "192.168.1.0/24"
        assert net.netmask == "255.255.255.0"
        assert net.broadcast == "192.168.1.255"
        assert net.usable_host_count == 254

    def test_large_class_a(self):
        net = calculate_ipv4_network("10.0.0.1/8")
        assert net.network == "10.0.0.0/8"
        assert net.netmask == "255.0.0.0"
        assert net.broadcast == "10.255.255.255"
        assert net.first_host == "10.0.0.1"
        assert net.last_host == "10.255.255.254"
        assert net.total_addresses == 16777216
        assert net.usable_host_count == 16777214
        assert net.scope == "PRIVATE"

    def test_class_b_slash_16(self):
        net = calculate_ipv4_network("172.16.50.20/16")
        assert net.network == "172.16.0.0/16"
        assert net.netmask == "255.255.0.0"
        assert net.broadcast == "172.16.255.255"
        assert net.first_host == "172.16.0.1"
        assert net.last_host == "172.16.255.254"
        assert net.total_addresses == 65536
        assert net.usable_host_count == 65534

    def test_small_subnet_slash_30(self):
        net = calculate_ipv4_network("192.168.1.1/30")
        assert net.network == "192.168.1.0/30"
        assert net.netmask == "255.255.255.252"
        assert net.broadcast == "192.168.1.3"
        assert net.first_host == "192.168.1.1"
        assert net.last_host == "192.168.1.2"
        assert net.total_addresses == 4
        assert net.usable_host_count == 2

    def test_point_to_point_slash_31(self):
        # RFC 3021: Both endpoints are usable host addresses, no broadcast address
        net = calculate_ipv4_network("192.168.1.1/31")
        assert net.network == "192.168.1.0/31"
        assert net.netmask == "255.255.255.254"
        assert net.broadcast is None
        assert net.first_host == "192.168.1.0"
        assert net.last_host == "192.168.1.1"
        assert net.total_addresses == 2
        assert net.usable_host_count == 2

    def test_host_route_slash_32(self):
        net = calculate_ipv4_network("192.168.1.1/32")
        assert net.network == "192.168.1.1/32"
        assert net.netmask == "255.255.255.255"
        assert net.broadcast is None
        assert net.first_host == "192.168.1.1"
        assert net.last_host == "192.168.1.1"
        assert net.total_addresses == 1
        assert net.usable_host_count == 1


class TestIPv6NetworkMath:
    def test_standard_slash_64(self):
        net = calculate_ipv6_network("2001:db8::1234/64")
        assert net.network == "2001:db8::/64"
        assert net.broadcast is None  # IPv6 has no broadcast
        assert net.first_host == "2001:db8::"
        assert net.last_host == "2001:db8::ffff:ffff:ffff:ffff"
        assert net.first_address == "2001:db8::"
        assert net.last_address == "2001:db8::ffff:ffff:ffff:ffff"
        assert net.total_addresses == 2**64
        assert net.prefix_length == 64
        assert net.ip_version == 6

    def test_link_local_with_scope_id(self):
        net = calculate_ipv6_network("fe80::1234%eth0/64")
        assert net.network == "fe80::/64"
        assert net.broadcast is None
        assert net.scope == "LINK_LOCAL"

    def test_loopback_slash_128(self):
        net = calculate_ipv6_network("::1/128")
        assert net.network == "::1/128"
        assert net.broadcast is None
        assert net.total_addresses == 1
        assert net.usable_host_count == 1
        assert net.scope == "LOOPBACK"

    def test_point_to_point_slash_127(self):
        # RFC 6164: Point-to-point /127 has 2 addresses
        net = calculate_ipv6_network("2001:db8::1/127")
        assert net.network == "2001:db8::/127"
        assert net.total_addresses == 2
        assert net.usable_host_count == 2
        assert net.broadcast is None

    def test_enterprise_prefix_slash_48(self):
        net = calculate_ipv6_network("2001:db8:acad::1/48")
        assert net.network == "2001:db8:acad::/48"
        assert net.total_addresses == 2**80
        assert net.prefix_length == 48

    def test_isp_delegation_slash_56(self):
        # /56 ISP customer prefix allocation
        net = calculate_ipv6_network("2001:db8:1234:5600::1/56")
        assert net.network == "2001:db8:1234:5600::/56"
        assert net.total_addresses == 2**72
        assert net.prefix_length == 56
        assert net.usable_host_count == 2**72
        assert net.is_prefix_known is True

    def test_missing_prefix_does_not_default_to_64(self):
        # Strict Phase 2 contract: missing prefix must NOT assume /64
        net = calculate_ipv6_network("2001:db8::1")
        assert net.is_prefix_known is False
        assert net.prefix_length is None
        assert net.network is None
        assert net.netmask is None
        assert net.broadcast is None
        assert net.first_host is None
        assert net.last_host is None
        assert net.total_addresses == 0
        assert net.usable_host_count == 0
        assert net.address == "2001:db8::1"
        assert net.cidr == "2001:db8::1"

    def test_calculate_network_info_ipv6_without_prefix(self):
        # Dispatcher must preserve unknown prefix state and correct scope
        net = calculate_network_info("2606:4700:4700::1111")
        assert net is not None
        assert net.is_prefix_known is False
        assert net.prefix_length is None
        assert net.network is None
        assert net.scope == "GLOBAL"


class TestAddressScopeClassification:
    def test_scope_classification(self):
        assert classify_address_scope(ipaddress.ip_address("127.0.0.1")) == "LOOPBACK"
        assert classify_address_scope(ipaddress.ip_address("169.254.10.5")) == "LINK_LOCAL"
        assert classify_address_scope(ipaddress.ip_address("192.168.1.1")) == "PRIVATE"
        assert classify_address_scope(ipaddress.ip_address("10.0.0.1")) == "PRIVATE"
        assert classify_address_scope(ipaddress.ip_address("172.20.0.1")) == "PRIVATE"
        assert classify_address_scope(ipaddress.ip_address("8.8.8.8")) == "GLOBAL"
        assert classify_address_scope(ipaddress.ip_address("224.0.0.1")) == "MULTICAST"
        assert classify_address_scope(ipaddress.ip_address("0.0.0.0")) == "UNSPECIFIED"
        assert classify_address_scope(ipaddress.ip_address("::1")) == "LOOPBACK"
        assert classify_address_scope(ipaddress.ip_address("fe80::1")) == "LINK_LOCAL"
        assert classify_address_scope(ipaddress.ip_address("fc00::1")) == "PRIVATE"
        assert classify_address_scope(ipaddress.ip_address("2001:4860:4860::8888")) == "GLOBAL"


class TestInvalidAndGracefulFailure:
    def test_invalid_ipv4_returns_none(self):
        assert calculate_network_info("999.999.999.999/24") is None
        assert calculate_network_info("192.168.1") is None
        assert calculate_network_info("256.0.0.1/24") is None

    def test_invalid_ipv6_returns_none(self):
        assert calculate_network_info("fe80:::1/64") is None
        assert calculate_network_info("gggg::1/64") is None

    def test_invalid_prefix_returns_none(self):
        assert calculate_network_info("192.168.1.1/35") is None
        assert calculate_network_info("192.168.1.1/-1") is None
        assert calculate_network_info("2001:db8::/130") is None

    def test_empty_or_malformed_returns_none(self):
        assert calculate_network_info("") is None
        assert calculate_network_info("not-an-ip") is None
        assert calculate_network_info(None) is None

    def test_normalize_ip_string(self):
        assert normalize_ip_string("  192.168.1.1  ") == "192.168.1.1"
        assert normalize_ip_string("fe80::1%eth0") == "fe80::1"
        assert normalize_ip_string("fe80::1%12") == "fe80::1"
