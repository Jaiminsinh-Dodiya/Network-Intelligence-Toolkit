"""Public Internet Identity Collector with field-aware fallback and privacy enforcement."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
import socket
from typing import Any

from core.models import InterfaceInfo, PublicIpInfo
from .base import BasePublicIpProvider, ProviderResult
from .capabilities import ProviderCapability
from .providers import ICanHazIpProvider, IPApiProvider, IPWhoisProvider, IpifyProvider
from .validation import is_valid_public_ip

logger = logging.getLogger(__name__)


def lookup_system_ptr(ip_str: str, timeout_seconds: float = 2.0) -> str | None:
    """Perform system-resolver PTR lookup using socket.gethostbyaddr.

    Ensures that socket default timeout is safely scoped and restored in a finally block.
    Failures (NXDOMAIN, timeout, socket error) return None and do not raise exceptions.
    """
    if not is_valid_public_ip(ip_str):
        return None

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        return hostname if hostname else None
    except (socket.herror, socket.gaierror, socket.timeout, OSError) as err:
        logger.debug("System-resolver PTR lookup failed for %s: %s", ip_str, err)
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def detect_cgnat(selected_iface: InterfaceInfo | None) -> tuple[bool, str | None, str | None, str | None]:
    """Inspect the selected active interface for RFC 6598 Shared Address Space (100.64.0.0/10).

    Returns:
        (detected, local_address, interface_name, details)
    """
    if not selected_iface:
        return False, None, None, None

    cgnat_net = ipaddress.ip_network("100.64.0.0/10")
    for net in selected_iface.networks:
        if net.ip_version == 4 and net.address:
            try:
                addr = ipaddress.ip_address(net.address)
                if addr in cgnat_net:
                    return (
                        True,
                        net.address,
                        selected_iface.name,
                        f"Local IPv4 address {net.address} on interface {selected_iface.name} is within RFC 6598 Shared Address Space (100.64.0.0/10)."
                    )
            except ValueError:
                continue

    return False, None, None, None


class PublicIdentityCollector:
    """Coordinates public IP, ASN, ISP, and Geolocation discovery across providers."""

    def __init__(
        self,
        providers: list[BasePublicIpProvider] | None = None,
        config_path: Path | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.providers: list[BasePublicIpProvider] = []

        if providers is not None:
            self.providers = providers
        else:
            self._load_configuration(config_path)

    def _load_configuration(self, config_path: Path | None = None) -> None:
        """Load data-driven provider configuration from config/config.yaml or use defaults."""
        config_data: dict[str, Any] = {}
        if config_path is None:
            # Default to config/config.yaml relative to project root
            config_path = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"

        if config_path.is_file():
            try:
                import yaml
                with open(config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        config_data = loaded.get("public_ip", {})
            except Exception as err:
                logger.debug("Failed to read public_ip config from %s: %s", config_path, err)

        timeout = float(config_data.get("timeout_seconds", self.timeout_seconds))
        providers_conf = config_data.get("providers", {})

        # 1. ipapi
        ipapi_conf = providers_conf.get("ipapi", {})
        if ipapi_conf.get("enabled", True):
            self.providers.append(
                IPApiProvider(
                    name="ipapi",
                    enabled=True,
                    timeout_seconds=timeout,
                    identity_url=ipapi_conf.get("identity_url", "https://ipapi.co/json/"),
                    metadata_url_template=ipapi_conf.get("metadata_url_template", "https://ipapi.co/{ip}/json/"),
                )
            )

        # 2. ipwhois
        ipwhois_conf = providers_conf.get("ipwhois", {})
        if ipwhois_conf.get("enabled", True):
            self.providers.append(
                IPWhoisProvider(
                    name="ipwhois",
                    enabled=True,
                    timeout_seconds=timeout,
                    identity_url=ipwhois_conf.get("identity_url", "https://ipwhois.app/json/"),
                    metadata_url_template=ipwhois_conf.get("metadata_url_template", "https://ipwhois.app/json/{ip}"),
                )
            )

        # 3. ipify
        ipify_conf = providers_conf.get("ipify", {})
        if ipify_conf.get("enabled", True):
            self.providers.append(
                IpifyProvider(
                    name="ipify",
                    enabled=True,
                    timeout_seconds=timeout,
                    ipv4_url=ipify_conf.get("ipv4_url", "https://api.ipify.org?format=json"),
                    ipv6_url=ipify_conf.get("ipv6_url", "https://api6.ipify.org?format=json"),
                    dual_stack_url=ipify_conf.get("dual_stack_url", "https://api64.ipify.org?format=json"),
                )
            )

        # 4. icanhazip
        icanhazip_conf = providers_conf.get("icanhazip", {})
        if icanhazip_conf.get("enabled", True):
            self.providers.append(
                ICanHazIpProvider(
                    name="icanhazip",
                    enabled=True,
                    timeout_seconds=timeout,
                    ipv4_url=icanhazip_conf.get("ipv4_url", "https://4.icanhazip.com"),
                    ipv6_url=icanhazip_conf.get("ipv6_url", "https://6.icanhazip.com"),
                )
            )

    def collect(
        self,
        selected_iface: InterfaceInfo | None = None,
        no_internet: bool = False,
    ) -> PublicIpInfo:
        """Collect public IP, ASN, ISP, PTR, and Geolocation metadata.

        Strict Isolation Boundary:
            If `no_internet` is True, ZERO network and ZERO PTR requests will be executed.
        """
        # 1. Hard Isolation Boundary for --no-internet
        if no_internet:
            cgnat_detected, cgnat_addr, cgnat_iface, cgnat_details = detect_cgnat(selected_iface)
            return PublicIpInfo(
                available=False,
                status="DISABLED",
                reason="--no-internet flag specified",
                cgnat_detected=cgnat_detected,
                cgnat_local_address=cgnat_addr,
                cgnat_interface=cgnat_iface,
                cgnat_details=cgnat_details,
            )

        # 2. Local CGNAT Evaluation
        cgnat_detected, cgnat_addr, cgnat_iface, cgnat_details = detect_cgnat(selected_iface)

        merged = ProviderResult()
        errors: list[str] = []

        # 3. Primary Observed Public IP & Metadata Discovery
        for provider in self.providers:
            if not provider.enabled or not provider.has_capability(ProviderCapability.PUBLIC_IP):
                continue

            try:
                res = provider.lookup_identity()
                # Verify any reported IP is a valid public IP
                valid_ip_found = False
                for field_name in ("ip", "ipv4", "ipv6"):
                    val = getattr(res, field_name, None)
                    if val:
                        if is_valid_public_ip(val):
                            valid_ip_found = True
                        else:
                            setattr(res, field_name, None)
                            err_msg = f"{provider.name} returned unusable or non-public IP address"
                            if err_msg not in res.errors:
                                res.errors.append(err_msg)

                if valid_ip_found:
                    merged.merge(res)
                    break
                else:
                    merged.merge(res)
                    errors.extend(res.errors)
            except Exception as err:
                logger.debug("Provider %s error: %s", provider.name, err)
                errors.append(f"{provider.name}: {err}")

        # Normalization: Ensure merged.ip and ip_version are populated if only ipv4 or ipv6 was returned
        if not merged.ip:
            if merged.ip_version == 4 and merged.ipv4:
                merged.ip = merged.ipv4
                if "ipv4" in merged.sources and "ip" not in merged.sources:
                    merged.sources["ip"] = merged.sources["ipv4"]
            elif merged.ip_version == 6 and merged.ipv6:
                merged.ip = merged.ipv6
                if "ipv6" in merged.sources and "ip" not in merged.sources:
                    merged.sources["ip"] = merged.sources["ipv6"]
            elif merged.ipv4:
                merged.ip = merged.ipv4
                merged.ip_version = 4
                if "ipv4" in merged.sources and "ip" not in merged.sources:
                    merged.sources["ip"] = merged.sources["ipv4"]
            elif merged.ipv6:
                merged.ip = merged.ipv6
                merged.ip_version = 6
                if "ipv6" in merged.sources and "ip" not in merged.sources:
                    merged.sources["ip"] = merged.sources["ipv6"]

        if merged.ip and not merged.ip_version:
            merged.ip_version = 6 if ":" in merged.ip else 4

        if merged.ip:
            if merged.ip_version == 4 and not merged.ipv4:
                merged.ipv4 = merged.ip
                if "ip" in merged.sources and "ipv4" not in merged.sources:
                    merged.sources["ipv4"] = merged.sources["ip"]
            elif merged.ip_version == 6 and not merged.ipv6:
                merged.ipv6 = merged.ip
                if "ip" in merged.sources and "ipv6" not in merged.sources:
                    merged.sources["ipv6"] = merged.sources["ip"]

        # 4. Field-Aware Fallback for missing Metadata
        # If we have an IP but are missing ASN, Geolocation, or ISP, query metadata-capable providers for this specific IP
        metadata_errors: list[str] = []
        if merged.has_ip() and merged.ip and is_valid_public_ip(merged.ip):
            target_ip = str(merged.ip)
            for provider in self.providers:
                if not provider.enabled:
                    continue
                # If we still miss ASN or Geolocation or ISP, query capable provider
                needs_asn = merged.asn is None and provider.has_capability(ProviderCapability.ASN)
                needs_geo = (merged.country is None or merged.city is None) and provider.has_capability(ProviderCapability.GEOLOCATION)
                needs_isp = merged.isp is None and provider.has_capability(ProviderCapability.ISP)

                if needs_asn or needs_geo or needs_isp:
                    try:
                        meta_res = provider.lookup_identity(requested_ip=target_ip)
                        merged.merge(meta_res)
                        if meta_res.errors:
                            metadata_errors.extend(meta_res.errors)
                    except Exception as err:
                        error_msg = f"{provider.name} metadata lookup failed: {err}"
                        logger.debug("%s", error_msg)
                        metadata_errors.append(error_msg)

        # 5. Dual-Stack Independent Discovery
        # Primary observed IP -> independent opposite-family public-IP lookup.
        # This discovery operates independently without checking or coupling to local OS routing tables.
        if merged.has_ip():
            primary_is_v4 = merged.ip_version == 4 or (merged.ip and ":" not in merged.ip)
            if primary_is_v4:
                # Seek IPv6 independently via dedicated family endpoints
                for provider in self.providers:
                    if provider.enabled and provider.has_capability(ProviderCapability.IPV6):
                        try:
                            v6_candidate = provider.lookup_ip(version=6)
                            if v6_candidate and is_valid_public_ip(v6_candidate) and ":" in v6_candidate:
                                merged.ipv6 = v6_candidate
                                merged.sources["ipv6"] = provider.name
                                break
                        except Exception as err:
                            logger.debug("IPv6 discovery with %s failed: %s", provider.name, err)
            else:
                # Seek IPv4 independently via dedicated family endpoints
                for provider in self.providers:
                    if provider.enabled and provider.has_capability(ProviderCapability.IPV4):
                        try:
                            v4_candidate = provider.lookup_ip(version=4)
                            if v4_candidate and is_valid_public_ip(v4_candidate) and ":" not in v4_candidate:
                                merged.ipv4 = v4_candidate
                                merged.sources["ipv4"] = provider.name
                                break
                        except Exception as err:
                            logger.debug("IPv4 discovery with %s failed: %s", provider.name, err)

        # 6. System-Resolver PTR Lookup
        reverse_dns: str | None = None
        if merged.ip and is_valid_public_ip(merged.ip):
            ptr_name = lookup_system_ptr(merged.ip, timeout_seconds=2.0)
            if ptr_name:
                reverse_dns = ptr_name
                merged.sources["reverse_dns"] = "system_resolver"

        # 7. Evaluate Final Availability and Status
        now_ts = datetime.now(timezone.utc).isoformat()
        if not merged.has_ip():
            # External providers could not be reached or returned invalid data
            all_errs = errors + merged.errors
            is_error = any(
                "non-dictionary" in e
                or "API error" in e
                or "unusable or non-public" in e
                for e in all_errs
            )
            status = "ERROR" if is_error else "OFFLINE"
            reason = (
                "External providers responded with invalid or unusable data"
                if is_error
                else "External providers could not be reached (offline or blocked)"
            )

            return PublicIpInfo(
                available=False,
                status=status,
                reason=reason,
                lookup_timestamp=now_ts,
                cgnat_detected=cgnat_detected,
                cgnat_local_address=cgnat_addr,
                cgnat_interface=cgnat_iface,
                cgnat_details=cgnat_details,
            )

        # Discovered at least one valid public IP
        # Core identity metadata requires ASN, AS Organization, and approximate Country or City
        has_core_metadata = (
            merged.asn is not None
            and merged.as_org is not None
            and (merged.country is not None or merged.city is not None)
        )
        status = "AVAILABLE" if has_core_metadata else "PARTIAL"
        if has_core_metadata:
            reason = None
        else:
            if metadata_errors:
                reason = f"Observed public IP discovered; partial metadata retrieved ({'; '.join(metadata_errors)})"
            else:
                reason = "Observed public IP discovered; partial metadata retrieved"

        # Primary source is the provider that discovered the primary observed public IP
        primary_source = merged.sources.get("ip") or (self.providers[0].name if self.providers else None)

        return PublicIpInfo(
            available=True,
            status=status,
            reason=reason,
            ip=merged.ip,
            ip_version=merged.ip_version,
            ipv4=merged.ipv4,
            ipv6=merged.ipv6,
            asn=merged.asn,
            as_org=merged.as_org,
            isp=merged.isp,
            country=merged.country,
            region=merged.region,
            city=merged.city,
            reverse_dns=reverse_dns,
            source=primary_source,
            sources=merged.sources,
            lookup_timestamp=now_ts,
            cgnat_detected=cgnat_detected,
            cgnat_local_address=cgnat_addr,
            cgnat_interface=cgnat_iface,
            cgnat_details=cgnat_details,
            geolocation_accuracy="APPROXIMATE",
        )
