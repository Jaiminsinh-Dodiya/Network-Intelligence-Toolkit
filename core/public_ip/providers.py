"""Concrete Public IP and Metadata Provider Implementations."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from .base import BasePublicIpProvider, ProviderResult
from .capabilities import ProviderCapability
from .validation import is_valid_public_ip, normalize_asn

logger = logging.getLogger(__name__)

USER_AGENT = "NetworkIntelligenceToolkit/1.0"


def _fetch_url(url: str, timeout: float) -> tuple[int, bytes]:
    """Execute a safe GET request returning HTTP status code and response bytes."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        code = resp.getcode()
        body = resp.read()
        return code, body


class IPApiProvider(BasePublicIpProvider):
    """Provider for ipapi.co (IP, ASN, AS Organization, Geolocation)."""

    def __init__(
        self,
        name: str = "ipapi",
        enabled: bool = True,
        timeout_seconds: float = 3.0,
        identity_url: str = "https://ipapi.co/json/",
        metadata_url_template: str = "https://ipapi.co/{ip}/json/",
    ) -> None:
        super().__init__(name=name, enabled=enabled, timeout_seconds=timeout_seconds)
        self.identity_url = identity_url
        self.metadata_url_template = metadata_url_template

    @property
    def capabilities(self) -> set[ProviderCapability]:
        # ipapi provides generic observed identity and metadata, not family-specific endpoints
        return {
            ProviderCapability.PUBLIC_IP,
            ProviderCapability.ASN,
            ProviderCapability.AS_ORG,
            ProviderCapability.GEOLOCATION,
        }

    def lookup_identity(self, requested_ip: str | None = None) -> ProviderResult:
        result = ProviderResult()
        if requested_ip:
            if not is_valid_public_ip(requested_ip):
                result.errors.append(f"Invalid public IP rejected for metadata lookup: {requested_ip}")
                return result
            url = self.metadata_url_template.format(ip=requested_ip)
        else:
            url = self.identity_url

        try:
            _, body = _fetch_url(url, timeout=self.timeout_seconds)
            data = json.loads(body.decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as err:
            logger.debug("Provider %s request to %s failed: %s", self.name, url, err)
            result.errors.append(f"{self.name} error: {err}")
            return result

        if not isinstance(data, dict):
            result.errors.append(f"{self.name} returned non-dictionary JSON")
            return result

        if data.get("error") is True:
            reason = data.get("reason", "unknown error")
            result.errors.append(f"{self.name} API error: {reason}")
            return result

        raw_ip = data.get("ip")
        if raw_ip:
            if is_valid_public_ip(str(raw_ip)):
                result.ip = str(raw_ip).strip()
                result.sources["ip"] = self.name
                version_str = data.get("version", "")
                if version_str == "IPv6" or ":" in result.ip:
                    result.ip_version = 6
                    result.ipv6 = result.ip
                    result.sources["ipv6"] = self.name
                else:
                    result.ip_version = 4
                    result.ipv4 = result.ip
                    result.sources["ipv4"] = self.name
            else:
                result.errors.append(f"{self.name} returned unusable or non-public IP address")

        raw_asn = data.get("asn")
        if raw_asn:
            norm_asn = normalize_asn(raw_asn)
            if norm_asn:
                result.asn = norm_asn
                result.sources["asn"] = self.name

        raw_org = data.get("org")
        if raw_org:
            result.as_org = str(raw_org).strip()
            result.sources["as_org"] = self.name

        # Geolocation fields
        country = data.get("country_name") or data.get("country")
        if country:
            result.country = str(country).strip()
            result.sources["country"] = self.name

        region = data.get("region")
        if region:
            result.region = str(region).strip()
            result.sources["region"] = self.name

        city = data.get("city")
        if city:
            result.city = str(city).strip()
            result.sources["city"] = self.name

        return result

    def lookup_ip(self, version: int = 4) -> str | None:
        """Generic identity endpoint does not perform family-specific discovery."""
        return None
