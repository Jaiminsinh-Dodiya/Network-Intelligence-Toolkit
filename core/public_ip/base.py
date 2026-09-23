"""Abstract Base Class and Result models for Public IP providers."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from .capabilities import ProviderCapability


@dataclass
class ProviderResult:
    """Normalized output from an individual public IP or metadata provider.

    Supports partial success: individual fields may be present or None.
    """
    ip: str | None = None
    ip_version: int | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    asn: str | None = None
    as_org: str | None = None
    isp: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    sources: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def has_ip(self) -> bool:
        """Return True if an IP address was discovered."""
        return bool(self.ip or self.ipv4 or self.ipv6)

    def has_metadata(self) -> bool:
        """Return True if any ASN, organization, ISP, or geolocation data is present."""
        return any(
            getattr(self, k) is not None
            for k in ("asn", "as_org", "isp", "country", "region", "city")
        )

    def merge_field(self, field_name: str, value: Any, provider_name: str) -> None:
        """Merge a non-empty field if not already populated, updating field-level provenance."""
        if value is not None and getattr(self, field_name, None) is None:
            setattr(self, field_name, value)
            self.sources[field_name] = provider_name

    def merge(self, other: ProviderResult) -> None:
        """Merge fields from another ProviderResult without overwriting existing data."""
        fields_to_merge = (
            "ip",
            "ip_version",
            "ipv4",
            "ipv6",
            "asn",
            "as_org",
            "isp",
            "country",
            "region",
            "city",
        )
        for f in fields_to_merge:
            other_val = getattr(other, f, None)
            if other_val is not None and getattr(self, f, None) is None:
                setattr(self, f, other_val)
                if f in other.sources:
                    self.sources[f] = other.sources[f]

        for err in other.errors:
            if err not in self.errors:
                self.errors.append(err)


class BasePublicIpProvider(abc.ABC):
    """Abstract interface for external public IP and network identity providers."""

    def __init__(
        self,
        name: str,
        enabled: bool = True,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.name = name
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds

    @property
    @abc.abstractmethod
    def capabilities(self) -> set[ProviderCapability]:
        """Set of capabilities supported by this provider."""
        pass

    def has_capability(self, cap: ProviderCapability) -> bool:
        """Check if this provider supports a specific capability."""
        return cap in self.capabilities

    @abc.abstractmethod
    def lookup_identity(self, requested_ip: str | None = None) -> ProviderResult:
        """Query provider for observed public IP and/or metadata.

        Args:
            requested_ip: Optional pre-discovered public IP to fetch metadata for.
                          Must be validated as a public/global address before calling.
        """
        pass

    @abc.abstractmethod
    def lookup_ip(self, version: int = 4) -> str | None:
        """Query provider for an observed public IP of a specific address family (4 or 6)."""
        pass
