"""Provider capabilities for Public Internet Identity."""

from __future__ import annotations

import enum


class ProviderCapability(str, enum.Enum):
    """Capabilities that an external public IP / metadata provider can advertise."""
    PUBLIC_IP = "PUBLIC_IP"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    ASN = "ASN"
    AS_ORG = "AS_ORG"
    ISP = "ISP"
    GEOLOCATION = "GEOLOCATION"
    PTR_METADATA = "PTR_METADATA"

# Provider capability verification
