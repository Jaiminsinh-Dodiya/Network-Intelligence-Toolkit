"""Strict IP validation and ASN normalization utilities."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


def is_valid_public_ip(ip_str: str | None) -> bool:
    """Validate that ip_str is a syntactically valid public/global IPv4 or IPv6 address.

    Strict security checks applied before sending any IP to external metadata providers:
    1. Parse as IPv4/IPv6 address (reject malformed strings)
    2. Reject private addresses (RFC 1918, RFC 4193)
    3. Reject loopback (127.0.0.0/8, ::1)
    4. Reject link-local (169.254.0.0/16, fe80::/10)
    5. Reject multicast (224.0.0.0/4, ff00::/8)
    6. Reject unspecified (0.0.0.0, ::)
    7. Reject reserved addresses (including RFC 6598 100.64.0.0/10)
    8. Require globally routable address (ip_obj.is_global)
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    cleaned = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
        or not ip_obj.is_global
    ):
        return False

    return True


def normalize_asn(asn_val: Any) -> str | None:
    """Normalize ASN value to standard 'AS<number>' format.

    Examples:
        13335 -> 'AS13335'
        '13335' -> 'AS13335'
        'AS13335' -> 'AS13335'
        'as13335' -> 'AS13335'
        'AS 13335' -> 'AS13335'
    """
    if asn_val is None:
        return None

    if isinstance(asn_val, int):
        return f"AS{asn_val}" if asn_val > 0 else None

    if not isinstance(asn_val, str):
        return None

    s = asn_val.strip()
    if not s:
        return None

    match = re.search(r"\d+", s)
    if match:
        return f"AS{match.group(0)}"

    return None

# Carrier-grade and internal address hardening
