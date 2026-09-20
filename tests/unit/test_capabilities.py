"""Unit tests for capability system."""

from core.capabilities import CapabilityEntry, CapabilityRegistry, CapabilityStatus


def test_capability_statuses():
    assert CapabilityStatus.AVAILABLE.value == "AVAILABLE"
    assert CapabilityStatus.PARTIAL.value == "PARTIAL"
    assert CapabilityStatus.UNAVAILABLE.value == "UNAVAILABLE"
    assert CapabilityStatus.NOT_APPLICABLE.value == "NOT_APPLICABLE"
    assert CapabilityStatus.REQUIRES_PRIVILEGE.value == "REQUIRES_PRIVILEGE"
    assert CapabilityStatus.MISSING_DEPENDENCY.value == "MISSING_DEPENDENCY"


def test_capability_registry():
    registry = CapabilityRegistry()
    registry.register(
        CapabilityEntry(
            name="routing",
            status=CapabilityStatus.AVAILABLE,
            description="Routing table collection",
        )
    )
    registry.register(
        CapabilityEntry(
            name="dhcp",
            status=CapabilityStatus.PARTIAL,
            description="DHCP lease inspection",
            reason="Lease times require elevated privilege",
        )
    )
    registry.register(
        CapabilityEntry(
            name="linux_kernel",
            status=CapabilityStatus.NOT_APPLICABLE,
            description="Linux /proc/net stats",
            reason="Not a Linux platform",
        )
    )

    assert registry.is_available("routing") is True
    assert registry.is_usable("routing") is True
    assert registry.is_fully_available("routing") is True
    assert registry.requires_privilege("routing") is False

    assert registry.is_available("dhcp") is True
    assert registry.is_usable("dhcp") is True
    assert registry.is_fully_available("dhcp") is False

    assert registry.is_available("linux_kernel") is False
    assert registry.is_usable("linux_kernel") is False
    assert registry.is_available("nonexistent") is False

    cap = registry.get("dhcp")
    assert cap is not None
    assert cap.reason == "Lease times require elevated privilege"
    assert cap.is_usable() is True
    assert cap.is_fully_available() is False

    counts = registry.summary_counts()
    assert counts[CapabilityStatus.AVAILABLE.value] == 1
    assert counts[CapabilityStatus.PARTIAL.value] == 1
    assert counts[CapabilityStatus.NOT_APPLICABLE.value] == 1
    assert counts[CapabilityStatus.UNAVAILABLE.value] == 0


def test_capability_to_dict():
    entry = CapabilityEntry(
        name="pcap_analysis",
        status=CapabilityStatus.MISSING_DEPENDENCY,
        description="Packet analysis",
        reason="TShark not found in PATH",
        platform="all",
    )
    d = entry.to_dict()
    assert d["name"] == "pcap_analysis"
    assert d["status"] == "MISSING_DEPENDENCY"
    assert d["reason"] == "TShark not found in PATH"
