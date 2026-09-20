"""Capability detection and status registry.

Every platform-specific or optional feature registers its availability state.
Features that are unavailable or not applicable on a given platform report their
status cleanly without causing an application failure.

Distinction between Platform Capability and Toolkit Implementation Status:
- Platform Capability (CapabilityStatus):
    Can the host operating system provide this data?
    (AVAILABLE, PARTIAL, UNAVAILABLE, NOT_APPLICABLE, REQUIRES_PRIVILEGE, MISSING_DEPENDENCY)
- Toolkit Implementation Status (toolkit_status):
    Has this collector module been implemented in the Network Intelligence Toolkit?
    (e.g., 'IMPLEMENTED (Phase 1)', 'PLANNED (Phase 3)', etc.)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class CapabilityStatus(str, enum.Enum):
    """Status of a feature or capability on the current platform."""
    AVAILABLE = "AVAILABLE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUIRES_PRIVILEGE = "REQUIRES_PRIVILEGE"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"


@dataclass
class CapabilityEntry:
    """Individual capability descriptor, its platform capability, and its toolkit roadmap status."""
    name: str
    status: CapabilityStatus
    description: str
    reason: str | None = None
    platform: str = "all"
    toolkit_status: str = "IMPLEMENTED"

    def is_usable(self) -> bool:
        """Return True if the feature can execute on this platform (even with partial fidelity)."""
        return self.status in (CapabilityStatus.AVAILABLE, CapabilityStatus.PARTIAL)

    def is_fully_available(self) -> bool:
        """Return True only if the feature is 100% available on this platform without restrictions."""
        return self.status == CapabilityStatus.AVAILABLE

    def requires_privilege(self) -> bool:
        """Return True if this feature requires elevation (root/Admin)."""
        return self.status == CapabilityStatus.REQUIRES_PRIVILEGE

    def is_implemented(self) -> bool:
        """Return True if the toolkit has implemented this collector."""
        return self.toolkit_status.startswith("IMPLEMENTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "description": self.description,
            "reason": self.reason,
            "platform": self.platform,
            "is_usable": self.is_usable(),
            "toolkit_status": self.toolkit_status,
        }


class CapabilityRegistry:
    """Central registry of system and platform capabilities."""

    def __init__(self) -> None:
        self._capabilities: dict[str, CapabilityEntry] = {}

    def register(self, entry: CapabilityEntry) -> None:
        """Register or update a capability entry."""
        self._capabilities[entry.name] = entry

    def register_many(self, entries: list[CapabilityEntry]) -> None:
        """Register multiple capability entries."""
        for entry in entries:
            self.register(entry)

    def get(self, name: str) -> CapabilityEntry | None:
        """Retrieve a capability by name."""
        return self._capabilities.get(name)

    def is_usable(self, name: str) -> bool:
        """Check if a capability can be executed on this OS (AVAILABLE or PARTIAL)."""
        cap = self._capabilities.get(name)
        return cap.is_usable() if cap else False

    def is_available(self, name: str) -> bool:
        """Backward-compatible alias for is_usable."""
        return self.is_usable(name)

    def is_fully_available(self, name: str) -> bool:
        """Check if a capability is 100% fully available on this OS."""
        cap = self._capabilities.get(name)
        return cap.is_fully_available() if cap else False

    def requires_privilege(self, name: str) -> bool:
        """Check if a capability requires elevated privileges."""
        cap = self._capabilities.get(name)
        return cap.requires_privilege() if cap else False

    def is_implemented(self, name: str) -> bool:
        """Check if a capability is currently implemented in the toolkit."""
        cap = self._capabilities.get(name)
        return cap.is_implemented() if cap else False

    def all_capabilities(self) -> dict[str, CapabilityEntry]:
        """Return all registered capabilities."""
        return dict(self._capabilities)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        """Serialize all capabilities to dictionary format."""
        return {name: entry.to_dict() for name, entry in self._capabilities.items()}

    def summary_counts(self) -> dict[str, int]:
        """Count capabilities by platform status."""
        counts = {status.value: 0 for status in CapabilityStatus}
        for entry in self._capabilities.values():
            counts[entry.status.value] += 1
        return counts
