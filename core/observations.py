"""Observations & Findings Engine for Network Intelligence Toolkit (Phase 9 & 9.1).

Transforms collected toolkit evidence into structured, deterministic, evidence-backed
observations with complete collection scope awareness. Strictly passive, in-memory analysis layer.

Key Guarantees:
- Zero active network activity (no socket connections, DNS queries, HTTP probes, ARP sweeps).
- Scope awareness: unrequested subsystems are never treated as empty, partial, or failed.
- Read-only analysis of existing NetworkIntelligenceReport.
- Objective, evidence-proven conclusions (no arbitrary threat scoring, no speculation).
- Deterministic observation IDs, categories, severities, and sorting.
- Automatic contradiction suppression and deduplication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import logging
from pathlib import Path
from typing import Any, Callable

from core.models import (
    NetworkIntelligenceReport,
    Observation,
    ObservationEvidence,
    VALID_OBSERVATION_CATEGORIES,
    VALID_OBSERVATION_CONFIDENCES,
    VALID_OBSERVATION_SEVERITIES,
    VALID_OBSERVATION_STATUSES,
)

logger = logging.getLogger(__name__)

# RFC 6598 Shared Address Space (Carrier-Grade NAT)
RFC6598_NET = ipaddress.ip_network("100.64.0.0/10")

# Loopback resolver addresses commonly used by local caching resolvers (e.g. systemd-resolved)
STUB_RESOLVER_IPS = {"127.0.0.53", "127.0.0.54", "127.0.0.1", "::1"}

# Mapping from capability name to canonical collected_section name
CAPABILITY_TO_SECTION = {
    "interface_info": "interfaces",
    "routing_info": "routing",
    "dns_info": "dns",
    "dhcp_info": "dhcp",
    "wifi_info": "wifi",
    "neighbor_table": "neighbors",
    "socket_summary": "sockets",
    "public_ip": "public_ip",
    "connectivity": "connectivity",
    "pcap_analysis": "pcap_analysis",
    "linux_kernel_info": "linux_kernel_info",
}


@dataclass(frozen=True)
class ObservationContext:
    """Immutable collection execution scope context for observation analysis."""

    collected_sections: frozenset[str] = field(default_factory=frozenset)
    policy_disabled_sections: frozenset[str] = field(default_factory=frozenset)

    def is_collected(self, section: str) -> bool:
        return section in self.collected_sections

    def is_policy_disabled(self, section: str) -> bool:
        return section in self.policy_disabled_sections


class ObservationEngine:
    """Deterministic, passive observations and findings engine with scope awareness."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration options and thresholds from config file if not provided."""
        if not self.config:
            config_path = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
            if config_path.is_file():
                try:
                    import yaml

                    with open(config_path, "r", encoding="utf-8") as f:
                        self.config = yaml.safe_load(f) or {}
                except Exception as err:
                    logger.debug("Failed to read config from %s: %s", config_path, err)

        obs_cfg = self.config.get("observations", {})
        self.enabled: bool = obs_cfg.get("enabled", True)

        # PCAP observation thresholds
        pcap_cfg = obs_cfg.get("pcap", {})
        self.pcap_retrans_threshold: int = int(pcap_cfg.get("retransmission_notice_threshold", 1))
        self.pcap_reset_threshold: int = int(pcap_cfg.get("tcp_reset_notice_threshold", 1))

    def analyze(
        self,
        report: NetworkIntelligenceReport,
        collected_sections: set[str] | frozenset[str] | ObservationContext | None = None,
    ) -> list[Observation]:
        """Analyze a NetworkIntelligenceReport and return deterministic observations.

        Args:
            report: The normalized NetworkIntelligenceReport to analyze.
            collected_sections: Optional explicit set of subsystems actually executed during
                the collection run. If omitted/None, scope filtering is relaxed for testing.
        """
        if not self.enabled:
            return []

        # Normalize collected_sections
        scope: set[str] | None = None
        if isinstance(collected_sections, ObservationContext):
            scope = set(collected_sections.collected_sections)
        elif isinstance(collected_sections, (set, frozenset, list, tuple)):
            scope = set(collected_sections)

        rules: list[Callable[[NetworkIntelligenceReport, set[str] | None], list[Observation]]] = [
            self.observe_default_gateway_consistency,
            self.observe_routing_state,
            self.observe_dns_consistency,
            self.observe_ipv6_state,
            self.observe_public_identity,
            self.observe_neighbor_state,
            self.observe_socket_state,
            self.observe_connectivity_state,
            self.observe_pcap_state,
            self.observe_data_quality,
        ]

        raw_observations: list[Observation] = []
        for rule in rules:
            try:
                findings = rule(report, scope)
                if findings:
                    raw_observations.extend(findings)
            except Exception as err:
                logger.error("Error executing observation rule %s: %s", rule.__name__, err)
                raw_observations.append(
                    Observation(
                        id="DATA.COLLECTION.ERROR",
                        category="DATA_QUALITY",
                        severity="WARNING",
                        title=f"Error in observation rule {rule.__name__}",
                        summary=f"Observation rule {rule.__name__} failed during analysis: {err}",
                        details=str(err),
                        confidence="HIGH",
                        source_sections=["observations"],
                        evidence=[
                            ObservationEvidence(
                                source="observations",
                                field="rule",
                                value=rule.__name__,
                                description=str(err),
                            )
                        ],
                        related_entities=[rule.__name__],
                        status="OBSERVED",
                    )
                )

        # Apply suppression rules
        suppressed_observations = self._apply_suppressions(raw_observations, report)

        # Apply deduplication
        deduplicated = self._deduplicate(suppressed_observations)

        # Sort deterministically
        return self._sort_observations(deduplicated)

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 1: Gateway / Neighbor Correlation
    # ──────────────────────────────────────────────────────────────────────────
