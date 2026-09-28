"""Core Authorized PCAP/PCAPNG Packet Analysis Engine.

This module provides offline, bounded, read-only packet capture decoding using TShark.
It strictly enforces:
- Offline execution only (tshark -r <file>; never -i or --interface)
- Zero packet transmission, injection, replay, or live capture
- Zero credential extraction (no auth headers, cookies, tokens, passwords)
- Zero payload dumping or file extraction
- Hard bounds on output bytes, packet count, sample count, and execution time
- Preserves the original capture file completely unmodified
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import struct
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from core.models import (
    PcapAnalysisInfo,
    PcapConversationStat,
    PcapDnsSummary,
    PcapEndpointStat,
    PcapHttpSummary,
    PcapPacketSample,
    PcapProtocolStat,
    PcapTcpSummary,
    PcapTlsSummary,
    PcapTrafficTimelineBucket,
)
from core.network import normalize_ip_string

logger = logging.getLogger(__name__)

# Default safety and resource boundaries
DEFAULT_MAX_FILE_SIZE_MB = 2048
DEFAULT_MAX_PACKETS = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_OUTPUT_BYTES = 52_428_800  # 50 MB
DEFAULT_PACKET_SAMPLE_LIMIT = 100
DEFAULT_TIMELINE_INTERVAL_SECONDS = 1.0


def validate_capture_file(
    capture_path: Path,
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB,
) -> tuple[bool, str | None, str | None]:
    """Validate capture file status, readability, size, and header magic.

    Returns:
        tuple[is_valid, format_str, error_message]
    """
    if not capture_path.exists():
        return False, None, f"Capture file not found: {capture_path}"

    if not capture_path.is_file():
        return False, None, f"Specified path is a directory or special file, not a regular file: {capture_path}"

    if not os.access(capture_path, os.R_OK):
        return False, None, f"Capture file is not readable (permission denied): {capture_path}"

    try:
        size_bytes = capture_path.stat().st_size
    except Exception as err:
        return False, None, f"Failed to access capture file attributes: {err}"

    if size_bytes > (max_file_size_mb * 1024 * 1024):
        return (
            False,
            None,
            f"Capture file size ({size_bytes / (1024 * 1024):.1f} MB) exceeds configured limit ({max_file_size_mb} MB)",
        )

    # Inspect file header magic
    try:
        with open(capture_path, "rb") as f:
            header = f.read(32)
    except Exception as err:
        return False, None, f"Failed to read capture file header: {err}"

    if len(header) < 4:
        return False, None, "Capture file is empty or too short to contain a valid capture header"

    magic32 = struct.unpack("<I", header[:4])[0]

    # PCAP classic (microsecond or nanosecond)
    if magic32 in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
        return True, "PCAP", None

    # PCAPNG Section Header Block magic (0x0A0D0D0A)
    if magic32 == 0x0A0D0D0A:
        return True, "PCAPNG", None

    # If it claims to be .pcap or .pcapng but magic is invalid, it is corrupt
    suffix = capture_path.suffix.lower()
    if suffix in (".pcap", ".pcapng"):
        return False, None, "Corrupt or invalid capture file: header magic does not match PCAP or PCAPNG specifications"

    if suffix in (".cap", ".dmp"):
        return True, "CAP", None

    return False, None, "Unrecognized or invalid capture file format (neither standard PCAP nor PCAPNG header)"
