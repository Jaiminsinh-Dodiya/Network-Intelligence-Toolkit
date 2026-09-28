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


def run_bounded_subprocess(
    cmd: list[str],
    timeout: float,
    max_output_bytes: int,
) -> tuple[int, str, str, bool]:
    """Execute a subprocess while incrementally reading stdout/stderr with a hard output byte limit.

    Guarantees:
    - Never passes shell=True
    - Stops immediately and terminates process if cumulative output reaches max_output_bytes
    - Hardened bounded grace period with force-kill and reaping on overflow
    - Safely enforces timeouts
    - Returns (returncode, stdout, stderr, was_truncated)
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except FileNotFoundError:
        return 127, "", "Executable not found", False
    except Exception as err:
        return 1, "", f"Failed to launch process: {err}", False

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    total_bytes = 0
    truncated = False
    lock = threading.Lock()
    stop_event = threading.Event()

    def reader(stream: Any, chunks: list[bytes]) -> None:
        nonlocal total_bytes, truncated
        try:
            while not stop_event.is_set():
                chunk = stream.read(65536)
                if not chunk:
                    break
                with lock:
                    total_bytes += len(chunk)
                    if total_bytes > max_output_bytes:
                        truncated = True
                        excess = total_bytes - max_output_bytes
                        allowed = len(chunk) - excess
                        if allowed > 0:
                            chunks.append(chunk[:allowed])
                        stop_event.set()
                        break
                    else:
                        chunks.append(chunk)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=reader, args=(proc.stdout, stdout_chunks), daemon=True)
    t_err = threading.Thread(target=reader, args=(proc.stderr, stderr_chunks), daemon=True)
    t_out.start()
    t_err.start()

    start_time = time.monotonic()
    timed_out = False

    while True:
        # Check if output limit was hit
        if stop_event.is_set():
            # 1. Output overflow: stop accepting further output (stop_event already set)
            # 2. Request subprocess termination
            try:
                proc.terminate()
            except Exception:
                pass
            # 3. Wait only a bounded grace period (1.0s)
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                # 4. Force-kill if it remains alive
                try:
                    proc.kill()
                except Exception:
                    pass
                # 5. Reap the process
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
            break

        # Check if process exited on its own
        try:
            proc.wait(timeout=0.05)
            break
        except subprocess.TimeoutExpired:
            pass

        # Check overall execution timeout
        if (time.monotonic() - start_time) >= timeout:
            timed_out = True
            stop_event.set()
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
            break

    # Ensure streams are closed
    try:
        if proc.stdout:
            proc.stdout.close()
    except Exception:
        pass
    try:
        if proc.stderr:
            proc.stderr.close()
    except Exception:
        pass

    t_out.join(timeout=0.5)
    t_err.join(timeout=0.5)

    if timed_out:
        return -1, "", f"TShark analysis execution timed out after {timeout:.1f}s", False

    out_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    err_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")
    return proc.returncode if proc.returncode is not None else 0, out_str, err_str, truncated


class PcapAnalyzer:
    """Offline, bounded PCAP/PCAPNG packet capture analysis engine using TShark."""

    def __init__(self, backend: Any = None, config: dict[str, Any] | None = None) -> None:
        self.backend = backend
        if config is None:
            config_path = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
            if config_path.is_file():
                try:
                    import yaml
                    with open(config_path, "r", encoding="utf-8") as f:
                        loaded = yaml.safe_load(f)
                        if isinstance(loaded, dict):
                            config = loaded
                except Exception as err:
                    logger.debug("Failed to read config from %s: %s", config_path, err)

        pcap_cfg = config.get("pcap", {}) if config else {}
        self.max_file_size_mb = int(pcap_cfg.get("max_file_size_mb", DEFAULT_MAX_FILE_SIZE_MB))
        self.max_packets = int(pcap_cfg.get("max_packets", DEFAULT_MAX_PACKETS))
        self.timeout_seconds = float(pcap_cfg.get("tshark_timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
        self.max_output_bytes = int(pcap_cfg.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES))
        self.packet_sample_limit = int(pcap_cfg.get("packet_sample_limit", DEFAULT_PACKET_SAMPLE_LIMIT))
        self.timeline_interval = float(pcap_cfg.get("timeline_interval_seconds", DEFAULT_TIMELINE_INTERVAL_SECONDS))

    def _resolve_tshark(self) -> str | None:
        """Find the platform-specific TShark executable."""
        if self.backend and hasattr(self.backend, "get_tshark_path"):
            return self.backend.get_tshark_path()
        which = shutil.which("tshark")
        if which:
            return which
        if os.name == "nt":
            for p in (
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ):
                if os.path.isfile(p):
                    return p
        else:
            for p in ("/usr/bin/tshark", "/usr/local/bin/tshark"):
                if os.path.isfile(p):
                    return p
        return None

    def analyze(
        self,
        capture_path: Path,
        display_filter: str | None = None,
    ) -> PcapAnalysisInfo:
        """Analyze an offline PCAP/PCAPNG capture file."""
        capture_path = Path(capture_path)

        # 1. File validation
        is_valid, fmt, err_msg = validate_capture_file(
            capture_path=capture_path,
            max_file_size_mb=self.max_file_size_mb,
        )
        if not is_valid:
            return PcapAnalysisInfo(
                file_path=str(capture_path),
                file_format=fmt,
                file_size_bytes=capture_path.stat().st_size if capture_path.exists() and capture_path.is_file() else None,
                status="ERROR",
                reason=err_msg,
            )

        size_bytes = capture_path.stat().st_size

        # 2. TShark discovery
        tshark_bin = self._resolve_tshark()
        if not tshark_bin:
            return PcapAnalysisInfo(
                file_path=str(capture_path),
                file_format=fmt,
                file_size_bytes=size_bytes,
                status="UNAVAILABLE",
                reason="TShark executable not found in PATH or standard installation directories (install Wireshark / TShark)",
            )

        applied_filters: list[str] = [display_filter] if display_filter else []
        is_truncated = False
        truncation_reason: str | None = None

        # 3. Filter check & bounded packet limit preflight
        preflight_cmd = [tshark_bin, "-r", str(capture_path), "-n"]
        if display_filter:
            preflight_cmd.extend(["-Y", display_filter])
        preflight_cmd.extend(["-c", str(self.max_packets + 1), "-T", "fields", "-e", "frame.number"])

        ret, out, err, was_truncated = run_bounded_subprocess(
            preflight_cmd,
            timeout=min(self.timeout_seconds, 15.0),
            max_output_bytes=self.max_output_bytes,
        )

        if ret == -1 or "timed out" in err.lower():
            return PcapAnalysisInfo(
                file_path=str(capture_path),
                file_format=fmt,
                file_size_bytes=size_bytes,
                filters_applied=applied_filters,
                status="ERROR",
                reason=f"TShark execution timed out after {self.timeout_seconds:.1f}s",
            )

        if ret != 0 and err:
            lower_err = err.lower()
            if "neither a field nor a protocol" in lower_err or "filter" in lower_err or "syntax" in lower_err:
                sanitized = err.strip().splitlines()[-1] if err.strip() else "Invalid filter expression"
                return PcapAnalysisInfo(
                    file_path=str(capture_path),
                    file_format=fmt,
                    file_size_bytes=size_bytes,
                    filters_applied=applied_filters,
                    status="ERROR",
                    reason=f"Invalid display filter '{display_filter}': {sanitized}",
                )

        frame_numbers = [int(line.strip()) for line in out.splitlines() if line.strip().isdigit()]
        preflight_packets = len(frame_numbers)

        # Check empty valid capture (0 packets)
        if preflight_packets == 0 and not was_truncated and size_bytes <= 24:
            return PcapAnalysisInfo(
                file_path=str(capture_path),
                file_format=fmt,
                file_size_bytes=size_bytes,
                analyzed_packets=0,
                total_packets=0,
                filters_applied=applied_filters,
                status="AVAILABLE",
                truncated=False,
                reason=None,
            )

        packet_limit_exceeded = preflight_packets > self.max_packets
        if packet_limit_exceeded:
            is_truncated = True
            truncation_reason = f"Capture packet count exceeds configured limit of {self.max_packets} packets"
        elif was_truncated:
            is_truncated = True
            truncation_reason = f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 4. Extract protocol hierarchy
        phs_protocols, phs_trunc = self._parse_protocol_hierarchy(
            tshark_bin, capture_path, display_filter
        )
        if phs_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 5. Extract endpoints (IPv4 and IPv6)
        endpoints, ep_trunc = self._parse_endpoints(
            tshark_bin, capture_path, display_filter
        )
        if ep_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 6. Extract conversations (TCP and UDP)
        conversations, conv_trunc = self._parse_conversations(
            tshark_bin, capture_path, display_filter
        )
        if conv_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 7. Extract DNS metadata
        dns_summary, dns_trunc = self._parse_dns_metadata(
            tshark_bin, capture_path, display_filter
        )
        if dns_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 8. Extract HTTP metadata
        http_summary, http_trunc = self._parse_http_metadata(
            tshark_bin, capture_path, display_filter
        )
        if http_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 9. Extract TLS metadata
        tls_summary, tls_trunc = self._parse_tls_metadata(
            tshark_bin, capture_path, display_filter
        )
        if tls_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 10. Extract TCP metadata
        tcp_summary, tcp_trunc = self._parse_tcp_metadata(
            tshark_bin, capture_path, display_filter
        )
        if tcp_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        # 11. Extract packet samples and traffic timeline
        samples, timeline, stats, sample_trunc = self._parse_packet_samples_and_stats(
            tshark_bin, capture_path, display_filter
        )
        if sample_trunc:
            is_truncated = True
            truncation_reason = truncation_reason or f"Analysis output exceeded configured limit of {self.max_output_bytes} bytes"

        total_pkt_count = stats.get("total_packets", 0)
        if total_pkt_count == 0 and preflight_packets > 0:
            total_pkt_count = min(preflight_packets, self.max_packets)

        status = "PARTIAL" if is_truncated else "AVAILABLE"
        reason = truncation_reason if is_truncated else None

        return PcapAnalysisInfo(
            file_path=str(capture_path),
            file_format=fmt,
            file_size_bytes=size_bytes,
            analyzed_packets=total_pkt_count,
            capture_start=stats.get("capture_start"),
            capture_end=stats.get("capture_end"),
            duration_seconds=stats.get("duration_seconds"),
            link_types=stats.get("link_types", ["Ethernet"]),
            protocols=[p.to_dict() for p in phs_protocols],
            endpoints=[e.to_dict() for e in endpoints],
            conversations=[c.to_dict() for c in conversations],
            dns=dns_summary.to_dict() if dns_summary else None,
            http=http_summary.to_dict() if http_summary else None,
            tls=tls_summary.to_dict() if tls_summary else None,
            tcp=tcp_summary.to_dict() if tcp_summary else None,
            packet_samples=[s.to_dict() for s in samples],
            filters_applied=applied_filters,
            truncated=is_truncated,
            status=status,
            reason=reason,
            total_packets=total_pkt_count,
            total_bytes=stats.get("total_bytes", 0),
            average_packet_size=stats.get("average_packet_size"),
            min_packet_size=stats.get("min_packet_size"),
            max_packet_size=stats.get("max_packet_size"),
            packets_per_second=stats.get("packets_per_second"),
            bytes_per_second=stats.get("bytes_per_second"),
            timeline=[t.to_dict() for t in timeline],
        )

    # --------------------------------------------------------------------------
    # Subsystem Parsers
    # --------------------------------------------------------------------------

    def _parse_protocol_hierarchy(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[list[PcapProtocolStat], bool]:
        """Extract protocol distribution using tshark -q -z io,phs."""
        cmd = [tshark, "-r", str(pcap), "-n", "-q", "-c", str(self.max_packets)]
        phs_arg = f"io,phs,{filter_exp}" if filter_exp else "io,phs"
        cmd.extend(["-z", phs_arg])

        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return [], trunc

        protocols = parse_tshark_protocol_hierarchy(out)
        return protocols, trunc

    def _parse_endpoints(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[list[PcapEndpointStat], bool]:
        """Extract IPv4 and IPv6 endpoint statistics."""
        endpoints: list[PcapEndpointStat] = []
        is_trunc = False

        # 1. IPv4 Endpoints
        cmd4 = [tshark, "-r", str(pcap), "-n", "-q", "-c", str(self.max_packets)]
        ep4_arg = f"endpoints,ip,{filter_exp}" if filter_exp else "endpoints,ip"
        cmd4.extend(["-z", ep4_arg])
        ret4, out4, _, t4 = run_bounded_subprocess(cmd4, self.timeout_seconds, self.max_output_bytes)
        if t4:
            is_trunc = True
        if ret4 == 0 and out4:
            endpoints.extend(parse_tshark_endpoints(out4, family=4))

        # 2. IPv6 Endpoints
        cmd6 = [tshark, "-r", str(pcap), "-n", "-q", "-c", str(self.max_packets)]
        ep6_arg = f"endpoints,ipv6,{filter_exp}" if filter_exp else "endpoints,ipv6"
        cmd6.extend(["-z", ep6_arg])
        ret6, out6, _, t6 = run_bounded_subprocess(cmd6, self.timeout_seconds, self.max_output_bytes)
        if t6:
            is_trunc = True
        if ret6 == 0 and out6:
            endpoints.extend(parse_tshark_endpoints(out6, family=6))

        return sort_endpoints(endpoints), is_trunc

    def _parse_conversations(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[list[PcapConversationStat], bool]:
        """Extract TCP and UDP conversations."""
        conversations: list[PcapConversationStat] = []
        is_trunc = False

        # TCP Conversations
        cmd_tcp = [tshark, "-r", str(pcap), "-n", "-q", "-c", str(self.max_packets)]
        tcp_arg = f"conv,tcp,{filter_exp}" if filter_exp else "conv,tcp"
        cmd_tcp.extend(["-z", tcp_arg])
        ret_tcp, out_tcp, _, t_tcp = run_bounded_subprocess(cmd_tcp, self.timeout_seconds, self.max_output_bytes)
        if t_tcp:
            is_trunc = True
        if ret_tcp == 0 and out_tcp:
            conversations.extend(parse_tshark_conversations(out_tcp, proto="TCP"))

        # UDP Conversations
        cmd_udp = [tshark, "-r", str(pcap), "-n", "-q", "-c", str(self.max_packets)]
        udp_arg = f"conv,udp,{filter_exp}" if filter_exp else "conv,udp"
        cmd_udp.extend(["-z", udp_arg])
        ret_udp, out_udp, _, t_udp = run_bounded_subprocess(cmd_udp, self.timeout_seconds, self.max_output_bytes)
        if t_udp:
            is_trunc = True
        if ret_udp == 0 and out_udp:
            conversations.extend(parse_tshark_conversations(out_udp, proto="UDP"))

        return sort_conversations(conversations), is_trunc

    def _parse_dns_metadata(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[PcapDnsSummary, bool]:
        """Extract DNS query and response metadata."""
        dns_filter = f"({filter_exp}) and dns" if filter_exp else "dns"
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-n",
            "-c",
            str(self.max_packets),
            "-Y",
            dns_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "dns.id",
            "-e",
            "dns.flags.response",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.qry.type",
            "-e",
            "dns.flags.rcode",
        ]
        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return PcapDnsSummary(), trunc

        summary = parse_tshark_dns_output(out)
        return summary, trunc

    def _parse_http_metadata(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[PcapHttpSummary, bool]:
        """Extract safe HTTP request/response metadata without cookies, credentials, or bodies."""
        http_filter = f"({filter_exp}) and http" if filter_exp else "http"
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-n",
            "-c",
            str(self.max_packets),
            "-Y",
            http_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri.path",
            "-e",
            "http.response.code",
        ]
        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return PcapHttpSummary(), trunc

        summary = parse_tshark_http_output(out)
        return summary, trunc

    def _parse_tls_metadata(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[PcapTlsSummary, bool]:
        """Extract TLS handshake metadata (SNI, versions, cipher suites) without keys or secrets."""
        tls_filter = f"({filter_exp}) and tls.handshake" if filter_exp else "tls.handshake"
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-n",
            "-c",
            str(self.max_packets),
            "-Y",
            tls_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tls.record.version",
            "-e",
            "tls.handshake.type",
            "-e",
            "tls.handshake.extensions_server_name",
            "-e",
            "tls.handshake.ciphersuite",
        ]
        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return PcapTlsSummary(), trunc

        summary = parse_tshark_tls_output(out)
        return summary, trunc

    def _parse_tcp_metadata(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[PcapTcpSummary, bool]:
        """Extract TCP control flags, retransmissions, duplicate ACKs, and resets."""
        tcp_filter = f"({filter_exp}) and tcp" if filter_exp else "tcp"
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-n",
            "-c",
            str(self.max_packets),
            "-Y",
            tcp_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.flags.syn",
            "-e",
            "tcp.flags.ack",
            "-e",
            "tcp.flags.reset",
            "-e",
            "tcp.flags.fin",
            "-e",
            "tcp.analysis.retransmission",
            "-e",
            "tcp.analysis.duplicate_ack",
            "-e",
            "tcp.analysis.zero_window",
        ]
        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return PcapTcpSummary(), trunc

        summary = parse_tshark_tcp_output(out)
        return summary, trunc

    _parse_tcp_diagnostics = _parse_tcp_metadata

    def _parse_packet_samples_and_stats(
        self, tshark: str, pcap: Path, filter_exp: str | None
    ) -> tuple[list[PcapPacketSample], list[PcapTrafficTimelineBucket], dict[str, Any], bool]:
        """Extract bounded packet samples and capture-level statistics."""
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-n",
            "-c",
            str(self.max_packets),
        ]
        if filter_exp:
            cmd.extend(["-Y", filter_exp])

        cmd.extend([
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.src",
            "-e",
            "ipv6.src",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "frame.len",
            "-e",
            "_ws.col.Info",
        ])

        ret, out, _, trunc = run_bounded_subprocess(cmd, self.timeout_seconds, self.max_output_bytes)
        if ret != 0 or not out:
            return [], [], {}, trunc

        samples, timeline, stats = parse_tshark_packet_samples_and_timeline(
            out,
            sample_limit=self.packet_sample_limit,
            interval_seconds=self.timeline_interval,
        )
        return samples, timeline, stats, trunc


# ==============================================================================
# Helper Parsers for TShark Outputs
# ==============================================================================

def parse_tshark_protocol_hierarchy(output: str) -> list[PcapProtocolStat]:
    """Parse output of tshark -q -z io,phs."""
    protocols: list[PcapProtocolStat] = []
    lines = output.strip().splitlines()

    in_table = False
    for line in lines:
        if "Protocol Hierarchy Statistics" in line or "Filter:" in line:
            in_table = True
            continue
        if "===" in line:
            continue
        if not in_table or not line.strip():
            continue

        # Format example:
        # eth                                      frames:100 bytes:15000
        #   ip                                     frames:90 bytes:14000
        m = re.search(r"^\s*([a-zA-Z0-9_\-]+)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if m:
            proto_name = m.group(1).strip()
            frames = int(m.group(2))
            byte_count = int(m.group(3))
            protocols.append(
                PcapProtocolStat(
                    protocol=proto_name,
                    packet_count=frames,
                    byte_count=byte_count,
                )
            )

    # Calculate percentages relative to topmost protocol
    if protocols:
        top_frames = protocols[0].packet_count or 1
        for p in protocols:
            p.percentage = round((p.packet_count / top_frames) * 100.0, 2)

    return sorted(protocols, key=lambda x: (-x.packet_count, x.protocol.lower()))


def parse_tshark_endpoints(output: str, family: int) -> list[PcapEndpointStat]:
    """Parse output of tshark -q -z endpoints,ip or endpoints,ipv6."""
    endpoints: list[PcapEndpointStat] = []
    lines = output.strip().splitlines()

    in_table = False
    for line in lines:
        if "IPv4 Endpoints" in line or "IPv6 Endpoints" in line or "Filter:" in line:
            in_table = True
            continue
        if "===" in line:
            continue
        if not in_table or not line.strip():
            continue

        parts = [p for p in line.split() if p.lower() != "bytes"]
        # Columns typically: Address, Packets, Bytes, Tx Packets, Tx Bytes, Rx Packets, Rx Bytes
        if len(parts) >= 3:
            addr = parts[0].strip()
            if addr.lower() in ("address", "filter:", "ipv4", "ipv6"):
                continue
            try:
                pkts = int(parts[1])
                byte_count = int(parts[2])
                tx_pkts = int(parts[3]) if len(parts) > 3 else 0
                tx_bytes = int(parts[4]) if len(parts) > 4 else 0
                rx_pkts = int(parts[5]) if len(parts) > 5 else 0
                rx_bytes = int(parts[6]) if len(parts) > 6 else 0
            except (ValueError, TypeError):
                continue

            endpoints.append(
                PcapEndpointStat(
                    address=normalize_ip_string(addr),
                    address_family=family,
                    packet_count=pkts,
                    byte_count=byte_count,
                    sent_packets=tx_pkts,
                    sent_bytes=tx_bytes,
                    received_packets=rx_pkts,
                    received_bytes=rx_bytes,
                )
            )

    return endpoints
