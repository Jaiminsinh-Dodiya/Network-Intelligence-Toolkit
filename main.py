#!/usr/bin/env python3
"""Network Intelligence Toolkit - Cross-Platform CLI Entry Point.

Supports Windows 10/11 and Kali Linux.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path to allow running directly from any directory
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure UTF-8 output encoding on legacy Windows consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backends import get_platform_backend
from core.capabilities import CapabilityStatus
from core.collector import CollectorCoordinator
from core.errors import ToolkitError
from core.registry import CollectorOptions

logger = logging.getLogger("network_intelligence")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_capability_banner(backend) -> None:
    """Print a clean capability matrix banner with distinct Platform and Toolkit statuses."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()
        sys_info = backend.get_platform_info()
        caps = backend.detect_capabilities()

        table = Table(show_header=True, header_style="bold cyan", border_style="bright_blue")
        table.add_column("Capability / Feature", style="bold")
        table.add_column("Platform Support", justify="center")
        table.add_column("Toolkit Status", justify="center")
        table.add_column("Details / Reason", style="dim")

        status_symbols = {
            CapabilityStatus.AVAILABLE: "[green]✓ AVAILABLE[/green]",
            CapabilityStatus.PARTIAL: "[yellow]⚠ PARTIAL[/yellow]",
            CapabilityStatus.UNAVAILABLE: "[red]✗ UNAVAILABLE[/red]",
            CapabilityStatus.NOT_APPLICABLE: "[bright_black]— N/A[/bright_black]",
            CapabilityStatus.REQUIRES_PRIVILEGE: "[yellow]🔒 REQUIRES ROOT[/yellow]",
            CapabilityStatus.MISSING_DEPENDENCY: "[red]✗ MISSING DEP[/red]",
        }

        for cap in caps.values():
            platform_badge = status_symbols.get(cap.status, cap.status.value)
            toolkit_badge = f"[cyan]{cap.toolkit_status}[/cyan]" if "IMPLEMENTED" in cap.toolkit_status else f"[dim]{cap.toolkit_status}[/dim]"
            reason = cap.reason or cap.description
            table.add_row(cap.name.replace("_", " ").title(), platform_badge, toolkit_badge, reason)

        priv_text = "[bold green]Elevated / Root[/bold green]" if sys_info.is_privileged else "[yellow]Standard User[/yellow]"
        meta_panel = Panel(
            f"[bold]Platform:[/bold] {sys_info.os_name} ({sys_info.architecture})  |  "
            f"[bold]Python:[/bold] {sys_info.python_version}  |  "
            f"[bold]Privileges:[/bold] {priv_text}",
            title="[bold white]NETWORK INTELLIGENCE TOOLKIT[/bold white]",
            border_style="bright_blue",
        )
        console.print(meta_panel)
        console.print(table)
    except ImportError:
        sys_info = backend.get_platform_info()
        print(f"=== NETWORK INTELLIGENCE TOOLKIT ===")
        print(f"Platform: {sys_info.os_name} | Python: {sys_info.python_version}")
        for cap in backend.detect_capabilities().values():
            print(f" - {cap.name}: OS={cap.status.value}, Toolkit={cap.toolkit_status}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-intelligence",
        description="Cross-Platform Network Intelligence Toolkit for Kali Linux and Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode_group = parser.add_argument_group("Scan Modes")
    mutex_mode = mode_group.add_mutually_exclusive_group()
    mutex_mode.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan: system info, capabilities, interfaces, and default routing only.",
    )
    mutex_mode.add_argument(
        "--full",
        action="store_true",
        help="Full scan: baseline collection plus Wi-Fi, neighbors, and sockets.",
    )

    scope_group = parser.add_argument_group("Scope & Collector Control")
    scope_group.add_argument("-i", "--interface", type=str, help="Target network interface (e.g. eth0, wlan0, Wi-Fi)")
    scope_group.add_argument("--wifi", action="store_true", help="Inspect Wi-Fi connection and signal metrics")
    scope_group.add_argument("--neighbors", action="store_true", help="Inspect local ARP / neighbor cache")
    scope_group.add_argument("--sockets", action="store_true", help="Inspect local listening and active sockets")
    scope_group.add_argument(
        "--no-internet",
        action="store_true",
        help="Skip external public IP, ASN, and internet connectivity queries",
    )
    scope_group.add_argument(
        "--pcap",
        type=Path,
        help="Path to authorized PCAP/PCAPNG file for offline traffic analysis",
    )
    scope_group.add_argument(
        "--pcap-filter",
        type=str,
        default=None,
        help="Wireshark display filter to apply during PCAP analysis (e.g. 'dns', 'tcp.port == 80')",
    )

    diff_group = parser.add_argument_group("Snapshot & Comparison (Scheduled for Phase 10)")
    diff_group.add_argument("--snapshot", type=Path, help="Capture network state snapshot (scheduled for Phase 10)")
    diff_group.add_argument("--compare", type=Path, help="Compare current state against baseline snapshot (scheduled for Phase 10)")

    output_group = parser.add_argument_group("Output Formats")
    output_group.add_argument("--json", action="store_true", help="Output results in JSON format")
    output_group.add_argument("--html", action="store_true", help="Generate self-contained HTML cybersecurity dashboard (scheduled for Phase 11)")
    output_group.add_argument("-o", "--output", type=Path, help="Output destination file path for JSON report")
    output_group.add_argument("--capabilities", action="store_true", help="Display platform capability matrix and exit")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Validate unimplemented future options explicitly
    if args.snapshot is not None or args.compare is not None:
        print("[-] Error: --snapshot/--compare is not implemented yet (scheduled for Phase 10: Snapshot & Diff Engine).", file=sys.stderr)
        return 2
    if args.html:
        print("[-] Error: --html report generation is not implemented yet (scheduled for Phase 11: Multi-Format Reporting).", file=sys.stderr)
        return 2

    # Validate PCAP options
    if args.pcap_filter is not None and args.pcap is None:
        print("[-] Error: --pcap-filter requires --pcap to be specified.", file=sys.stderr)
        return 2

    # Validate that --output is only used with --json
    if args.output is not None and not args.json:
        print("[-] Error: --output currently requires --json format flag.", file=sys.stderr)
        return 2

    if args.no_internet and args.verbose:
        logger.debug("--no-internet flag is active (no external calls in Phase 1)")

    try:
        backend = get_platform_backend()
    except ToolkitError as err:
        print(f"[!] Platform Error: {err}", file=sys.stderr)
        return 1

    if args.capabilities:
        print_capability_banner(backend)
        return 0

    options = CollectorOptions(
        interface=args.interface,
        quick_mode=args.quick,
        full_mode=args.full,
        no_internet=args.no_internet,
        include_neighbors=args.neighbors,
        include_sockets=args.sockets,
        include_wifi=args.wifi,
        pcap_path=args.pcap,
        pcap_filter=args.pcap_filter,
        verbose=args.verbose,
    )

    coordinator = CollectorCoordinator(backend=backend, options=options)
    report = coordinator.collect()

    if args.json:
        report_data = report.to_dict()
        json_output = json.dumps(report_data, indent=2)
        if args.output:
            args.output.write_text(json_output, encoding="utf-8")
            print(f"[+] JSON report written to: {args.output}")
        else:
            print(json_output)
        return 0

    # Default terminal output
    print_capability_banner(backend)
    mode_str = "[Quick Scan]" if args.quick else ("[Full Scan]" if args.full else "[Standard Scan]")
    print(f"\n{mode_str}")
    if report.selected_interface:
        iface = report.selected_interface
        print(f"[+] Selected Active Interface: {iface.name}")
        print(f"    State:        {iface.state}")
        print(f"    MAC:          {iface.mac or 'Unknown'}")
        print(f"    MTU:          {iface.mtu or 'Unknown'}")
        if iface.speed_mbps:
            print(f"    Speed:        {iface.speed_mbps} Mbps")

        # IPv4 Network Details
        v4_nets = [n for n in iface.networks if n.ip_version == 4]
        if v4_nets:
            print("\n  IPv4 Subnet Information:")
            for net in v4_nets:
                if net.is_prefix_known and net.prefix_length is not None:
                    print(f"    Address:      {net.cidr or net.address}")
                    print(f"    Network:      {net.network}")
                    print(f"    Netmask:      {net.netmask}")
                    if net.broadcast:
                        print(f"    Broadcast:    {net.broadcast}")
                    if net.first_host and net.last_host:
                        if net.first_host == net.last_host:
                            print(f"    Host:         {net.first_host}")
                        else:
                            print(f"    Host Range:   {net.first_host} -> {net.last_host}")
                    print(f"    Total:        {net.total_addresses}")
                    print(f"    Usable Hosts: {net.usable_host_count}")
                else:
                    print(f"    Address:      {net.address} (prefix unavailable)")
                print(f"    Scope:        {net.scope}")
        elif iface.ipv4:
            print(f"    IPv4:         {', '.join(iface.ipv4)}")

        # IPv6 Network Details
        v6_nets = [n for n in iface.networks if n.ip_version == 6]
        if v6_nets:
            print("\n  IPv6 Network Information:")
            for net in v6_nets:
                if net.is_prefix_known and net.prefix_length is not None:
                    print(f"    Address:      {net.cidr or net.address}")
                    print(f"    Network:      {net.network}")
                    if net.first_host and net.last_host:
                        print(f"    Range:        {net.first_host} -> {net.last_host}")
                    print(f"    Total Addrs:  {net.total_addresses}")
                else:
                    print(f"    Address:      {net.address} (prefix unavailable)")
                print(f"    Scope:        {net.scope}")
        elif iface.ipv6:
            print(f"    IPv6:         {', '.join(iface.ipv6)}")
    else:
        print("[-] No active network interface detected.")

    # Routing Information (Quick, Default, and Full modes)
    if report.routing:
        print("\nRouting")
        print("─" * 32)
        if report.routing.default_ipv4:
            r4 = report.routing.default_ipv4
            print("\nIPv4 Default Route")
            print(f"  Destination: {r4.destination}")
            print(f"  Gateway:     {r4.gateway or 'Direct link'}")
            print(f"  Interface:   {r4.interface or 'Unknown'}")
            print(f"  Metric:      {r4.metric if r4.metric is not None else 'Unknown'}")
        else:
            print("\nIPv4 Default Route: Not configured")

        if report.routing.default_ipv6:
            r6 = report.routing.default_ipv6
            print("\nIPv6 Default Route")
            print(f"  Destination: {r6.destination}")
            print(f"  Gateway:     {r6.gateway or 'Direct link'}")
            print(f"  Interface:   {r6.interface or 'Unknown'}")
            print(f"  Metric:      {r6.metric if r6.metric is not None else 'Unknown'}")
        else:
            print("\nIPv6 Default Route: Not configured")

        if report.routing.selection_reason and args.verbose:
            print(f"\nSelection Reason: {report.routing.selection_reason}")

    # DNS Information (excluded in quick mode)
    if not args.quick and report.dns:
        print("\nDNS")
        print("─" * 32)
        if report.dns.is_stub:
            print(f"\nLocal Resolver: {report.dns.stub_address or '127.0.0.53'}")
            print("Role:           LOCAL_STUB")
            if report.dns.upstream_servers:
                print("\nUpstream Resolvers:")
                for s in report.dns.upstream_servers:
                    print(f"  {s.address} (Family: IPv{s.family}, Interface: {s.interface or 'global'}, Protocol: {s.protocol})")
            else:
                print(f"Upstream:       Available through {report.dns.source}")
        elif report.dns.servers:
            print("\nResolvers:")
            for s in report.dns.servers:
                print(f"  {s.address}")
                print(f"    Family:    IPv{s.family}")
                print(f"    Protocol:  {s.protocol}")
                if s.interface:
                    print(f"    Interface: {s.interface}")
                if s.source:
                    print(f"    Source:    {s.source}")
                if s.doh_template:
                    print(f"    DoH URL:   {s.doh_template}")
        else:
            print("\nResolvers:      None configured")

        if report.dns.search_domains:
            print(f"\nSearch Domains: {', '.join(report.dns.search_domains)}")
        else:
            print("\nSearch Domains: None")

        print(f"Source:         {report.dns.source}")
        print(f"Status:         {report.dns.status}")

    # DHCP Information (excluded in quick mode)
    if not args.quick and report.dhcp:
        print("\nDHCP")
        print("─" * 32)
        print(f"Status:         {report.dhcp.status}")
        if report.dhcp.server:
            print(f"DHCP Server:    {report.dhcp.server}")
        else:
            print("DHCP Server:    Unknown / None")
        if report.dhcp.address:
            print(f"Client IP:      {report.dhcp.address}")
        if report.dhcp.router:
            print(f"Gateway:        {report.dhcp.router}")
        if report.dhcp.subnet_mask:
            print(f"Subnet Mask:    {report.dhcp.subnet_mask}")
        if report.dhcp.lease_start:
            print(f"Lease Obtained: {report.dhcp.lease_start}")
        if report.dhcp.lease_expiry:
            print(f"Lease Expires:  {report.dhcp.lease_expiry}")
        if report.dhcp.lease_duration is not None:
            hours = report.dhcp.lease_duration / 3600.0
            print(f"Lease Duration: {report.dhcp.lease_duration}s ({hours:.1f}h)")
        if report.dhcp.interface:
            print(f"Interface:      {report.dhcp.interface}")
        if report.dhcp.source:
            print(f"Source:         {report.dhcp.source}")

    # Wi-Fi Information (excluded in quick mode; shown if --wifi, --full, or report.wifi is present)
    if not args.quick and report.wifi:
        print("\nWi-Fi")
        print("─" * 32)
        print(f"State:          {report.wifi.state}")
        if report.wifi.interface:
            print(f"Interface:      {report.wifi.interface}")
        if report.wifi.state == "CONNECTED":
            if report.wifi.ssid:
                print(f"SSID:           {report.wifi.ssid}")
            if report.wifi.bssid:
                print(f"BSSID:          {report.wifi.bssid}")
            if report.wifi.channel is not None or report.wifi.frequency_mhz is not None:
                ch_str = str(report.wifi.channel) if report.wifi.channel is not None else "Unknown"
                freq_str = f" ({report.wifi.frequency_mhz} MHz)" if report.wifi.frequency_mhz is not None else ""
                print(f"Channel:        {ch_str}{freq_str}")
            if report.wifi.signal_percent is not None or report.wifi.signal_dbm is not None:
                pct_str = ""
                if report.wifi.signal_percent is not None:
                    if getattr(report.wifi, "signal_percent_estimated", False):
                        pct_str = f"estimated {report.wifi.signal_percent}%"
                    else:
                        pct_str = f"{report.wifi.signal_percent}%"

                dbm_str = ""
                if report.wifi.signal_dbm is not None:
                    if getattr(report.wifi, "signal_dbm_estimated", False):
                        dbm_str = f"(estimated RSSI: {report.wifi.signal_dbm} dBm)"
                    else:
                        dbm_str = f"({report.wifi.signal_dbm} dBm)"

                if pct_str and dbm_str:
                    print(f"Signal:         {pct_str} {dbm_str}")
                elif pct_str:
                    print(f"Signal:         {pct_str}")
                elif dbm_str:
                    print(f"Signal:         {dbm_str}")
            if report.wifi.rx_rate_mbps is not None or report.wifi.tx_rate_mbps is not None:
                rx_str = f"{report.wifi.rx_rate_mbps} Mbps" if report.wifi.rx_rate_mbps is not None else "Unknown"
                tx_str = f"{report.wifi.tx_rate_mbps} Mbps" if report.wifi.tx_rate_mbps is not None else "Unknown"
                print(f"Link Rate:      RX: {rx_str} / TX: {tx_str}")
            if report.wifi.wifi_standard and report.wifi.wifi_standard != "UNKNOWN":
                print(f"Standard:       {report.wifi.wifi_standard}")
            if report.wifi.security_mode and report.wifi.security_mode != "UNKNOWN":
                raw_info = f" ({report.wifi.raw_security})" if report.wifi.raw_security else ""
                print(f"Security:       {report.wifi.security_mode}{raw_info}")
        elif report.wifi.state == "NOT_APPLICABLE":
            print("Reason:         Non-wireless interface")
        elif report.wifi.state == "DISCONNECTED":
            print("Link:           Disconnected from network")

    # Public Internet Identity & ASN (excluded in quick mode; shown if report.public_ip is present)
    if not args.quick and report.public_ip:
        print("\nPublic Internet Identity & ASN")
        print("─" * 32)
        print(f"Status:             {report.public_ip.status}")
        if report.public_ip.reason:
            print(f"Details:            {report.public_ip.reason}")
        if report.public_ip.available:
            if report.public_ip.ipv4:
                print(f"Observed Public IPv4: {report.public_ip.ipv4}")
            if report.public_ip.ipv6:
                print(f"Observed Public IPv6: {report.public_ip.ipv6}")
            if report.public_ip.ip:
                print(f"Metadata Target:      {report.public_ip.ip} (IPv{report.public_ip.ip_version})")
            if report.public_ip.reverse_dns:
                print(f"Reverse DNS (PTR):    {report.public_ip.reverse_dns}")
            if report.public_ip.asn:
                print(f"ASN:                  {report.public_ip.asn}")
            if report.public_ip.as_org:
                print(f"AS Organization:      {report.public_ip.as_org}")
            if report.public_ip.isp:
                print(f"ISP:                  {report.public_ip.isp}")
            location_parts = [p for p in (report.public_ip.city, report.public_ip.region, report.public_ip.country) if p]
            if location_parts:
                loc_str = ", ".join(location_parts)
                print(f"Location:             {loc_str} ({report.public_ip.geolocation_accuracy})")
            if report.public_ip.cgnat_detected:
                addr_info = f" ({report.public_ip.cgnat_local_address} on {report.public_ip.cgnat_interface})" if report.public_ip.cgnat_local_address else ""
                print(f"Carrier-Grade NAT:    Detected{addr_info} - Local IPv4 address is within RFC 6598 Shared Address Space (100.64.0.0/10)")
            if report.public_ip.sources:
                sources_str = ", ".join(f"{k}: {v}" for k, v in report.public_ip.sources.items())
                print(f"Field Provenance:     {sources_str}")
            elif report.public_ip.source:
                print(f"Lookup Source:        {report.public_ip.source}")
            if report.public_ip.disclaimer:
                print(f"Disclaimer:           {report.public_ip.disclaimer}")
        elif report.public_ip.cgnat_detected:
            addr_info = f" ({report.public_ip.cgnat_local_address} on {report.public_ip.cgnat_interface})" if report.public_ip.cgnat_local_address else ""
            print(f"Carrier-Grade NAT:    Detected{addr_info} - Local IPv4 address is within RFC 6598 Shared Address Space (100.64.0.0/10)")

    # Safe Connectivity Probes (Phase 6: excluded in quick mode)
    if not args.quick and report.connectivity:
        conn = report.connectivity
        print("\nConnectivity")
        print("─" * 32)

        # 1. Gateway
        if conn.gateway:
            gw = conn.gateway
            print("\nGateway")
            print(f"  Target:        {gw.target}")
            print(f"  Status:        {gw.status}")
            if gw.latency_ms is not None:
                print(f"  Latency:       {gw.latency_ms:.2f} ms")
            if gw.packet_loss_pct is not None:
                print(f"  Packet Loss:   {gw.packet_loss_pct:.0f}%")
            if gw.details and gw.status != "SUCCESS":
                print(f"  Details:       {gw.details}")

        # 2. DNS
        print("\nDNS")
        if args.no_internet:
            print("  Status:        DISABLED")
            print("  Details:       --no-internet flag specified")
        else:
            dns_targets = [t for t in conn.all_targets if t.name.startswith("dns_") and t.name != "dns_aggregate"]
            if dns_targets:
                for dt in dns_targets:
                    print(f"  {dt.target}")
                    print(f"    Status:       {dt.status}")
                    if dt.latency_ms is not None:
                        print(f"    Latency:      {dt.latency_ms:.1f} ms")
                    if dt.details:
                        if "Resolved" in dt.details:
                            addrs = dt.details.split(":", 1)[-1].strip()
                            print(f"    Resolved Addresses: {addrs}")
                        elif dt.status != "SUCCESS":
                            print(f"    Details:      {dt.details}")
            elif conn.dns:
                print(f"  Status:        {conn.dns.status}")
                if conn.dns.details:
                    print(f"  Details:       {conn.dns.details}")

        # 3. Internet HTTP
        print("\nInternet HTTP")
        if args.no_internet:
            print("  Status:        DISABLED")
            print("  Details:       --no-internet flag specified")
        else:
            http_targets = [t for t in conn.all_targets if t.name == "internet_http"]
            if http_targets:
                for ht in http_targets:
                    print(f"  {ht.target}")
                    print(f"    Status:       {ht.status}")
                    if ht.http_status is not None:
                        print(f"    HTTP Status:  {ht.http_status}")
                    if ht.latency_ms is not None:
                        print(f"    Latency:      {ht.latency_ms:.1f} ms")
                    if ht.details and ht.status != "SUCCESS":
                        print(f"    Details:      {ht.details}")
            elif conn.internet:
                print(f"  Status:        {conn.internet.status}")
                if conn.internet.details:
                    print(f"  Details:       {conn.internet.details}")

        # 4. IPv4 Connectivity
        print("\nIPv4 Connectivity")
        if conn.ipv4:
            v4 = conn.ipv4
            print(f"  Status:         {v4.status}")
            if v4.status == "SUCCESS":
                print(f"  Target:         {v4.target}")
                if v4.latency_ms is not None:
                    print(f"  Latency:        {v4.latency_ms:.1f} ms")
            elif v4.details:
                print(f"  Details:        {v4.details}")

        # 5. IPv6 Connectivity
        print("\nIPv6 Connectivity")
        if conn.ipv6:
            v6 = conn.ipv6
            print(f"  Status:         {v6.status}")
            if v6.status == "SUCCESS":
                print(f"  Target:         {v6.target}")
                if v6.latency_ms is not None:
                    print(f"  Latency:        {v6.latency_ms:.1f} ms")
            elif v6.details:
                print(f"  Details:        {v6.details}")

    # Neighbors / ARP Table (Phase 7: included in full mode or --neighbors, excluded in quick mode)
    if options.should_collect_neighbors():
        print("\nNeighbors / ARP Table")
        print("─" * 32)
        if report.neighbors:
            header = f"{'IP Address':<20} {'MAC Address':<20} {'Interface':<15} {'State':<12} {'Router':<8}"
            print(header)
            print("─" * len(header))
            for n in report.neighbors:
                router_str = "Yes" if n.is_router else "No"
                print(f"{n.ip_address:<20} {n.mac_address:<20} {n.interface:<15} {n.state:<12} {router_str:<8}")
        else:
            print("No neighbor entries found in local cache.")

    # Local Sockets & Ports (Phase 7: included in full mode or --sockets, excluded in quick mode)
    if options.should_collect_sockets():
        print("\nLocal Sockets & Ports")
        print("─" * 32)
        if report.sockets:
            header = f"{'Proto':<6} {'Local Endpoint':<25} {'Remote Endpoint':<25} {'State':<13} {'PID':<8} {'Process':<20}"
            print(header)
            print("─" * len(header))
            for s in report.sockets:
                local_ep = f"{s.local_address}:{s.local_port}"
                if s.remote_address and s.remote_port is not None:
                    remote_ep = f"{s.remote_address}:{s.remote_port}"
                elif s.remote_address:
                    remote_ep = str(s.remote_address)
                else:
                    remote_ep = "*:*"
                pid_str = str(s.pid) if s.pid is not None else "-"
                proc_str = s.process_name if s.process_name else "-"
                print(f"{s.protocol:<6} {local_ep:<25} {remote_ep:<25} {s.state:<13} {pid_str:<8} {proc_str:<20}")
        else:
            print("No listening or active sockets found.")

    # PCAP Analysis (Phase 8: offline capture analysis)
    if report.pcap_analysis or (options.should_analyze_pcap() and report.pcap):
        pcap = report.pcap_analysis or report.pcap
        print("\nPCAP Analysis")
        print("─" * 32)
        if pcap:
            file_name = Path(pcap.file_path).name if pcap.file_path else "Unknown"
            print(f"Capture File:         {file_name}")
            if pcap.file_format:
                print(f"Format:               {pcap.file_format}")
            if pcap.file_size_bytes is not None:
                size_mb = pcap.file_size_bytes / (1024 * 1024)
                if size_mb >= 1.0:
                    print(f"Size:                 {size_mb:.1f} MB")
                else:
                    print(f"Size:                 {pcap.file_size_bytes / 1024:.1f} KB")
            if pcap.status == "ERROR" or not pcap.available:
                print(f"Status:               {pcap.status}")
                if pcap.reason:
                    print(f"Reason:               {pcap.reason}")
            else:
                print(f"Packets Analyzed:     {pcap.packet_count:,}")
                if pcap.packets_dropped is not None:
                    print(f"Packets Dropped:      {pcap.packets_dropped:,}")
                if pcap.duration_seconds is not None:
                    print(f"Duration:             {pcap.duration_seconds:.2f} s")
                if pcap.avg_packet_rate_pps is not None and pcap.avg_bit_rate_bps is not None:
                    mbps = pcap.avg_bit_rate_bps / 1_000_000
                    print(f"Average Rate:         {pcap.avg_packet_rate_pps:.1f} packets/s ({mbps:.1f} Mbps)")
                status_display = pcap.status
                if pcap.truncated:
                    status_display += " (Truncated: exceeded packet or byte limit)"
                print(f"Status:               {status_display}")

                def _pcap_get(obj: Any, key: str, default: Any = None) -> Any:
                    if obj is None:
                        return default
                    if isinstance(obj, dict):
                        return obj.get(key, default)
                    return getattr(obj, key, default)

                # Top Protocols
                if pcap.protocols:
                    print("\nTop Protocols:")
                    total_pkts = pcap.packet_count or 1
                    for proto in pcap.protocols[:5]:
                        proto_name = _pcap_get(proto, "protocol", "")
                        proto_pkts = _pcap_get(proto, "packet_count", 0)
                        pct = (proto_pkts / total_pkts) * 100
                        print(f"  {proto_name:<18} {proto_pkts:>8,} ({pct:4.1f}%)")

                # Top Endpoints
                if pcap.endpoints:
                    print("\nTop Endpoints:")
                    for ep in pcap.endpoints[:5]:
                        addr = _pcap_get(ep, "address", "")
                        pkts = _pcap_get(ep, "packet_count", 0)
                        print(f"  {addr:<20} {pkts:>8,} packets")

                # Top Conversations
                if pcap.conversations:
                    print("\nTop Conversations:")
                    for conv in pcap.conversations[:5]:
                        ep_a = _pcap_get(conv, "endpoint_a", "")
                        port_a = _pcap_get(conv, "port_a")
                        ep_b = _pcap_get(conv, "endpoint_b", "")
                        port_b = _pcap_get(conv, "port_b")
                        conv_pkts = _pcap_get(conv, "packet_count", 0)
                        ep_a_str = f"{ep_a}:{port_a}" if port_a is not None else str(ep_a)
                        ep_b_str = f"{ep_b}:{port_b}" if port_b is not None else str(ep_b)
                        pair = f"{ep_a_str} <-> {ep_b_str}"
                        print(f"  {pair:<36} {conv_pkts:>8,} packets")

                # DNS Summary
                dns = pcap.dns_summary or pcap.dns
                dns_queries = _pcap_get(dns, "total_queries", 0) or _pcap_get(dns, "query_count", 0)
                dns_responses = _pcap_get(dns, "total_responses", 0) or _pcap_get(dns, "response_count", 0)
                if dns and (dns_queries > 0 or dns_responses > 0):
                    unres = _pcap_get(dns, "unresolved_queries", 0)
                    print(f"\nDNS Summary:")
                    print(f"  Queries: {dns_queries:,} | Responses: {dns_responses:,} | Unresolved: {unres:,}")
                    top_doms = _pcap_get(dns, "top_queried_domains", []) or _pcap_get(dns, "top_queries", [])
                    if top_doms:
                        print("  Top Domains:")
                        for item in top_doms[:5]:
                            if isinstance(item, (tuple, list)) and len(item) >= 2:
                                dom, cnt = item[0], item[1]
                            elif isinstance(item, dict):
                                dom, cnt = item.get("name", ""), item.get("count", 0)
                            else:
                                dom, cnt = str(item), 1
                            print(f"    {dom} ({cnt:,} queries)")

                # HTTP Summary
                http = pcap.http_summary or pcap.http
                http_requests = _pcap_get(http, "total_requests", 0) or _pcap_get(http, "request_count", 0)
                http_responses = _pcap_get(http, "total_responses", 0) or _pcap_get(http, "response_count", 0)
                if http and (http_requests > 0 or http_responses > 0):
                    print(f"\nHTTP Summary:")
                    print(f"  Requests: {http_requests:,} | Responses: {http_responses:,}")
                    top_h = _pcap_get(http, "top_hosts", [])
                    if top_h:
                        print("  Top Hosts:")
                        for item in top_h[:5]:
                            if isinstance(item, (tuple, list)) and len(item) >= 2:
                                host, cnt = item[0], item[1]
                            elif isinstance(item, dict):
                                host, cnt = item.get("host", ""), item.get("count", 0)
                            else:
                                host, cnt = str(item), 1
                            print(f"    {host} ({cnt:,} requests)")

                # TLS Summary
                tls = pcap.tls_summary or pcap.tls
                tls_sessions = _pcap_get(tls, "total_sessions", 0) or _pcap_get(tls, "session_count", 0)
                top_snis = _pcap_get(tls, "top_server_names", []) or _pcap_get(tls, "sni_list", [])
                if tls and (tls_sessions > 0 or top_snis):
                    print(f"\nTLS Summary:")
                    print(f"  Sessions: {tls_sessions:,}")
                    if top_snis:
                        print("  Top SNIs:")
                        for item in top_snis[:5]:
                            if isinstance(item, (tuple, list)) and len(item) >= 2:
                                sni, cnt = item[0], item[1]
                            elif isinstance(item, dict):
                                sni, cnt = item.get("sni", ""), item.get("count", 0)
                            else:
                                sni, cnt = str(item), 1
                            print(f"    {sni} ({cnt:,})")

                # TCP Diagnostics
                tcp = pcap.tcp_summary or pcap.tcp
                if tcp and pcap.packet_count > 0:
                    total_pkts = pcap.packet_count
                    retrans = _pcap_get(tcp, "retransmissions", 0) or _pcap_get(tcp, "retransmission_count", 0)
                    dup_ack = _pcap_get(tcp, "duplicate_acks", 0) or _pcap_get(tcp, "duplicate_ack_count", 0)
                    zero_win = _pcap_get(tcp, "zero_window_advertisements", 0) or _pcap_get(tcp, "zero_window_count", 0)
                    rst = _pcap_get(tcp, "rst_flag_count", 0) or _pcap_get(tcp, "rst_count", 0)

                    retrans_pct = (retrans / total_pkts) * 100
                    dup_ack_pct = (dup_ack / total_pkts) * 100
                    zero_win_pct = (zero_win / total_pkts) * 100
                    rst_pct = (rst / total_pkts) * 100
                    print(f"\nTCP Diagnostics:")
                    print(f"  Retransmissions:    {retrans:>6,} ({retrans_pct:.2f}%)")
                    print(f"  Duplicate ACKs:     {dup_ack:>6,} ({dup_ack_pct:.2f}%)")
                    print(f"  Zero Window:        {zero_win:>6,} ({zero_win_pct:.2f}%)")
                    print(f"  RST Flags:          {rst:>6,} ({rst_pct:.2f}%)")

    # Observations & Findings (Phase 9)
    if report.observations:
        print("\nObservations")
        print("─" * 32)
        for obs in report.observations:
            print(f"[{obs.severity}] {obs.id}")
            print(f"{obs.summary}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())

# DHCP and Wi-Fi console table rendering

# Public Internet Identity & ASN terminal rendering

# Connectivity diagnostic tables console rendering

# Connectivity TIMEOUT badge formatting
