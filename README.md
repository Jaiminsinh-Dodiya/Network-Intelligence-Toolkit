# Network Intelligence Toolkit

A modular, cross-platform CLI network diagnostics and intelligence toolkit designed for **Kali Linux** and **Windows 10/11**.

The toolkit automatically inspects, normalizes, and reports local network configuration, routing, DNS, DHCP, Wi-Fi link parameters, public Internet identity, sockets, neighbors, and authorized packet captures.

---

## Safety & Ethics Boundary

This tool is strictly designed for **authorized network diagnostics, visibility, learning, and assessment** on machines and networks you own or are explicitly authorized to test.

The application intentionally **does not** implement:
* Credential harvesting or extraction (no authentication headers, cookies, tokens, or passwords parsed or stored)
* Live packet capture or sniffing (`tshark -i` or `--interface` strictly forbidden)
* Packet injection, replay, transmission, or traffic generation
* Packet sniffing intended to intercept private communications of others
* Password cracking or hash dumping
* Stealth, persistence, or rootkit techniques
* Exploitation or unauthorized network attacks
* Modification or alteration of provided capture files (strictly read-only)

---

## Architecture Overview

The application is structured into decoupled layers where the core engine interacts exclusively with normalized models and an abstract platform interface:

```text
┌─────────────────────────────────────────────────────────┐
│                       CLI / UI                          │
│               (main.py, Rich Terminal)                  │
├─────────────────────────────────────────────────────────┤
│                   Execution Engine                      │
│             (core/collector.py, registry.py)            │
├─────────────────────────────────────────────────────────┤
│                 Analysis & Reporting                    │
│                 (JSON, Terminal, HTML)                  │
├─────────────────────────────────────────────────────────┤
│                   Normalized Models                     │
│                   (core/models.py)                      │
├─────────────────────────────────────────────────────────┤
│               Platform Abstraction API                  │
│                 (backends/base.py)                      │
├────────────────────────────┬────────────────────────────┤
│       Linux Backend        │      Windows Backend       │
│    (backends/linux/)       │    (backends/windows/)     │
│   ip, ss, iw, nmcli, /sys  │  PowerShell, NetAdapter,   │
│   /proc, resolvectl, dhcp  │  NetRoute, NetTCP, netsh   │
└────────────────────────────┴────────────────────────────┘
```

---

## Current Implementation Status (Phase 9)

| Feature / Subsystem | Status | Implementation Details |
|---|---|---|
| **CLI & Argument Parser** | **Implemented** | `--quick`, `--full` (mutually exclusive), `-i`, `--wifi`, `--neighbors`, `--sockets`, `--pcap`, `--pcap-filter`, `--json`, `--output`, `--capabilities`, `--no-internet` |
| **Centralized Platform Factory** | **Implemented** | `backends.get_platform_backend()` auto-detects Windows vs Linux |
| **Normalized Models** | **Implemented** | Strongly-typed Python dataclasses in `core/models.py` |
| **Capability Detection** | **Implemented** | Runtime tracking (`AVAILABLE`, `PARTIAL`, `UNAVAILABLE`, `MISSING_DEPENDENCY`, etc.) |
| **Subnet & Network Engine** | **Implemented (Phase 2)** | Mathematical normalization of IPv4/IPv6 networks, CIDR, netmasks, broadcast, and host boundaries |
| **Special Prefix Support** | **Implemented (Phase 2)** | Proper RFC 3021 (/31 ptp), /32 host routes, RFC 6164 (/127 IPv6), /128, and standard subnets |
| **Address Scope Classification**| **Implemented (Phase 2)** | Scopes: `GLOBAL`, `PRIVATE`, `LINK_LOCAL`, `LOOPBACK`, `MULTICAST`, `UNSPECIFIED` |
| **Interface Selection Groundwork**|**Implemented (Phase 2)** | Traffic-aware scoring prioritizing active non-virtual adapters |
| **JSON Export** | **Implemented** | `--json` outputs structured schema with all interface network entries |
| **Routing Table Collector** | **Implemented (Phase 3)** | Cross-platform IPv4/IPv6 default routing, metrics, and policy rules |
| **DNS Configuration** | **Implemented (Phase 3)** | Resolvers, search domains, conservative DoH/DoT transport, and stub detection |
| **DHCP Lease Collector** | **Implemented (Phase 4)** | Windows WMI/CimInstance, Linux systemd-networkd, dhclient, nmcli, and route fallback |
| **Wi-Fi Link Analysis** | **Implemented (Phase 4)** | Windows `netsh wlan`, Linux `iw`/`nmcli`; canonical BSSID, frequencies, signal, rates, standards |
| **Public IP / ASN Geolocation** | **Implemented (Phase 5)** | Safe, read-only external lookups with data-driven fallback, field-level provenance, dual-stack, and strict privacy |
| **Safe Connectivity Probes** | **Implemented (Phase 6)** | Non-intrusive latency, packet loss, DNS, HTTP, and IPv4/IPv6 TCP reachability |
| **Neighbor / ARP Table** | **Implemented (Phase 7)** | Passive local ARP/neighbor inspection (Windows `Get-NetNeighbor`, Linux `ip neigh` / `/proc/net/arp`) |
| **Socket & Port Summary** | **Implemented (Phase 7)** | Local TCP/UDP sockets and process attribution (Windows `Get-NetTCPConnection`, Linux `ss -tunapn -H`) |
| **Authorized PCAP/PCAPNG Engine** | **Implemented (Phase 8)** | Bounded, read-only offline packet analysis with TShark (protocols, endpoints, conversations, DNS, HTTP, TLS, TCP, timeline) |
| **Observations & Findings Engine** | **Implemented (Phase 9)** | Deterministic, evidence-backed security observations correlating collector telemetry with strict privacy & bounds |
| **Snapshot & Diff Engine** | *Planned (Phase 10)* | `--snapshot` and `--compare` baseline tracking |
| **HTML Dashboard** | *Planned (Phase 11)* | Self-contained cybersecurity reporting dashboard |

---

## Subnet & Network Engine Documentation (Phase 2)

The toolkit incorporates a cross-platform network calculation engine (`core/network.py`) leveraging Python's `ipaddress` standard library:

### 1. IPv4 Subnet Mathematics
* **Standard Subnets (/1 to /29)**: Calculates network address, netmask, broadcast address, first usable host, last usable host, total addresses ($2^{32-p}$), and usable hosts ($2^{32-p} - 2$).
* **/30 Subnets**: 4 total addresses, 2 usable hosts (.1 and .2), network on .0, broadcast on .3.
* **/31 Point-to-Point Links (RFC 3021)**: 2 total addresses, 2 usable hosts (.0 and .1), broadcast is `None`.
* **/32 Single Host Routes**: 1 total address, 1 usable host, broadcast is `None`.

### 2. IPv6 Network Mathematics
* Calculates prefix length, network address, first address (`net[0]`), last address (`net[-1]`), and total addresses ($2^{128-p}$).
* **Broadcast**: In conformance with IPv6 standards, broadcast is strictly `None`.
* **/127 Point-to-Point (RFC 6164)**: 2 addresses, both usable hosts.
* **/128 Loopback/Host**: 1 address, 1 usable host.

### 3. Address Reachability Scope Classification
* Addresses are categorized using standardized architectural scopes:
  * `LOOPBACK` (`127.0.0.0/8`, `::1/128`)
  * `LINK_LOCAL` (`169.254.0.0/16`, `fe80::/10`)
  * `PRIVATE` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
  * `GLOBAL` (Public Internet routable)
  * `MULTICAST` (`224.0.0.0/4`, `ff00::/8`)
  * `UNSPECIFIED` (`0.0.0.0`, `::`)

### 4. Multiple Address Preservation
* Interfaces with multiple IPv4 and IPv6 addresses preserve all discovered allocations in `InterfaceInfo.networks` without overwriting.

### Platform Validation Status
* **Windows 10/11**: **Validated & Passing** (Tested live on Windows 11 host with Python 3.12).
* **Kali Linux**: **Not Yet Validated on Live Hardware** (Platform abstraction and Linux backend contracts tested via unit tests; live testing planned on Kali environment).

---

## Routing & DNS Engine Documentation (Phase 3)

### 1. Cross-Platform Routing
* **Windows Route & Interface Metric Calculation**:
  * Queries `Get-NetRoute` for route metrics (`RouteMetric`) and `Get-NetIPInterface` for interface metrics (`InterfaceMetric`).
  * Computes `effective_metric = RouteMetric + InterfaceMetric` by joining on `InterfaceIndex` and address family.
  * Filters for active routes (`State == 'Alive'`). Inactive routes (e.g. `State == 'Dead'`) remain preserved in `ipv4_routes` and `ipv6_routes`, but are strictly excluded from active default route selection.
* **Linux iproute2 Routing**:
  * Queries `ip -j route` (IPv4) and `ip -j -6 route` (IPv6), with automatic fallbacks to plain text `ip route show` and `/proc/net/route` (decoding hex addresses and netmasks).
* **Linux Policy-Routing Rules & Limitation**:
  * **Policy Routing**: Detected via `ip -j rule` (or `ip rule show`) and preserved as metadata in `RoutingInfo.rules`.
  * **Preferred Default Route**: Evaluated using the lowest metric among parsed active default routes.
  * **Effective Destination-Specific Route**: Not fully evaluated yet (kernel destination-rule emulation is deferred).

### 2. DNS Engine & Transport Detection
* **Conservative Transport Detection**:
  * Transport protocol strictly defaults to `UNKNOWN` and is never assumed to be plaintext UDP.
  * `DoH` (DNS-over-HTTPS) is only reported when verified via configured DoH server templates (e.g. Windows `Get-DnsClientDohServerAddress`).
  * `DoT` (DNS-over-TLS) is only reported when verified via link protocol status (e.g. Linux `resolvectl status` with `+DNSOverTLS`).
  * **Link-Specific Scope**: On Linux `systemd-resolved`, `+DNSOverTLS` state is strictly scoped per network interface link and does not leak across link boundaries.
* **DNS Source Precedence**:
  * **Linux**: Prioritizes `systemd-resolved` (`resolvectl status`), falling back to `/etc/resolv.conf`, then NetworkManager (`nmcli dev show`).
  * **Windows**: Native PowerShell DNS client cmdlets (`Get-DnsClientServerAddress`, `Get-DnsClientGlobalSetting`, `Get-DnsClientDohServerAddress`).
* **Local Stub Detection**:
  * Identifies `systemd-resolved` local stubs (`127.0.0.53`, `127.0.0.54`) and marks their role as `LOCAL_STUB`, categorizing non-stub resolvers as `UPSTREAM_RESOLVER`.
* **Primary Resolver Semantics**:
  * `is_primary` is `True` only when the operating system explicitly designates a server as current/preferred (e.g. `Current DNS Server:` in `resolvectl`). It is never inferred from enumeration order.

---

## DHCP & Wi-Fi Intelligence Documentation (Phase 4)

### 1. Cross-Platform DHCP Intelligence
* **Explicit Status Model**: Reports standardized statuses: `CONFIGURED`, `PARTIAL`, `NOT_DHCP`, `UNAVAILABLE`, and `ERROR`.
* **Separation of Gateway and DHCP Server**:
  * On Linux systems where lease files are absent but the default route has `proto dhcp`, the toolkit reports `status = PARTIAL`, `server = None` (Unknown), and preserves the gateway in `router`. It strictly **never** copies the gateway address into the DHCP server field.
  * `NOT_DHCP` is never inferred solely from `proto static`; only explicit platform evidence of disabled DHCP triggers `NOT_DHCP`.
* **Interface-Specific Lease Isolation**:
  * **systemd-networkd**: Resolves kernel ifindex via `/sys/class/net/<iface>/ifindex` to access exact `/run/systemd/netif/leases/<ifindex>`. Never falls back to arbitrary lease files when an explicit interface is requested.
  * **ISC dhclient**: In `/var/lib/dhcp/dhclient*.leases`, blocks missing an explicit `interface "<iface>";` statement are rejected when a target interface is specified to avoid unsafe attribution.
* **Duration Support**: Supports lease duration independently without fabricating unobserved `lease_start` or `lease_expiry` timestamps.
* **Backward-Compatible Field Sync**: Canonical fields (`server`, `address`, `lease_start`, `lease_expiry`, `lease_duration`, `enabled`) remain bidirectionally synchronized with legacy aliases (`server_ip`, `assigned_ip`, `lease_obtained`, `lease_expires`, `lease_duration_seconds`, `available`).

### 2. Wi-Fi Intelligence & Radio Metrics
* **Strict Security Boundary**: Read-only host inspection. Strictly **never** queries, extracts, or exposes Wi-Fi passwords, security keys, or PSKs.
* **Interface Precedence & Selection**:
  * `--interface <name>` is authoritative. Specifying a non-wireless adapter with `--wifi` (e.g. `--interface Ethernet --wifi`) cleanly returns `state = NOT_APPLICABLE` without silent replacement.
  * Automatic selection (when `--wifi` is passed without `--interface`) implements strict priority:
    1. Connected wireless interface (via `iw dev <iface> link`)
    2. Wireless interface that is UP
    3. First available wireless interface
* **Signal Provenance & Heuristic Conversions**:
  * Signal quality percentage to RSSI dBm conversions are documented as approximate linear heuristics.
  * Data provenance is explicitly tracked via `signal_percent_estimated` and `signal_dbm_estimated`. When the OS directly supplies RSSI (such as `Rssi : -44` in Windows 11 `netsh` or `signal: -54 dBm` in Linux `iw`), `signal_dbm_estimated` is `False`. When derived, it is marked estimated and rendered as `(estimated RSSI: ...)` in the terminal.
* **Canonical Formatting**:
  * BSSID is normalized to lowercase colon-delimited format (`aa:bb:cc:dd:ee:ff`).
  * Frequencies and channels are mapped across 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E / Wi-Fi 7). Unambiguous mapping requires an explicit frequency band; channel-only lookups without band return `None`.
  * Security modes are normalized to canonical categories (`OPEN`, `WEP`, `WPA`, `WPA2`, `WPA3`, `WPA2-ENTERPRISE`, `WPA3-ENTERPRISE`, `OTHER`, `UNKNOWN`). Generic `Enterprise` without explicit WPA2/WPA3 designation maps to `OTHER` and never infers `WPA2-ENTERPRISE`. Original OS string is preserved in `raw_security`.
  * 802.11 radio standards (`802.11ax`, `802.11ac`, `802.11n`, `802.11g`, etc.) are reported strictly when exposed by the operating system, and never inferred from bitrate or frequency.

---

## Public Internet Identity & ASN Intelligence (Phase 5)

Phase 5 equips the toolkit with safe, read-only external lookups to discover the host's public Internet presence, autonomous system profile, and network perimeter characteristics.

### 1. Architectural Distinction: Local View vs. External View
* **Local View (Authoritative OS Subsystem)**:
  * The operating system's local routing table and interface stack remain authoritative for: Default Route, Default Gateway, Default Interface, and local IP assignments.
* **External View (Observed Identity)**:
  * External services report the public IP address observed as the source for egress requests.
  * Terminology: `Observed Public IPv4`, `Observed Public IPv6`, and `Primary Observed Public IP`.
  * This distinction is vital for multi-WAN, VPN tunnels, HTTP proxies, policy-based routing, and Carrier-Grade NAT (CGNAT) topologies.

### 2. Data-Driven Provider Architecture & Capability Model
* Configured declaratively via `config/config.yaml` (`public_ip.providers`).
* Pluggable provider implementations (`core/public_ip/`):
  * `IPApiProvider`: IP, ASN, AS Organization, Geolocation (`ipapi.co`).
  * `IPWhoisProvider`: IP, ASN, AS Organization, ISP, Geolocation (`ipwhois.app`).
  * `IpifyProvider`: Observed Public IPv4 / IPv6 (`api.ipify.org`, `api6.ipify.org`, `api64.ipify.org`).
  * `ICanHazIpProvider`: Plaintext fallback IP discovery (`icanhazip.com`).
* **Capability Matrix & Field-Aware Fallback**:
  * Providers advertise supported capabilities (`PUBLIC_IP`, `IPV4`, `IPV6`, `ASN`, `AS_ORG`, `ISP`, `GEOLOCATION`, `PTR_METADATA`).
  * When primary lookups yield partial metadata, fallback queries specifically target metadata-capable endpoints for the discovered IP.
  * Partial successes are cleanly merged without discarding previously discovered fields.

### 3. Field-Level Provenance Tracking
* Each attribute in `PublicIpInfo` records its originating source in `sources`:
  ```json
  "sources": {
    "ip": "ipapi",
    "ipv4": "ipify",
    "ipv6": "ipapi",
    "asn": "ipapi",
    "as_org": "ipapi",
    "isp": "ipwhois",
    "country": "ipapi",
    "region": "ipapi",
    "city": "ipapi",
    "reverse_dns": "system_resolver"
  }
  ```

### 4. Dual-Stack Independent Discovery
* `ipv4` and `ipv6` are discovered independently.
* The presence of IPv4 does not imply IPv6, and vice versa.
* When IPv6 is unavailable or not routed externally, `ipv6 = None` is reported as a normal condition.

### 5. Strict Separation of ASN Organization and ISP
* `asn`, `as_org`, and `isp` represent distinct network concepts and entities.
* The toolkit never copies `as_org` into `isp` or vice versa unless explicitly corroborated by the provider response.

### 6. Geolocation Transparency & Disclaimer
* Approximate geolocation is reported (`country`, `region`, `city`).
* Explicitly tagged with `geolocation_accuracy = "APPROXIMATE"`.
* Persistent disclaimer: *Approximate geolocation is estimated based on publicly registered IP allocations and does not represent precise physical location.*

### 7. Carrier-Grade NAT (CGNAT) Observation
* Evaluates the selected active Internet interface for addresses within the RFC 6598 Shared Address Space (`100.64.0.0/10`).
* Reports factual, neutral observations (`cgnat_detected`, `cgnat_local_address`, `cgnat_interface`, `cgnat_details`) without speculative claims.

### 8. System-Resolver PTR (Reverse DNS) Lookup
* Discovered public IP is resolved via `socket.gethostbyaddr()` using the host's configured system resolver.
* Scoped with temporary socket timeouts that are safely restored in a `finally` block to prevent global side-effects.
* NXDOMAIN, timeouts, or resolution failures result in `reverse_dns = None` without interrupting collection.

### 9. Strict Privacy Guardrails & `--no-internet` Hard Isolation
* **Zero Local Leaks**: External requests never transmit private IPs, MAC addresses, SSIDs, BSSIDs, default gateways, local hostnames, internal DNS servers, or routing tables.
* **Strict Public-IP Validation**: Before constructing IP-specific metadata queries (`/json/<ip>`), the target IP is strictly validated using Python's `ipaddress` module to ensure it is a public, globally routable address (`is_global == True`). Private, loopback, link-local, multicast, unspecified, and reserved IPs are strictly rejected.
* **`--no-internet` Hard Isolation**:
  * When `--no-internet` is specified, zero external HTTP/HTTPS queries and zero PTR socket queries are made.
  * Reports `status = "DISABLED"`, `available = False`, `reason = "--no-internet flag specified"`.

### 10. Status Codes
* `AVAILABLE`: Public IP and primary metadata successfully discovered.
* `PARTIAL`: Public IP discovered, but some metadata attributes were unavailable.
* `OFFLINE`: External providers could not be reached (host offline or outbound traffic blocked).
* `ERROR`: External providers responded with invalid or unusable data.
* `DISABLED`: External operations disabled via `--no-internet`.

---

## Safe Connectivity Engine (Phase 6)

Phase 6 equips the toolkit with a safe, bounded, read-only active connectivity diagnostics engine across Windows and Linux. It measures actual host reachability, round-trip latency, packet loss, DNS resolution times, and dual-stack egress without port scanning, subnet probing, or traffic interception.

### 1. Security Boundary & Safety Guarantees
* **Strict Target Boundary**: Probes are restricted exclusively to:
  * Authoritative local default gateways.
  * Explicitly configured DNS test hostnames (`config/config.yaml`).
  * Explicitly configured HTTP/HTTPS probe endpoints (`config/config.yaml`).
  * Fixed TCP port 443 connectivity targets for IPv4 and IPv6.
* **No Intrusive Scanning**: Never performs host sweeps, subnet scans, port ranges, service enumeration, or banner grabbing.
* **No Traffic Manipulation**: Strictly read-only OS ping utilities and standard library network calls (`socket`, `urllib.request`).

### 2. The Five Standard Probes

#### A. Default Gateway Reachability (ICMP Ping)
* **Native Execution**: Invokes OS native ping utilities (`ping -n 2 -w 2000` on Windows, `ping -c 2 -W 2 -I <iface>` on Linux).
* **IPv6 Link-Local Handling**: Automatically extracts and resolves interface index (`%ifindex`) on Windows (e.g. `fe80::1%10`) to satisfy Windows ICMP routing requirements.
* **Metrics**: Reports `latency_ms` (average round-trip time) and `packet_loss_pct` (0.0% to 100.0%).

#### B. DNS Resolution Latency
* **Scoped Thread Execution**: Uses Python's standard `socket.getaddrinfo()` wrapped in an isolated thread executor (`concurrent.futures.ThreadPoolExecutor`).
* **No Global State Side-Effects**: Enforces DNS timeouts (default 3.0s) strictly without mutating Python's global `socket.setdefaulttimeout()`.
* **Resolution Metrics**: Accurately measures round-trip DNS resolution latency and records resolved IP addresses in result details.

#### C. HTTP/HTTPS Endpoint Reachability
* **Direct Connection**: Uses `urllib.request.build_opener(ProxyHandler({}))` to measure direct host egress without proxy interference.
* **Bounded Redirects**: Uses custom `BoundedRedirectHandler(max_redirects=1)` to avoid crawling or following unexpected redirect loops.
* **Status Discrimination**: Correctly recognizes and distinguishes HTTP 204 (No Content — standard captive portal probe) from HTTP 200 (OK) and other statuses.
* **Minimal User-Agent**: Transmits minimal header `User-Agent: NetworkIntelligenceToolkit/1.0` without leaking local OS attributes, hostnames, or hardware identifiers.

#### D. Dual-Stack TCP Reachability (IPv4 & IPv6)
* **Fixed Destination Port**: Strictly targets TCP port 443 on configured global endpoints.
* **Bounded Candidate Resolution**: Resolves candidate endpoints and evaluates them sequentially, stopping immediately on first successful TCP three-way handshake (`socket.connect()`).
* **Graceful Fallback**: If an address family or default route is not configured (e.g. host has no IPv6 route), reports `NOT_APPLICABLE` rather than failure or timeout.

### 3. Strict `--no-internet` Privacy Guardrails
* **External Probes Blocked**: When `--no-internet` is specified, all DNS resolution, HTTP reachability, and TCP family probes are immediately skipped and reported as `status = "DISABLED"`.
* **Local Gateway Authorization**:
  * Default gateways are strictly evaluated by `is_local_gateway()`.
  * The ICMP ping probe is executed **only if** the gateway address is demonstrably local:
    * IPv4 Private (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
    * IPv4 Link-Local (`169.254.0.0/16`)
    * IPv6 Link-Local (`fe80::/10`)
    * IPv6 Unique Local (ULA: `fc00::/7`)
    * Directly connected subnet (address falls within the local interface's assigned network CIDR)
  * If a gateway is a public/external IP, it is considered non-local under `--no-internet` and marked `status = "NOT_APPLICABLE"` with **0 ICMP packets emitted**.

### 4. Quick Mode (`--quick`) Optimization
* Quick mode completely excludes Phase 6 connectivity probes, preserving execution speeds under 3 seconds.

### 5. Canonical Status Codes
* `SUCCESS`: Probe succeeded with valid response / latency measurement.
* `FAILED`: Probe failed (e.g. 100% ICMP packet loss, TCP connection refused, HTTP error).
* `TIMEOUT`: Network timeout exceeded before response received.
* `ERROR`: System execution error (e.g. missing ping utility or DNS resolution error).
* `DISABLED`: Probe disabled by policy (e.g. `--no-internet`).
* `NOT_APPLICABLE`: Target family or prerequisite not present (e.g. IPv6 route not configured).

---

## Local Neighbor & Socket Intelligence (Phase 7)

Phase 7 introduces passive, strictly local network state inspection across Windows and Linux. The engine reads only pre-existing operating-system cache tables and kernel socket structures:

### 1. Security Boundary & Passive Guarantees
* **Strictly Read-Only Local OS State**: Never initiates active network discovery, ARP sweeps, ICMP ping sweeps, port scanning, connection attempts, packet injection, or packet capture.
* **Zero Remote DNS Lookups**: Never performs reverse DNS (PTR) or hostname lookups for neighbors or socket endpoints. All lookups are strictly numerical (`ss -n`).
* **Passive Guarantee Verified**: Explicit unit tests assert zero calls to `socket.connect`, `socket.create_connection`, `urllib.request.urlopen`, or `socket.getaddrinfo`.

### 2. Neighbor / ARP Table Collector
* **Linux Execution**: Queries `ip -j neigh` (structured JSON from iproute2) with fallback to `ip neigh` text parsing and `/proc/net/arp` (kernel ARP cache).
* **Windows Execution**: Queries `Get-NetNeighbor` via PowerShell with fallback to `Get-NetNeighbor` text.
* **State Normalization**: Unifies platform states to canonical names: `REACHABLE`, `PERMANENT`, `STALE`, `DELAY`, `PROBE`, `INCOMPLETE`, `UNREACHABLE`, `FAILED`, `UNKNOWN`.
* **State Hierarchy & Deduplication**: Entries are conservatively deduplicated on `(ip_address, interface)`. The entry with the highest state priority is preserved, valid MAC addresses are favored over `UNKNOWN`, and router flags are merged.
* **Default Router Correlation**: Correlates entries against authoritative default routes by requiring exact matching of IP address, address family, and network interface.
* **Incomplete Entries Preserved**: Entries in `INCOMPLETE` or `FAILED` states are retained with `mac_address = "UNKNOWN"`.

### 3. Socket & Port Summary Collector
* **Linux Execution**: Executes `ss -tunapn -H` using `-n` to guarantee zero DNS/service resolution, with `psutil` fallback.
* **Windows Execution**: Executes a single PowerShell script querying `Get-NetTCPConnection` and `Get-NetUDPEndpoint` with batch PID process attribution (`Get-Process`), with `psutil` fallback.
* **TCP State Normalization**: Windows TCP state integers (1..12, 100) are mapped strictly against `System.Net.NetworkInformation.TcpState` (`LISTEN`, `ESTABLISHED`, `CLOSE_WAIT`, `TIME_WAIT`, `SYN_SENT`, etc.).
* **UDP State Integrity**: UDP endpoints are strictly reported with `state = "UNKNOWN"`. Listening or established states are never fabricated for UDP.
* **Listening Socket Remote Normalization**: For listening TCP sockets and UDP endpoints, remote address and port are normalized to `None` (`*:*`).
* **Process Attribution**: Extracts process name and PID where available, gracefully degrading to `None` when operating without root/Administrator privileges.

### 4. Scope Control & CLI Flags
* `--quick`: Excludes both neighbors and sockets.
* Default scan: Excludes neighbors and sockets (lightweight baseline).
* `--full`: Includes both neighbors and sockets.
* `--neighbors`: Explicitly includes neighbor table only.
* `--sockets`: Explicitly includes socket summary only.
* `--no-internet`: Phase 7 collectors remain active, operating strictly locally with zero network I/O.

---

## Authorized PCAP/PCAPNG Analysis Engine (Phase 8)

The toolkit introduces bounded, read-only offline packet analysis via TShark (`core/pcap.py`).

### Security Boundaries
* **Strictly Offline**: Uses `tshark -r <file>`; live capture flags (`-i` / `--interface`) are strictly forbidden.
* **Non-Intrusive**: Never transmits, replays, or injects packets.
* **Privacy Guarantees**: Never extracts passwords, authorization tokens, cookies, or payloads. Only protocol-level metadata is analyzed.
* **Zero Modification**: Target capture files are treated as strictly immutable (original file hashes remain unchanged).

### Resource Bounding
* **Output Limit**: Enforces incremental reading via `subprocess.Popen` chunk reader, terminating execution if output reaches `max_output_bytes` (default: 50 MB).
* **Packet Limit**: Passes `-c <max_packets>` directly to TShark (default: 1,000,000 packets).
* **Execution Timeout**: Enforces timeout with process kill guarantees (default: 120s).
* **Sample Limit**: Caps packet summary samples to `packet_sample_limit` (default: 100).

### Decoders & Summaries
* **Protocol Hierarchy**: Hierarchical protocol statistics (`io,phs`) sorted by packet volume.
* **Endpoints**: IPv4 and IPv6 endpoint conversation volumes (`endpoints,ip`, `endpoints,ipv6`).
* **Conversations**: TCP and UDP flow volumes (`conv,tcp`, `conv,udp`).
* **DNS Intelligence**: Queries, responses, unresolved queries, and top queried domains.
* **HTTP Intelligence**: Request methods, responses, status codes, and top hosts (zero cookies/auth headers).
* **TLS Intelligence**: Client Hello sessions, TLS record versions, top SNIs, and cipher suites (zero secrets/keys).
* **TCP Diagnostics**: Retransmissions, duplicate ACKs, zero-window advertisements, RST, and SYN flags.
* **Traffic Timeline**: Bounded interval time-series buckets (default: 1.0s interval).

---

## Observations & Findings Engine (Phase 9)

Phase 9 introduces an automated, deterministic analysis layer (`core/observations.py`) that correlates collected evidence across all existing subsystems to produce factual, evidence-backed observations.

### Core Principles
Every observation answers five fundamental questions:
1. **WHAT** was observed? (Objective condition or finding)
2. **WHERE** was it observed? (Source subsystems and related entities like IPs or interfaces)
3. **WHY** was it generated? (Clear explanation of the factual configuration condition)
4. **WHICH** evidence supports it? (Bounded `ObservationEvidence` records citing specific fields and values)
5. **HOW** certain is the observation? (Standardized confidence level based on direct vs derived facts)

### Security & Privacy Boundaries
* **Strictly Passive**: Operates completely in-memory over the immutable `NetworkIntelligenceReport`.
* **Zero Active Network Traffic**: Generates no DNS queries, HTTP probes, ARP sweeps, socket connections, or packet transmission.
* **Zero Threat Scoring**: Severity represents the *operational importance* of an observation, not malice or exploitability.
* **No Speculation**: Uses neutral, objective language. Avoids unsupported claims such as "compromised", "attacker", or "malicious".
* **Provenance Preserved**: Observations cite specific source fields without duplicating full reports.
* **Offline Independence**: Fully functional in offline mode (`--no-internet`).

### Taxonomy & Vocabularies
* **Categories**: `NETWORK`, `HOST`, `CONNECTIVITY`, `PUBLIC_IDENTITY`, `PCAP`, `DATA_QUALITY`
* **Severities**:
  * `INFO`: Purely informational factual states (e.g. gateway neighbor match, stub resolver detected, listening sockets count).
  * `NOTICE`: Notable configuration anomalies or operational constraints (e.g. gateway missing from cache, unmapped socket process names, capture retransmissions).
  * `WARNING`: Subsystem collection errors or acute degradation (e.g. collector timeout/failure).
* **Confidence**: `HIGH` (directly represented by normalized OS fields), `MEDIUM` (derived from multiple correlated observations), `LOW` (heuristic with incomplete supporting data).
* **Status**: `OBSERVED`, `INFORMATIONAL`, `UNAVAILABLE`, `SUPPRESSED`

### Contradiction Suppression & Deduplication
* **Suppression Rules**: Prevents contradictory findings (e.g. matching gateway neighbor automatically suppresses missing neighbor; verified IPv6 connectivity probe suppresses unverified IPv6 warnings).
* **Deduplication**: Automatically coalesces duplicate findings by `(id, related_entities)`, prioritizing higher-severity records.
* **Deterministic Ordering**: Output order is strictly reproducible across runs, sorted by category, severity, ID, and related entities.

### Limitations
> [!IMPORTANT]
> Phase 9 produces evidence-backed observations. It does not determine whether a host or network is compromised.

---

## Installation

### Prerequisites
* Python 3.11+
* (Optional) `tshark` (Wireshark) for PCAP analysis

### Setup
```bash
# Clone or navigate to the repository
cd network-intelligence

# Install Python dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Display platform capability matrix
python main.py --capabilities

# Run standard network inspection (lightweight baseline)
python main.py

# Run quick mode (interfaces and routing only)
python main.py --quick

# Run full scan (baseline + Wi-Fi + neighbors + sockets)
python main.py --full

# Inspect local ARP / neighbor cache only
python main.py --neighbors

# Inspect local listening and active sockets only
python main.py --sockets

# Target a specific interface
python main.py -i eth0

# Inspect neighbors on a specific interface
python main.py --neighbors -i "Wi-Fi"

# Offline mode (strictly local inspection; 0 external calls)
python main.py --full --no-internet

# Analyze offline PCAP/PCAPNG capture file
python main.py --pcap capture.pcapng

# Apply Wireshark display filter to PCAP analysis
python main.py --pcap capture.pcapng --pcap-filter "tcp.port == 443"

# Analyze PCAP with 100% offline execution (zero internet queries)
python main.py --pcap capture.pcapng --no-internet

# Combine PCAP analysis with quick system scan
python main.py --pcap capture.pcapng --quick

# Export complete output including PCAP analysis as JSON
python main.py --pcap capture.pcapng --json

# Save JSON report to file
python main.py --pcap capture.pcapng --json -o report.json
```

---

## Running Tests

```bash
python -m pytest tests -v
```


<!-- Phase 5.1 Public Identity Hardening Documentation -->
