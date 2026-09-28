"""Script to generate realistic, representative, deterministic PCAP and PCAPNG test fixtures.

Contains purely documentation-safe IPs (RFC 5737 192.0.2.x, RFC 3849 2001:db8::x)
and domains (RFC 2606 example.com).
Includes:
- Ethernet
- IPv4 and IPv6
- TCP and UDP
- DNS query and response
- HTTP GET and HTTP 200 OK response
- TCP SYN, SYN-ACK, ACK, RST
- TLS ClientHello with SNI extension (zero secrets, zero keys)
- Strictly zero credentials, cookies, tokens, or auth headers.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent


def calc_checksum(data: bytes) -> int:
    """Calculate 16-bit one's complement Internet checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_eth(src_mac: bytes, dst_mac: bytes, eth_type: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def build_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ip_id: int = 1, ttl: int = 64) -> bytes:
    v_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000  # DF
    csum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    hdr_without_csum = struct.pack("!BBHHHBBH4s4s", v_ihl, tos, total_len, ip_id, flags_frag, ttl, proto, 0, src_bytes, dst_bytes)
    csum = calc_checksum(hdr_without_csum)
    hdr = struct.pack("!BBHHHBBH4s4s", v_ihl, tos, total_len, ip_id, flags_frag, ttl, proto, csum, src_bytes, dst_bytes)
    return hdr + payload


def build_ipv6(src_ip: str, dst_ip: str, next_hdr: int, payload: bytes, hop_limit: int = 64) -> bytes:
    vtcf = 0x60000000  # Version 6, traffic class 0, flow label 0
    payload_len = len(payload)
    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    hdr = struct.pack("!IHBB16s16s", vtcf, payload_len, next_hdr, hop_limit, src_bytes, dst_bytes)
    return hdr + payload


def build_udp(src_port: int, dst_port: int, payload: bytes, src_ip: str | None = None, dst_ip: str | None = None, is_ipv6: bool = False) -> bytes:
    length = 8 + len(payload)
    csum = 0
    if src_ip and dst_ip:
        if is_ipv6:
            pseudo = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip) + struct.pack("!I3xB", length, 17)
        else:
            pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 17, length)
        udp_raw = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
        csum = calc_checksum(pseudo + udp_raw)
        if csum == 0:
            csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def build_tcp(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 65535,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    is_ipv6: bool = False,
) -> bytes:
    data_offset_res = (5 << 4)
    urg_ptr = 0
    tcp_len = 20 + len(payload)
    csum = 0
    if src_ip and dst_ip:
        if is_ipv6:
            pseudo = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip) + struct.pack("!I3xB", tcp_len, 6)
        else:
            pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, tcp_len)
        tcp_raw = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_res, flags, window, 0, urg_ptr) + payload
        csum = calc_checksum(pseudo + tcp_raw)
    return struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_res, flags, window, csum, urg_ptr) + payload


def build_dns_query(tx_id: int, qname: str = "example.com") -> bytes:
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    hdr = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Encode qname
    qname_bytes = b""
    for part in qname.split("."):
        qname_bytes += bytes([len(part)]) + part.encode("ascii")
    qname_bytes += b"\x00"

    qtype = 1  # A
    qclass = 1  # IN
    return hdr + qname_bytes + struct.pack("!HH", qtype, qclass)


def build_dns_response(tx_id: int, qname: str = "example.com", ip_addr: str = "192.0.2.1") -> bytes:
    flags = 0x8180  # Standard response, recursion desired, recursion available, no error
    qdcount = 1
    ancount = 1
    nscount = 0
    arcount = 0
    hdr = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    qname_bytes = b""
    for part in qname.split("."):
        qname_bytes += bytes([len(part)]) + part.encode("ascii")
    qname_bytes += b"\x00"
    question = qname_bytes + struct.pack("!HH", 1, 1)

    # Answer: pointer to name at offset 12 (0xc00c)
    ans_ptr = struct.pack("!H", 0xC00C)
    ans_type = 1  # A
    ans_class = 1  # IN
    ans_ttl = 300
    ans_rdlen = 4
    rdata = socket.inet_aton(ip_addr)
    answer = ans_ptr + struct.pack("!HHIH", ans_type, ans_class, ans_ttl, ans_rdlen) + rdata

    return hdr + question + answer


def build_http_request(method: str = "GET", path: str = "/index.html", host: str = "example.com") -> bytes:
    # Strictly documentation safe; no credentials, cookies, tokens, or auth headers
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: NetworkIntelligenceToolkit/1.0",
        "Accept: text/html,application/xhtml+xml",
        "Connection: keep-alive",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def build_http_response(status_code: int = 200, status_text: str = "OK", host: str = "example.com") -> bytes:
    body = b"<!DOCTYPE html><html><head><title>Example</title></head><body><h1>Example Domain</h1></body></html>"
    lines = [
        f"HTTP/1.1 {status_code} {status_text}",
        "Date: Wed, 24 Sep 2026 12:00:00 GMT",
        "Server: ExampleServer/1.0",
        "Content-Type: text/html; charset=UTF-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        "",
    ]
    hdr = "\r\n".join(lines).encode("ascii")
    return hdr + body


def build_tls_client_hello(sni: str = "example.com") -> bytes:
    # Build SNI extension (0x0000)
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_sni = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # Build Supported Versions extension (0x002B) with TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
    supp_vers = struct.pack("!HH", 0x0304, 0x0303)
    supp_vers_data = struct.pack("!B", len(supp_vers)) + supp_vers
    ext_supp_vers = struct.pack("!HH", 0x002B, len(supp_vers_data)) + supp_vers_data

    extensions_data = ext_sni + ext_supp_vers
    extensions = struct.pack("!H", len(extensions_data)) + extensions_data

    # Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    cipher_suites = struct.pack("!HH", 0x1301, 0xC02F)
    cipher_suites_data = struct.pack("!H", len(cipher_suites)) + cipher_suites

    # Compression: Null (0x00)
    comp_methods = b"\x01\x00"

    client_version = struct.pack("!H", 0x0303)  # TLS 1.2 in ClientHello
    random_bytes = b"\xaa" * 32
    session_id = b"\x00"  # length 0

    handshake_body = client_version + random_bytes + session_id + cipher_suites_data + comp_methods + extensions
    # Handshake header: type 0x01 (ClientHello), 3-byte length
    hs_len = len(handshake_body)
    handshake_hdr = struct.pack("!B", 0x01) + struct.pack("!I", hs_len)[1:]  # 3 bytes length

    tls_record_payload = handshake_hdr + handshake_body

    # TLS Record Header: Content Type 0x16 (Handshake), Version 0x0301 (TLS 1.0), Length
    tls_record = struct.pack("!BHH", 0x16, 0x0301, len(tls_record_payload)) + tls_record_payload
    return tls_record


def generate_packet_sequence() -> list[bytes]:
    """Generate the full multi-protocol packet sequence."""
    packets: list[bytes] = []

    mac_client = b"\x00\x11\x22\x33\x44\x55"
    mac_gw = b"\x00\xaa\xbb\xcc\xdd\xee"
    mac_server = b"\x00\x66\x77\x88\x99\xaa"

    ip_client_v4 = "192.0.2.10"
    ip_dns_v4 = "192.0.2.53"
    ip_web_v4 = "192.0.2.1"

    ip_client_v6 = "2001:db8::10"
    ip_server_v6 = "2001:db8::1"

    # 1. DNS Query (UDP, IPv4)
    dns_q = build_dns_query(0x1001, "example.com")
    udp_dns_q = build_udp(53531, 53, dns_q, ip_client_v4, ip_dns_v4)
    ip_dns_q = build_ipv4(ip_client_v4, ip_dns_v4, 17, udp_dns_q, ip_id=101)
    packets.append(build_eth(mac_client, mac_gw, 0x0800, ip_dns_q))

    # 2. DNS Response (UDP, IPv4)
    dns_r = build_dns_response(0x1001, "example.com", ip_web_v4)
    udp_dns_r = build_udp(53, 53531, dns_r, ip_dns_v4, ip_client_v4)
    ip_dns_r = build_ipv4(ip_dns_v4, ip_client_v4, 17, udp_dns_r, ip_id=102)
    packets.append(build_eth(mac_gw, mac_client, 0x0800, ip_dns_r))

    # 3. HTTP Connection TCP SYN (IPv4)
    tcp_syn = build_tcp(49152, 80, seq=1000, ack=0, flags=0x02, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_syn = build_ipv4(ip_client_v4, ip_web_v4, 6, tcp_syn, ip_id=201)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_syn))

    # 4. HTTP Connection TCP SYN-ACK (IPv4)
    tcp_synack = build_tcp(80, 49152, seq=5000, ack=1001, flags=0x12, src_ip=ip_web_v4, dst_ip=ip_client_v4)
    ip_synack = build_ipv4(ip_web_v4, ip_client_v4, 6, tcp_synack, ip_id=202)
    packets.append(build_eth(mac_server, mac_client, 0x0800, ip_synack))

    # 5. HTTP Connection TCP ACK (IPv4)
    tcp_ack = build_tcp(49152, 80, seq=1001, ack=5001, flags=0x10, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_ack = build_ipv4(ip_client_v4, ip_web_v4, 6, tcp_ack, ip_id=203)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_ack))

    # 6. HTTP GET Request (IPv4) with query string to test privacy boundary
    http_req = build_http_request("GET", "/login?token=SYNTHETIC_SECRET&password=SYNTHETIC_PASSWORD", "example.com")
    tcp_http_req = build_tcp(49152, 80, seq=1001, ack=5001, flags=0x18, payload=http_req, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_http_req = build_ipv4(ip_client_v4, ip_web_v4, 6, tcp_http_req, ip_id=204)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_http_req))

    # 7. HTTP 200 OK Response (IPv4)
    http_resp = build_http_response(200, "OK", "example.com")
    tcp_http_resp = build_tcp(80, 49152, seq=5001, ack=1001 + len(http_req), flags=0x18, payload=http_resp, src_ip=ip_web_v4, dst_ip=ip_client_v4)
    ip_http_resp = build_ipv4(ip_web_v4, ip_client_v4, 6, tcp_http_resp, ip_id=205)
    packets.append(build_eth(mac_server, mac_client, 0x0800, ip_http_resp))

    # 8. HTTP Connection TCP RST (IPv4)
    tcp_rst = build_tcp(49152, 80, seq=1001 + len(http_req), ack=0, flags=0x04, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_rst = build_ipv4(ip_client_v4, ip_web_v4, 6, tcp_rst, ip_id=206)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_rst))

    # 9. TLS Connection TCP SYN (IPv4, Port 443)
    tls_syn = build_tcp(49153, 443, seq=2000, ack=0, flags=0x02, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_tls_syn = build_ipv4(ip_client_v4, ip_web_v4, 6, tls_syn, ip_id=301)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_tls_syn))

    # 10. TLS Connection TCP SYN-ACK (IPv4, Port 443)
    tls_synack = build_tcp(443, 49153, seq=6000, ack=2001, flags=0x12, src_ip=ip_web_v4, dst_ip=ip_client_v4)
    ip_tls_synack = build_ipv4(ip_web_v4, ip_client_v4, 6, tls_synack, ip_id=302)
    packets.append(build_eth(mac_server, mac_client, 0x0800, ip_tls_synack))

    # 11. TLS Connection TCP ACK (IPv4, Port 443)
    tls_ack = build_tcp(49153, 443, seq=2001, ack=6001, flags=0x10, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_tls_ack = build_ipv4(ip_client_v4, ip_web_v4, 6, tls_ack, ip_id=303)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_tls_ack))

    # 12. TLS ClientHello with SNI (IPv4, Port 443)
    client_hello = build_tls_client_hello("example.com")
    tcp_tls_ch = build_tcp(49153, 443, seq=2001, ack=6001, flags=0x18, payload=client_hello, src_ip=ip_client_v4, dst_ip=ip_web_v4)
    ip_tls_ch = build_ipv4(ip_client_v4, ip_web_v4, 6, tcp_tls_ch, ip_id=304)
    packets.append(build_eth(mac_client, mac_server, 0x0800, ip_tls_ch))

    # 13. IPv6 UDP Packet
    udp_v6_payload = b"TEST_IPV6_UDP_PAYLOAD"
    udp_v6 = build_udp(54321, 54322, udp_v6_payload, ip_client_v6, ip_server_v6, is_ipv6=True)
    ip_v6 = build_ipv6(ip_client_v6, ip_server_v6, 17, udp_v6)
    packets.append(build_eth(mac_client, mac_server, 0x86DD, ip_v6))

    # 14. IPv6 UDP Response Packet
    udp_v6_resp_payload = b"TEST_IPV6_UDP_RESPONSE"
    udp_v6_resp = build_udp(54322, 54321, udp_v6_resp_payload, ip_server_v6, ip_client_v6, is_ipv6=True)
    ip_v6_resp = build_ipv6(ip_server_v6, ip_client_v6, 17, udp_v6_resp)
    packets.append(build_eth(mac_server, mac_client, 0x86DD, ip_v6_resp))

    # 15. IPv6 TCP SYN
    tcp_v6_syn = build_tcp(49154, 80, seq=3000, ack=0, flags=0x02, src_ip=ip_client_v6, dst_ip=ip_server_v6, is_ipv6=True)
    ip_v6_syn = build_ipv6(ip_client_v6, ip_server_v6, 6, tcp_v6_syn)
    packets.append(build_eth(mac_client, mac_server, 0x86DD, ip_v6_syn))

    # 16. IPv6 TCP SYN-ACK
    tcp_v6_synack = build_tcp(80, 49154, seq=7000, ack=3001, flags=0x12, src_ip=ip_server_v6, dst_ip=ip_client_v6, is_ipv6=True)
    ip_v6_synack = build_ipv6(ip_server_v6, ip_client_v6, 6, tcp_v6_synack)
    packets.append(build_eth(mac_server, mac_client, 0x86DD, ip_v6_synack))

    # 17. IPv6 TCP ACK
    tcp_v6_ack = build_tcp(49154, 80, seq=3001, ack=7001, flags=0x10, src_ip=ip_client_v6, dst_ip=ip_server_v6, is_ipv6=True)
    ip_v6_ack = build_ipv6(ip_client_v6, ip_server_v6, 6, tcp_v6_ack)
    packets.append(build_eth(mac_client, mac_server, 0x86DD, ip_v6_ack))

    return packets


def write_pcap(path: Path, packets: list[bytes]) -> None:
    # PCAP Global Header: magic, major (2), minor (4), thiszone (0), sigfigs (0), snaplen (65535), network (1: Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    base_ts = 1700000000

    with open(path, "wb") as f:
        f.write(global_hdr)
        for i, pkt in enumerate(packets):
            sec = base_ts + (i // 10)
            usec = (i % 10) * 100000
            pkt_hdr = struct.pack("<IIII", sec, usec, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)


def write_pcapng(path: Path, packets: list[bytes]) -> None:
    # 1. Section Header Block (SHB): 28 bytes
    shb_type = 0x0A0D0D0A
    shb_len = 28
    bom = 0x1A2B3C4D
    major = 1
    minor = 0
    shb = struct.pack("<IIIHHqI", shb_type, shb_len, bom, major, minor, -1, shb_len)

    # 2. Interface Description Block (IDB): 20 bytes
    idb_type = 0x00000001
    idb_len = 20
    link_type = 1  # Ethernet
    reserved = 0
    snaplen = 65535
    idb = struct.pack("<IIHHI I", idb_type, idb_len, link_type, reserved, snaplen, idb_len)

    with open(path, "wb") as f:
        f.write(shb)
        f.write(idb)

        base_ts = 1700000000 * 1_000_000  # microsecond units
        for i, pkt in enumerate(packets):
            ts = base_ts + (i * 100_000)
            ts_high = (ts >> 32) & 0xFFFFFFFF
            ts_low = ts & 0xFFFFFFFF
            pad_len = (4 - (len(pkt) % 4)) % 4
            padded_pkt = pkt + (b"\x00" * pad_len)
            epb_len = 32 + len(padded_pkt)
            epb_type = 0x00000006
            iface_id = 0
            cap_len = len(pkt)
            orig_len = len(pkt)
            epb_data = struct.pack("<IIIIIII", epb_type, epb_len, iface_id, ts_high, ts_low, cap_len, orig_len) + padded_pkt + struct.pack("<I", epb_len)
            f.write(epb_data)


def write_empty_pcap(path: Path) -> None:
    """Empty 0-byte file fixture."""
    path.write_bytes(b"")


def write_empty_valid_pcap(path: Path) -> None:
    """Valid PCAP file with 0 packets (standard 24-byte global header)."""
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(global_hdr)


def write_corrupt_pcap(path: Path) -> None:
    """Corrupt file with invalid magic bytes."""
    path.write_bytes(b"CORRUPT_NOT_A_REAL_PCAP_FILE_MAGIC_BYTES_1234567890")


def generate_all() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    packets = generate_packet_sequence()

    pcap_path = FIXTURES_DIR / "valid_sample.pcap"
    pcapng_path = FIXTURES_DIR / "valid_sample.pcapng"
    empty_path = FIXTURES_DIR / "empty.pcap"
    empty_valid_path = FIXTURES_DIR / "empty_valid.pcap"
    corrupt_path = FIXTURES_DIR / "corrupt.pcap"

    write_pcap(pcap_path, packets)
    write_pcapng(pcapng_path, packets)
    write_empty_pcap(empty_path)
    write_empty_valid_pcap(empty_valid_path)
    write_corrupt_pcap(corrupt_path)

    print(f"Generated {len(packets)} packets in:")
    print(f"  {pcap_path} ({pcap_path.stat().st_size} bytes)")
    print(f"  {pcapng_path} ({pcapng_path.stat().st_size} bytes)")
    print(f"  {empty_path} ({empty_path.stat().st_size} bytes)")
    print(f"  {empty_valid_path} ({empty_valid_path.stat().st_size} bytes)")
    print(f"  {corrupt_path} ({corrupt_path.stat().st_size} bytes)")


if __name__ == "__main__":
    generate_all()
