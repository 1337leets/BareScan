#!/usr/bin/env python3
"""
BareScan — Minimal, low-noise service fingerprinting via conservative banner grabbing.

Features:
  - Banner grabbing (--banner)
  - Service fingerprinting (--fingerprint)
  - JSON output (--json), with optional base64 raw banner (--raw)
  - Centralized PRODUCT_PATTERNS and mapping tables for easy extension
  - Debian package token -> Debian version mapping (debNN -> Debian NN)
  - Preservation of packaging/revision tokens in fp_version (parentheses)
  - Recognition of common services (Dovecot, OpenSSH, Caddy, Apache, IIS, MariaDB, etc.)
  - Evidence-based TCP state model: open / closed / filtered via connect() errno
  - OPEN/NO-DATA: handshake completed but no application data (responsive flag)
  - Network-interference hints: upstream SYN-proxy/tarpit and ISP transparent-proxy

Responsible use:
  - Run only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

__version__ = "0.2.0"

import argparse
import base64
import concurrent.futures
import errno
import json
import math
import re
import select
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMPTRAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 514: "SYSLOG", 587: "SMTP-Sub", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "Postgres", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

# ------------------------
# Centralized patterns & mappings
# ------------------------
# PRODUCT_PATTERNS -> list of tuples (regex, canonical_name, version_group_index or None)
PRODUCT_PATTERNS: List[Tuple[re.Pattern, str, Optional[int]]] = [
    (re.compile(r"apache(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "Apache", 1),
    (re.compile(r"openresty(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "OpenResty", 1),
    (re.compile(r"nginx(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "nginx", 1),
    (re.compile(r"litespeed(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "LiteSpeed", 1),
    (re.compile(r"microsoft-iis(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "IIS", 1),
    (re.compile(r"caddy(?:/|\s)?([0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+)?", re.I), "Caddy", 1),
    (re.compile(r"mariadb[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "MariaDB", 1),
    (re.compile(r"mysql[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "MySQL", 1),
    (re.compile(r"vsftpd(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I), "vsftpd", 1),
    (re.compile(r"proftpd(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I), "ProFTPD", 1),
    (re.compile(r"pure[-_]?ftpd(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I), "Pure-FTPd", 1),
    (re.compile(r"openssh[_\-/ ]?([0-9A-Za-z\.\-p]+)", re.I), "OpenSSH", 1),
    (re.compile(r"dovecot(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I), "Dovecot", 1),
    (re.compile(r"exim(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I), "Exim", 1),
    # CDN / edge / LB platforms — no meaningful version exposed, g=None
    (re.compile(r"\bcloudflare\b", re.I), "Cloudflare", None),
    (re.compile(r"\bvercel\b", re.I), "Vercel", None),
    (re.compile(r"\bakamai\b", re.I), "Akamai", None),
    (re.compile(r"\bfastly\b", re.I), "Fastly", None),
    (re.compile(r"\bawselb\b", re.I), "AWS ELB", None),
    (re.compile(r"\bawsalb\b", re.I), "AWS ALB", None),
    (re.compile(r"\bnginx-cloudfront\b", re.I), "CloudFront", None),
    (re.compile(r"\bcloudfront\b", re.I), "CloudFront", None),
    # add more as needed
]

# Common IIS -> Windows mapping for os_guess
IIS_TO_WINDOWS = {
    "5.0": "Windows NT 5.0",
    "5.1": "Windows NT 5.1 (XP)",
    "5.2": "Windows NT 5.2 (Server 2003)",
    "6.0": "Windows NT 6.0 (Vista/Server 2008)",
    "6.1": "Windows NT 6.1 (7/Server 2008 R2)",
    "6.2": "Windows NT 6.2 (8/Server 2012)",
    "6.3": "Windows NT 6.3 (8.1/Server 2012 R2)",
    "10.0": "Windows NT 10.0"
}

# ------------------------
# Utilities
# ------------------------
def parse_ports(spec: str) -> List[int]:
    if not spec:
        return sorted(COMMON_PORTS.keys())
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = map(int, part.split("-", 1))
            if a > b:
                a, b = b, a
            a = max(1, min(65535, a)); b = max(1, min(65535, b))
            out.update(range(a, b+1))
        else:
            v = int(part)
            if 1 <= v <= 65535:
                out.add(v)
    return sorted(out)

def _parse_timeout(value: str) -> float:
    """Parse timeout; accept '.' or ',' decimal separator and require >0."""
    try:
        v = value.replace(",", ".")
        t = float(v)
        if t <= 0:
            raise argparse.ArgumentTypeError("timeout must be positive")
        return t
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid timeout value: {value}")

def resolve_target(host: str) -> str:
    return socket.gethostbyname(host)

def parse_target_url(raw: str) -> dict:
    """
    Parse a raw target string that may be a URL, hostname, or IP.
    Returns dict with:
      'host'   : clean hostname or IP (no scheme, no path, no port)
      'scheme' : 'https' | 'http' | '' 
      'port'   : int port from URL (e.g. 8080) or None
    Examples:
      'https://google.com'                    → host='google.com',  scheme='https', port=None
      'http://example.com:8080/path?q=1'      → host='example.com', scheme='http',  port=8080
      'https://rp-tamganews.vercel.app'       → host='rp-tamganews.vercel.app', scheme='https', port=None
      'google.com'                            → host='google.com',  scheme='',      port=None
      '192.168.1.1'                           → host='192.168.1.1', scheme='',      port=None
      'google.com:9090'                       → host='google.com',  scheme='',      port=9090
    """
    scheme = ""
    port = None

    # strip leading/trailing whitespace
    s = raw.strip()

    # extract scheme if present
    m_scheme = re.match(r"^(https?)://(.+)$", s, flags=re.I)
    if m_scheme:
        scheme = m_scheme.group(1).lower()
        s = m_scheme.group(2)   # everything after '://'

    # strip path and query: keep only host[:port]
    s = s.split("/")[0]    # drop /path
    s = s.split("?")[0]    # drop ?query (shouldn't survive split above but be safe)
    s = s.split("#")[0]    # drop #fragment

    # extract port if present (handle IPv6 [::1]:port separately)
    if s.startswith("["):
        # IPv6 literal: [::1] or [::1]:port
        m_v6 = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if m_v6:
            s = m_v6.group(1)
            if m_v6.group(2):
                port = int(m_v6.group(2))
    else:
        parts = s.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            s = parts[0]
            port = int(parts[1])

    return {"host": s, "scheme": scheme, "port": port}

def _parse_mysql_handshake_raw(raw: bytes) -> dict:
    """
    Robust MySQL handshake parser:
     - handles binary length/seq header prefixes,
     - finds proto marker like '5.5.5-<ver>-MariaDB',
     - finds version strings like '8.0.43-34' and packaging tokens,
     - returns dict: { 'proto': <proto_marker or None>, 'version': <version or None>, 'pack': <pack or None>, 'product': <'MariaDB'|'MySQL'|''> }
    """
    try:
        if not raw:
            return {}
        # decode latin-1 to preserve bytes
        s = raw.decode("latin-1", errors="ignore")

        # Strategy:
        # 1. Try to locate a printable area likely to contain version: find first occurrence of a digit followed by digit+dot pattern
        # 2. Extract a window around it and run regexes to capture proto/version/pack/product.

        # find index of first digit that is part of x.y.z pattern
        m_start = re.search(r"[0-9]+\.[0-9]+\.[0-9]+", s)
        search_area = s
        if m_start:
            idx = max(0, m_start.start() - 16)  # include some bytes before
            search_area = s[idx: idx + 200]     # window of interest

        # 1) proto marker like '5.5.5-10.11.10-MariaDB'
        m = re.search(r"\b(5\.5\.5)-([0-9]+\.[0-9]+\.[0-9]+)-mariadb", search_area, flags=re.I)
        if m:
            return {"proto": m.group(1), "version": m.group(2), "pack": None, "product": "MariaDB"}

        # 2) "5.5.5-<ver>-MariaDB" but in other formats (looser)
        m = re.search(r"\b(5\.5\.5)-([0-9]+\.[0-9]+\.[0-9]+)[-_A-Za-z0-9]*mariadb", search_area, flags=re.I)
        if m:
            return {"proto": m.group(1), "version": m.group(2), "pack": None, "product": "MariaDB"}

        # 3) version first then -MariaDB e.g. '11.8.3-MariaDB' or '11.8.3-MariaDB-log'
        m = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)[-_A-Za-z0-9]*mariadb", search_area, flags=re.I)
        if m:
            return {"proto": None, "version": m.group(1), "pack": None, "product": "MariaDB"}

        # 4) common pattern '8.0.43-34' optionally near 'mysql' or within handshake
        m = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)(?:-([0-9A-Za-z\.\+\-]+))?", search_area)
        if m:
            # determine product hint by looking near the match for 'mariadb' or 'mysql'
            prod_hint_area = search_area.lower()
            product = ""
            if "mariadb" in prod_hint_area:
                product = "MariaDB"
            elif "mysql" in prod_hint_area:
                product = "MySQL"
            version = m.group(1)
            pack = m.group(2) if m.group(2) else None
            return {"proto": None, "version": version, "pack": pack, "product": product}

        # 5) as fallback, try to extract any X.Y or X.Y.Z
        m = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", s)
        if m:
            product = "MariaDB" if "mariadb" in s.lower() else ("MySQL" if "mysql" in s.lower() else "")
            return {"proto": None, "version": m.group(1), "pack": None, "product": product}

    except Exception:
        pass
    return {}

def build_dns_query_qname(name: Optional[str] = None) -> bytes:
    name = name or "www.example.com"
    header = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return header + qname + b"\x00\x01\x00\x01"

def _parse_ntp_response(data: bytes) -> Dict[str, Any]:
    """
    48-byte NTP response → structured fields + readable summary.
    Returns dict with 'summary' (str) and parsed numeric fields, or empty dict on failure.
    """
    if not data or len(data) < 4:
        return {}
    try:
        import struct
        li_vn_mode = data[0]
        li      = (li_vn_mode >> 6) & 0x3
        vn      = (li_vn_mode >> 3) & 0x7
        mode    = li_vn_mode & 0x7
        stratum = data[1]
        out: Dict[str, Any] = {
            "ntp_li": li, "ntp_version": vn, "ntp_mode": mode, "ntp_stratum": stratum,
        }
        if len(data) >= 16:
            ref_id = data[12:16]
            # Stratum 0/1: ASCII identifier (GPS, PPS, ATOM, etc.)
            # Stratum >=2: upstream server IPv4
            if stratum <= 1:
                try:
                    ref_str = ref_id.decode("ascii").rstrip("\x00").strip()
                    if not ref_str or not all(c.isprintable() for c in ref_str):
                        ref_str = ".".join(str(b) for b in ref_id)
                except Exception:
                    ref_str = ".".join(str(b) for b in ref_id)
            else:
                ref_str = ".".join(str(b) for b in ref_id)
            out["ntp_ref"] = ref_str
        if len(data) >= 12:
            poll = data[2]
            out["ntp_poll"] = poll
        # Build readable summary
        summary = f"NTPv{vn} stratum={stratum}"
        if out.get("ntp_ref"):
            summary += f" ref={out['ntp_ref']}"
        out["summary"] = summary
        return out
    except Exception:
        return {}

def _parse_dns_response(data: bytes, query_for: str = "") -> Dict[str, Any]:
    """
    DNS response → first A/AAAA record + summary.
    Returns dict with 'summary' (str) and parsed fields, or empty dict on failure.
    """
    if not data or len(data) < 12:
        return {}
    try:
        import struct
        flags   = struct.unpack(">H", data[2:4])[0]
        qdcount = struct.unpack(">H", data[4:6])[0]
        ancount = struct.unpack(">H", data[6:8])[0]
        rcode   = flags & 0x000f
        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                       4: "NOTIMP", 5: "REFUSED"}
        out: Dict[str, Any] = {
            "dns_qdcount": qdcount, "dns_ancount": ancount,
            "dns_rcode": rcode, "dns_rcode_name": rcode_names.get(rcode, str(rcode)),
        }
        if ancount == 0:
            if rcode != 0:
                out["summary"] = f"DNS {out['dns_rcode_name']}"
            else:
                out["summary"] = f"DNS response (no answers)"
            return out

        # Skip question section: walk qname, then qtype(2) + qclass(2)
        pos = 12
        for _ in range(qdcount):
            while pos < len(data):
                l = data[pos]
                if l == 0:
                    pos += 1
                    break
                elif (l & 0xc0) == 0xc0:   # compression pointer
                    pos += 2
                    break
                pos += 1 + l
            pos += 4   # qtype + qclass

        # Parse first answer
        answers = []
        for _ in range(ancount):
            if pos >= len(data):
                break
            # answer name (may be pointer or labels)
            l = data[pos]
            if (l & 0xc0) == 0xc0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    if (data[pos] & 0xc0) == 0xc0:
                        pos += 2
                        break
                    pos += 1 + data[pos]
                else:
                    pos += 1
            if pos + 10 > len(data):
                break
            rtype  = struct.unpack(">H", data[pos:pos+2])[0]
            rclass = struct.unpack(">H", data[pos+2:pos+4])[0]
            ttl    = struct.unpack(">I", data[pos+4:pos+8])[0]
            rdlen  = struct.unpack(">H", data[pos+8:pos+10])[0]
            pos   += 10
            if pos + rdlen > len(data):
                break
            rdata = data[pos:pos+rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:   # A
                ip = ".".join(str(b) for b in rdata)
                answers.append(("A", ip))
            elif rtype == 28 and rdlen == 16:   # AAAA
                groups = [rdata[i:i+2].hex() for i in range(0, 16, 2)]
                answers.append(("AAAA", ":".join(groups)))

        out["dns_answers"] = answers
        if answers:
            first_type, first_val = answers[0]
            if query_for:
                out["summary"] = f"{query_for} → {first_val} ({first_type})"
            else:
                out["summary"] = f"{first_val} ({first_type})"
        else:
            out["summary"] = f"DNS response ({ancount} answer{'s' if ancount>1 else ''})"
        return out
    except Exception:
        return {}

# ------------------------
# Improved Debian/Ubuntu token extractors
# ------------------------
def _extract_debian_from_text(s: str) -> Optional[str]:
    """
    Prefer 'debNN' packaging token (deb11, deb10u2, etc.) as the Debian major version.
    Fallback to 'Debian NN' (whitespace only) — hyphen-separated 'Debian-7' is a
    package revision number, NOT a Debian release, so it is intentionally excluded.
    Returns numeric major version as string (e.g. '11') or None.
    """
    if not s:
        return None
    # Primary: deb11, deb12u3, etc.
    m = re.search(r"deb(\d{1,2})(?=[^\d]|$)", s, flags=re.I)
    if m:
        return m.group(1)
    # Fallback: 'Debian 11' or 'Debian GNU/Linux 12' — whitespace separator only
    m2 = re.search(r"\bDebian\s+(?:GNU/Linux\s+)?([0-9]{1,2})\b", s, flags=re.I)
    if m2:
        return m2.group(1)
    return None

def _extract_ubuntu_from_text(s: str) -> Optional[str]:
    """
    Extract Ubuntu release only when it's clearly a release like 'Ubuntu-18.04' or 'Ubuntu 20.04'.
    Avoid treating packaging tokens like 'Ubuntu-2ubuntu2.13' as a release.
    Returns release string (e.g. '18.04') or None.
    """
    if not s:
        return None
    # require major.minor (two-digit major like 18,20 etc) to consider it a real Ubuntu release
    m = re.search(r"\bUbuntu[-_\s/]*([0-9]{2}\.[0-9]+(?:\.[0-9]+)?)\b", s, flags=re.I)
    if m:
        return m.group(1)
    m2 = re.search(r"\bUbuntu(?:/|\s|-)([0-9]{2}\.[0-9]+)\b", s, flags=re.I)
    if m2:
        return m2.group(1)
    return None

# ------------------------
# Banner probing
# ------------------------

def _recv_select_wait(sock: socket.socket, timeout: float, bufsize: int = 8192) -> bytes:
    """
    Daha güvenilir recv: select ile socket okunabilir olana kadar bekler (toplam `timeout` süresi boyunca),
    ilk veri geldiğinde okur ve kısa bir 'drain' ile ek baytları toplar.
    Return: alınan bytes (boş olabilir).
    """
    if timeout is None or timeout <= 0:
        timeout = 1.0
    end = time.time() + float(timeout)
    out = b""
    # Döngü: artan küçük beklemeler kullan (minimize busy-wait, toplam süre timeout)
    while time.time() < end:
        remaining = max(0.01, end - time.time())
        rlist, _, _ = select.select([sock], [], [], remaining)
        if not rlist:
            # select timeout, tekrar dene
            continue
        try:
            part = sock.recv(bufsize)
            if not part:
                # connection closed by peer
                break
            out += part
            # kısa bir zaman diliminde kalan veriyi de almaya çalış (drain)
            try:
                sock.setblocking(0)
                while True:
                    try:
                        more = sock.recv(bufsize)
                        if not more:
                            break
                        out += more
                    except BlockingIOError:
                        break
                    except Exception:
                        break
            finally:
                try:
                    sock.setblocking(1)
                except Exception:
                    pass
            break
        except socket.timeout:
            continue
        except BlockingIOError:
            continue
        except Exception:
            break
    return out

def tcp_probe_banner(ip: str, port: int, timeout: float, host_header: Optional[str] = None, existing_sock: Optional[socket.socket] = None) -> Tuple[str, bytes]:
    """
    Daha güvenilir banner probe:
      - existing_sock verilirse yeni bağlantı açılmaz, mevcut bağlantı kullanılır
      - connect, immediate select-based recv (kısa süre)
      - port'a özgü gentle probe (HEAD, EHLO, newline, vs.)
      - HEAD => bekle; eğer boşsa GET fallback (HTTP için)
      - toplam bekleme davranışı `timeout` ile sınırlı
    """
    raw = b""
    preview = ""
    _owns_sock = existing_sock is None  # sadece kendi açtığımız soketi kapatırız
    try:
        if existing_sock is not None:
            s = existing_sock
            try:
                s.settimeout(min(max(timeout, 0.1), 10.0))
            except Exception:
                pass
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(min( max(timeout, 0.1 ), 10.0 ))
            try:
                s.connect((ip, port))
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                return ("", b"")

        def mk_preview(b: bytes) -> str:
            try:
                return b.decode("latin-1", errors="ignore").strip()
            except Exception:
                return ""

        host_hdr = host_header or ip

        # 1) immediate small select/recv (banner-on-connect services)
        try:
            data = _recv_select_wait(s, min(timeout, 0.25), bufsize=4096)
            if data:
                raw = data
                return (mk_preview(data), raw)
        except Exception:
            pass

        # 2) port-specific gentle probes with waits and fallback
        # helper to do probe+wait: send bytes (if provided) then wait up to part_timeout
        def _send_and_wait(sock_obj, payload: Optional[bytes], wait_total: float) -> bytes:
            if payload:
                try:
                    sock_obj.sendall(payload)
                except Exception:
                    pass
            # wait up to wait_total seconds (smaller chunks)
            return _recv_select_wait(sock_obj, wait_total, bufsize=8192)

        # HTTP ports: try HEAD then GET fallback if no response
        if port in (80, 8000, 8080, 8888):
            head = f"HEAD / HTTP/1.0\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode()
            data = _send_and_wait(s, head, max(0.5, timeout))
            raw = data or raw
            preview = mk_preview(data) if data else ""
            if not data:
                # fallback to GET which some servers handle while HEAD ignored
                getr = f"GET / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: meintool/1.0\r\nConnection: close\r\n\r\n".encode()
                data = _send_and_wait(s, getr, max(0.5, timeout))
                raw = data or raw
                preview = mk_preview(data) if data else preview

        # HTTPS: wrap then do same HEAD->GET fallback
        elif port in (443, 8443):
            try:
                # SSL handshake may need more time than the default.
                # Add a fixed buffer rather than multiplying — keeps scan predictable.
                ssl_timeout = min(timeout + 1.5, 5.0)
                try:
                    s.settimeout(ssl_timeout)
                except Exception:
                    pass
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host_header or ip)
                ss.settimeout(min(max(timeout, 0.5), 10.0))
                head = f"HEAD / HTTP/1.0\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode()
                data = _send_and_wait(ss, head, max(0.5, timeout))
                raw = data or raw
                preview = mk_preview(data) if data else ""
                if not data:
                    getr = f"GET / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: meintool/1.0\r\nConnection: close\r\n\r\n".encode()
                    data = _send_and_wait(ss, getr, max(0.5, timeout))
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                try:
                    ss.close()
                except Exception:
                    pass
            except Exception:
                # SSL handshake/wrap hatası -> sessizce devam et
                pass

        # SMTP
        elif port in (25, 587):
            data = _send_and_wait(s, b"EHLO scanner.example\r\n", max(0.5, timeout))
            raw = data or raw
            preview = mk_preview(data) if data else preview

        # FTP typically sends banner immediately but try newline+wait
        elif port == 21:
            data = _send_and_wait(s, b"\r\n", max(0.5, timeout))
            raw = data or raw
            preview = mk_preview(data) if data else preview

        # SSH: banner on connect; we already tried immediate; try small wait
        elif port == 22:
            data = _recv_select_wait(s, max(0.5, timeout))
            raw = data or raw
            preview = mk_preview(data) if data else preview

        # POP3 plain (110) — gentle QUIT
        elif port == 110:
            try:
                try:
                    s.sendall(b"QUIT\r\n")
                except Exception:
                    pass
                data = _recv_select_wait(s, timeout, bufsize=4096)
                raw = data or raw
                preview = mk_preview(data) if data else preview
            except Exception:
                pass

        # POP3S (995) and IMAPS (993) — TLS wrap then gentle probes
        elif port in (993, 995):
            try:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host_header or ip)
                ss.settimeout(min(max(timeout, 0.1), 10.0))
                # IMAPS (993): CAPABILITY if needed
                if port == 993:
                    data = _recv_select_wait(ss, min(timeout, 0.5), bufsize=4096)
                    if not data:
                        try:
                            ss.sendall(b"A001 CAPABILITY\r\n")
                        except Exception:
                            pass
                        data = _recv_select_wait(ss, timeout, bufsize=4096)
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                # POP3S (995): QUIT (harmless)
                else:
                    data = _recv_select_wait(ss, min(timeout, 0.5), bufsize=4096)
                    if not data:
                        try:
                            ss.sendall(b"QUIT\r\n")
                        except Exception:
                            pass
                        data = _recv_select_wait(ss, timeout, bufsize=4096)
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                try:
                    ss.close()
                except Exception:
                    pass
            except Exception:
                # TLS handshake failed or wrap not supported; fall back to previous raw handling
                try:
                    data = _recv_select_wait(s, timeout, bufsize=4096)
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                except Exception:
                    pass

        # IMAP (143) — gentle capability probe
        elif port == 143:
            try:
                # many IMAP servers send banner immediately; try a NOOP/CAPABILITY if not
                data = _recv_select_wait(s, min(timeout, 0.5), bufsize=4096)
                if not data:
                    try:
                        s.sendall(b"A001 CAPABILITY\r\n")
                    except Exception:
                        pass
                    data = _recv_select_wait(s, timeout, bufsize=4096)
                raw = data or raw
                preview = mk_preview(data) if data else preview
            except Exception:
                pass

        # MYSQL
        elif port == 3306:
            try:
                # first attempt: slightly longer immediate read and larger buffer
                data = _recv_select_wait(s, min(max(timeout, 0.5), 2.0), bufsize=8192)
                if data:
                    raw = data
                    preview = mk_preview(data)
                else:
                    # fallback: second read with normal timeout
                    data = _recv_select_wait(s, timeout, bufsize=8192)
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
            except Exception:
                pass

        # ------------------------
        # Extra gentle probes for more services (add BEFORE the final generic else)
        # ------------------------

        # RDP (3389) - try TLS/SSL wrap and read certificate subject (non-intrusive)
        elif port == 3389:
            try:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host_hdr, do_handshake_on_connect=True)
                ss.settimeout(min(max(timeout, 0.1), 10.0))
                try:
                    # If handshake succeeded, try to read peer cert
                    cert = ss.getpeercert()
                    if cert:
                        # build a short preview from subject/issuer
                        subj = cert.get('subject', ())
                        cn = ""
                        for t in subj:
                            for kv in t:
                                if kv[0].lower() == 'commonname':
                                    cn = kv[1]
                        preview = f"RDP TLS cert: {cn}" if cn else "RDP TLS cert"
                        raw = raw or b""  # keep whatever we have
                except Exception:
                    # If no cert or handshake read fails, ignore silently
                    pass
                try:
                    ss.close()
                except Exception:
                    pass
            except Exception:
                # fallback: try a short recv if server speaks first (already attempted above)
                try:
                    data = s.recv(4096)
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                except Exception:
                    pass

        # Redis (6379) - safe & common: send INFO\r\n to get textual server info
        elif port == 6379:
            try:
                s.sendall(b"INFO\r\n")
            except Exception:
                pass
            try:
                data = s.recv(4096)
                raw = data or raw
                preview = mk_preview(data) if data else ""
            except Exception:
                pass

        # VNC (5900) - request protocol version; server usually replies with 'RFB 003.xxx'
        elif port == 5900:
            try:
                # server often speaks first; if not, send a client version line (harmless)
                try:
                    data = s.recv(64)
                    if data:
                        raw = data or raw
                        preview = mk_preview(data) if data else preview
                    else:
                        s.sendall(b"RFB 003.003\n")
                        data = s.recv(64)
                        raw = data or raw
                        preview = mk_preview(data) if data else ""
                except Exception:
                    # try sending client version anyway
                    try:
                        s.sendall(b"RFB 003.003\n")
                        data = s.recv(64)
                        raw = data or raw
                        preview = mk_preview(data) if data else ""
                    except Exception:
                        pass
            except Exception:
                pass

        # PostgreSQL (5432) - send SSLRequest (8 bytes), server replies 'S' or 'N' (safe, lightweight)
        elif port == 5432:
            try:
                # SSLRequest: length(4) = 8, code(4) = 80877103 (0x04D2162F)
                sslreq = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                try:
                    s.sendall(sslreq)
                except Exception:
                    pass
                data = s.recv(8)
                raw = data or raw
                if data:
                    try:
                        # 'S' => supports TLS, 'N' => does not
                        if data[:1] in (b'S', b'N'):
                            preview = f"Postgres SSLResponse: {data[:1].decode(errors='ignore')}"
                        else:
                            preview = mk_preview(data)
                    except Exception:
                        preview = mk_preview(data)
            except Exception:
                pass

        # SIP (TCP 5060) - send lightweight OPTIONS (application-level); optional but useful
        elif port == 5060:
            try:
                callid = f"meintool-{int(time.time()*1000)}"
                opts = (
                    f"OPTIONS sip:{host_hdr} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TCP {host_hdr};branch=z9hG4bK{callid}\r\n"
                    f"From: <sip:meintool@{host_hdr}>;tag=mt{callid}\r\n"
                    f"To: <sip:{host_hdr}>\r\n"
                    f"Call-ID: {callid}\r\n"
                    f"CSeq: 1 OPTIONS\r\n"
                    f"Contact: <sip:meintool@{host_hdr}>\r\n"
                    f"Max-Forwards: 70\r\n"
                    f"Content-Length: 0\r\n\r\n"
                ).encode()
                try:
                    s.sendall(opts)
                except Exception:
                    pass
                data = s.recv(4096)
                raw = data or raw
                preview = mk_preview(data) if data else preview
            except Exception:
                pass

        # LDAP (389) - **optional**; LDAP uses BER binary frames — non-textual.
        # This is more intrusive; include only if you opt-in. Below we just try a short recv first.
        elif port == 389:
            try:
                data = s.recv(4096)
                raw = data or raw
                preview = mk_preview(data) if data else preview
            except Exception:
                pass

        else:
            # generic gentle newline probe and wait
            data = _send_and_wait(s, b"\r\n", max(0.3, timeout))
            raw = data or raw
            preview = mk_preview(data) if data else preview

        if _owns_sock:
            try:
                s.close()
            except Exception:
                pass

    except Exception:
        return ("", b"")
    return (preview[:4000], raw)

# ------------------------
# Fingerprinting helpers & improved logic
# ------------------------
def fingerprint_banner(port: int, banner_text: str, raw_bytes: Optional[bytes] = None) -> Optional[Dict[str, Any]]:
    """
    Return fingerprint dict:
      {
        'fp_service': "HTTP 1.1" or "SSH 2.0",
        'fp_product': "OpenSSH",
        'fp_version': "8.4p1 (Debian-5+deb11u5)" or "6.6.1p1 (Ubuntu-2ubuntu2.13)"
      }
    or None when nothing confidently detected.

    Important: fp_version preserves the raw parenthetical distro token if present (so user sees original packaging/revision).
    Meanwhile, os guessing logic elsewhere will use debNN/Ubuntu-X.Y extraction to map to distro versions.
    """
    if not banner_text:
        return None
    b = banner_text
    lower = b.lower()

    # find proto versions
    proto_ver = None
    if re.search(r"(?m)^HTTP/([0-9\.]+)", b, flags=re.I):
        m = re.search(r"(?m)^HTTP/([0-9\.]+)", b, flags=re.I)
        proto_ver = m.group(1)
    if re.search(r"(?m)^SSH-([0-9\.]+)-", b, flags=re.I):
        m = re.search(r"(?m)^SSH-([0-9\.]+)-", b, flags=re.I)
        proto_ver = m.group(1)

    # 1) Server header preferred for HTTP-like products
    m_srv = re.search(r"(?m)^Server:\s*([^\r\n]+)", b, flags=re.I)
    if m_srv:
        server_hdr = m_srv.group(1).strip()
        # extract parenthetical distro if any (preserve raw)
        mm_paren = re.search(r"\(([^)]+)\)", server_hdr)
        distro_raw = mm_paren.group(1).strip() if mm_paren else ""

        # try product patterns against server header
        for pat, canon, g in PRODUCT_PATTERNS:
            m = pat.search(server_hdr)
            if m:
                ver = ""
                try:
                    if g is not None and m.group(g):
                        ver = m.group(g).strip()
                except Exception:
                    ver = ""
                # "?" only when version group exists but couldn't be captured.
                # If g is None the product genuinely has no version (e.g. Cloudflare).
                ver = ver or ("?" if g is not None else "")
                # build fp_version with packaging/distrib token if present
                display_paren = ""
                if distro_raw:
                    display_paren = distro_raw  # preserve full raw token for display
                fp_version = ver
                if display_paren:
                    fp_version = f"{ver} ({display_paren})"
                # fp_service: HTTP + proto_ver if known
                fp_service = f"HTTP {proto_ver}" if proto_ver else "HTTP"
                return {"fp_service": fp_service, "fp_product": canon, "fp_version": fp_version, "raw_distro": distro_raw}

        # fallback: if none matched, parse generically 'Name/Version (Distro)'
        m_generic = re.match(r"([^\s/]+)(?:/([0-9A-Za-z\.\-]+))?", server_hdr)
        if m_generic:
            prod = m_generic.group(1)
            ver = m_generic.group(2) or "?"
            fp_version = ver
            if distro_raw:
                fp_version = f"{ver} ({distro_raw})"
            fp_service = f"HTTP {proto_ver}" if proto_ver else "HTTP"
            # normalize product tokens a bit
            prod_l = prod.lower()
            if "apache" in prod_l:
                prod = "Apache"
            elif "nginx" in prod_l:
                prod = "nginx"
            elif "iis" in prod_l or "microsoft" in prod_l:
                prod = "IIS"
            return {"fp_service": fp_service, "fp_product": prod, "fp_version": fp_version, "raw_distro": distro_raw}

    # 2) HTTP response fakat Server header yok (örn. bazı LB/CDN/backend'ler)
    if proto_ver and re.search(r"(?m)^HTTP/", b, flags=re.I) and not m_srv:
        # Status code + reason phrase
        m_status = re.search(r"(?m)^HTTP/[0-9\.]+ (\d{3})([ \t]+([^\r\n]+))?", b, flags=re.I)
        if m_status:
            code   = m_status.group(1)
            reason = (m_status.group(3) or "").strip()
            status_str = f"{code} {reason}".strip()
        else:
            status_str = ""
        fp_service = f"HTTP {proto_ver}"
        # Location header takes priority over bare status for the note
        m_loc = re.search(r"(?m)^Location:\s*([^\r\n]+)", b, flags=re.I)
        if m_loc:
            note = f"→ {m_loc.group(1).strip()}"
        elif status_str:
            note = f"→ {status_str}"
        else:
            note = ""
        return {"fp_service": fp_service, "fp_product": "", "fp_version": "",
                "raw_distro": "", "fp_note": note, "fp_status": status_str}

    # 3) token scanning in body/banners
    for pat, canon, g in PRODUCT_PATTERNS:
        m = pat.search(b)
        if m:
            ver = ""
            try:
                if g is not None and m.group(g):
                    ver = m.group(g).strip()
            except Exception:
                ver = ""
            ver = ver or ("?" if g is not None else "")
            # special OpenSSH handling: include raw packaging token in parentheses (if present)
            if canon == "OpenSSH":
                raw_distro_token = ""
                # Find raw Debian token-ish substring (preserve)
                mm_deb_raw = re.search(r"(Debian[-_\w\+]*\d+[^ \r\n]*)", b, flags=re.I)
                if mm_deb_raw:
                    raw_distro_token = mm_deb_raw.group(1)
                else:
                    mm_ub_raw = re.search(r"(Ubuntu[-_\w\+]*[0-9]+(?:\.[0-9]+)?)", b, flags=re.I)
                    if mm_ub_raw:
                        raw_distro_token = mm_ub_raw.group(1)
                # Use helper to extract canonical packaging target for OS guess if possible
                distro_token_for_os = ""
                ddeb = _extract_debian_from_text(b)
                if ddeb:
                    distro_token_for_os = f"deb{ddeb}"
                else:
                    dub = _extract_ubuntu_from_text(b)
                    if dub:
                        distro_token_for_os = f"Ubuntu-{dub}"
                fp_version = ver
                if raw_distro_token:
                    # preserve full raw token inside parentheses for display
                    fp_version = f"{ver} ({raw_distro_token})"
                proto_sv = ""
                mproto = re.search(r"(?m)^SSH-([0-9\.]+)-", b, flags=re.I)
                if mproto:
                    proto_sv = mproto.group(1)
                fp_service = f"SSH {proto_sv}" if proto_sv else "SSH"
                # raw_distro returns the raw token (for display); the OS guesser uses debNN/dub separately
                return {"fp_service": fp_service, "fp_product": "OpenSSH", "fp_version": fp_version, "raw_distro": raw_distro_token}
            # generic
            fp_service = ""
            if canon in ("Apache", "nginx", "OpenResty", "LiteSpeed", "IIS", "Caddy"):
                fp_service = f"HTTP {proto_ver}" if proto_ver else "HTTP"
            return {"fp_service": fp_service, "fp_product": canon, "fp_version": ver, "raw_distro": ""}

    # 3) FTP banners
    if port == 21 or "ftp" in lower:
        first = b.splitlines()[0].strip() if b.splitlines() else ""
        if "vsftpd" in lower:
            mm = re.search(r"vsftpd[/ ]?([0-9\.]+)?", lower)
            return {"fp_service": "FTP", "fp_product": "vsftpd", "fp_version": (mm.group(1) if mm and mm.group(1) else "?"), "raw_distro": ""}
        if "proftpd" in lower:
            mm = re.search(r"proftpd[/ ]?([0-9\.]+)?", lower)
            return {"fp_service": "FTP", "fp_product": "ProFTPD", "fp_version": (mm.group(1) if mm and mm.group(1) else "?"), "raw_distro": ""}
        if "microsoft ftp" in lower or "microsoft-ftp" in lower:
            return {"fp_service": "FTP", "fp_product": "Microsoft FTP", "fp_version": "?", "raw_distro": ""}
        # fallback: prefer first numeric-like product/version on first line
        mm = re.search(r"([A-Za-z0-9_\-]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", first)
        if mm:
            prod = mm.group(1)
            ver = mm.group(2)
            return {"fp_service": "FTP", "fp_product": prod, "fp_version": ver, "raw_distro": ""}
        return {"fp_service": "FTP", "fp_product": "", "fp_version": "?", "raw_distro": ""}

    # 4) SSH generic
    if port == 22 or "ssh" in lower:
        m_open = re.search(r"OpenSSH[_\-/ ]?([0-9A-Za-z\.\-p]+)", b, flags=re.I)
        if m_open:
            ver = m_open.group(1)
            # preserve raw token for display if exists
            mm_deb_raw = re.search(r"(Debian[-_\w\+]*\d+[^ \r\n]*)", b, flags=re.I)
            mm_ub_raw = re.search(r"(Ubuntu[-_\w\+]*[0-9]+(?:\.[0-9]+)?)", b, flags=re.I)
            raw_token = mm_deb_raw.group(1) if mm_deb_raw else (mm_ub_raw.group(1) if mm_ub_raw else "")
            # determine canonical token for os guess separately (debNN or Ubuntu-X.Y)
            ddeb = _extract_debian_from_text(b)
            dub = _extract_ubuntu_from_text(b)
            fp_version = ver
            if raw_token:
                fp_version = f"{ver} ({raw_token})"
            # proto version may exist in SSH banner
            mproto = re.search(r"(?m)^SSH-([0-9\.]+)-", b, flags=re.I)
            proto_sv = mproto.group(1) if mproto else ""
            fp_service = f"SSH {proto_sv}" if proto_sv else "SSH"
            return {"fp_service": fp_service, "fp_product": "OpenSSH", "fp_version": fp_version, "raw_distro": raw_token}
        # generic SSH banner like 'SSH-2.0-ServerName'
        m2 = re.search(r"(?m)^SSH-([0-9\.]+)-([^\s\r\n]+)", b, flags=re.I)
        if m2:
            proto_sv = m2.group(1)
            prod = m2.group(2)
            return {"fp_service": f"SSH {proto_sv}", "fp_product": prod, "fp_version": "?", "raw_distro": ""}

    # 5) SMTP heuristics
    if port in (25, 587) or "smtp" in lower:
        if "exim" in lower:
            mm = re.search(r"exim/?\s*([0-9\.]+)?", lower)
            return {"fp_service": "SMTP", "fp_product": "Exim", "fp_version": (mm.group(1) if mm and mm.group(1) else "?"), "raw_distro": ""}
        if "postfix" in lower:
            return {"fp_service": "SMTP", "fp_product": "Postfix", "fp_version": "?", "raw_distro": ""}
        # fallback
        first = b.splitlines()[0].strip() if b.splitlines() else ""
        return {"fp_service": "SMTP", "fp_product": "", "fp_version": "?", "raw_distro": ""}

    # 6) MySQL/MariaDB handshake parsing
    # If we have raw bytes (handshake), try strict parse first (most reliable for MySQL/MariaDB)
    if raw_bytes and (port == 3306 or "mysql" in (banner_text or "").lower() or "mariadb" in (banner_text or "").lower()):
        parsed = _parse_mysql_handshake_raw(raw_bytes)
        if parsed:
            proto = parsed.get("proto")  # may be None or '5.5.5'
            version = parsed.get("version") or "?"
            pack = parsed.get("pack")
            product = parsed.get("product") or ""
            # build fp_version preserving packaging/revision token in parentheses if present
            fp_version = version
            if pack:
                fp_version = f"{version} (pkg-{pack})"
            # choose displayed product name
            display_product = "MariaDB" if "mariadb" in product.lower() else ("MySQL Community Server" if "mysql" in product.lower() and pack else ("MySQL" if "mysql" in product.lower() else product))
            # build fp_service with proto marker if present
            fp_service = f"MySQL {proto}" if proto else "MySQL"
            return {
                "fp_service": fp_service,
                "fp_protocol": "MySQL",
                "fp_proto_version": proto or "",
                "fp_product": display_product,
                "fp_version": fp_version,
                "raw_distro": pack or ""
            }
    if port == 3306 or "mysql" in lower or "mariadb" in lower:
        # 1) explicit proto-marker + version + -MariaDB (e.g. '5.5.5-10.3.29-MariaDB')
        m = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+\.[0-9]+\.[0-9]+)-mariadb", b, flags=re.I)
        if m:
            proto_marker = m.group(1)
            version = m.group(2)
            fp_service = f"MySQL {proto_marker}"
            return {"fp_service": fp_service, "fp_product": "MariaDB", "fp_version": version, "raw_distro": ""}

        # 2) If proto-marker appears somewhere else (e.g. '... 5.5.5 ... 11.8.3-MariaDB ...'),
        #    try to detect a standalone '5.5.5' token first and then extract version nearby.
        proto_marker_any = None
        m_any_proto = re.search(r"\b5\.5\.5\b", b, flags=re.I)
        if m_any_proto:
            proto_marker_any = m_any_proto.group(0)

        # 3) version-before-MariaDB e.g. '11.8.3-MariaDB-log' or similar
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)[-_A-Za-z0-9]*mariadb", b, flags=re.I)
        if m:
            version = m.group(1)
            if proto_marker_any:
                fp_service = f"MySQL {proto_marker_any}"
            else:
                # try to find a proto marker of form X.Y.Z-<ver>-mariadb (if existed earlier)
                mproto = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+\.[0-9]+\.[0-9]+-mariadb", b, flags=re.I)
                proto_marker = mproto.group(1) if mproto else None
                fp_service = f"MySQL {proto_marker}" if proto_marker else "MySQL"
            return {"fp_service": fp_service, "fp_product": "MariaDB", "fp_version": version, "raw_distro": ""}

        # 4) older pattern '5.5.5-<ver>-MariaDB' (catch if earlier missed)
        m = re.search(r"5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-mariadb", b, flags=re.I)
        if m:
            version = m.group(1)
            return {"fp_service": "MySQL 5.5.5", "fp_product": "MariaDB", "fp_version": version, "raw_distro": ""}

        # 5) 'MariaDB 10.5.12' or 'mariadb-10.5.12' variants
        m = re.search(r"mariadb[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", b, flags=re.I)
        if m:
            version = m.group(1)
            if proto_marker_any:
                fp_service = f"MySQL {proto_marker_any}"
            else:
                fp_service = "MySQL"
            return {"fp_service": fp_service, "fp_product": "MariaDB", "fp_version": version, "raw_distro": ""}

        # 6) MySQL fallback 'MySQL 5.7.31' etc.
        m = re.search(r"(?:mysql)[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", b, flags=re.I)
        if m:
            version = m.group(1)
            if proto_marker_any:
                fp_service = f"MySQL {proto_marker_any}"
            else:
                fp_service = "MySQL"
            return {"fp_service": fp_service, "fp_product": "MySQL", "fp_version": version, "raw_distro": ""}

        # 7) last-resort binary/embedded search
        m = re.search(r"[\x00-\x20]*([0-9]+\.[0-9]+\.[0-9]+)[-_A-Za-z0-9]*mariadb", b, flags=re.I)
        if m:
            version = m.group(1)
            fp_service = f"MySQL {proto_marker_any}" if proto_marker_any else "MySQL"
            return {"fp_service": fp_service, "fp_product": "MariaDB", "fp_version": version, "raw_distro": ""}

        # fallback: unknown MySQL-like service
        return {"fp_service": "MySQL", "fp_product": "", "fp_version": "?", "raw_distro": ""}

    # 7) IMAP / Dovecot
    if "dovecot" in lower:
        mm = re.search(r"dovecot(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", lower)
        v = mm.group(1) if mm and mm.group(1) else "?"
        return {"fp_service": "IMAP", "fp_product": "Dovecot", "fp_version": v, "raw_distro": ""}

    # 8) generic product/version fallback
    mm = re.search(r"([A-Za-z0-9_\-\.]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", b)
    if mm:
        prod_raw = mm.group(1)
        ver = mm.group(2)
        if prod_raw.lower() in ("http", "httpd"):
            return None
        # normalize a bit
        prod = prod_raw
        if "iis" in prod_raw.lower() or "microsoft" in prod_raw.lower():
            prod = "IIS"
        return {"fp_service": f"{proto_ver or ''}".strip(), "fp_product": prod, "fp_version": ver, "raw_distro": ""}

    return None

# OpenSSH version prefix → likely Debian release (heuristic, not authoritative)
# Debian unstable/sid packages often lack +debNNuX suffix — use SSH version as fallback signal.
OPENSSH_DEBIAN_HINTS: List[Tuple[str, str]] = [
    ("10.", "13"),   # Trixie / sid (2024+)
    ("9.8", "13"),
    ("9.7", "13"),
    ("9.6", "13"),
    ("9.2", "12"),   # Bookworm
    ("8.9", "12"),
    ("8.4", "11"),   # Bullseye
    ("7.9", "10"),   # Buster
    ("7.4", "9"),    # Stretch
    ("6.7", "8"),    # Jessie
]

# ------------------------
# OS guess (improved)
# ------------------------
def os_guess_from_banners(all_banners_texts: List[str]) -> Optional[Dict[str, str]]:
    joined = "\n".join([t for t in all_banners_texts if t])
    lower = joined.lower()
    if not lower:
        return None

    # Debian: prefer debNN tokens (deb11, deb12u3, etc.) — most reliable
    m_deb_pack = re.search(r"\bdeb(\d{1,2})(?=[^\d]|$)", lower, flags=re.I)
    if m_deb_pack:
        return {"os_family": "Linux", "os_distro": "Debian", "os_version": m_deb_pack.group(1)}

    # Fallback: 'Debian 11' or 'Debian GNU/Linux 12' with whitespace separator only.
    # NOTE: 'Debian-7' (hyphen) is a package revision number, NOT a Debian release — excluded.
    m_debian = re.search(r"\bdebian\s+(?:gnu/linux\s+)?([0-9]{1,2})\b", lower, flags=re.I)
    if m_debian:
        return {"os_family": "Linux", "os_distro": "Debian", "os_version": m_debian.group(1)}

    # 'debian' is present but version couldn't be extracted from packaging tokens.
    # Try to infer Debian release from OpenSSH version (heuristic).
    if "debian" in lower:
        m_ssh = re.search(r"\bopenssh[_\-/ ]?([0-9]+\.[0-9]+)", joined, flags=re.I)
        if m_ssh:
            ssh_ver = m_ssh.group(1)  # e.g. "10.0"
            inferred = None
            for prefix, deb_rel in OPENSSH_DEBIAN_HINTS:
                if ssh_ver.startswith(prefix) or (ssh_ver + ".").startswith(prefix):
                    inferred = deb_rel
                    break
            if inferred:
                return {"os_family": "Linux", "os_distro": "Debian",
                        "os_version": inferred, "os_version_note": f"~{inferred}, inferred from OpenSSH {ssh_ver}"}
        # debian detected but no version signal at all
        return {"os_family": "Linux", "os_distro": "Debian", "os_version": ""}

    # Ubuntu: prefer explicit 'Ubuntu X.Y'
    m_ub = re.search(r"ubuntu[^\d]*([0-9]{2}\.[0-9]+)", lower)
    if m_ub:
        return {"os_family": "Linux", "os_distro": "Ubuntu", "os_version": m_ub.group(1)}
    if "ubuntu" in lower:
        # presence of 'ubuntu' but no clear version -> report distro without version
        return {"os_family": "Linux", "os_distro": "Ubuntu", "os_version": ""}

    # Windows: via IIS header mapping
    m_iis = re.search(r"microsoft[- ]?iis/?\s*([0-9\.]+)", joined, flags=re.I)
    if m_iis:
        v = m_iis.group(1)
        mapped = IIS_TO_WINDOWS.get(v, f"Windows NT {v}")
        return {"os_family": "Windows", "os_distro": "Windows", "os_version": mapped}

    # CentOS/RedHat
    # Strategy: look inside parentheticals first (e.g. Apache's "(CentOS)" or "(CentOS Linux 7.4)"),
    # then try tight inline match. [^\d]* was too greedy — it grabbed charset=iso-8859-1 numbers.
    if "centos" in lower or "red hat" in lower or "redhat" in lower:
        version = ""
        # 1) Parenthetical: "(CentOS release 7.4)" / "(CentOS Linux 7)" / "(Red Hat ...)"
        m = re.search(r"\((?:centos|red\s*hat)[^)]{0,40}?(\d{1,2}(?:\.\d+)?)[^)]*\)", joined, flags=re.I)
        if m:
            version = m.group(1)
        if not version:
            # 2) Tight inline: "CentOS 7" / "CentOS release 7.4" / "Red Hat 8"
            m2 = re.search(r"(?:centos|red\s*hat)\s+(?:linux\s+|enterprise\s+linux\s+|release\s+)?(\d{1,2}(?:\.\d+)?)\b", joined, flags=re.I)
            if m2:
                version = m2.group(1)
        return {"os_family": "Linux", "os_distro": "RHEL/CentOS", "os_version": version}

    # Alpine
    if "alpine" in lower:
        m = re.search(r"alpine[^\d]*([0-9]+\.[0-9]+)?", lower)
        return {"os_family": "Linux", "os_distro": "Alpine", "os_version": m.group(1) if m and m.group(1) else ""}

    # BSD
    if "freebsd" in lower:
        return {"os_family": "BSD", "os_distro": "FreeBSD", "os_version": ""}
    if "openbsd" in lower:
        return {"os_family": "BSD", "os_distro": "OpenBSD", "os_version": ""}

    return None

# ------------------------
# Presentation helpers
# ------------------------
def console_preview_from_banner(banner_text: str, port: int) -> str:
    if not banner_text:
        return ""
    info = fingerprint_banner(port, banner_text)
    if info and info.get("fp_product"):
        prod = info.get("fp_product", "").strip()
        ver = info.get("fp_version", "?")
        s = f"{prod} {ver}".strip()
        if len(s) > 80:
            s = s[:77] + "..."
        return s
    first = banner_text.splitlines()[0].strip()
    first = re.sub(r"\s{2,}", " ", first)
    if len(first) > 80:
        first = first[:77] + "..."
    return first

def _sanitize_console(s: str, max_len: int = 100) -> str:
    """Strip non-printable bytes for safe terminal display."""
    return "".join(c if 0x20 <= ord(c) < 0x7f else "." for c in s)[:max_len]

def format_line(rec: Dict[str, Any], show_preview: bool = False, preview_text: str = "") -> str:
    proto = rec.get("proto", "?").upper()
    state = rec.get("state", "?")
    port = rec.get("port", 0)
    svc = rec.get("service", "")
    proto_ver = rec.get("fp_proto_version", "") or ""
    # responsive=False: TCP handshake succeeded but zero bytes received.
    # Display as OPEN/NO-DATA to mirror CLOSED/FILTERED ambiguity pattern.
    # Could be: SYN-proxy / ISP tarpit, or a real service that waits for client first.
    display_state = state.upper()
    if state == "open" and rec.get("responsive") is False:
        display_state = "OPEN/NO-DATA"
    service_part = f"({svc}" + (f" / {proto_ver}" if proto_ver else "") + ")"
    base = f"[{display_state:15}] {proto:3} {port:5d} {service_part}"
    if rec.get("fp_product"):
        ver = rec.get("fp_version", "")
        prod_str = rec.get("fp_product")
        base += f"  / {prod_str}" + (f" {ver}" if ver else "")
    elif rec.get("fp_note"):
        # No product but we have a note (e.g. HTTP status/redirect with no Server header)
        base += f"  {rec.get('fp_note')}"
    else:
        if show_preview and preview_text:
            base += f"  banner: {_sanitize_console(preview_text)}"
    if rec.get("note"):
        base += f"  note: {rec.get('note')}"
    return base

def sanitize_for_json(rec: Dict[str, Any], dns_query_for: Optional[str] = None, include_banner: bool = False, include_b64: bool = False, preview_max: int = 200) -> Dict[str, Any]:
    r = dict(rec)
    raw = r.pop("_raw_banner", None)
    banner = r.get("banner", "")
    banner_preview = r.get("_console_preview", "")
    banner_b64 = None
    banner_len = 0
    banner_is_binary = False

    if raw:
        banner_len = len(raw)
        banner_is_binary = True
        if include_banner:
            try:
                text = raw.decode("latin-1")
            except Exception:
                text = repr(raw)
            r["banner_text"] = text
            preview = text
            banner_preview = preview[:preview_max] + ("..." if len(preview) > preview_max else "")
        if include_b64:
            try:
                banner_b64 = base64.b64encode(raw).decode("ascii")
            except Exception:
                banner_b64 = base64.b64encode(repr(raw).encode()).decode("ascii")
    else:
        if banner:
            if include_banner:
                r["banner_text"] = banner
            preview = banner
            banner_preview = preview[:preview_max] + ("..." if len(preview) > preview_max else "")
            banner_len = len(banner)
            banner_is_binary = not all((ch.isprintable() or ch.isspace()) for ch in banner)

    if include_b64 and banner_b64 is not None:
        r["banner_b64"] = banner_b64
    if include_banner:
        r["banner_preview"] = banner_preview
    if include_banner or include_b64:
        r["banner_len"] = banner_len
        r["banner_is_binary"] = bool(banner_is_binary)

    # ensure fingerprint fields exist
    r["fp_service"] = r.get("fp_service", "")
    r["fp_product"] = r.get("fp_product", "")
    r["fp_version"] = r.get("fp_version", "")
    r["fp_protocol"] = r.get("fp_protocol", "")
    r["fp_proto_version"] = r.get("fp_proto_version", "")

    if (include_banner or include_b64) and r.get("proto") == "udp" and r.get("port") == 53:
        r["dns_query_for"] = dns_query_for or "www.example.com"

    if "banner" in r:
        del r["banner"]
    if "_console_preview" in r:
        del r["_console_preview"]
    return r

# ------------------------
# Scanning workers
# ------------------------
def tcp_scan_one(ip: str, port: int, timeout: float, retries: int, need_banner: bool, host_header: str) -> Dict[str, Any]:
    r: Dict[str, Any] = {"proto": "tcp", "port": port, "service": COMMON_PORTS.get(port, ""), "state": "closed", "banner": ""}
    last_err = None
    for _ in range(max(1, retries)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            err = s.connect_ex((ip, port))
            if err == 0:
                r["state"] = "open"
                if need_banner:
                    # Default: handshake oldu ama henüz veri gelmedi.
                    # Bu, SYN-proxy / ISP tarpit tespitinin temel sinyali.
                    r["responsive"] = False
                    try:
                        # Açık socketi geçir — yeni bağlantı açılmaz
                        text, raw = tcp_probe_banner(ip, port, timeout, host_header, existing_sock=s)
                        r["banner"] = text or ""
                        if raw:
                            r["_raw_banner"] = raw
                            r["responsive"] = True   # gerçek byte aldık → uygulama katmanı var
                    except Exception:
                        r["banner"] = r.get("banner", "")
                try:
                    s.close()
                except Exception:
                    pass
                return r
            else:
                last_err = err
            try:
                s.close()
            except Exception:
                pass
        except Exception as e:
            last_err = str(e)
    # Map last errno to a more precise state:
    #   ECONNREFUSED       → "closed"   (real RST from target)
    #   EAGAIN/EWOULDBLOCK → "filtered" (Python translates connect timeout to this)
    #   ETIMEDOUT          → "filtered" (kernel-level connect timeout)
    #   EHOSTUNREACH/ENETUNREACH → "filtered" (ICMP unreach received)
    # Anything else (or non-int from exception path) stays "closed" as a conservative
    # default, but we keep the raw error in _err so post-hoc analysis is possible.
    if last_err is not None:
        r["_err"] = str(last_err)
        if isinstance(last_err, int):
            if last_err == errno.ECONNREFUSED:
                r["state"] = "closed"
            elif last_err in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT,
                              errno.EHOSTUNREACH, errno.ENETUNREACH):
                r["state"] = "filtered"
            # else: leave as "closed" default
    return r

def udp_scan_one(ip: str, port: int, timeout: float, dns_query_for: Optional[str] = None, need_banner: bool = False) -> Dict[str, Any]:
    r: Dict[str, Any] = {"proto": "udp", "port": port, "service": COMMON_PORTS.get(port, ""), "state": "closed/filtered", "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        payload = b"\x00"
        if port == 53:
            payload = build_dns_query_qname(dns_query_for)
        elif port == 123:
            payload = b"\x1b" + b"\x00" * 47
        elif port == 161:
            payload = b"\x30\x0c\x02\x01\x01\x04\x06public\xa0\x00\x02\x01\x00"
        elif port == 69:
            payload = b"\x00\x01" + b"test" + b"\x00" + b"octet" + b"\x00"
        try:
            s.sendto(payload, (ip, port))
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return r
        try:
            data, addr = s.recvfrom(4096)
            if data:
                r["state"] = "open"
                r["_raw_banner"] = data

                # Protocol-specific parsing for readable banner
                if port == 53:
                    parsed = _parse_dns_response(data, dns_query_for or "")
                    if parsed:
                        r["banner"] = parsed.get("summary", "")
                        # Stash structured fields for JSON
                        for k in ("dns_rcode_name", "dns_ancount", "dns_answers"):
                            if k in parsed:
                                r[k] = parsed[k]
                    else:
                        r["banner"] = data.decode("latin-1").strip()[:4000]
                elif port == 123:
                    parsed = _parse_ntp_response(data)
                    if parsed:
                        r["banner"] = parsed.get("summary", "")
                        for k in ("ntp_version", "ntp_stratum", "ntp_mode", "ntp_ref"):
                            if k in parsed:
                                r[k] = parsed[k]
                    else:
                        r["banner"] = data.decode("latin-1").strip()[:4000]
                else:
                    try:
                        r["banner"] = data.decode("latin-1").strip()[:4000]
                    except Exception:
                        r["banner"] = repr(data)[:200]

                if addr and addr[0] != ip:
                    r["note"] = f"udp response from {addr[0]}"
        except socket.timeout:
            r["state"] = "closed/filtered"
        except Exception as e:
            r["state"] = "error"
            r["_err"] = str(e)
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as e:
        r["state"] = "error"
        r["_err"] = str(e)
    return r

# ------------------------
# Main
# ------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Ordered TCP/UDP scanner with fingerprint and banner options.")
    p.add_argument("target", help="domain or IP")
    p.add_argument("-p", "--ports", default="", help="comma list or range e.g. '22,80' or '1-1024' (default: common set)")
    p.add_argument("--udp", action="store_true", help="scan both TCP and UDP (TCP+UDP)")
    p.add_argument("--udp-only", action="store_true", help="scan only UDP (no TCP)")
    p.add_argument("--timeout", "-t", type=_parse_timeout, default=1.0, help="per-port timeout (s)")
    p.add_argument("--threads", "-T", type=int, default=200, help="worker threads")
    p.add_argument("--fingerprint", action="store_true", help="run banner-based fingerprinting (console + JSON fields)")
    p.add_argument("--banner", action="store_true", help="grab full banners (JSON); console shows short preview only when fingerprint not used")
    p.add_argument("--raw", action="store_true", help="include raw banner bytes (base64) in JSON output (use with --banner)")
    p.add_argument("--retries", type=int, default=1, help="connect retries")
    p.add_argument("--open", action="store_true", help="print only open ports")
    p.add_argument("--json", help="write results to JSON file")
    p.add_argument("--dns-domain", default=None, help="custom domain used for UDP/53 queries (overrides using target if specified)")
    args = p.parse_args()

    scan_udp = False; scan_tcp = True
    if args.udp_only:
        scan_udp = True; scan_tcp = False
    elif args.udp:
        scan_udp = True; scan_tcp = True

    # --- URL parsing ---
    # args.target may be a full URL (https://example.com), plain host, or IP.
    # Extract clean host, scheme, and any explicit port from the URL.
    parsed = parse_target_url(args.target)
    clean_host = parsed["host"]          # e.g. "google.com"
    url_scheme = parsed["scheme"]        # "https" | "http" | ""
    url_port   = parsed["port"]          # int or None

    # If user gave a raw URL, show both original and resolved form
    display_target = args.target if args.target != clean_host else clean_host

    # Override port list if URL contained an explicit port and user didn't specify -p
    if url_port and not args.ports:
        args.ports = str(url_port)

    try:
        ip = resolve_target(clean_host)
    except Exception as e:
        print(f"[!] Could not resolve target: {e}")
        return

    # host_header for HTTP probes: use clean hostname (not raw URL)
    host_header = clean_host

    domain_for_query = args.dns_domain if args.dns_domain else (clean_host if "." in clean_host else "www.example.com")
    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No ports to scan.")
        return

    ordered_keys = []
    for port in ports:
        if scan_tcp:
            ordered_keys.append(("tcp", port))
        if scan_udp:
            ordered_keys.append(("udp", port))

    results_map: Dict[Tuple[str,int], Optional[Dict[str,Any]]] = {k: None for k in ordered_keys}
    total_tasks = len(ordered_keys)

    scan_type_str = "UDP only" if (scan_udp and not scan_tcp) else ("TCP+UDP" if (scan_udp and scan_tcp) else "TCP only")
    print(f"Target: {display_target} → {ip}")
    print(f"Scan type: {scan_type_str}  Ports: {len(ports)}  Threads: {args.threads}  Timeout: {args.timeout}s")
    start_ts = datetime.now(timezone.utc).isoformat()
    start_time = time.time()

    need_banner_flag = (args.banner or args.fingerprint)

    future_to_key: Dict[Any, Tuple[str,int]] = {}
    all_banner_texts: List[str] = []

    actual_threads = min(args.threads, total_tasks) if total_tasks > 0 else 1

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=actual_threads) as ex:
            for proto, port in ordered_keys:
                if proto == "tcp":
                    fut = ex.submit(tcp_scan_one, ip, port, args.timeout, args.retries, need_banner_flag, host_header)
                else:
                    fut = ex.submit(udp_scan_one, ip, port, args.timeout, domain_for_query, need_banner_flag)
                future_to_key[fut] = (proto, port)

            next_index = 0
            for fut in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"proto": key[0], "port": key[1], "service": COMMON_PORTS.get(key[1], ""), "state": "error", "_err": str(e), "banner": ""}
                results_map[key] = r

                # flush ready results in order
                while next_index < total_tasks:
                    k = ordered_keys[next_index]
                    if results_map[k] is None:
                        break
                    rec = results_map[k]
                    next_index += 1

                    if args.open and rec.get("state") != "open":
                        continue

                    # prepare banner_text for fingerprinting/preview
                    banner_text = rec.get("banner","") or ""
                    if not banner_text and rec.get("_raw_banner") is not None:
                        try:
                            banner_text = rec["_raw_banner"].decode("latin-1")
                        except Exception:
                            banner_text = repr(rec["_raw_banner"])

                    if banner_text:
                        all_banner_texts.append(banner_text)

                    # fingerprinting when requested
                    if args.fingerprint:
                        info = fingerprint_banner(rec.get("port"), banner_text, rec.get("_raw_banner"))
                        if info:
                            rec["fp_service"] = info.get("fp_service","")
                            rec["fp_product"] = info.get("fp_product","")
                            rec["fp_version"] = info.get("fp_version","?")
                            mproto = None
                            if info.get("fp_service"):
                                mproto = re.search(r"([A-Za-z]+)\s*([0-9\.]+)", info.get("fp_service"))
                            if mproto:
                                rec["fp_protocol"] = mproto.group(1)
                                rec["fp_proto_version"] = mproto.group(2)
                            else:
                                rec["fp_protocol"] = ""
                                rec["fp_proto_version"] = ""
                            # fp_note de varsa al (HTTP Server-yok dalı)
                            if info.get("fp_note"):
                                rec["fp_note"] = info.get("fp_note")
                        else:
                            rec.setdefault("fp_service", "")
                            rec.setdefault("fp_product", "")
                            rec.setdefault("fp_version", "")
                            rec.setdefault("fp_protocol", "")
                            rec.setdefault("fp_proto_version", "")

                        # ISP transparent-proxy / aile filtresi tespiti:
                        # 30x cevabındaki Location header'ı target ile alakasız bir hosta
                        # yönlendiriyorsa, edge'de interceptor var demektir.
                        note = rec.get("fp_note", "") or ""
                        m_redir = re.search(r"https?://([^/\s]+)", note)
                        if m_redir:
                            redir_host = m_redir.group(1).split(":")[0].lower()
                            tgt = (clean_host or "").lower()
                            # tgt'nin altdomeni veya kendisi değilse şüpheli
                            if tgt and redir_host != tgt \
                               and not redir_host.endswith("." + tgt) \
                               and not tgt.endswith("." + redir_host):
                                rec["isp_intercept_suspected"] = True
                                rec["isp_intercept_redirect"] = redir_host

                    # --- Console preview oluştur ---
                    # format_line fp_product varsa onu doğrudan kullanır;
                    # console_preview sadece fp_product yokken (banner fallback) anlam taşır.
                    console_preview = ""
                    show_preview_flag = False

                    # UDP DNS/NTP için parser zaten okunabilir summary üretti — direkt kullan
                    if rec.get("proto") == "udp" and rec.get("port") in (53, 123) and rec.get("banner"):
                        console_preview = rec.get("banner", "")
                        show_preview_flag = True
                    elif not rec.get("fp_product") and args.banner:
                        # fp_product yok — banner'dan bir şeyler göstermeye çalış
                        if rec.get("port") == 3306:
                            # MySQL/MariaDB: binary handshake'ten okunabilir preview üret
                            raw_hs = rec.get("_raw_banner")
                            if raw_hs:
                                try:
                                    parsed = _parse_mysql_handshake_raw(raw_hs)
                                    if parsed:
                                        p   = parsed.get("proto")
                                        ver = parsed.get("version") or parsed.get("pack") or "?"
                                        prod = parsed.get("product") or "MySQL"
                                        console_preview = (
                                            f"MySQL / {p}  / {prod} {ver}" if p else f"{prod} {ver}"
                                        )
                                        show_preview_flag = True
                                except Exception:
                                    pass
                        if not console_preview:
                            console_preview = console_preview_from_banner(banner_text, rec.get("port"))
                            show_preview_flag = bool(console_preview)

                    # attach console preview for JSON
                    rec["_console_preview"] = console_preview

                    print(format_line(rec, show_preview_flag, console_preview))

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Runtime error: {e}")

    end_time = time.time()
    finish_ts = datetime.now(timezone.utc).isoformat()

    # OS guess
    os_guess = os_guess_from_banners(all_banner_texts) if all_banner_texts else None
    if os_guess:
        family = os_guess.get("os_family", "")
        distro = os_guess.get("os_distro", "")
        ver = os_guess.get("os_version", "")
        note = os_guess.get("os_version_note", "")
        if family == "Windows" and distro == "Windows" and ver:
            print(f"\nOS guess: {ver}")
        elif distro:
            ver_str = f" {note}" if note else (f" {ver}" if ver else "")
            print(f"\nOS guess: {family} ({distro}{ver_str})")
        else:
            print(f"\nOS guess: {family}")

    # summary
    open_tcp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="tcp" and r.get("state")=="open")
    open_udp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="udp" and r.get("state")=="open")
    closed_tcp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="tcp" and r.get("state")=="closed")
    filtered_tcp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="tcp" and r.get("state")=="filtered")
    responsive_tcp = sum(
        1 for k,r in results_map.items()
        if r and r.get("proto")=="tcp" and r.get("state")=="open" and r.get("responsive") is True
    )
    handshake_only_tcp = sum(
        1 for k,r in results_map.items()
        if r and r.get("proto")=="tcp" and r.get("state")=="open" and r.get("responsive") is False
    )
    intercept_flagged = sum(
        1 for k,r in results_map.items()
        if r and r.get("isp_intercept_suspected")
    )
    print("\n--- Scan summary ---")
    if scan_tcp and not scan_udp:
        if args.open:
            print(f"TCP open: {open_tcp}")
        else:
            print(f"TCP open: {open_tcp}, closed: {closed_tcp}, filtered: {filtered_tcp}")
    elif scan_udp and not scan_tcp:
        if args.open:
            print(f"UDP open: {open_udp}")
        else:
            total_udp = sum(1 for k in results_map if k[0] == "udp")
            print(f"UDP open: {open_udp}, total results: {total_udp}")
    else:
        if args.open:
            print(f"TCP open: {open_tcp}, UDP open: {open_udp}")
        else:
            print(f"TCP open: {open_tcp}, closed: {closed_tcp}, filtered: {filtered_tcp}; UDP open: {open_udp}")
    # Responsive split is only meaningful when banner-grabbing is on.
    if args.banner and scan_tcp:
        print(f"TCP responsive: {responsive_tcp}, no-data: {handshake_only_tcp}")
        if handshake_only_tcp > 0 and responsive_tcp < handshake_only_tcp:
            print(f"[!] Many no-data ports - upstream SYN-proxy or tarpit likely.")
    if intercept_flagged > 0:
        print(f"[!] ISP intercept suspected: {intercept_flagged} port(s) redirected off-target.")
    print(f"Duration: {end_time - start_time:.2f}s")

    # JSON output
    if args.json:
        ordered_results = [
            results_map[k] for k in ordered_keys
            if results_map[k] is not None and (not args.open or results_map[k].get("state") == "open")
        ]
        include_banner = args.banner
        include_b64 = args.raw and args.banner
        sanitized = [sanitize_for_json(r, dns_query_for=domain_for_query, include_banner=include_banner, include_b64=include_b64) for r in ordered_results]

        summary = {
            "tcp_open": open_tcp,
            "udp_open": open_udp,
            "total_results": len(results_map),
            "ports_scanned": ports,
            "scan_type": scan_type_str,
            "duration_s": round(end_time - start_time, 3)
        }

        out = {
            "target": clean_host,
            "ip": ip,
            "started_at_utc": start_ts,
            "finished_at_utc": finish_ts,
            "duration_s": round(end_time - start_time, 3),
            "summary": summary,
            "ports": ports,
            "scan_type": scan_type_str,
            "results": sanitized,
            "os_guess": os_guess or {}
        }
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            print(f"Results written to {args.json}")
        except Exception as e:
            print(f"[!] JSON write failed: {e}")

if __name__ == "__main__":
    main()
