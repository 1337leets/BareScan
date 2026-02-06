#!/usr/bin/env python3

"""
BareScan — Minimal, low-noise service fingerprinting via conservative banner grabbing.

Features:
  - Banner grabbing (--banner)
  - Service fingerprinting (--fingerprint)
  - JSON output (--json)
  - Centralized PRODUCT_PATTERNS and mapping tables for easy extension
  - Debian package token → Debian version mapping (debNN → Debian NN)
  - Preservation of packaging/revision tokens in fp_version (parentheses)
  - Recognition of common services (Dovecot, OpenSSH, Caddy, Apache, IIS, MariaDB, etc.)

Responsible use:
  - Run only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

__version__ = "0.1.0"

import argparse
import base64
import concurrent.futures
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

# ------------------------
# Improved Debian/Ubuntu token extractors
# ------------------------
def _extract_debian_from_text(s: str) -> Optional[str]:
    """
    Prefer 'debNN' packaging token (deb11, deb10u2, etc.) as the Debian major version.
    Fallback to explicit 'Debian-<num>' only if 'debNN' not found.
    Returns numeric major version as string (e.g. '11') or None.
    """
    if not s:
        return None
    # Look for 'deb' followed by 1-2 digits (captures deb11 in deb11u5)
    m = re.search(r"deb(\d{1,2})(?=[^\d]|$)", s, flags=re.I)
    if m:
        return m.group(1)
    # Fallback: 'Debian-<num>' or 'Debian <num>'
    m2 = re.search(r"\bDebian[-_\s]*([0-9]{1,2})(?:\b|[^\d])", s, flags=re.I)
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
    More reliable recv:
  - Waits until the socket becomes readable using select (up to total `timeout`)
  - Reads the first available data, then performs a short drain to collect extra bytes
    Returns:
  The received bytes (may be empty).
    """
    if timeout is None or timeout <= 0:
        timeout = 1.0
    end = time.time() + float(timeout)
    out = b""
    # Loop: use small, increasing waits (minimize busy-wait; total time bounded by timeout)
    while time.time() < end:
        remaining = max(0.01, end - time.time())
        rlist, _, _ = select.select([sock], [], [], remaining)
        if not rlist:
            # select timeout, retry again
            continue
        try:
            part = sock.recv(bufsize)
            if not part:
                # connection closed by peer
                break
            out += part
            # Attempt to drain any remaining data within a short time window
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

def tcp_probe_banner(ip: str, port: int, timeout: float, host_header: Optional[str] = None) -> Tuple[str, bytes]:
    """
    More reliable banner probing strategy:
  - Connect, then perform an immediate select-based recv (short window)
  - Use a port-specific gentle probe (HEAD, EHLO, newline, etc.)
  - For HTTP: wait after HEAD; if empty, fall back to GET
  - Overall wait behavior is bounded by `timeout`
    """
    raw = b""
    preview = ""
    try:
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
                getr = f"GET / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: barescan/1.0\r\nConnection: close\r\n\r\n".encode()
                data = _send_and_wait(s, getr, max(0.5, timeout))
                raw = data or raw
                preview = mk_preview(data) if data else preview

        # HTTPS: wrap then do same HEAD->GET fallback
        elif port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=host_header or ip)
                ss.settimeout(min(max(timeout, 0.1), 10.0))
                head = f"HEAD / HTTP/1.0\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode()
                data = _send_and_wait(ss, head, max(0.5, timeout))
                raw = data or raw
                preview = mk_preview(data) if data else ""
                if not data:
                    getr = f"GET / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: barescan/1.0\r\nConnection: close\r\n\r\n".encode()
                    data = _send_and_wait(ss, getr, max(0.5, timeout))
                    raw = data or raw
                    preview = mk_preview(data) if data else preview
                try:
                    ss.close()
                except Exception:
                    pass
            except Exception:
                # SSL handshake/wrap hatası -> geri dön normal soket ile (raw) data varsa onu kullan
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
                callid = f"barescan-{int(time.time()*1000)}"
                opts = (
                    f"OPTIONS sip:{host_hdr} SIP/2.0\r\n"
                    f"Via: SIP/2.0/TCP {host_hdr};branch=z9hG4bK{callid}\r\n"
                    f"From: <sip:barescan@{host_hdr}>;tag=mt{callid}\r\n"
                    f"To: <sip:{host_hdr}>\r\n"
                    f"Call-ID: {callid}\r\n"
                    f"CSeq: 1 OPTIONS\r\n"
                    f"Contact: <sip:barescan@{host_hdr}>\r\n"
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
        # This is more intrusive; include only when explicitly enabled. Here, only a short recv is attempted first.
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
                ver = ver or "?"
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

    # 2) token scanning in body/banners
    for pat, canon, g in PRODUCT_PATTERNS:
        m = pat.search(b)
        if m:
            ver = ""
            try:
                if g is not None and m.group(g):
                    ver = m.group(g).strip()
            except Exception:
                ver = ""
            ver = ver or "?"
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

# ------------------------
# OS guess (improved)
# ------------------------
def os_guess_from_banners(all_banners_texts: List[str]) -> Optional[Dict[str, str]]:
    joined = "\n".join([t for t in all_banners_texts if t])
    lower = joined.lower()
    if not lower:
        return None

    # Debian: prefer debNN tokens (deb11 etc)
    m_deb_pack = re.search(r"\bdeb(\d{1,2})(?=[^\d]|$)", lower, flags=re.I)
    if m_deb_pack:
        return {"os_family": "Linux", "os_distro": "Debian", "os_version": m_deb_pack.group(1)}

    # fallback Debian pattern 'Debian-11' or 'Debian 11'
    m_debian = re.search(r"debian[-_\s]*([0-9]+(?:\.[0-9]+)?)", joined, flags=re.I)
    if m_debian:
        return {"os_family": "Linux", "os_distro": "Debian", "os_version": m_debian.group(1)}

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
    if "centos" in lower or "red hat" in lower or "redhat" in lower:
        m = re.search(r"(centos|red ?hat)[^\d]*([0-9]+(?:\.[0-9]+)?)", lower)
        return {"os_family": "Linux", "os_distro": "RHEL/CentOS", "os_version": m.group(2) if m else ""}

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

def format_line(rec: Dict[str, Any], show_preview: bool = False, preview_text: str = "") -> str:
    proto = rec.get("proto", "?").upper()
    state = rec.get("state", "?")
    port = rec.get("port", 0)
    svc = rec.get("service", "")
    proto_ver = rec.get("fp_proto_version", "") or ""
    service_part = f"({svc}" + (f" / {proto_ver}" if proto_ver else "") + ")"
    base = f"[{state.upper():14}] {proto:3} {port:5d} {service_part}"
    if rec.get("fp_product"):
        ver = rec.get("fp_version", "?")
        base += f"  / {rec.get('fp_product')} {ver}".rstrip()
    else:
        if show_preview and preview_text:
            base += f"  banner: {preview_text}"
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
                text = raw.decode(errors="ignore")
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
                    try:
                        text, raw = tcp_probe_banner(ip, port, timeout, host_header)
                        r["banner"] = text or ""
                        if raw:
                            r["_raw_banner"] = raw
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
    if last_err is not None:
        r["_err"] = str(last_err)
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
                try:
                    r["banner"] = data.decode(errors="ignore").strip()[:4000] or repr(data)[:200]
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

    try:
        ip = resolve_target(args.target)
    except Exception as e:
        print(f"[!] Could not resolve target: {e}")
        return

    domain_for_query = args.dns_domain if args.dns_domain else (args.target if "." in args.target else "www.example.com")
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
    print(f"Target: {args.target} → {ip}")
    print(f"Scan type: {scan_type_str}  Ports: {len(ports)}  Threads: {args.threads}  Timeout: {args.timeout}s")
    start_ts = datetime.now(timezone.utc).isoformat()
    start_time = time.time()

    need_banner_flag = (args.banner or args.fingerprint)

    future_to_key: Dict[Any, Tuple[str,int]] = {}
    all_banner_texts: List[str] = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for proto, port in ordered_keys:
                if proto == "tcp":
                    fut = ex.submit(tcp_scan_one, ip, port, args.timeout, args.retries, need_banner_flag, args.target)
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
                            # set output fields
                            rec["fp_service"] = info.get("fp_service","")
                            rec["fp_product"] = info.get("fp_product","")
                            rec["fp_version"] = info.get("fp_version","?")
                            # also keep proto info for display
                            # try to keep proto version separately for nice paren printing
                            mproto = None
                            if info.get("fp_service"):
                                mproto = re.search(r"([A-Za-z]+)\s*([0-9\.]+)", info.get("fp_service"))
                            if mproto:
                                rec["fp_protocol"] = mproto.group(1)
                                rec["fp_proto_version"] = mproto.group(2)
                            else:
                                rec["fp_protocol"] = ""
                                rec["fp_proto_version"] = ""
                        else:
                            rec["fp_service"] = rec.get("fp_service","")
                            rec["fp_product"] = rec.get("fp_product","")
                            rec["fp_version"] = rec.get("fp_version","")
                            rec["fp_protocol"] = rec.get("fp_protocol","")
                            rec["fp_proto_version"] = rec.get("fp_proto_version","")
                        # --- MySQL-specific console preview enhancement (use raw handshake if available) ---
                        # If this record corresponds to a MySQL port, generate a more readable preview
                        # using fingerprint data when available. Priority:
                        #   1) Use fp_product / fp_version from fingerprinting
                        #   2) Otherwise, extract from the raw handshake via _parse_mysql_handshake_raw
                        if rec.get("port") == 3306:
                            # If fingerprinting already provided product/version, use it.
                            if rec.get("fp_product"):
                                proto_v = rec.get("fp_proto_version", "")
                                proto_part = f" / {proto_v}" if proto_v else ""
                                # example: "(MySQL / 5.5.5)  / MariaDB 11.8.3"
                                if proto_v:
                                    console_preview = f"MySQL{proto_part}  / {rec.get('fp_product')} {rec.get('fp_version','?')}"
                                else:
                                    console_preview = f"{rec.get('fp_product')} {rec.get('fp_version','?')}"
                                show_preview_flag = True
                            else:
                                # Fallback: if a raw banner is available, parse the handshake directly.
                                raw = rec.get("_raw_banner")
                                if raw:
                                    try:
                                        parsed = _parse_mysql_handshake_raw(raw)
                                        if parsed:
                                            proto = parsed.get("proto")
                                            ver = parsed.get("version") or parsed.get("pack") or "?"
                                            prod = parsed.get("product") or "MySQL"
                                            if proto:
                                                console_preview = f"MySQL / {proto}  / {prod} {ver}"
                                            else:
                                                console_preview = f"{prod} {ver}"
                                            show_preview_flag = True
                                    except Exception:
                                        # If parsing fails, continue silently and fall back to console_previewFromBanner.
                                        pass

                    # MySQL-specific preview using fingerprint or raw handshake
                    if rec.get("port") == 3306:
                        # prefer fingerprint result if present
                        if rec.get("fp_product"):
                            proto_v = rec.get("fp_proto_version", "")
                            if proto_v:
                                console_preview = f"MySQL / {proto_v}  / {rec.get('fp_product')} {rec.get('fp_version','?')}"
                            else:
                                console_preview = f"{rec.get('fp_product')} {rec.get('fp_version','?')}"
                            show_preview_flag = True
                        else:
                            # fallback: parse raw handshake if available
                            raw = rec.get("_raw_banner")
                            if raw:
                                try:
                                    parsed = _parse_mysql_handshake_raw(raw)
                                    if parsed:
                                        proto = parsed.get("proto")
                                        ver = parsed.get("version") or parsed.get("pack") or "?"
                                        prod = parsed.get("product") or "MySQL"
                                        if proto:
                                            console_preview = f"MySQL / {proto}  / {prod} {ver}"
                                        else:
                                            console_preview = f"{prod} {ver}"
                                        show_preview_flag = True
                                except Exception:
                                    # If parsing fails, continue silently and use the fallback.
                                    pass

                    # decide console presentation (keep behaviour compatible with original)
                    if args.fingerprint:
                        if rec.get("fp_product"):
                            # fingerprint produced a product — we already set show_preview_flag=True for MySQL if applicable.
                            # For non-MySQL entries, respect original behaviour (do not show banner preview).
                            if not show_preview_flag:
                                show_preview_flag = False
                        else:
                            if args.banner:
                                if not console_preview:
                                    console_preview = console_preview_from_banner(banner_text, rec.get("port"))
                                show_preview_flag = bool(console_preview)
                    else:
                        if args.banner:
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
        # If Windows mapping returned distro == "Windows" and version already describes Windows NT,
        # avoid repeating the word "Windows" twice.
        if family == "Windows" and distro == "Windows" and ver:
            # ver is like "Windows NT 5.1 (XP)" — print that directly
            print(f"\nOS guess: {ver}")
        elif distro:
            # General case: "Family (Distro Version)"
            print(f"\nOS guess: {family} ({distro}{(' ' + ver) if ver else ''})")
        else:
            print(f"\nOS guess: {family}")

    # summary
    open_tcp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="tcp" and r.get("state")=="open")
    open_udp = sum(1 for k,r in results_map.items() if r and r.get("proto")=="udp" and r.get("state")=="open")
    print("\n--- Scan summary ---")
    if scan_tcp and not scan_udp:
        if args.open:
            print(f"TCP open: {open_tcp}")
        else:
            total_tcp = sum(1 for k in results_map if k[0] == "tcp")
            print(f"TCP open: {open_tcp}, total results: {total_tcp}")
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
            total_results = len(results_map)
            print(f"TCP open: {open_tcp}, UDP open: {open_udp}, total results: {total_results}")
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
            "target": args.target,
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
