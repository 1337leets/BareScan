# BareScan

Minimal, low-noise network service fingerprinting tool using conservative banner grabbing and lightweight protocol probes.

> **Warning / Responsible use:** Run BareScan **only** against systems you own or are explicitly authorized to test. Unauthorized scanning can be illegal and cause service disruption. See **Security & Responsible Use** below.

## Features

- Conservative banner grabbing (HTTP HEAD/GET fallback, SMTP EHLO, FTP newline, SSH banner capture, MySQL handshake parsing, Redis INFO, etc.)
- Service fingerprinting with canonical product/version extraction
- Preservation of packaging/revision tokens (e.g. `Debian-5+deb11u5`) in displayed versions
- Lightweight UDP probes (DNS, NTP, SNMP, TFTP) for low noise discovery
- JSON output with optional base64 raw banner inclusion
- Single-file, stdlib-first implementation — minimal dependencies

## Quickstart

```bash
# clone
git clone https://github.com/<you>/barescan.git
cd barescan

# run (python 3.8+ recommended)
python3 barescan.py example.com -p 22,80,3306 --fingerprint --banner --json results.json
```

## Requirements

Python 3.8+ (uses ssl, socket, concurrent.futures, select, etc.)
No non-stdlib dependencies required for baseline usage.

Note: TLS probing requires system CA bundle for certificate verification (default ssl context). Running certain probes against some services may require additional privileges or network configuration.

## Usage & options (highlights)

```bash
usage: barescan.py target [-p PORTS] [--udp] [--udp-only] [-t TIMEOUT] [-T THREADS]
                         [--fingerprint] [--banner] [--raw] [--retries N]
                         [--open] [--json FILE] [--dns-domain DOMAIN]
```

# Key flags:
* -p, --ports — comma list or ranges, e.g. 22,80,1-1024. Default: common ports set in COMMON_PORTS.
* --udp, --udp-only — include UDP scanning (UDP is optional by default).
* -t, --timeout — per-port timeout in seconds (accepts , or . decimal).
* -T, --threads — worker threads (default 200).
* --fingerprint — attempt fingerprint extraction (adds fp_* fields to JSON).
* --banner — include banner text in JSON output.
* --raw — include raw banner bytes as base64 (only with --banner).
* --open — print only open ports to console.
* --json — save full output to specified JSON file.
* --dns-domain — override domain used for UDP/53 queries.

## Implementation notes & heuristics

Protocol-specific probes are intentionally gentle (e.g. HEAD for HTTP, EHLO for SMTP, INFO for Redis).
MySQL/MariaDB: parses binary handshake to extract proto marker and packaging tokens (5.5.5-<ver>-MariaDB, 8.0.XX-YY).
Debian/Ubuntu packaging tokens (debNN, Ubuntu X.Y) are extracted conservatively for OS guessing.
Banner collection uses latin-1 decoding to preserve byte values.

## Security & Responsible Use

Do not scan networks you do not own or lack explicit authorization for.
Use appropriate rate limits and timeouts; high concurrency can resemble hostile scanning.
If you discover a vulnerability, follow a responsible disclosure process (vendor/security contact, CERT, or coordinated disclosure).
Consider running scans from an isolated lab network (and notify affected parties if scanning production infra).
