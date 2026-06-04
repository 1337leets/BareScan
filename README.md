# BareScan

Minimal, low-noise network service fingerprinting tool using conservative banner grabbing and lightweight protocol probes.

> **Warning / Responsible use:** Run BareScan **only** against systems you own or are explicitly authorized to test. Unauthorized scanning can be illegal and cause service disruption. See **Security & Responsible Use** below.

## Features

- Conservative banner grabbing (HTTP HEAD/GET fallback, SMTP EHLO, FTP newline, SSH banner capture, MySQL handshake parsing, Redis INFO, etc.)
- Service fingerprinting with canonical product/version extraction
- Preservation of packaging/revision tokens (e.g. `Debian-5+deb11u5`) in displayed versions
- **Evidence-based TCP state model** — distinguishes `open`, `closed`, and `filtered` using the actual `connect()` errno, instead of lumping every non-open port into one bucket
- **`OPEN/NO-DATA` detection** — separates ports that completed a TCP handshake *and sent application data* from ports that only completed the handshake but stayed silent
- **Network-environment awareness** — flags upstream SYN-proxies / tarpits and ISP transparent-proxy interception, so you can tell a target's real posture apart from your own network's interference
- Lightweight UDP probes (DNS, NTP, SNMP, TFTP) for low-noise discovery
- JSON output with optional base64 raw banner inclusion
- Single-file, stdlib-first implementation — no non-stdlib dependencies

## Quickstart

```bash
# clone
git clone https://github.com/1337leets/BareScan.git
cd BareScan

# run (python 3.8+ recommended)
python3 barescan.py example.com -p 22,80,3306 --fingerprint --banner --json results.json
```

## Requirements

Python 3.8+ (uses `ssl`, `socket`, `concurrent.futures`, `select`, `errno`, etc.). No non-stdlib dependencies required for baseline usage.

## TCP state model

BareScan reports four TCP outcomes. The distinction matters because a port that is silently dropped is a very different signal from one that actively refuses you.

| State | Console label | Meaning |
|-------|---------------|---------|
| open (responsive) | `[OPEN]` | Handshake completed and the service sent data (banner / protocol response) |
| open (silent) | `[OPEN/NO-DATA]` | Handshake completed but no bytes arrived within the timeout. Either a service that waits for the client to speak first (TLS ports, Redis, ...), or an upstream proxy/tarpit accepting the SYN on the target's behalf |
| closed | `[CLOSED]` | The target sent a TCP RST (`ECONNREFUSED`) — nothing is listening |
| filtered | `[FILTERED]` | No response at all within the timeout (`EAGAIN`/`ETIMEDOUT`/ICMP unreach) — a firewall is dropping the packet |

UDP is reported as `open` or `closed/filtered`; without ICMP port-unreachable handling the two cannot be reliably separated, so the label stays honest about that ambiguity.

## Reading the network around the target

A scan result is only as trustworthy as the path it traveled. BareScan surfaces two common sources of distortion:

- **Upstream SYN-proxy / tarpit.** If many more ports come back `OPEN/NO-DATA` than `OPEN`, something between you and the target is completing handshakes it shouldn't. This is common on mobile carrier CGN, some hosting edges, and CDN front-ends. The summary prints a hint when this pattern dominates. (Tip: the *cause* is usually visible in the responsive ports — if they all fingerprint as one CDN such as Cloudflare, the no-data ports are CDN edge artifacts rather than real services.)
- **ISP transparent proxy.** If an HTTP response redirects to a host unrelated to the target (for example an ISP "safe internet" / family-filter page), BareScan flags `isp_intercept_suspected` on that port and notes the redirect host. That response came from your ISP, not the target.

Because of this, scanning the same target from two different vantage points and diffing the JSON is a reliable way to separate target-side behavior from network-side interference.

## Usage & options (highlights)

```
usage: barescan.py target [-p PORTS] [--udp] [--udp-only] [-t TIMEOUT] [-T THREADS]
                         [--fingerprint] [--banner] [--raw] [--retries N]
                         [--open] [--json FILE] [--dns-domain DOMAIN]
```

Key flags:

- `-p`, `--ports` — comma list or ranges, e.g. `22,80,1-1024`. Default: common ports set in `COMMON_PORTS`.
- `--udp`, `--udp-only` — include UDP scanning (UDP is optional by default).
- `-t`, `--timeout` — per-port timeout in seconds (accepts `,` or `.` decimal).
- `-T`, `--threads` — worker threads (default 200).
- `--fingerprint` — attempt fingerprint extraction (adds `fp_*` fields to JSON).
- `--banner` — include banner text in JSON output. Required for the responsive / no-data distinction.
- `--raw` — include raw banner bytes as base64 (only with `--banner`).
- `--open` — print only open ports to console.
- `--json` — save full output to specified JSON file.
- `--dns-domain` — override domain used for UDP/53 queries.

## Example console output

```
[OPEN           ] TCP    22 (SSH / 2.0)  / OpenSSH 8.9p1
[OPEN           ] TCP    80 (HTTP / 1.1)  / Apache 2.4.52 (Ubuntu)
[OPEN/NO-DATA   ] TCP   993 (IMAPS)
[CLOSED         ] TCP    23 (TELNET)
[FILTERED       ] TCP  3389 (RDP)

--- Scan summary ---
TCP open: 3, closed: 1, filtered: 1
TCP responsive: 2, no-data: 1
```

## Implementation notes & heuristics

Protocol-specific probes are intentionally gentle (e.g. HEAD for HTTP, EHLO for SMTP, INFO for Redis).

- MySQL/MariaDB: parses the binary handshake to extract proto marker and packaging tokens (`5.5.5-...-MariaDB`, `8.0.XX-YY`).
- Debian/Ubuntu packaging tokens (`debNN`, `Ubuntu X.Y`) are extracted conservatively for OS guessing. Note that `Debian-N` in an OpenSSH banner is a *package revision*, not an OS release.
- Banner collection uses latin-1 decoding to preserve byte values 1:1 (UTF-8 with `errors=ignore` silently corrupts binary handshakes).
- TCP state is derived from the `connect()` errno, not from a single open/closed flag.

## Security & Responsible Use

- Do not scan networks you do not own or lack explicit authorization for.
- Use appropriate rate limits and timeouts; high concurrency can resemble hostile scanning.
- If you discover a vulnerability, follow a responsible disclosure process (vendor/security contact, CERT, or coordinated disclosure).
- Consider running scans from an isolated lab network (and notify affected parties if scanning production infrastructure).

## License

Apache-2.0. See [LICENSE](LICENSE).
