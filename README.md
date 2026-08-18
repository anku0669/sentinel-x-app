# PentaForge

**One target. One command. Fifty security assessment modules.**

PentaForge is a Python-based orchestration layer for authorized penetration testing and network security assessment. It normalizes IP addresses, IPv6, hostnames/FQDNs, URLs, CIDR ranges, and comma-separated target lists, then coordinates reconnaissance, port scanning, service enumeration, web discovery, TLS checks, protocol enumeration, vulnerability scanning, and result collection.

> **Authorization required:** PentaForge is designed for systems you own or are explicitly authorized to assess. The `--authorized` flag is required before a scan can start.

## Web control panel

The repository includes a browser-based control panel designed for GitHub Pages. It normalizes target input and generates the correct local PentaForge command. The hosted page does **not** execute Nmap, Nuclei, or other network scanners from a user's browser. Actual assessment execution remains on the authorized operator's machine/backend.

## Target types

| Input | Example | Supported |
| --- | --- | --- |
| IPv4 | `192.168.1.10` | Yes |
| IPv6 | `2001:db8::10` | Yes |
| Hostname / FQDN | `server.example.com` | Yes |
| HTTP URL | `http://example.com/login` | Yes |
| HTTPS URL | `https://example.com/app` | Yes |
| CIDR | `192.168.1.0/28` | Yes, bounded |
| Multiple targets | `10.0.0.5,web.example.com,10.0.0.0/30` | Yes |

CIDR expansion is capped at 64 hosts by default. Use `--max-hosts` to change it, with a hard ceiling of 4096 hosts per invocation.

## Features

- **50 integrated modules** exposed through one controller.
- **Multiple target types** with automatic target normalization.
- **Single target, CIDR, URL, or mixed-target workflows.**
- **Parallel execution** with configurable worker count.
- **Graceful tool detection**: missing tools are reported and skipped.
- **Raw evidence preserved** as per-module output files.
- **JSON + Markdown reporting** for automation and human review.
- **Web control panel** for target normalization and command generation.
- **GitHub Pages deployment workflow** included.
- **Safe default design** with no brute force, password spraying, persistence, exploit execution, payload delivery, or DoS functionality.

## Usage

### IP address

```bash
./pentaforge 192.168.1.10 --authorized
```

### Hostname / FQDN

```bash
./pentaforge example.com --authorized
```

### URL

```bash
./pentaforge https://example.com/login --authorized
```

The URL is preserved for web modules while the hostname is used for network/service modules.

### CIDR range

```bash
./pentaforge 192.168.1.0/28 --authorized
```

Increase the host limit when appropriate:

```bash
./pentaforge 10.10.10.0/24 --authorized --max-hosts 256
```

### Multiple targets

```bash
./pentaforge '10.10.10.5,web.example.com,https://portal.example.com' --authorized
```

### Full TCP profile

```bash
./pentaforge example.com --authorized --profile full
```

## Web deployment

The repository contains `.github/workflows/pages.yml`, which deploys the static control panel to GitHub Pages after pushes to `main`.

After enabling **Settings → Pages → GitHub Actions** in the repository, the site is served from the repository's GitHub Pages URL.

The UI is intentionally a control plane, not a browser-based scanner. Browsers cannot directly run privileged native tools such as Nmap or Nuclei, and exposing an unauthenticated scanning backend would be a spectacularly bad idea.

## Architecture

```text
                         +----------------------+
                         |      PentaForge      |
                         |      Web / CLI       |
                         +----------+-----------+
                                    |
                           Target Normalizer
                                    |
                +-------------------+-------------------+
                |                   |                   |
             IP/IPv6             Hostname              URL
                |                   |                   |
                +-------------------+-------------------+
                                    |
                             CIDR Expansion
                              (bounded)
                                    |
                         +----------v-----------+
                         | Parallel Module Run  |
                         +----------+-----------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
     Network Recon             Web Recon              Service Checks
          |                         |                         |
          +-------------------------+-------------------------+
                                    |
                         +----------v-----------+
                         | Evidence + Reports   |
                         +-----------------------+
```

## 50 modules

### Network and discovery

Nmap TCP, Nmap safe/default scripts, RustScan, Naabu, Masscan, Nmap UDP top ports, Nmap OS detection, Nmap vulnerability scripts.

### HTTP and web

HTTPX, Nuclei HTTP, Nuclei HTTPS, Nikto HTTP, Nikto HTTPS, WhatWeb, WAFW00F, Katana, Feroxbuster, FFUF, Gobuster, Dirsearch, WPScan.

### TLS and secure protocols

testssl.sh, SSLScan, SSLyze, SSH audit.

### DNS and infrastructure

DNSX, reverse DNS with dig, DNS record query, DNSRecon, Fierce, NBTSCan.

### Windows / enterprise protocols

SMBClient, Enum4Linux-ng, NetExec SMB, SNMPWalk, OneSixtyOne, LDAP RootDSE, rpcinfo, showmount.

### Common service enumeration

FTP scripts, SMTP scripts, RDP scripts, VNC scripts, MySQL information, Redis information, MongoDB information, Elasticsearch probing, HTTP headers, HTTPS headers, HTTPS health check.

## Requirements

- Python 3.9+
- Linux/macOS recommended
- Any subset of the external CLI tools detected by `check_tools.py`

PentaForge does **not** require Python packages for its controller. External scanners are optional. Run `./check_tools.py` to see what is installed.

## Installation

```bash
git clone https://github.com/anku0669/sentinel-x-app.git
cd sentinel-x-app
./install.sh
./check_tools.py
```

## Output

Each run creates a timestamped directory:

```text
reports/<timestamp>/
├── REPORT.md
├── summary.json
├── results.json
├── <target>_<module>.stdout.txt
└── <target>_<module>.stderr.txt
```

## Profiles

| Profile | Port scope | Intended use |
| --- | --- | --- |
| `fast` | Common service ports | Quick assessment |
| `full` | TCP 1-65535 | Deep TCP discovery |

## Safety model

PentaForge focuses on discovery and verification. The controller requires explicit `--authorized` confirmation and blocks obvious credential-attack and denial-of-service tool tokens.

This is not a guarantee that an individual third-party scanner is harmless in every configuration. Always review tool flags, target scope, and rate limits before assessment.

## Important limitations

- Hostname input does not magically discover every IP behind a domain. PentaForge scans the hostname through the selected tools and lets those tools resolve it.
- A URL path is preserved for web-oriented modules, while the hostname is used for network modules.
- CIDR ranges are expanded locally and bounded to avoid accidental large-scale scans.
- Finding normalization produces **verification hints**, not confirmed vulnerabilities.
- Third-party tools must be installed separately.
- Full exploitation and post-exploitation are deliberately outside the default orchestration layer.

## Roadmap

- Intelligent module selection based on discovered ports/services.
- DNS resolution and controlled subdomain discovery as an explicit phase.
- CVSS/CWE normalization and deduplication.
- Authenticated backend/API for authorized remote execution.
- Live task status and historical results.
- SQLite result store.
- Pluggable scanners with per-tool schemas.
- SARIF and HTML export.
- Scope files and rate-limit policies.

## Project status

PentaForge is an early orchestration framework. It reduces repetitive terminal work, but it should not be treated as an autonomous oracle that proves a host is secure or insecure.

## License

MIT License. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting and usage boundaries.
