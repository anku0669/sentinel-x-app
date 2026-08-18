#!/usr/bin/env python3
"""PentaForge: authorized multi-target security assessment orchestrator."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
REPORT_ROOT = ROOT / "reports"

MODULES = [
    ('nmap_tcp', 'nmap', ['nmap','-Pn','-sT','-sV','--version-light','--reason','-p','{ports}','{target}']),
    ('nmap_default_scripts', 'nmap', ['nmap','-Pn','-sV','--script','default,safe','-p','{ports}','{target}']),
    ('rustscan', 'rustscan', ['rustscan','-a','{target}','--ulimit','5000']),
    ('naabu', 'naabu', ['naabu','-host','{target}','-scan-type','connect','-silent']),
    ('masscan', 'masscan', ['masscan','{target}','-p1-65535','--rate','1000']),
    ('nmap_udp_top', 'nmap', ['nmap','-Pn','-sU','--top-ports','100','--reason','{target}']),
    ('nmap_os', 'nmap', ['nmap','-Pn','-O','--osscan-guess','{target}']),
    ('nmap_vuln_scripts', 'nmap', ['nmap','-Pn','-sV','--script','vuln','-p','{ports}','{target}']),
    ('httpx', 'httpx', ['httpx','-u','{http_url}','{https_url}','-silent','-status-code','-title','-tech-detect','-follow-redirects']),
    ('nuclei_http', 'nuclei', ['nuclei','-u','{http_url}','-severity','info,low,medium,high,critical','-no-color']),
    ('nuclei_https', 'nuclei', ['nuclei','-u','{https_url}','-severity','info,low,medium,high,critical','-no-color']),
    ('nikto_http', 'nikto', ['nikto','-host','{http_url}','-nointeractive']),
    ('nikto_https', 'nikto', ['nikto','-host','{https_url}','-nointeractive']),
    ('whatweb', 'whatweb', ['whatweb','-a','3','{http_url}']),
    ('wafw00f', 'wafw00f', ['wafw00f','{http_url}']),
    ('katana', 'katana', ['katana','-u','{http_url}','-silent','-depth','3']),
    ('feroxbuster', 'feroxbuster', ['feroxbuster','-u','{http_url}','-n','-q','-t','10']),
    ('ffuf', 'ffuf', ['ffuf','-u','{http_url}/FUZZ','-w','/usr/share/seclists/Discovery/Web-Content/common.txt','-mc','200,204,301,302,307,401,403']),
    ('gobuster', 'gobuster', ['gobuster','dir','-u','{http_url}','-w','/usr/share/wordlists/dirb/common.txt','-q']),
    ('dirsearch', 'dirsearch', ['dirsearch','-u','{http_url}','--plain-text-report={report}/dirsearch.txt','--quiet-mode']),
    ('wpscan', 'wpscan', ['wpscan','--url','{http_url}','--no-update']),
    ('testssl', 'testssl.sh', ['testssl.sh','--warnings','batch','{https_url}']),
    ('sslscan', 'sslscan', ['sslscan','{target}:443']),
    ('sslyze', 'sslyze', ['sslyze','--regular','{target}:443']),
    ('ssh_audit', 'ssh-audit.py', ['ssh-audit.py','{target}']),
    ('dnsx', 'dnsx', ['dnsx','-silent','-a','-resp','-host','{target}']),
    ('dig_ptr', 'dig', ['dig','+short','-x','{target}']),
    ('dig_any', 'dig', ['dig','{target}','ANY','+noall','+answer']),
    ('dnsrecon', 'dnsrecon', ['dnsrecon','-r','{target}']),
    ('fierce', 'fierce', ['fierce','--domain','{target}']),
    ('nbtscan', 'nbtscan', ['nbtscan','-v','{target}']),
    ('smbclient', 'smbclient', ['smbclient','-L','//{target}/','-N','--option','client min protocol=SMB2']),
    ('enum4linux_ng', 'enum4linux-ng', ['enum4linux-ng','-A','{target}']),
    ('netexec_smb', 'nxc', ['nxc','smb','{target}']),
    ('snmpwalk', 'snmpwalk', ['snmpwalk','-v2c','-c','public','{target}','1.3.6.1.2.1.1']),
    ('onesixtyone', 'onesixtyone', ['onesixtyone','-c','/usr/share/doc/onesixtyone/dict.txt','{target}']),
    ('ldap_rootdse', 'ldapsearch', ['ldapsearch','-x','-H','ldap://{target}','-s','base','-b','','namingContexts','supportedLDAPVersion']),
    ('rpcinfo', 'rpcinfo', ['rpcinfo','-p','{target}']),
    ('showmount', 'showmount', ['showmount','-e','{target}']),
    ('ftp_enum', 'nmap', ['nmap','-Pn','-sV','--script','ftp-syst,ftp-anon','-p','21','{target}']),
    ('smtp_enum', 'nmap', ['nmap','-Pn','-sV','--script','smtp-commands,smtp-open-relay','-p','25,465,587','{target}']),
    ('rdp_enum', 'nmap', ['nmap','-Pn','-sV','--script','rdp-enum-encryption,rdp-ntlm-info','-p','3389','{target}']),
    ('vnc_enum', 'nmap', ['nmap','-Pn','-sV','--script','vnc-info','-p','5900-5905','{target}']),
    ('mysql_info', 'nmap', ['nmap','-Pn','-sV','--script','mysql-info','-p','3306','{target}']),
    ('redis_info', 'nmap', ['nmap','-Pn','-sV','--script','redis-info','-p','6379','{target}']),
    ('mongodb_info', 'nmap', ['nmap','-Pn','-sV','--script','mongodb-info','-p','27017','{target}']),
    ('elasticsearch', 'curl', ['curl','-sk','--max-time','15','{https_url}:9200/']),
    ('http_headers', 'curl', ['curl','-skI','--max-time','15','{http_url}']),
    ('https_headers', 'curl', ['curl','-skI','--max-time','15','{https_url}']),
    ('https_health', 'curl', ['curl','-sk','--max-time','15','-o','/dev/null','-w','HTTP=%{http_code} TLS=%{ssl_verify_result} FINAL=%{url_effective}\\n','{https_url}']),
]

BANNED_TOKENS = ('hydra', 'medusa', 'ncrack', 'patator', 'hping3', '--flood', '--dos')


def die(message: str) -> None:
    print(f'[!] {message}', file=sys.stderr)
    raise SystemExit(2)


def command_exists(binary: str) -> bool:
    return shutil.which(binary) is not None


def normalize_hostname(value: str) -> str:
    host = value.strip().rstrip('.')
    if not host:
        raise ValueError('empty target')
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9.*_-]+(?:\.[A-Za-z0-9.*_-]+)*', host):
        raise ValueError(f'invalid hostname: {value}')
    return host


def parse_target(raw: str, max_hosts: int) -> list[dict[str, str]]:
    raw = raw.strip()
    parsed = urlparse(raw if '://' in raw else '')
    if parsed.scheme and parsed.hostname:
        host = normalize_hostname(parsed.hostname)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        http_url = raw if parsed.scheme in ('http', 'https') else f'http://{host}{path}'
        https_url = raw if parsed.scheme == 'https' else f'https://{host}{path}'
        return [{'input': raw, 'target': host, 'http_url': http_url, 'https_url': https_url, 'kind': 'url'}]

    try:
        network = ipaddress.ip_network(raw, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > max_hosts:
            raise ValueError(f'CIDR expands to {len(hosts)} hosts; limit is {max_hosts}. Use --max-hosts to raise it.')
        return [
            {'input': raw, 'target': str(h), 'http_url': f'http://{h}', 'https_url': f'https://{h}', 'kind': 'cidr-host'}
            for h in hosts
        ]
    except ValueError as exc:
        if str(exc).startswith('CIDR expands'):
            raise

    host = normalize_hostname(raw)
    return [{'input': raw, 'target': host, 'http_url': f'http://{host}', 'https_url': f'https://{host}', 'kind': 'hostname-or-ip'}]


def parse_targets(raw_targets: str, max_hosts: int) -> list[dict[str, str]]:
    items = [x.strip() for x in raw_targets.split(',') if x.strip()]
    if not items:
        raise ValueError('no target supplied')
    targets: list[dict[str, str]] = []
    for item in items:
        targets.extend(parse_target(item, max_hosts=max_hosts))
    unique = {}
    for target in targets:
        unique[(target['target'], target['http_url'], target['https_url'])] = target
    return list(unique.values())


def render(argv: list[str], target: dict[str, str], ports: str, report_dir: Path) -> list[str]:
    values = {
        'target': target['target'],
        'http_url': target['http_url'],
        'https_url': target['https_url'],
        'ports': ports,
        'report': str(report_dir),
    }
    return [
        part.replace('{target}', values['target'])
            .replace('{http_url}', values['http_url'])
            .replace('{https_url}', values['https_url'])
            .replace('{ports}', values['ports'])
            .replace('{report}', values['report'])
        for part in argv
    ]


def run_one(spec: tuple[str, str, list[str]], target: dict[str, str], ports: str, report_dir: Path, timeout: int) -> dict:
    name, binary, argv = spec
    if not command_exists(binary):
        return {'name': name, 'binary': binary, 'target': target['target'], 'status': 'missing', 'returncode': None, 'stdout': '', 'stderr': ''}

    cmd = render(argv, target, ports, report_dir)
    joined = ' '.join(cmd).lower()
    if any(token in joined for token in BANNED_TOKENS):
        return {'name': name, 'binary': binary, 'target': target['target'], 'status': 'blocked', 'returncode': None, 'stdout': '', 'stderr': 'safe-mode block'}

    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, cwd=report_dir)
        out, err = cp.stdout[-200_000:], cp.stderr[-100_000:]
        safe_target = target['target'].replace(':', '_')
        (report_dir / f'{safe_target}_{name}.stdout.txt').write_text(out, errors='replace')
        if err:
            (report_dir / f'{safe_target}_{name}.stderr.txt').write_text(err, errors='replace')
        return {'name': name, 'binary': binary, 'target': target['target'], 'status': 'ok' if cp.returncode == 0 else 'completed_with_error', 'returncode': cp.returncode, 'stdout': out, 'stderr': err}
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ''
        safe_target = target['target'].replace(':', '_')
        (report_dir / f'{safe_target}_{name}.stdout.txt').write_text(out[-100_000:], errors='replace')
        return {'name': name, 'binary': binary, 'target': target['target'], 'status': 'timeout', 'returncode': None, 'stdout': out, 'stderr': 'timeout'}
    except Exception as exc:
        return {'name': name, 'binary': binary, 'target': target['target'], 'status': 'failed', 'returncode': None, 'stdout': '', 'stderr': repr(exc)}


def normalize_findings(results: list[dict]) -> list[dict[str, str]]:
    patterns = [
        ('critical', r'\bcritical\b|CVE-\d{4}-\d{4,}'),
        ('high', r'\bhigh\b|remote code execution|\brce\b'),
        ('medium', r'\bmedium\b|misconfig|missing security header|weak cipher'),
        ('low', r'\blow\b|information disclosure|banner'),
    ]
    findings = []
    seen = set()
    for result in results:
        text = result.get('stdout', '') + '\n' + result.get('stderr', '')
        for severity, pattern in patterns:
            if re.search(pattern, text, re.I):
                key = (result['target'], result['name'], severity)
                if key not in seen:
                    findings.append({'target': result['target'], 'severity_hint': severity, 'source': result['name'], 'note': 'Keyword match only; verify manually.'})
                    seen.add(key)
                break
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description='PentaForge authorized multi-target security assessment orchestrator')
    parser.add_argument('targets', help='IP, IPv6, hostname/FQDN, URL, CIDR, or comma-separated targets')
    parser.add_argument('--authorized', action='store_true', help='Confirm you are authorized to assess the supplied scope')
    parser.add_argument('--profile', choices=['fast', 'full'], default='fast')
    parser.add_argument('--timeout', type=int, default=120, help='Per-tool timeout in seconds')
    parser.add_argument('--workers', type=int, default=None, help='Parallel tool workers per target batch')
    parser.add_argument('--max-hosts', type=int, default=64, help='Maximum hosts expanded from a CIDR target')
    args = parser.parse_args()

    if not args.authorized:
        die('Refusing to scan without --authorized.')
    if args.max_hosts < 1 or args.max_hosts > 4096:
        die('--max-hosts must be between 1 and 4096.')

    try:
        targets = parse_targets(args.targets, max_hosts=args.max_hosts)
    except ValueError as exc:
        die(str(exc))

    ports = ('1-65535' if args.profile == 'full' else '22,25,53,80,110,135,139,143,389,443,445,587,631,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9200,11211')
    workers = args.workers or (6 if args.profile == 'full' else 4)
    stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_dir = REPORT_ROOT / stamp
    report_dir.mkdir(parents=True, exist_ok=True)

    print(f'[+] PentaForge | {len(targets)} normalized target(s) | {args.profile} | {len(MODULES)} modules | safe mode')
    for t in targets:
        print(f'    - {t["input"]} -> {t["target"]} [{t["kind"]}]')

    jobs = [(spec, target) for target in targets for spec in MODULES]
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run_one, spec, target, ports, report_dir, args.timeout) for spec, target in jobs]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(f'[{result["status"]:>21}] {result["target"]:<40} {result["name"]}')

    results.sort(key=lambda item: (item['target'], item['name']))
    findings = normalize_findings(results)
    summary = {
        'tool': 'PentaForge',
        'started_at': stamp,
        'profile': args.profile,
        'safe_mode': True,
        'module_count': len(MODULES),
        'normalized_target_count': len(targets),
        'normalized_targets': targets,
        'missing_tool_runs': sum(r['status'] == 'missing' for r in results),
        'findings': findings,
    }

    (report_dir / 'summary.json').write_text(json.dumps(summary, indent=2))
    (report_dir / 'results.json').write_text(json.dumps(results, indent=2))

    md = [
        '# PentaForge Report', '',
        f'- Profile: `{args.profile}`',
        f'- Modules: `{len(MODULES)}`',
        f'- Targets: `{len(targets)}`',
        f'- Missing tool runs: `{summary["missing_tool_runs"]}`',
        '', '## Normalized targets', ''
    ]
    md.extend(f'- `{t["input"]}` → `{t["target"]}` (`{t["kind"]}`)' for t in targets)
    md += ['', '## Findings requiring verification', '']
    md.extend(f'- **{f["severity_hint"].upper()} hint** on `{f["target"]}` from `{f["source"]}`: {f["note"]}' for f in findings)
    if not findings:
        md.append('- No keyword-based findings. This is not proof of security.')
    md += ['', '## Module status', '']
    md.extend(f'- `{r["target"]}` / `{r["name"]}`: **{r["status"]}**' for r in results)
    (report_dir / 'REPORT.md').write_text('\n'.join(md))
    print(f'[+] Report: {report_dir / "REPORT.md"}')


if __name__ == '__main__':
    main()
