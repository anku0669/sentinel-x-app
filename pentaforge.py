#!/usr/bin/env python3
import argparse, concurrent.futures, datetime as dt, ipaddress, json, re, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
REPORT_ROOT=ROOT/'reports'
MODULES=[
('nmap_tcp','nmap',['nmap','-Pn','-sT','-sV','--version-light','--reason','-p','{ports}','{target}']),
('nmap_default_scripts','nmap',['nmap','-Pn','-sV','--script','default,safe','-p','{ports}','{target}']),
('rustscan','rustscan',['rustscan','-a','{target}','--ulimit','5000']),('naabu','naabu',['naabu','-host','{target}','-scan-type','connect','-silent']),('masscan','masscan',['masscan','{target}','-p1-65535','--rate','1000']),
('nmap_udp_top','nmap',['nmap','-Pn','-sU','--top-ports','100','--reason','{target}']),('nmap_os','nmap',['nmap','-Pn','-O','--osscan-guess','{target}']),('nmap_vuln_scripts','nmap',['nmap','-Pn','-sV','--script','vuln','-p','{ports}','{target}']),
('httpx','httpx',['httpx','-u','http://{target}','https://{target}','-silent','-status-code','-title','-tech-detect','-follow-redirects']),('nuclei_http','nuclei',['nuclei','-u','http://{target}','-severity','info,low,medium,high,critical','-no-color']),('nuclei_https','nuclei',['nuclei','-u','https://{target}','-severity','info,low,medium,high,critical','-no-color']),
('nikto_http','nikto',['nikto','-host','http://{target}','-nointeractive']),('nikto_https','nikto',['nikto','-host','https://{target}','-nointeractive']),('whatweb','whatweb',['whatweb','-a','3','http://{target}']),('wafw00f','wafw00f',['wafw00f','http://{target}']),
('katana','katana',['katana','-u','http://{target}','-silent','-depth','3']),('feroxbuster','feroxbuster',['feroxbuster','-u','http://{target}','-n','-q','-t','10']),('ffuf','ffuf',['ffuf','-u','http://{target}/FUZZ','-w','/usr/share/seclists/Discovery/Web-Content/common.txt','-mc','200,204,301,302,307,401,403']),('gobuster','gobuster',['gobuster','dir','-u','http://{target}','-w','/usr/share/wordlists/dirb/common.txt','-q']),('dirsearch','dirsearch',['dirsearch','-u','http://{target}','--plain-text-report={report}/dirsearch.txt','--quiet-mode']),('wpscan','wpscan',['wpscan','--url','http://{target}','--no-update']),
('testssl','testssl.sh',['testssl.sh','--warnings','batch','https://{target}']),('sslscan','sslscan',['sslscan','{target}:443']),('sslyze','sslyze',['sslyze','--regular','{target}:443']),('ssh_audit','ssh-audit.py',['ssh-audit.py','{target}']),
('dnsx','dnsx',['dnsx','-silent','-a','-resp','-host','{target}']),('dig_ptr','dig',['dig','+short','-x','{target}']),('dig_any','dig',['dig','{target}','ANY','+noall','+answer']),('dnsrecon','dnsrecon',['dnsrecon','-r','{target}']),('fierce','fierce',['fierce','--domain','{target}']),('nbtscan','nbtscan',['nbtscan','-v','{target}']),
('smbclient','smbclient',['smbclient','-L','//{target}/','-N','--option','client min protocol=SMB2']),('enum4linux_ng','enum4linux-ng',['enum4linux-ng','-A','{target}']),('netexec_smb','nxc',['nxc','smb','{target}']),('snmpwalk','snmpwalk',['snmpwalk','-v2c','-c','public','{target}','1.3.6.1.2.1.1']),('onesixtyone','onesixtyone',['onesixtyone','-c','/usr/share/doc/onesixtyone/dict.txt','{target}']),('ldap_rootdse','ldapsearch',['ldapsearch','-x','-H','ldap://{target}','-s','base','-b','','namingContexts','supportedLDAPVersion']),('rpcinfo','rpcinfo',['rpcinfo','-p','{target}']),('showmount','showmount',['showmount','-e','{target}']),
('ftp_enum','nmap',['nmap','-Pn','-sV','--script','ftp-syst,ftp-anon','-p','21','{target}']),('smtp_enum','nmap',['nmap','-Pn','-sV','--script','smtp-commands,smtp-open-relay','-p','25,465,587','{target}']),('rdp_enum','nmap',['nmap','-Pn','-sV','--script','rdp-enum-encryption,rdp-ntlm-info','-p','3389','{target}']),('vnc_enum','nmap',['nmap','-Pn','-sV','--script','vnc-info','-p','5900-5905','{target}']),('mysql_info','nmap',['nmap','-Pn','-sV','--script','mysql-info','-p','3306','{target}']),('redis_info','nmap',['nmap','-Pn','-sV','--script','redis-info','-p','6379','{target}']),('mongodb_info','nmap',['nmap','-Pn','-sV','--script','mongodb-info','-p','27017','{target}']),
('elasticsearch','curl',['curl','-sk','--max-time','15','https://{target}:9200/']),('http_headers','curl',['curl','-skI','--max-time','15','http://{target}']),('https_headers','curl',['curl','-skI','--max-time','15','https://{target}']),('https_health','curl',['curl','-sk','--max-time','15','-o','/dev/null','-w','HTTP=%{http_code} TLS=%{ssl_verify_result} FINAL=%{url_effective}\\n','https://{target}'])]
def die(m): print('[!] '+m,file=sys.stderr); raise SystemExit(2)
def exists(b): return shutil.which(b) is not None
def render(a,t,p,r): return [x.replace('{target}',t).replace('{ports}',p).replace('{report}',str(r)) for x in a]
def run(spec,t,ports,r,timeout):
    name,binary,argv=spec; actual=binary
    if not exists(actual): return {'name':name,'binary':actual,'status':'missing','returncode':None,'stdout':'','stderr':''}
    cmd=render(argv,t,ports,r); joined=' '.join(cmd).lower()
    if any(x in joined for x in ('hydra','medusa','ncrack','patator','hping3','--flood','--dos')): return {'name':name,'binary':actual,'status':'blocked','returncode':None,'stdout':'','stderr':'safe-mode block'}
    try:
        cp=subprocess.run(cmd,text=True,capture_output=True,timeout=timeout,cwd=r); out,err=cp.stdout[-200000:],cp.stderr[-100000:]
        (r/f'{name}.stdout.txt').write_text(out,errors='replace')
        if err: (r/f'{name}.stderr.txt').write_text(err,errors='replace')
        return {'name':name,'binary':actual,'status':'ok' if cp.returncode==0 else 'completed_with_error','returncode':cp.returncode,'stdout':out,'stderr':err}
    except subprocess.TimeoutExpired as e:
        out=e.stdout if isinstance(e.stdout,str) else ''; (r/f'{name}.stdout.txt').write_text(out[-100000:],errors='replace'); return {'name':name,'binary':actual,'status':'timeout','returncode':None,'stdout':out,'stderr':''}
    except Exception as e: return {'name':name,'binary':actual,'status':'failed','returncode':None,'stdout':'','stderr':repr(e)}
def main():
    ap=argparse.ArgumentParser(description='PentaForge authorized single-IP security assessment orchestrator'); ap.add_argument('target'); ap.add_argument('--authorized',action='store_true'); ap.add_argument('--profile',choices=['fast','full'],default='fast'); ap.add_argument('--timeout',type=int,default=120); ap.add_argument('--workers',type=int,default=None); a=ap.parse_args()
    if not a.authorized: die('Refusing to scan without --authorized.')
    try: target=str(ipaddress.ip_address(a.target))
    except ValueError: die('Target must be a single IPv4 or IPv6 address.')
    ports='1-65535' if a.profile=='full' else '22,25,53,80,110,135,139,143,389,443,445,587,631,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9200,11211'; workers=a.workers or (6 if a.profile=='full' else 4)
    stamp=dt.datetime.now().strftime('%Y%m%d_%H%M%S'); r=REPORT_ROOT/target.replace(':','_')/stamp; r.mkdir(parents=True,exist_ok=True); print(f'[+] PentaForge | {target} | {a.profile} | {len(MODULES)} modules | safe mode')
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex: results=list(ex.map(lambda s: run(s,target,ports,r,a.timeout),MODULES))
    patterns=[('critical',r'\bcritical\b|CVE-\d{4}-\d{4,}'),('high',r'\bhigh\b|remote code execution|\brce\b'),('medium',r'\bmedium\b|misconfig|missing security header|weak cipher'),('low',r'\blow\b|information disclosure|banner')]; findings=[]; seen=set()
    for x in results:
        for sev,pat in patterns:
            if re.search(pat,x['stdout']+'\n'+x['stderr'],re.I) and (x['name'],sev) not in seen: findings.append({'severity_hint':sev,'source':x['name'],'note':'Keyword match only; verify manually.'}); seen.add((x['name'],sev)); break
    summary={'tool':'PentaForge','target':target,'profile':a.profile,'safe_mode':True,'module_count':50,'missing':sum(x['status']=='missing' for x in results),'findings':findings}; (r/'summary.json').write_text(json.dumps(summary,indent=2)); (r/'results.json').write_text(json.dumps(results,indent=2))
    md=[f'# PentaForge Report','',f'- Target: `{target}`',f'- Profile: `{a.profile}`',f'- Modules: `50`',f'- Missing optional tools: `{summary["missing"]}`','', '## Findings requiring verification','']; md += [f'- **{f["severity_hint"].upper()} hint** from `{f["source"]}`: {f["note"]}' for f in findings] or ['- No keyword-based findings. This is not proof of security.']; md += ['', '## Module status','']+[f'- `{x["name"]}`: **{x["status"]}**' for x in results]; (r/'REPORT.md').write_text('\n'.join(md)); print(f'[+] Report: {r/"REPORT.md"}')
if __name__=='__main__': main()
