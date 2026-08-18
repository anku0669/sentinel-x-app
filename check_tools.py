#!/usr/bin/env python3
import shutil
TOOLS=['nmap','rustscan','naabu','masscan','httpx','nuclei','nikto','whatweb','wafw00f','katana','feroxbuster','ffuf','gobuster','dirsearch','wpscan','testssl.sh','sslscan','sslyze','ssh-audit.py','dnsx','dig','dnsrecon','fierce','nbtscan','smbclient','enum4linux-ng','nxc','snmpwalk','onesixtyone','ldapsearch','rpcinfo','showmount','curl']
for tool in TOOLS: print(f"{'OK  ' if shutil.which(tool) else 'MISS'} {tool}")
