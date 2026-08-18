#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 1; }
chmod +x pentaforge.py check_tools.py install.sh
echo 'PentaForge is ready.'
echo 'Run: ./pentaforge.py <IP> --authorized'
echo 'Check tools: ./check_tools.py'
