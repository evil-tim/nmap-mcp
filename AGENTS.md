# nmap-mcp -- Agent Context

## What This Is
Minimal MCP server wrapping `nmap` via FastMCP. Single tool: `nmap_scan`.

## Project Structure
- `main.py` -- All server logic: validation, tool definition, subprocess execution
- `pyproject.toml` -- Project metadata, single dep: `fastmcp>=3.2.4`
- `uv.lock` -- Locked dependencies
- `entrypoint.sh` -- Production entrypoint (`uv run fastmcp run main.py:mcp --transport http`)
- `Dockerfile` / `docker-compose.yml` -- Container build

## Running Locally
```bash
cd /opt/repos/nmap-mcp
source .venv/bin/activate
HOST=0.0.0.0 uv run fastmcp run main.py:mcp --transport http --host 0.0.0.0 --port 6777
```

## Prerequisites
- Python >=3.13 (installed via uv)
- `nmap` must be on PATH -- `sudo apt-get install -y nmap`
- SYN scans (`-sS`) require elevated privileges (root or CAP_NET_RAW)

## Key Architecture
- All validation in `main.py`: allowed flags whitelist, IP/CIDR-only targets, dangerous pattern blocking
- nmap runs via `subprocess.run` with 5-minute timeout
- Non-root execution; nmap needs `CAP_NET_RAW`/`CAP_NET_ADMIN` or root for SYN scans (`-sS`)
- `fastmcp>=3.2.4` is the only dependency

## GitHub
- Repo: `evil-tim/nmap-mcp`
- Access: ADMIN (push, PR, merge)

## Testing
No test suite exists. Validate changes by:
1. Starting the server locally
2. Sending MCP requests to the `nmap_scan` tool
3. Checking validation rejects bad inputs (hostnames, disallowed flags, shell injection patterns)

## Constraints
- Python >=3.13
- nmap must be on PATH
- SYN scans (`-sS`) require elevated privileges (root or CAP_NET_RAW)
