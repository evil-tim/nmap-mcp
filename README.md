# nmap-mcp

Minimal MCP wrapper for running `nmap` scans via FastMCP.

Build:

```sh
docker build -t nmap-mcp .
```

Run (example):

```sh
docker run --rm -p 7777:7777 nmap-mcp
```

Notes:
- The container runs as a non-root user `mcp`. `nmap` is given the minimal capabilities (`CAP_NET_RAW`,`CAP_NET_ADMIN`) via `setcap` so scans work without full root.
- The service listens on port `7777` by default
- For security, main.py validates flags and targets; do not allow untrusted users to supply arbitrary flags.
