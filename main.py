import subprocess
from fastmcp import FastMCP

mcp = FastMCP(name="NMAP-MCP")

# Whitelist of allowed nmap flags
ALLOWED_FLAGS = {
    # Port scanning
    "-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX",
    # Host discovery
    "-sn", "-PE", "-PP", "-PM", "-PS", "-PA", "-PY"
    # Port specification
    "-p", "--port-ratio", "--ports",
    # Host discovery
    "-Pn", "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM", "-PO",
    # Verbosity and debugging
    "-v", "-vv", "-d", "-dd",
    # Timing
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    # Service/version detection
    "-sV", "--version-intensity",
    # OS detection
    "-O", "--osscan-limit", "--osscan-guess",
    # Misc
    "--reason", "--stats-every", "-A",
}

import re
from ipaddress import ip_network

HOST_PATTERN = re.compile(r"^[0-9A-Za-z\\-\\.]+$")  # simple hostname pattern
PORT_RANGE_PATTERN = re.compile(r"^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$")

def _is_valid_target(token: str) -> bool:
    if token.startswith("-"):
        return False
    try:
        # accept CIDR or IP
        ip_network(token)
        return True
    except Exception:
        # fallback to hostname regex
        return bool(HOST_PATTERN.match(token))

def _validate_nmap_args(args: list[str]) -> None:
    """Validate nmap arguments to prevent command injection and dangerous flags."""
    dangerous_patterns = ["\\\\", "$", "`", "&", "|", ";"]

    i = 0
    while i < len(args):
        arg = args[i]
        # check for shell metacharacters
        for pattern in dangerous_patterns:
            if pattern in arg:
                raise ValueError(f"Dangerous pattern in argument: {pattern}")

        if arg.startswith("-"):
            # handle flag=value and flag separate value
            flag = arg.split("=")[0]
            if flag not in ALLOWED_FLAGS:
                raise ValueError(f"Nmap flag not allowed: {flag}")

            # validate value for certain flags
            if flag == "-p":
                # value either in same token (-p=80) or next token
                if "=" in arg:
                    val = arg.split("=", 1)[1]
                else:
                    i += 1
                    if i >= len(args):
                        raise ValueError("-p requires a value")
                    val = args[i]
                if not PORT_RANGE_PATTERN.match(val):
                    raise ValueError(f"Invalid port spec: {val}")
        else:
            # non-flag token: must be a valid target (IP/CIDR/hostname)
            if not _is_valid_target(arg):
                raise ValueError(f"Invalid target: {arg}")

        i += 1

@mcp.tool(name = "nmap_scan", description = "Execute nmap scan with validated arguments.")
def nmap_scan(args: list[str]) -> str:
    """Execute nmap scan with validated arguments."""
    try:
        _validate_nmap_args(args)
    except ValueError as e:
        return f"Error: {str(e)}"

    try:
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        output = (result.stdout or "") + (result.stderr or "")
        return f"Return code: {result.returncode}\n{output}"
    except subprocess.TimeoutExpired:
        return "Error: nmap scan timed out"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    mcp.run()
