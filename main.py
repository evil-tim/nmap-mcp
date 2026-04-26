import subprocess
from fastmcp import FastMCP

mcp = FastMCP(name="NMAP-MCP")

# Whitelist of allowed nmap flags
ALLOWED_FLAGS = {
    # Port scanning
    "-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX",
    # Port specification
    "-p",
    # Host discovery
    "-sL", "-sn", "-Pn", "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM", "-PO",
    # Verbosity and debugging
    "-v", "-vv", "-d", "-dd",
    # Timing
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    # Service/version detection
    "-sV", "--version-intensity",
    # OS detection
    "-O", "--osscan-limit", "--osscan-guess",
    # Misc
    "--reason", "-A",
}

import re
from ipaddress import ip_network

PORT_RANGE_PATTERN = re.compile(r"^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$")

def _is_valid_target(token: str) -> bool:
    if token.startswith("-"):
        return False
    try:
        # accept CIDR or IP
        ip_network(token)
        return True
    except Exception:
        # hostnames are disallowed: only accept IPs/CIDR
        return False

def _validate_nmap_args(args: list[str]) -> None:
    """Validate nmap arguments to prevent command injection and dangerous flags."""
    dangerous_patterns = ["\\\\", "$", "`", "&", "|", ";", ">", "<", "\n", "%", "\r"]

    i = 0
    while i < len(args):
        arg = args[i]
        # check for shell metacharacters
        for pattern in dangerous_patterns:
            if pattern in arg:
                raise ValueError(f"Dangerous pattern in argument: {pattern}")

        if arg.startswith("-"):
            # handle -PS, -PA, -PU, -PY which can have comma-separated ports
            # if starts with -P and followed by S/A/U/Y, it's a flag that can take ports
            if arg.startswith("-P") and len(arg) > 2 and arg[2] in "SAUY":
                flag = arg[:3]  # e.g. -PS
                if flag not in ALLOWED_FLAGS:
                    raise ValueError(f"Nmap flag not allowed: {flag}")
                # ports can be in same token (-PS=80,443) or next token
                if "=" in arg:
                    val = arg.split("=", 1)[1]
                else:
                    i += 1
                    if i >= len(args):
                        raise ValueError(f"{flag} requires a value")
                    val = args[i]
                if not PORT_RANGE_PATTERN.match(val):
                    raise ValueError(f"Invalid port spec for {flag}: {val}")
                i += 1
                continue

            # handle -PO which can have comma-separated protocols
            if arg.startswith("-PO"):
                flag = "-PO"
                if flag not in ALLOWED_FLAGS:
                    raise ValueError(f"Nmap flag not allowed: {flag}")
                # protocols can be in same token (-PO=ICMP,UDP) or next token
                if "=" in arg:
                    val = arg.split("=", 1)[1]
                else:
                    i += 1
                    if i >= len(args):
                        raise ValueError(f"{flag} requires a value")
                    val = args[i]
                # simple validation: protocols should be comma-separated words
                if not re.match(r"^[A-Za-z]+(?:,[A-Za-z]+)*$", val):
                    raise ValueError(f"Invalid protocol spec for {flag}: {val}")
                i += 1
                continue


            # handle flag=value and flag separate value
            flag = arg.split("=")[0]
            if flag not in ALLOWED_FLAGS:
                raise ValueError(f"Nmap flag not allowed: {flag}")

            # validate --version-intensity: must be integer 0-9
            if flag == "--version-intensity":
                if "=" in arg:
                    val = arg.split("=", 1)[1]
                else:
                    i += 1
                    if i >= len(args):
                        raise ValueError("--version-intensity requires a value")
                    val = args[i]
                if not val.isdigit() or not (0 <= int(val) <= 9):
                    raise ValueError(f"Invalid --version-intensity value: {val}")
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

@mcp.tool(name = "nmap_scan", description = """Runs an nmap scan.

INPUT: A list of strings — each token must be either an allowed flag (with its value as the next token if required) or a valid Python ip_network string (e.g. "192.168.1.0/24", "10.0.0.1").

ALLOWED FLAGS:
  Port scanning:   -sS -sT -sA -sW -sM -sU -sN -sF -sX
  Port spec:       -p <range>
  Host discovery:  -sL -sn -Pn -PS -PA -PU -PY -PE -PP -PM -PO
  Version:         -sV --version-intensity <0-9>
  OS detection:    -O --osscan-limit --osscan-guess
  Timing:          -T0 -T1 -T2 -T3 -T4 -T5
  Output/debug:    -v -vv -d -dd --reason
  Aggressive:      -A

EXAMPLES:
  ["-sn", "10.0.0.0/24"]
  ["-sS", "-sV", "-p", "22,80,443", "-T3", "192.168.1.0/24"]
  ["-O", "--osscan-guess", "-T2", "10.0.0.5"]

RULES:
  - Flags not in the list above will be rejected by the server.
  - Flags that take a value (-p, --version-intensity) must be followed by their value as the next token.
  - Multiple targets can be included as separate tokens.
  - No hostnames — targets must be valid IP addresses or CIDR ranges.""")
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
