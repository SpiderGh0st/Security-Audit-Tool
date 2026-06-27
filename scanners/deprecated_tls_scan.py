#!/usr/bin/env python3
"""
Deprecated SSL/TLS protocol scanner.

Checks whether SSLv2, SSLv3, TLS 1.0, or TLS 1.1 are offered on multiple
IP addresses and ports, then prints a report-style table.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable


PROTOCOLS = [
    ("SSLv2", "-ssl2"),
    ("SSLv3", "-ssl3"),
    ("TLS1.0", "-tls1"),
    ("TLS1.1", "-tls1_1"),
]

DEFAULT_PORTS = [
    443,
    3389,
    1433,
    8443,
    631,
    7627,
    21,
    25,
    110,
    143,
    465,
    587,
    636,
    993,
    995,
]

SERVICES = {
    21: "FTP",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3389: "RDP",
    5986: "WINRM",
    7627: "HTTPS",
    8443: "HTTPS",
}

RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

@dataclass(frozen=True)
class ScanTarget:
    ip: str
    port: int


@dataclass(frozen=True)
class ScanResult:
    ip: str
    port: int
    service: str
    protocols: dict[str, str]
    status: str
    open_port: bool


def parse_ports(value: str) -> list[int]:
    if value.strip().lower() == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(f"Bad port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if p < 1 or p > 65535]
    if bad:
        raise argparse.ArgumentTypeError(f"Invalid port(s): {bad}")
    return sorted(ports)


def expand_targets(values: Iterable[str], input_file: str | None) -> list[str]:
    raw_items: list[str] = []
    raw_items.extend(values)

    if input_file:
        with open(input_file, "r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if item and not item.startswith("#"):
                    raw_items.append(item)

    ips: list[str] = []
    for item in raw_items:
        try:
            if "/" in item:
                network = ipaddress.ip_network(item, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            else:
                ips.append(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise SystemExit(f"Invalid target '{item}': {exc}") from exc

    return sorted(set(ips), key=lambda x: ipaddress.ip_address(x))
    
def is_port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def openssl_supports(protocol_option: str) -> bool:
    openssl = shutil.which("openssl")
    if not openssl:
        return False

    try:
        proc = subprocess.run(
            [openssl, "s_client", protocol_option, "-help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    combined = (proc.stdout + proc.stderr).lower()
    return "unknown option" not in combined and "unknown command" not in combined


def check_protocol(
    ip: str,
    port: int,
    protocol_option: str,
    timeout: float,
    client_supports_protocol: bool,
) -> str:
    if not client_supports_protocol:
        return "UNTESTED"

    openssl = shutil.which("openssl")
    if not openssl:
        return "UNTESTED"

    cmd = [
        openssl,
        "s_client",
        "-connect",
        f"{ip}:{port}",
        protocol_option,
        "-brief",
        "-ign_eof",
    ]

    try:
        proc = subprocess.run(
            cmd,
            input="Q\n",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "DISABLED"
    except OSError:
        return "UNTESTED"

    output = (proc.stdout + proc.stderr).lower()
    success_markers = [
        "connection established",
        "protocol version:",
        "ciphersuite:",
        "cipher    :",
        "verify return code:",
    ]
    failure_markers = [
        "handshake failure",
        "wrong version number",
        "no protocols available",
        "unsupported protocol",
        "alert protocol version",
        "tlsv1 alert",
        "ssl handshake failure",
        "connection refused",
        "unknown option",
    ]

    if any(marker in output for marker in success_markers):
        return "OFFERED"
    if proc.returncode == 0 and not any(marker in output for marker in failure_markers):
        return "OFFERED"
    return "DISABLED"
    
def scan_one(
    target: ScanTarget,
    timeout: float,
    protocol_support: dict[str, bool],
    show_closed: bool,
) -> ScanResult | None:
    if not is_port_open(target.ip, target.port, timeout):
        if not show_closed:
            return None
        return ScanResult(
            ip=target.ip,
            port=target.port,
            service=SERVICES.get(target.port, "UNKNOWN"),
            protocols={name: "CLOSED" for name, _ in PROTOCOLS},
            status="CLOSED",
            open_port=False,
        )

    results = {
        name: check_protocol(
            target.ip,
            target.port,
            option,
            timeout,
            protocol_support.get(name, False),
        )
        for name, option in PROTOCOLS
    }
    vulnerable = any(value == "OFFERED" for value in results.values())
    status = "VULNERABLE" if vulnerable else "SECURE"

    return ScanResult(
        ip=target.ip,
        port=target.port,
        service=SERVICES.get(target.port, "UNKNOWN"),
        protocols=results,
        status=status,
        open_port=True,
    )


def color(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    if text in {"OFFERED", "VULNERABLE"}:
        return f"{RED}{text}{RESET}"
    if text in {"DISABLED", "SECURE"}:
        return f"{GREEN}{text}{RESET}"
    return text


def cell(text: str, width: int, use_color: bool) -> str:
    padded = f"{text:<{width}}"
    if not use_color:
        return padded
    if text in {"OFFERED", "VULNERABLE"}:
        return f"{RED}{padded}{RESET}"
    if text in {"DISABLED", "SECURE"}:
        return f"{GREEN}{padded}{RESET}"
    return padded
    
    
def print_report(
    results: list[ScanResult],
    title: str,
    organization: str,
    checks: str,
    use_color: bool,
) -> None:
    line = "=" * 91
    now = dt.datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y").replace(" 0", " ")

    print(color(line, use_color and False))
    print(f"{BLUE if use_color else ''}    {title}{RESET if use_color else ''}")
    print(f"{BLUE if use_color else ''}    Checks: {checks}{RESET if use_color else ''}")
    if organization:
        print(f"{BLUE if use_color else ''}    {organization}{RESET if use_color else ''}")
    print(f"{BLUE if use_color else ''}    {now}{RESET if use_color else ''}")
    print(line)
    print()

    header = (
        f"{'IP ADDRESS':<18}{'PORT':<10}{'SERVICE':<12}"
        f"{'SSLv2':<12}{'SSLv3':<12}{'TLS1.0':<12}{'TLS1.1':<12}{'STATUS':<12}"
    )
    print(header)
    print("-" * len(header))

    for item in results:
        row = (
            f"{item.ip:<18}{item.port:<10}{item.service:<12}"
            f"{cell(item.protocols['SSLv2'], 12, use_color)}"
            f"{cell(item.protocols['SSLv3'], 12, use_color)}"
            f"{cell(item.protocols['TLS1.0'], 12, use_color)}"
            f"{cell(item.protocols['TLS1.1'], 12, use_color)}"
            f"{cell(item.status, 12, use_color)}"
        )
        print(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check multiple IPs for deprecated SSL/TLS protocol support."
    )
    parser.add_argument("targets", nargs="*", help="IP addresses or CIDRs, for example 203.0.113.0/24")
    parser.add_argument(
        "-f",
        "--file",
        "--input-file",
        dest="input_file",
        help="Text file with one IP or CIDR per line",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=DEFAULT_PORTS,
        help="Comma-separated ports/ranges, or 'all'. Default: common TLS-enabled service ports",
    )
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout per check in seconds")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Concurrent worker count")
    parser.add_argument("--organization", default="Authorized Network", help="Report organization/name line")
    parser.add_argument("--title", default="DEPRECATED SSL/TLS VERSIONS IN USE", help="Report title")
    parser.add_argument("--show-closed", action="store_true", help="Include closed ports in the report")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not args.targets and not args.input_file:
        parser.error("Provide at least one target IP/CIDR or use -f/--file/--input-file")

    if not shutil.which("openssl"):
        print("ERROR: openssl was not found in PATH. Install OpenSSL and try again.", file=sys.stderr)
        return 2

    ips = expand_targets(args.targets, args.input_file)
    scan_targets = [ScanTarget(ip=ip, port=port) for ip in ips for port in args.ports]

    protocol_support = {name: openssl_supports(option) for name, option in PROTOCOLS}

    results: list[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_one, target, args.timeout, protocol_support, args.show_closed)
            for target in scan_targets
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda r: (ipaddress.ip_address(r.ip), r.port))
    check_names = " | ".join(name for name, _ in PROTOCOLS)
    print_report(
        results,
        title=f"{args.title} - {', '.join(args.targets) if args.targets else args.input_file}",
        organization=args.organization,
        checks=check_names,
        use_color=not args.no_color,
    )

    untested = [name for name, supported in protocol_support.items() if not supported]
    if untested:
        print()
        print("NOTE: Local OpenSSL cannot test: " + ", ".join(untested))
        print("Use an OpenSSL build that still supports those protocol switches for full coverage.")

    return 1 if any(item.status == "VULNERABLE" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main()) 

