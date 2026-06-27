#!/usr/bin/env python3
"""
Fast Nmap-backed TLS 1.0 / TLS 1.1 detector.

Default behavior:
  - Reads targets from a file, one IP/hostname per line.
  - Scans common SSL/TLS ports.
  - Uses nmap service detection and ssl-enum-ciphers.
  - Prints a compact screenshot-friendly table in the requested audit format.
  - Marks a service vulnerable only when TLS 1.0 or TLS 1.1 is offered.

Only scan systems you are authorized to test.
"""

import argparse
import csv
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime


DEFAULT_PORTS = (
    "21,25,110,143,443,465,587,631,636,989,990,993,995,"
    "1433,1521,2376,3389,5061,5432,5800,5986,6172,6443,"
    "7443,8000,8080,8443,8444,8543,8544,8545,8834,9402,"
    "9403,9404,9419,9443,10443,20443,33034,49720,49726,61662"
)

GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"


@dataclass
class Finding:
    host: str
    port: int
    service: str
    sslv2: str
    sslv3: str
    tls10: str
    tls11: str
    status: str


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [value]


def load_targets(path=None, direct_targets=None):
    targets = []
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                targets.extend(expand_target(line))
    for value in direct_targets or []:
        targets.extend(expand_target(value))
    return sorted(set(targets), key=target_sort_key)


def target_sort_key(value):
    try:
        return (0, ipaddress.ip_address(value))
    except ValueError:
        return (1, value)


def normalize_ports(value):
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ",".join(str(port) for port in sorted(p for p in ports if 1 <= p <= 65535))


def chunks(items, size):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def run_nmap(nmap_path, targets, ports, timing, host_timeout, extra_args):
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        target_file = handle.name
        handle.write("\n".join(targets))
        handle.write("\n")

    cmd = [
        nmap_path,
        timing,
        "-n",
        "-Pn",
        "-sV",
        "--open",
        "--host-timeout",
        host_timeout,
        "--script",
        "ssl-enum-ciphers",
        "-p",
        ports,
        "-iL",
        target_file,
        "-oX",
        "-",
    ]
    cmd.extend(extra_args)

    printable_cmd = subprocess.list2cmdline(cmd)
    try:
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
            return proc.returncode, proc.stdout, proc.stderr, printable_cmd
        except OSError as exc:
            return 127, "", str(exc), printable_cmd
    finally:
        try:
            os.unlink(target_file)
        except OSError:
            pass


def offered_protocols(script):
    """Return exact protocol sections emitted by ssl-enum-ciphers."""
    offered = set()
    aliases = {
        "sslv2": "SSLv2",
        "sslv3": "SSLv3",
        "tlsv1.0": "TLS1.0",
        "tlsv1": "TLS1.0",
        "tlsv1.1": "TLS1.1",
    }

    for table in script.iter("table"):
        key = table.attrib.get("key", "").strip().lower()
        if key in aliases:
            offered.add(aliases[key])

    # Older Nmap versions may only expose formatted script output.
    if not offered:
        output = script.attrib.get("output", "")
        line_patterns = {
            "SSLv2": r"(?mi)^\s*SSLv2\s*:",
            "SSLv3": r"(?mi)^\s*SSLv3\s*:",
            "TLS1.0": r"(?mi)^\s*TLSv?1(?:\.0)?\s*:",
            "TLS1.1": r"(?mi)^\s*TLSv?1\.1\s*:",
        }
        for protocol, pattern in line_patterns.items():
            if re.search(pattern, output):
                offered.add(protocol)

    return offered


def parse_xml(xml_text):
    root = ET.fromstring(xml_text)
    rows = []

    for host_node in root.findall("host"):
        addr = host_node.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host_node.find("address")
        if addr is None:
            continue
        host = addr.attrib.get("addr", "")

        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            script = port_node.find("script[@id='ssl-enum-ciphers']")
            if script is None:
                continue

            port = int(port_node.attrib["portid"])
            service_node = port_node.find("service")
            service = "tcp"
            if service_node is not None:
                service = service_node.attrib.get("name", "tcp")

            offered = offered_protocols(script)
            sslv2 = "OFFERED" if "SSLv2" in offered else "DISABLED"
            sslv3 = "OFFERED" if "SSLv3" in offered else "DISABLED"
            tls10 = "OFFERED" if "TLS1.0" in offered else "DISABLED"
            tls11 = "OFFERED" if "TLS1.1" in offered else "DISABLED"

            # This scanner reports the TLSv1.0/TLSv1.1 findings. SSLv2 and
            # SSLv3 remain visible as context but do not drive this status.
            status = "VULNERABLE" if tls10 == "OFFERED" or tls11 == "OFFERED" else "SECURE"

            rows.append(Finding(host, port, service.upper(), sslv2, sslv3, tls10, tls11, status))

    rows.sort(key=lambda row: (target_sort_key(row.host), row.port))
    return rows


def status_cell(value, width, colors):
    if value in ("OFFERED", "VULNERABLE"):
        return color(value.ljust(width), RED, colors)
    return color(value.ljust(width), GREEN, colors)


def print_banner(title, target_label, network_name, colors):
    line = "=" * 94
    now = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y").replace(" 0", " ")
    print(color(line, BLUE, colors))
    print(color(f"    {title} - {target_label}", BLUE, colors))
    print(color("    Checks: SSLv2 | SSLv3 | TLS 1.0 | TLS 1.1", BLUE, colors))
    print(color(f"    {network_name}", BLUE, colors))
    print(color(f"    {now}", BLUE, colors))
    print(color(line, BLUE, colors))
    print()


def print_rows(rows, colors, limit):
    header = (
        f"{'IP ADDRESS':<18}"
        f"{'PORT':<8}"
        f"{'SERVICE':<16}"
        f"{'SSLv2':<11}"
        f"{'SSLv3':<11}"
        f"{'TLS1.0':<11}"
        f"{'TLS1.1':<11}"
        f"{'STATUS':<12}"
    )
    print(header)
    print("-" * len(header))

    shown = rows[:limit] if limit else rows
    for row in shown:
        print(
            f"{row.host:<18.18}"
            f"{row.port:<8}"
            f"{row.service:<16.16}"
            f"{status_cell(row.sslv2, 11, colors)}"
            f"{status_cell(row.sslv3, 11, colors)}"
            f"{status_cell(row.tls10, 11, colors)}"
            f"{status_cell(row.tls11, 11, colors)}"
            f"{status_cell(row.status, 12, colors)}"
        )

    hidden = len(rows) - len(shown)
    if hidden > 0:
        print(color(f"... {hidden} more rows hidden. Use --limit 0 or --csv for full results.", YELLOW, colors))
    if not rows:
        print("No rows.")
    print()


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "port", "service", "sslv2", "sslv3", "tls1_0", "tls1_1", "status"])
        for row in rows:
            writer.writerow([row.host, row.port, row.service, row.sslv2, row.sslv3, row.tls10, row.tls11, row.status])


def main():
    parser = argparse.ArgumentParser(description="Detect TLS 1.0 and TLS 1.1 using Nmap ssl-enum-ciphers.")
    parser.add_argument("targets", nargs="*", help="IPs, hostnames, or CIDR subnets.")
    parser.add_argument("-f", "--file", help="Input file with one IP, hostname, or CIDR per line.")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"Ports/ranges. Default: {DEFAULT_PORTS}")
    parser.add_argument("--csv", help="Save full results to CSV.")
    parser.add_argument("--show-secure", action="store_true", help="Also print secure rows. Default prints vulnerable rows only.")
    parser.add_argument("--limit", type=int, default=30, help="Rows to print per section. Use 0 for no limit.")
    parser.add_argument("--chunk-size", type=int, default=128, help="Targets per Nmap process.")
    parser.add_argument("--timing", default="-T4", help="Nmap timing template. Default: -T4.")
    parser.add_argument("--host-timeout", default="45s", help="Nmap timeout per host. Default: 45s.")
    parser.add_argument("--nmap", default=shutil.which("nmap") or "nmap", help="Path to nmap binary.")
    parser.add_argument("--no-color", action="store_true", help="Disable colors.")
    parser.add_argument("--extra-nmap-arg", action="append", default=[], help="Extra Nmap arg. Can be repeated.")
    parser.add_argument("--network-name", default="Authorized Network", help="Banner network/customer label.")
    parser.add_argument("--title", default="DEPRECATED SSL/TLS VERSIONS IN USE", help="Banner title.")
    args = parser.parse_args()

    if not args.targets and not args.file:
        parser.error("Provide targets and/or --file.")

    targets = load_targets(args.file, args.targets)
    if not targets:
        print("No targets loaded.", file=sys.stderr)
        return 2

    ports = normalize_ports(args.ports)
    colors = not args.no_color
    all_rows = []
    scan_errors = 0

    target_label = args.file or ", ".join(args.targets)
    print_banner(args.title, target_label, args.network_name, colors)

    total_chunks = (len(targets) + args.chunk_size - 1) // args.chunk_size
    for number, group in enumerate(chunks(targets, args.chunk_size), start=1):
        print(f"Scanning chunk {number}/{total_chunks} ({len(group)} targets)...", file=sys.stderr, flush=True)
        code, stdout, stderr, cmd = run_nmap(
            args.nmap,
            group,
            ports,
            args.timing,
            args.host_timeout,
            args.extra_nmap_arg,
        )
        if stderr.strip():
            print(stderr.strip(), file=sys.stderr)
        if not stdout.strip():
            print(f"No XML output from Nmap. Command: {cmd}", file=sys.stderr)
            scan_errors += 1
            continue
        try:
            all_rows.extend(parse_xml(stdout))
        except ET.ParseError as exc:
            print(f"Could not parse Nmap XML: {exc}", file=sys.stderr)
            print(f"Command: {cmd}", file=sys.stderr)
            return 3
        if code not in (0, 1):
            print(f"Nmap exited with code {code}. Results may be incomplete.", file=sys.stderr)
            scan_errors += 1

    vuln_rows = [row for row in all_rows if row.status == "VULNERABLE"]
    secure_rows = [row for row in all_rows if row.status == "SECURE"]
    display_rows = all_rows if args.show_secure else vuln_rows

    print_rows(display_rows, colors, args.limit)

    print(f"SSL/TLS services found : {len(all_rows)}")
    print(f"Affected               : {len(vuln_rows)}")
    print(f"Not affected           : {len(secure_rows)}")
    print(f"Scan errors/incomplete : {scan_errors}")

    if args.csv:
        write_csv(args.csv, all_rows)
        print(f"CSV saved              : {args.csv}")

    if scan_errors:
        return 2
    return 1 if vuln_rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

