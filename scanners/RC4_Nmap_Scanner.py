#!/usr/bin/env python3
"""
Nmap-backed RC4 cipher detector.

Runs nmap ssl-enum-ciphers in the backend and prints a screenshot-friendly
audit table using the preferred blue/green/red report template.

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
    "21,25,110,143,443,465,587,636,989,990,993,995,"
    "1433,1521,2376,3389,3527,3999,5061,5432,5800,5985,5986,"
    "6443,7443,8000,8080,8443,8834,9443,10443"
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
    rc4: str
    cipher_count: int
    status: str
    ciphers: str


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def target_sort_key(value):
    try:
        return (0, ipaddress.ip_address(value))
    except ValueError:
        return (1, value)


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


def load_targets(ip_file=None, subnet=None, direct_targets=None):
    targets = []

    if ip_file:
        with open(ip_file, "r", encoding="utf-8") as handle:
            for line in handle:
                targets.extend(expand_target(line))

    if subnet:
        targets.extend(expand_target(subnet))

    for value in direct_targets or []:
        targets.extend(expand_target(value))

    return sorted(set(targets), key=target_sort_key)


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


def save_debug_xml(path, chunk_number, xml_text):
    base, ext = os.path.splitext(path)
    out_path = f"{base}_chunk{chunk_number}{ext or '.xml'}"
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(xml_text)
    return out_path


def script_text(script):
    parts = []
    output = script.attrib.get("output", "")
    if output:
        parts.append(output)
    for node in script.iter():
        if node.text:
            parts.append(node.text)
        parts.extend(node.attrib.values())
    return "\n".join(parts)


def extract_rc4_ciphers(script):
    text = script_text(script)
    ciphers = []

    for match in re.finditer(r"\b(?:TLS_)?[A-Z0-9_-]*RC4[A-Z0-9_-]*\b", text, re.I):
        value = match.group(0).upper()
        if value in {"RC4"}:
            continue
        ciphers.append(value)

    if not ciphers and "RC4" in text.upper():
        ciphers.append("RC4")

    return sorted(set(ciphers))


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
            service = service_node.attrib.get("name", "tcp").upper() if service_node is not None else "TCP"
            ciphers = extract_rc4_ciphers(script)
            rc4 = "OFFERED" if ciphers else "DISABLED"
            status = "VULNERABLE" if ciphers else "SECURE"
            cipher_text = ", ".join(ciphers[:3])
            if len(ciphers) > 3:
                cipher_text += f" +{len(ciphers) - 3}"

            rows.append(
                Finding(
                    host=host,
                    port=port,
                    service=service,
                    rc4=rc4,
                    cipher_count=len(ciphers),
                    status=status,
                    ciphers=cipher_text or "-",
                )
            )

    rows.sort(key=lambda row: (target_sort_key(row.host), row.port))
    return rows


def status_cell(value, width, colors):
    if value in ("OFFERED", "VULNERABLE"):
        return color(value.ljust(width), RED, colors)
    return color(value.ljust(width), GREEN, colors)


def print_banner(title, target_label, network_name, colors):
    line = "=" * 98
    now = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y").replace(" 0", " ")
    print(color(line, BLUE, colors))
    print(color(f"    {title} - {target_label}", BLUE, colors))
    print(color("    Checks: RC4 cipher suites only", BLUE, colors))
    print(color(f"    {network_name}", BLUE, colors))
    print(color(f"    {now}", BLUE, colors))
    print(color(line, BLUE, colors))
    print()


def print_rows(rows, colors, limit):
    header = (
        f"{'IP ADDRESS':<18}"
        f"{'PORT':<8}"
        f"{'SERVICE':<13}"
        f"{'RC4':<11}"
        f"{'COUNT':<8}"
        f"{'STATUS':<12}"
        f"{'CIPHERS':<34}"
    )
    print(header)
    print("-" * len(header))

    shown = rows[:limit] if limit else rows
    for row in shown:
        print(
            f"{row.host:<18.18}"
            f"{row.port:<8}"
            f"{row.service:<13.13}"
            f"{status_cell(row.rc4, 11, colors)}"
            f"{row.cipher_count:<8}"
            f"{status_cell(row.status, 12, colors)}"
            f"{row.ciphers:<34.34}"
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
        writer.writerow(["host", "port", "service", "rc4", "rc4_cipher_count", "status", "ciphers"])
        for row in rows:
            writer.writerow([row.host, row.port, row.service, row.rc4, row.cipher_count, row.status, row.ciphers])


def main():
    parser = argparse.ArgumentParser(description="Detect RC4 cipher suites using Nmap ssl-enum-ciphers.")
    parser.add_argument("targets", nargs="*", help="IPs, hostnames, or CIDR subnets.")
    parser.add_argument("-f", "--file", help="Input file with one IP, hostname, or CIDR per line.")
    parser.add_argument("-s", "--subnet", help="CIDR subnet to scan, for example 198.51.100.0/24.")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"Ports/ranges. Default: {DEFAULT_PORTS}")
    parser.add_argument("--csv", help="Save full results to CSV.")
    parser.add_argument("--show-secure", action="store_true", help="Also print services where RC4 was not offered.")
    parser.add_argument("--limit", type=int, default=30, help="Rows to print. Use 0 for no limit.")
    parser.add_argument("--chunk-size", type=int, default=128, help="Targets per Nmap process.")
    parser.add_argument("--timing", default="-T4", help="Nmap timing template. Default: -T4.")
    parser.add_argument("--host-timeout", default="45s", help="Nmap timeout per host. Default: 45s.")
    parser.add_argument("--nmap", default=shutil.which("nmap") or "nmap", help="Path to nmap binary.")
    parser.add_argument("--no-color", action="store_true", help="Disable colors.")
    parser.add_argument("--extra-nmap-arg", action="append", default=[], help="Extra Nmap arg. Can be repeated.")
    parser.add_argument("--debug-xml", help="Save raw Nmap XML output. Useful for troubleshooting parsing.")
    parser.add_argument("--network-name", default="Authorized Network", help="Banner network/customer label.")
    parser.add_argument("--title", default="SSL RC4 CIPHER SUITES SUPPORTED", help="Banner title.")
    args = parser.parse_args()

    if not args.targets and not args.file and not args.subnet:
        parser.error("Provide targets, --file, and/or --subnet.")

    targets = load_targets(args.file, args.subnet, args.targets)
    if not targets:
        print("No targets loaded.", file=sys.stderr)
        return 2

    ports = normalize_ports(args.ports)
    colors = not args.no_color
    target_label = args.subnet or args.file or ", ".join(args.targets)
    all_rows = []
    scan_errors = 0

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
        if args.debug_xml:
            saved_xml = save_debug_xml(args.debug_xml, number, stdout)
            print(f"Saved debug XML: {saved_xml}", file=sys.stderr)
        try:
            all_rows.extend(parse_xml(stdout))
        except ET.ParseError as exc:
            print(f"Could not parse Nmap XML: {exc}", file=sys.stderr)
            print(f"Command: {cmd}", file=sys.stderr)
            return 3
        if code not in (0, 1):
            print(f"Nmap exited with code {code}. Results may be incomplete.", file=sys.stderr)
            scan_errors += 1

    vulnerable_rows = [row for row in all_rows if row.status == "VULNERABLE"]
    secure_rows = [row for row in all_rows if row.status == "SECURE"]
    display_rows = all_rows if args.show_secure else vulnerable_rows

    print_rows(display_rows, colors, args.limit)

    print(f"SSL/TLS services found : {len(all_rows)}")
    print(f"RC4 vulnerable         : {len(vulnerable_rows)}")
    print(f"RC4 disabled           : {len(secure_rows)}")
    print(f"Scan errors/incomplete : {scan_errors}")

    if args.csv:
        write_csv(args.csv, all_rows)
        print(f"CSV saved              : {args.csv}")

    if scan_errors:
        return 2
    return 1 if vulnerable_rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

