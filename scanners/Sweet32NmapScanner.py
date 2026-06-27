#!/usr/bin/env python3
"""
Nmap-backed Sweet32 / deprecated SSL-TLS scanner.

Runs:
  nmap --script ssl-enum-ciphers -p <ports> <targets> -oX -

Then parses Nmap XML and prints a clean table with vulnerable and secure
sections. This is more reliable than hand-rolled TLS probing because Nmap's
ssl-enum-ciphers script handles many protocol details directly.

Only scan systems you are authorized to test.
"""

import argparse
import csv
import datetime as dt
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass


DEFAULT_PORTS = "443,8443,9443,3389,1433,631,7627,5800,21,25,465,587,993,995"
PROTOCOL_KEYS = {
    "SSLv2": ("sslv2", "ssl2", "SSLv2"),
    "SSLv3": ("sslv3", "ssl3", "SSLv3"),
    "TLS1.0": ("tlsv1.0", "tls1.0", "TLSv1.0", "TLS1.0"),
    "TLS1.1": ("tlsv1.1", "tls1.1", "TLSv1.1", "TLS1.1"),
}

SERVICES = {
    21: "FTP",
    25: "SMTP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3389: "RDP",
    5800: "HTTP",
    7627: "HTTPS",
    8443: "HTTPS",
    9443: "HTTPS",
}

GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"


@dataclass
class Result:
    ip: str
    port: int
    service: str
    sslv2: str
    sslv3: str
    tls10: str
    tls11: str
    sweet32: str
    status: str
    detail: str


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def normalize_ports(value):
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    ports = sorted(set(port for port in ports if 1 <= port <= 65535))
    return ",".join(str(port) for port in ports)


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


def target_sort_key(value):
    try:
        return (0, ipaddress.ip_address(value))
    except ValueError:
        return (1, value.lower())


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


def chunked(items, size):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def run_nmap(nmap_path, targets, ports, timing, host_timeout, extra_args):
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
        target_file = handle.name
        handle.write("\n".join(targets))
        handle.write("\n")

    cmd = [
        nmap_path,
        "--script",
        "ssl-enum-ciphers",
        "-p",
        ports,
        "-iL",
        target_file,
        "-oX",
        "-",
    ]

    if timing:
        cmd.insert(1, timing)
    if host_timeout:
        cmd.extend(["--host-timeout", host_timeout])
    if extra_args:
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


def script_text(script):
    parts = []
    output = script.attrib.get("output", "")
    if output:
        parts.append(output)
    for elem in script.iter():
        if elem.text:
            parts.append(elem.text)
        for value in elem.attrib.values():
            parts.append(value)
    return "\n".join(parts)


def protocol_offered(script, names):
    wanted = {name.lower() for name in names}
    for table in script.iter("table"):
        key = table.attrib.get("key", "").lower()
        if key in wanted:
            return "OFFERED"

    text = script_text(script).lower()
    for name in wanted:
        if re.search(rf"\b{re.escape(name)}\b", text):
            return "OFFERED"
    return "DISABLED"


def has_sweet32(script):
    text = script_text(script).lower()
    sweet32_markers = (
        "sweet32",
        "64-bit block cipher",
        "3des",
        "des-cbc3",
        "triple des",
    )
    if any(marker in text for marker in sweet32_markers):
        return "OFFERED"
    return "DISABLED"


def parse_nmap_xml(xml_text):
    results = []
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        address_node = host.find("address[@addrtype='ipv4']")
        if address_node is None:
            address_node = host.find("address")
        if address_node is None:
            continue
        ip = address_node.attrib.get("addr", "")

        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue

            script = port_node.find("script[@id='ssl-enum-ciphers']")
            if script is None:
                continue

            port = int(port_node.attrib["portid"])
            service_node = port_node.find("service")
            service = (
                service_node.attrib.get("name", "").upper()
                if service_node is not None
                else SERVICES.get(port, "TCP")
            )
            service = SERVICES.get(port, service) or "TCP"

            sslv2 = protocol_offered(script, PROTOCOL_KEYS["SSLv2"])
            sslv3 = protocol_offered(script, PROTOCOL_KEYS["SSLv3"])
            tls10 = protocol_offered(script, PROTOCOL_KEYS["TLS1.0"])
            tls11 = protocol_offered(script, PROTOCOL_KEYS["TLS1.1"])
            sweet32 = has_sweet32(script)

            vulnerable = (
                sslv2 == "OFFERED"
                or sslv3 == "OFFERED"
                or tls10 == "OFFERED"
                or tls11 == "OFFERED"
                or sweet32 == "OFFERED"
            )
            status = "VULNERABLE" if vulnerable else "SECURE"

            detail = []
            if sweet32 == "OFFERED":
                detail.append("Sweet32/3DES")
            for label, value in (
                ("SSLv2", sslv2),
                ("SSLv3", sslv3),
                ("TLS1.0", tls10),
                ("TLS1.1", tls11),
            ):
                if value == "OFFERED":
                    detail.append(label)

            results.append(
                Result(
                    ip=ip,
                    port=port,
                    service=service,
                    sslv2=sslv2,
                    sslv3=sslv3,
                    tls10=tls10,
                    tls11=tls11,
                    sweet32=sweet32,
                    status=status,
                    detail=", ".join(detail) if detail else "No deprecated protocols or Sweet32 ciphers",
                )
            )

    return results


def fmt_status(value, width, colors):
    code = RED if value in ("OFFERED", "VULNERABLE") else GREEN
    return color(value.ljust(width), code, colors)


def print_banner(title, target_label, ports, colors):
    line = "=" * 100
    now = dt.datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y").replace(" 0", " ")
    print(color(line, BLUE, colors))
    print(color(f"    {title} - {target_label}", BLUE, colors))
    print(color("    Backend: nmap --script ssl-enum-ciphers", BLUE, colors))
    print(color("    Checks : SSLv2 | SSLv3 | TLS 1.0 | TLS 1.1 | Sweet32/3DES", BLUE, colors))
    print(color(f"    Ports  : {ports}", BLUE, colors))
    print(color(f"    {now}", BLUE, colors))
    print(color(line, BLUE, colors))
    print()


def print_table(title, rows, colors):
    print(color(title, WHITE, colors))
    header = (
        f"{'IP ADDRESS':<18}"
        f"{'PORT':<8}"
        f"{'SERVICE':<11}"
        f"{'SSLv2':<11}"
        f"{'SSLv3':<11}"
        f"{'TLS1.0':<11}"
        f"{'TLS1.1':<11}"
        f"{'SWEET32':<11}"
        f"{'STATUS':<12}"
    )
    print(header)
    print("-" * len(header))

    if not rows:
        print("No results in this section.")
        print()
        return

    for row in rows:
        print(
            f"{row.ip:<18}"
            f"{row.port:<8}"
            f"{row.service:<11}"
            f"{fmt_status(row.sslv2, 11, colors)}"
            f"{fmt_status(row.sslv3, 11, colors)}"
            f"{fmt_status(row.tls10, 11, colors)}"
            f"{fmt_status(row.tls11, 11, colors)}"
            f"{fmt_status(row.sweet32, 11, colors)}"
            f"{fmt_status(row.status, 12, colors)}"
        )
    print()


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["ip", "port", "service", "sslv2", "sslv3", "tls1_0", "tls1_1", "sweet32", "status", "detail"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.ip,
                    row.port,
                    row.service,
                    row.sslv2,
                    row.sslv3,
                    row.tls10,
                    row.tls11,
                    row.sweet32,
                    row.status,
                    row.detail,
                ]
            )


def main():
    parser = argparse.ArgumentParser(
        description="Run nmap ssl-enum-ciphers and report Sweet32/deprecated SSL-TLS exposure."
    )
    parser.add_argument("targets", nargs="*", help="IPs, hostnames, or CIDR subnets.")
    parser.add_argument("-f", "--file", help="Text file with one IP, hostname, or CIDR per line.")
    parser.add_argument("-s", "--subnet", help="CIDR subnet to scan, for example 198.51.100.0/22.")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"Ports/ranges. Default: {DEFAULT_PORTS}")
    parser.add_argument("--csv", help="Optional CSV output path.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--nmap", default=shutil.which("nmap") or "nmap", help="Path to nmap binary.")
    parser.add_argument("--timing", default="-T3", help="Nmap timing template, for example -T3 or -T4.")
    parser.add_argument("--host-timeout", default="90s", help="Nmap host timeout, for example 90s or 2m.")
    parser.add_argument("--chunk-size", type=int, default=128, help="Targets per Nmap run.")
    parser.add_argument("--extra-nmap-arg", action="append", default=[], help="Extra Nmap argument. Can be repeated.")
    parser.add_argument("--title", default="DEPRECATED SSL/TLS VERSIONS IN USE")
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

    print_banner(args.title, target_label, ports, colors)
    print(f"Loaded targets : {len(targets)}", flush=True)
    print(f"Nmap binary    : {args.nmap}", flush=True)
    print(f"Chunk size     : {args.chunk_size}", flush=True)
    print()

    all_results = []
    scan_errors = 0
    for index, group in enumerate(chunked(targets, args.chunk_size), start=1):
        total_chunks = (len(targets) + args.chunk_size - 1) // args.chunk_size
        print(f"Running Nmap chunk {index}/{total_chunks} ({len(group)} targets)...", file=sys.stderr, flush=True)
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
            print(f"Nmap returned no XML output. Command was: {cmd}", file=sys.stderr)
            scan_errors += 1
            continue

        try:
            all_results.extend(parse_nmap_xml(stdout))
        except ET.ParseError as exc:
            print(f"Could not parse Nmap XML: {exc}", file=sys.stderr)
            print("Run the displayed nmap command manually to inspect raw output.", file=sys.stderr)
            print(f"Command: {cmd}", file=sys.stderr)
            return 3

        if code not in (0, 1):
            print(f"Nmap exited with code {code}. Some results may be incomplete.", file=sys.stderr)
            scan_errors += 1

    all_results.sort(key=lambda row: (target_sort_key(row.ip), row.port))
    vulnerable = [row for row in all_results if row.status == "VULNERABLE"]
    secure = [row for row in all_results if row.status == "SECURE"]

    print_table("VULNERABLE HOSTS", vulnerable, colors)
    print_table("NOT VULNERABLE / SECURE HOSTS", secure, colors)

    print(f"Open SSL/TLS services found : {len(all_results)}")
    print(f"Vulnerable                  : {len(vulnerable)}")
    print(f"Not vulnerable              : {len(secure)}")
    print(f"Scan errors/incomplete      : {scan_errors}")

    if not all_results:
        print()
        print("No ssl-enum-ciphers results were returned.")
        print("Try narrowing to known TLS ports, for example: -p 443,8443,5800")

    if args.csv:
        write_csv(args.csv, all_results)
        print(f"CSV saved                   : {args.csv}")

    if scan_errors:
        return 2
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

