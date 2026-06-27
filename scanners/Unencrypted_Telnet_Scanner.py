#!/usr/bin/env python3
"""
Find unencrypted Telnet services with Nmap.

Requirements:
    sudo apt install nmap

Examples:
    python3 UnencryptedTelnetScanner.py -f target_ips.txt
    python3 UnencryptedTelnetScanner.py 192.0.2.0/24 --workers 24
    python3 UnencryptedTelnetScanner.py -f target_ips.txt -p 23,2323,8023

Only confirmed plaintext Telnet endpoints are displayed. Services identified
as SSL/TLS-wrapped Telnet are excluded.

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
RESET = "\033[0m"

DEFAULT_PORTS = "23,2323,8023"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 10),
    ("SERVICE", 16),
    ("ENCRYPTION", 14),
    ("STATUS", 14),
    ("DETAIL", 72),
]


def paint(text, enabled=True):
    return f"{RED}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text[:width].ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


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
    valid = sorted(port for port in ports if 1 <= port <= 65535)
    if not valid:
        raise SystemExit("No valid TCP ports supplied.")
    return ",".join(str(port) for port in valid)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []

    value = value.split()[0]
    if re.match(r"^[0-9.]+:\d+$", value):
        value = value.rsplit(":", 1)[0]

    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(address) for address in network.hosts()]
    except ValueError:
        return [value]


def load_targets(args):
    targets = []

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                targets.extend(expand_target(line))

    for value in args.targets:
        targets.extend(expand_target(value))

    unique = list(dict.fromkeys(targets))
    if not unique:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return unique


async def run_nmap(ip, ports, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "-p",
        ports,
        "--script",
        "banner",
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        ip,
    ]

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "").strip() if script is not None else ""


def is_plaintext_telnet(port_node):
    service = port_node.find("service")
    if service is None:
        return False, None

    name = service.attrib.get("name", "").lower()
    product = service.attrib.get("product", "")
    version = service.attrib.get("version", "")
    tunnel = service.attrib.get("tunnel", "").lower()
    service_fp = service.attrib.get("servicefp", "")
    banner = script_output(port_node, "banner")

    evidence = " ".join([name, product, version, service_fp, banner]).lower()
    telnet_detected = name == "telnet" or bool(re.search(r"\btelnet\b", evidence))
    encrypted = tunnel in {"ssl", "tls"} or name in {"telnets", "ssl/telnet"}

    if telnet_detected and not encrypted:
        details = []
        if product:
            details.append(product)
        if version:
            details.append(version)
        if banner:
            clean_banner = re.sub(r"\s+", " ", banner).strip()
            details.append(f"banner: {clean_banner}")
        return True, " ".join(details)

    return False, None


def parse_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    findings = []
    for host_node in root.findall("host"):
        address = host_node.find("address[@addrtype='ipv4']")
        if address is None:
            address = host_node.find("address")
        if address is None:
            continue

        ip = address.attrib.get("addr", "")
        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            vulnerable, evidence = is_plaintext_telnet(port_node)
            if not vulnerable:
                continue

            service = port_node.find("service")
            service_name = service.attrib.get("name", "telnet").upper()
            port = int(port_node.attrib.get("portid", "0"))
            detail = "Plaintext Telnet service detected; credentials and session data are not encrypted."
            if evidence:
                detail += f" {evidence}"

            findings.append({
                "ip": ip,
                "port": f"{port}/TCP",
                "service": service_name,
                "encryption": "NONE",
                "status": "VULNERABLE",
                "detail": detail,
            })

    return findings


async def scan_one(ip, ports, timeout):
    return parse_xml(await run_nmap(ip, ports, timeout))


async def run_all(targets, workers, ports, timeout):
    queue = asyncio.Queue()
    results = []
    completed = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return

            try:
                results.extend(await scan_one(ip, ports, timeout))
                completed += 1
                sys.stdout.write(
                    f"\rScanning Telnet: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Vulnerable: {len(results)} | Current: {ip}".ljust(125)
                )
                sys.stdout.flush()
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()

    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")

    return results


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No unencrypted Telnet services were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0]))):
        line = " ".join([
            cell(row["ip"], 18),
            cell(row["port"], 10),
            cell(row["service"], 16),
            cell(row["encryption"], 14),
            cell(row["status"], 14),
            cell(row["detail"], 72),
        ])
        print(paint(line, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "port", "service", "encryption", "status", "detail"],
        )
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0]))):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted({row["ip"] for row in rows}, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(description="Find unencrypted Telnet services.")
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"TCP ports/ranges. Default: {DEFAULT_PORTS}")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Nmap host timeout in seconds")
    parser.add_argument("--csv", default="unencrypted_telnet.csv", help="CSV output")
    parser.add_argument("--list", default="unencrypted_telnet_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"TCP ports      : {ports}")
    print("Detection      : Nmap -sV --version-all and banner")
    print("Showing        : confirmed plaintext Telnet only")

    rows = asyncio.run(run_all(targets, workers, ports, args.timeout))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Vulnerable endpoints : {len(rows)}")
    print(f"Vulnerable hosts     : {len({row['ip'] for row in rows})}")
    print(f"CSV written          : {args.csv}")
    print(f"IP list written      : {args.list}")

    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

