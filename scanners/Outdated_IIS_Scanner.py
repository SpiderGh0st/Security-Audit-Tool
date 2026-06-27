#!/usr/bin/env python3
"""
Find Microsoft IIS web servers and identify outdated IIS versions.

Detection sources:
  - Nmap service/version detection
  - http-server-header
  - http-headers

Default classification:
  - IIS 7.5 and older: OUTDATED
  - IIS 8.0 / 8.5: LEGACY / ESU ONLY
  - IIS 10.0: REVIEW OS (IIS version alone cannot identify the Windows release)

Requirements:
    sudo apt install nmap

Examples:
    python3 OutdatedIisScanner.py -f target_ips.txt
    python3 OutdatedIisScanner.py 192.0.2.0/24 --workers 24
    python3 OutdatedIisScanner.py -f target_ips.txt --show-all
    python3 OutdatedIisScanner.py -f target_ips.txt --all-ports

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
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "80-90,443,444,591,593,631,1433,3000,3306,3910,3911,"
    "5000,5001,5985,5986,6172,7001-7005,7070,7080,7443,"
    "7777,8000-8012,8020,8030,8040,8050,8060,8070,8080-8090,"
    "8100,8180,8181,8200,8280,8282,8300,8383,8443,8444,"
    "8543,8544,8545,8834,8880,8888,9000,9001,9043,9080,"
    "9090,9091,9402,9403,9404,9419,9443,9990,9999,10000,"
    "10080,10443,18080,20443,33034,33035,47001,49720,49726,"
    "53048,61662"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTO", 7),
    ("IIS VERSION", 14),
    ("STATUS", 18),
    ("DETAIL", 78),
]


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


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


async def run_nmap(ip, ports, all_ports, timeout, min_rate):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "--host-timeout", timeout,
        "--script", "http-server-header,http-headers",
    ]
    if all_ports:
        command.extend(["-p-", "--min-rate", str(min_rate)])
    else:
        command.extend(["-p", ports])
    command.extend(["-oX", "-", ip])

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "") if script is not None else ""


def extract_iis_version(port_node):
    service = port_node.find("service")
    parts = []
    if service is not None:
        parts.extend([
            service.attrib.get("name", ""),
            service.attrib.get("product", ""),
            service.attrib.get("version", ""),
            service.attrib.get("extrainfo", ""),
        ])
    parts.extend([
        script_output(port_node, "http-server-header"),
        script_output(port_node, "http-headers"),
    ])
    evidence = "\n".join(parts)
    match = re.search(r"Microsoft-IIS[/\s-]+(\d+(?:\.\d+)?)", evidence, re.I)
    return (match.group(1), evidence) if match else ("", evidence)


def classify(version):
    try:
        numeric = tuple(int(part) for part in version.split("."))
    except ValueError:
        return "UNKNOWN", "IIS was detected, but its version could not be parsed."

    if numeric <= (7, 5):
        return (
            "LIFECYCLE REVIEW",
            "IIS 7.5 or older suggests an old Windows generation; confirm the underlying OS and support coverage.",
        )
    if numeric in {(8, 0), (8, 5)}:
        return (
            "ESU REVIEW",
            "IIS 8.x suggests Windows Server 2012/2012 R2; verify the underlying OS and ESU coverage.",
        )
    if numeric >= (10, 0):
        return (
            "REVIEW OS",
            "IIS 10.0 spans multiple Windows releases; determine the underlying OS and patch level.",
        )
    return "REVIEW", "Verify the underlying Windows lifecycle and patch level."


def parse_xml(xml_text, show_all):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    rows = []
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

            version, evidence = extract_iis_version(port_node)
            if not version:
                continue

            status, detail = classify(version)
            if not show_all and status not in {"LIFECYCLE REVIEW", "ESU REVIEW"}:
                continue

            service = port_node.find("service")
            tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
            name = service.attrib.get("name", "").lower() if service is not None else ""
            protocol = "HTTPS" if tunnel in {"ssl", "tls"} or name == "https" else "HTTP"
            port = int(port_node.attrib.get("portid", "0"))

            server_match = re.search(
                r"Microsoft-IIS[/\s-]+\d+(?:\.\d+)?",
                evidence,
                re.I,
            )
            server_header = server_match.group(0) if server_match else f"Microsoft-IIS/{version}"

            rows.append({
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "version": version,
                "status": status,
                "detail": detail,
                "evidence": server_header,
            })
    return rows


async def scan_one(ip, args, ports):
    xml_text = await run_nmap(
        ip, ports, args.all_ports, args.host_timeout, args.min_rate
    )
    return parse_xml(xml_text, args.show_all)


async def run_all(targets, args, ports):
    queue = asyncio.Queue()
    rows = []
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
                try:
                    rows.extend(await scan_one(ip, args, ports))
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rScanning IIS: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Findings: {len(rows)} | Current: {ip}".ljust(125)
                )
                sys.stdout.flush()
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")
    return rows


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No outdated Microsoft IIS versions were identified.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        rows,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 9),
            cell(row["protocol"], 7),
            cell(f"IIS {row['version']}", 14),
            cell(row["status"], 18),
            cell(row["detail"], 78),
        ])
        code = RED if row["status"] == "LIFECYCLE REVIEW" else (
            YELLOW if row["status"] != "SUPPORTED" else GREEN
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "version",
        "status", "detail", "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            writer.writerow(row)


def write_list(path, rows):
    affected = [
        row for row in rows
        if row["status"] in {"LIFECYCLE REVIEW", "ESU REVIEW"}
    ]
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(
            affected,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find outdated Microsoft IIS versions."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Web ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Scan all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="90s", help="Nmap host timeout")
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all detected IIS versions, including IIS 10 review rows",
    )
    parser.add_argument("--csv", default="outdated_iis_results.csv", help="CSV output")
    parser.add_argument("--list", default="outdated_iis_endpoints.txt", help="Affected IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"Scan ports     : {'all TCP ports' if args.all_ports else args.ports}")
    print("Detection      : Nmap -sV plus HTTP Server header")
    print(f"Showing        : {'all detected IIS servers' if args.show_all else 'outdated/legacy IIS only'}")

    rows = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    affected = sum(
        1 for row in rows
        if row["status"] in {"LIFECYCLE REVIEW", "ESU REVIEW"}
    )
    print()
    print(f"IIS endpoints displayed : {len(rows)}")
    print(f"Lifecycle review        : {affected}")
    print(f"CSV written             : {args.csv}")
    print(f"Endpoint list           : {args.list}")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())

