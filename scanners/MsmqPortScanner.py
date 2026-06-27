#!/usr/bin/env python3
"""
Find Microsoft Message Queuing services on TCP/1801.

The scanner performs service/version detection only. It does not send MSMQ
messages, enumerate queues, authenticate, or modify the target.

Requirements:
    sudo apt install nmap

Examples:
    python3 MsmqPortScanner.py -f target_ips.txt
    python3 MsmqPortScanner.py 192.0.2.0/24
    python3 MsmqPortScanner.py -f target_ips.txt -w 32

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


CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

DEFAULT_PORT = 1801

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("SERVICE", 24),
    ("VERSION", 28),
    ("STATUS", 18),
    ("DETAIL", 62),
]


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = re.sub(r"\s+", " ", str(value or "-")).strip()
    if len(text) > width:
        text = text[: max(1, width - 1)] + "~"
    return text.ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    value = re.sub(r":1801(?:/tcp)?$", "", value, flags=re.I)
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


async def run_nmap(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "-p",
        str(DEFAULT_PORT),
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return (
        stdout.decode("utf-8", errors="ignore"),
        stderr.decode("utf-8", errors="ignore"),
    )


def parse_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    rows = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address")
        if address is None:
            continue
        ip = address.attrib.get("addr", "")

        for port_node in host.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            port = int(port_node.attrib.get("portid", "0"))
            if port != DEFAULT_PORT:
                continue

            service = port_node.find("service")
            name = service.attrib.get("name", "") if service is not None else ""
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            extra = service.attrib.get("extrainfo", "") if service is not None else ""
            fingerprint = " ".join(
                value for value in [name, product, version, extra] if value
            )
            confirmed = bool(
                re.search(
                    r"\b(?:msmq|microsoft message queu(?:e|ing))\b",
                    fingerprint,
                    re.I,
                )
            )

            if confirmed:
                status = "MSMQ DETECTED"
                detail = "Microsoft Message Queuing service detected on TCP/1801."
            else:
                status = "MSMQ CANDIDATE"
                detail = "TCP/1801 is open, but the service fingerprint did not conclusively identify MSMQ."

            rows.append({
                "ip": ip,
                "port": "1801/TCP",
                "protocol": "MSMQ/TCP",
                "service": product or name or "unknown",
                "version": " ".join(
                    value for value in [version, extra] if value
                ) or "-",
                "status": status,
                "detail": detail,
            })
    return rows


async def scan_one(ip, timeout):
    xml_text, _ = await run_nmap(ip, timeout)
    return parse_xml(xml_text)


async def run_all(targets, workers, timeout):
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
                rows.extend(await scan_one(ip, timeout))
                completed += 1
                detected = sum(
                    row["status"] == "MSMQ DETECTED" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning MSMQ: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Open: {len(rows)} | Detected: {detected} | "
                    f"Current: {ip}".ljust(130)
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
    return rows


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No hosts with TCP/1801 open were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 18),
            cell(row["port"], 10),
            cell(row["protocol"], 12),
            cell(row["service"], 24),
            cell(row["version"], 28),
            cell(row["status"], 18),
            cell(row["detail"], 62),
        ])
        code = CYAN if row["status"] == "MSMQ DETECTED" else YELLOW
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "protocol",
        "service",
        "version",
        "status",
        "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda item: ip_sort(item["ip"])))


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted({row["ip"] for row in rows}, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find Microsoft Message Queuing services on TCP/1801."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent host workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument("--csv", default="msmq_port_scan.csv", help="CSV output path")
    parser.add_argument("--list", default="msmq_open_ips.txt", help="Open TCP/1801 IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Scan port      : 1801/TCP")
    print("Detection      : Nmap -sV --version-all")
    print("Showing        : hosts with TCP/1801 open only")

    rows = asyncio.run(run_all(targets, workers, max(10, args.timeout)))
    print_table(rows, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    detected = [row for row in rows if row["status"] == "MSMQ DETECTED"]
    candidates = [row for row in rows if row["status"] == "MSMQ CANDIDATE"]
    print()
    print(f"TCP/1801 open : {len(rows)}")
    print(f"MSMQ detected : {len(detected)}")
    print(f"Candidates    : {len(candidates)}")
    print(f"CSV written   : {args.csv}")
    print(f"IP list       : {args.list}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

