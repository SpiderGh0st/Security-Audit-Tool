#!/usr/bin/env python3
"""Find hosts with TCP port 1801 confirmed open."""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET


GREEN = "\033[92m"
RESET = "\033[0m"


def cell(value, width):
    text = re.sub(r"\s+", " ", str(value or "-")).strip()
    return text[:width].ljust(width)


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
    targets = list(dict.fromkeys(targets))
    if not targets:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return targets


async def scan_host(ip, timeout):
    command = [
        "nmap", "-Pn", "-n", "-sT", "--open",
        "-p", "1801", "--host-timeout", f"{timeout}s",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    try:
        root = ET.fromstring(stdout.decode("utf-8", errors="ignore"))
    except ET.ParseError:
        return None

    port = root.find(".//port[@protocol='tcp'][@portid='1801']")
    if port is None:
        return None
    state = port.find("state")
    if state is None or state.attrib.get("state") != "open":
        return None
    service = port.find("service")
    service_name = (
        service.attrib.get("name", "msmq")
        if service is not None else "msmq"
    )
    return {
        "ip": ip,
        "port": "1801/TCP",
        "service": service_name,
        "state": "OPEN",
    }


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
                result = await scan_host(ip, timeout)
                if result:
                    rows.append(result)
                completed += 1
                sys.stdout.write(
                    f"\rScanning port 1801: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Open: {len(rows)} | Current: {ip}".ljust(120)
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
        print("No hosts with TCP port 1801 open were found.")
        return
    header = " ".join([
        cell("IP ADDRESS", 18),
        cell("PORT", 12),
        cell("SERVICE", 24),
        cell("STATE", 12),
    ])
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 18),
            cell(row["port"], 12),
            cell(row["service"], 24),
            cell(row["state"], 12),
        ])
        print(f"{GREEN}{line}{RESET}" if colors else line)


def main():
    parser = argparse.ArgumentParser(
        description="Show only hosts with TCP port 1801 open."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=24)
    parser.add_argument("-t", "--timeout", type=int, default=20)
    parser.add_argument("--csv", default="port_1801_open.csv")
    parser.add_argument("--list", default="port_1801_open_ips.txt")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("Install Nmap with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Scan port      : 1801/TCP")
    print("Showing        : confirmed open only")

    rows = asyncio.run(run_all(targets, workers, args.timeout))
    print_table(rows, not args.no_color)

    with open(args.csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["ip", "port", "service", "state"]
        )
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda item: ip_sort(item["ip"])))

    with open(args.list, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")

    print()
    print(f"Open hosts     : {len(rows)}")
    print(f"CSV written    : {args.csv}")
    print(f"IP list written: {args.list}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

