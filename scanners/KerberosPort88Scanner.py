#!/usr/bin/env python3
"""
Find hosts with Kerberos port 88 open over TCP or UDP.

Requirements:
    sudo apt install nmap

Examples:
    sudo python3 KerberosPort88Scanner.py -f target_ips.txt
    sudo python3 KerberosPort88Scanner.py 192.0.2.0/24
    sudo python3 KerberosPort88Scanner.py -f target_ips.txt --show-uncertain

Only confirmed open ports are displayed by default. UDP open|filtered results
are not treated as confirmed unless --show-uncertain is used.

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET


GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 10),
    ("TRANSPORT", 12),
    ("SERVICE", 24),
    ("STATE", 16),
    ("STATUS", 18),
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
    value = re.sub(r":88(?:/(?:tcp|udp))?$", "", value, flags=re.I)
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


async def run_nmap(ip, args):
    command = [
        "nmap", "-Pn", "-n", "-sS", "-sU", "-sV", "--version-light",
        "-p", "T:88,U:88",
        "--reason",
        "--max-retries", str(args.retries),
        "--host-timeout", f"{args.timeout}s",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_xml(xml_text, show_uncertain=False):
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
            if port_node.attrib.get("portid") != "88":
                continue
            transport = port_node.attrib.get("protocol", "").upper()
            state_node = port_node.find("state")
            state = state_node.attrib.get("state", "") if state_node is not None else ""
            confirmed = state == "open"
            uncertain = state == "open|filtered"
            if not confirmed and not (show_uncertain and uncertain):
                continue

            service = port_node.find("service")
            parts = []
            if service is not None:
                parts = [
                    service.attrib.get("name", ""),
                    service.attrib.get("product", ""),
                    service.attrib.get("version", ""),
                ]
            service_text = " ".join(part for part in parts if part) or "kerberos-sec"
            rows.append({
                "ip": ip,
                "port": 88,
                "transport": transport,
                "service": service_text,
                "state": state.upper(),
                "status": "OPEN" if confirmed else "UNCERTAIN",
            })
    return rows


async def scan_host(ip, args):
    return parse_xml(await run_nmap(ip, args), args.show_uncertain)


async def run_all(targets, args):
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
                    rows.extend(await scan_host(ip, args))
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                open_hosts = len({
                    row["ip"] for row in rows if row["status"] == "OPEN"
                })
                sys.stdout.write(
                    f"\rScanning Kerberos port 88: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Open hosts: {open_hosts} | Current: {ip}".ljust(125)
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
        print("No hosts with confirmed open Kerberos port 88 were found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        rows, key=lambda item: (ip_sort(item["ip"]), item["transport"])
    ):
        line = " ".join([
            cell(row["ip"], 18),
            cell(f"{row['port']}/{row['transport']}", 10),
            cell(row["transport"], 12),
            cell(row["service"], 24),
            cell(row["state"], 16),
            cell(row["status"], 18),
        ])
        print(color(
            line,
            GREEN if row["status"] == "OPEN" else YELLOW,
            colors,
        ))


def write_csv(path, rows):
    fields = ["ip", "port", "transport", "service", "state", "status"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows, key=lambda item: (ip_sort(item["ip"]), item["transport"])
        ):
            writer.writerow(row)


def write_list(path, rows):
    hosts = sorted({
        row["ip"] for row in rows if row["status"] == "OPEN"
    }, key=ip_sort)
    with open(path, "w", encoding="utf-8") as handle:
        for ip in hosts:
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find hosts with Kerberos port 88 open over TCP or UDP."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent hosts")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Nmap timeout per host")
    parser.add_argument("--retries", type=int, default=2, help="Nmap probe retries")
    parser.add_argument(
        "--show-uncertain", action="store_true",
        help="Also show UDP open|filtered results as UNCERTAIN",
    )
    parser.add_argument("--csv", default="kerberos_port_88_results.csv", help="CSV output")
    parser.add_argument("--list", default="kerberos_port_88_open_ips.txt", help="Confirmed open IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit(
            "Run with sudo because TCP SYN and UDP scans require root: "
            "sudo python3 KerberosPort88Scanner.py ..."
        )

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))
    args.retries = max(0, args.retries)

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print("Scan port      : 88/TCP and 88/UDP")
    print("Service        : Kerberos / KDC discovery")
    print(f"Showing        : {'open and UDP open|filtered' if args.show_uncertain else 'confirmed open only'}")

    rows = asyncio.run(run_all(targets, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    open_endpoints = sum(row["status"] == "OPEN" for row in rows)
    open_hosts = len({
        row["ip"] for row in rows if row["status"] == "OPEN"
    })
    uncertain = sum(row["status"] == "UNCERTAIN" for row in rows)
    print()
    print(f"Open endpoints : {open_endpoints}")
    print(f"Open hosts     : {open_hosts}")
    if args.show_uncertain:
        print(f"Uncertain UDP  : {uncertain}")
    print(f"CSV written    : {args.csv}")
    print(f"IP list written: {args.list}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

