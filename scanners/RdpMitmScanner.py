#!/usr/bin/env python3
"""
Check hosts for the legacy RDP security layer associated with the
Remote Desktop Protocol Server Man-in-the-Middle Weakness.

The scanner uses Nmap's rdp-enum-encryption NSE script and only reports
hosts where Native RDP security is accepted.

Requirements:
    sudo apt install nmap

Examples:
    python3 RdpMitmScanner.py -f target_ips.txt
    python3 RdpMitmScanner.py 192.0.2.0/24 --workers 32
    python3 RdpMitmScanner.py 192.0.2.11:3389

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

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 8),
    ("NATIVE RDP", 13),
    ("STATUS", 14),
    ("DETAIL", 88),
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


def expand_target(value, default_port):
    value = value.strip()
    if not value or value.startswith("#"):
        return []

    value = value.split()[0]
    if re.match(r"^[0-9.]+:\d+$", value):
        ip, port = value.rsplit(":", 1)
        return [(ip, int(port))]

    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [(str(network.network_address), default_port)]
        return [(str(address), default_port) for address in network.hosts()]
    except ValueError:
        return [(value, default_port)]


def load_targets(args):
    targets = []

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                targets.extend(expand_target(line, args.port))

    for value in args.targets:
        targets.extend(expand_target(value, args.port))

    unique = list(dict.fromkeys(targets))
    if not unique:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return unique


async def run_nmap(ip, port, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-p",
        str(port),
        "--script",
        "rdp-enum-encryption",
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


def parse_nmap_xml(xml_text, expected_port):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False, ""

    for port_node in root.findall(".//port"):
        if port_node.get("portid") != str(expected_port):
            continue

        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            return False, ""

        for script in port_node.findall("script"):
            if script.get("id") != "rdp-enum-encryption":
                continue

            output = script.get("output", "")
            output += " " + " ".join(
                element.text or "" for element in script.iter() if element.text
            )

            if native_rdp_accepted(output):
                return True, summarize_output(output)

    return False, ""


def native_rdp_accepted(output):
    text = re.sub(r"\s+", " ", output)

    negative_patterns = [
        r"Native RDP[^.;\n]*(?:FAILED|REJECTED|NOT SUPPORTED|UNAVAILABLE)",
        r"RDP Encryption layer:[^;\n]*(?:FAILED|REJECTED)",
    ]
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in negative_patterns):
        return False

    positive_patterns = [
        r"Native RDP",
        r"RDP Encryption layer",
        r"RDP security layer",
        r"PROTOCOL_RDP",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in positive_patterns)


def summarize_output(output):
    text = re.sub(r"\s+", " ", output).strip()
    details = []

    if re.search(r"Native RDP|RDP Encryption layer|RDP security layer|PROTOCOL_RDP", text, re.I):
        details.append("Legacy Native RDP security was accepted")

    encryption = re.search(
        r"(?:Encryption level|RDP Encryption level)\s*:\s*([^;|]+)",
        text,
        re.IGNORECASE,
    )
    if encryption:
        details.append(f"encryption level: {encryption.group(1).strip()}")

    if re.search(r"\bRC4\b", text, re.IGNORECASE):
        details.append("RC4 reported")

    return "; ".join(details) or "Legacy Native RDP security was accepted."


async def scan_one(ip, port, timeout):
    xml_text = await run_nmap(ip, port, timeout)
    vulnerable, evidence = parse_nmap_xml(xml_text, port)
    if not vulnerable:
        return None

    return {
        "ip": ip,
        "port": f"{port}/TCP",
        "native_rdp": "ACCEPTED",
        "status": "VULNERABLE",
        "detail": (
            f"{evidence}. The server accepts legacy RDP security associated "
            "with the RDP server MITM weakness."
        ),
    }


async def run_all(targets, workers, timeout):
    queue = asyncio.Queue()
    results = []
    completed = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return

            ip, port = item
            try:
                row = await scan_one(ip, port, timeout)
                if row:
                    results.append(row)

                completed += 1
                sys.stdout.write(
                    f"\rScanning RDP MITM: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Vulnerable: {len(results)} | Current: {ip}:{port}".ljust(125)
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
        print("No hosts accepting legacy Native RDP security were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 8),
            cell(row["native_rdp"], 13),
            cell(row["status"], 14),
            cell(row["detail"], 88),
        ])
        print(paint(line, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "port", "native_rdp", "status", "detail"],
        )
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find RDP servers accepting the legacy Native RDP security layer."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="File containing IPs, CIDRs, or ip:port entries")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Default RDP port")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument("--csv", default="rdp_mitm_vulnerable.csv", help="CSV output")
    parser.add_argument("--list", default="rdp_mitm_vulnerable_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Nmap script    : rdp-enum-encryption")
    print("Showing        : Native RDP security accepted only")

    rows = asyncio.run(run_all(targets, workers, args.timeout))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Vulnerable found : {len(rows)}")
    print(f"CSV written      : {args.csv}")
    print(f"IP list written  : {args.list}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

