#!/usr/bin/env python3
"""
Find SMB servers that do not require password encryption.

This scanner uses Nmap's smb-security-mode NSE script. It reports SMB1
servers when either:
  - challenge/response password protection is not supported/required, or
  - share-level authentication is enabled.

These configurations may permit plaintext SMB passwords and expose
credentials to network sniffing.

Requirements:
    sudo apt install nmap

Examples:
    python3 SmbPasswordEncryptionScanner.py -f target_ips.txt
    python3 SmbPasswordEncryptionScanner.py 192.0.2.0/24 --workers 24
    python3 SmbPasswordEncryptionScanner.py 192.0.2.10

Only vulnerable findings are displayed.
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
    ("PORTS", 10),
    ("AUTH LEVEL", 14),
    ("CHALLENGE/RESPONSE", 21),
    ("STATUS", 14),
    ("DETAIL", 80),
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


async def run_nmap(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "--open",
        "-p",
        "139,445",
        "--script",
        "smb-security-mode",
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


def script_values(script):
    values = {}

    for element in script.iter("elem"):
        key = element.attrib.get("key", "").strip().lower()
        value = (element.text or "").strip()
        if key and value:
            values[key] = value

    output = script.attrib.get("output", "")
    for key in (
        "account_used",
        "authentication_level",
        "challenge_response",
        "message_signing",
    ):
        if key in values:
            continue
        match = re.search(
            rf"(?mi)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$",
            output,
        )
        if match:
            values[key] = match.group(1).strip()

    return values


def encryption_not_required(values, raw_output=""):
    auth_level = values.get("authentication_level", "unknown").lower()
    challenge = values.get("challenge_response", "unknown").lower()
    raw = raw_output.lower()

    share_level = auth_level.startswith("share")
    challenge_unprotected = (
        challenge not in {"unknown", ""}
        and (
            "not supported" in challenge
            or "unsupported" in challenge
            or "disabled" in challenge
            or "not required" in challenge
            or challenge in {"no", "false", "plaintext", "plain text"}
        )
    )
    explicit_plaintext = any(
        marker in raw
        for marker in (
            "plaintext passwords",
            "plain text passwords",
            "unencrypted passwords",
            "password encryption: disabled",
            "password encryption: not required",
            "encrypted passwords: disabled",
            "encrypted passwords: not required",
        )
    )

    return share_level or challenge_unprotected or explicit_plaintext


def parse_xml(xml_text, show_all=False):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    host_node = root.find("host")
    if host_node is None:
        return None

    address = host_node.find("address[@addrtype='ipv4']")
    if address is None:
        address = host_node.find("address")
    if address is None:
        return None
    ip = address.attrib.get("addr", "")

    open_ports = []
    for port_node in host_node.findall("./ports/port"):
        state = port_node.find("state")
        if state is not None and state.attrib.get("state") == "open":
            open_ports.append(int(port_node.attrib.get("portid", "0")))

    script = host_node.find("hostscript/script[@id='smb-security-mode']")
    if script is None:
        script = host_node.find(".//script[@id='smb-security-mode']")
    if script is None:
        if show_all and open_ports:
            return {
                "ip": ip,
                "ports": ",".join(str(port) for port in sorted(open_ports)),
                "auth_level": "UNKNOWN",
                "challenge_response": "NOT TESTED",
                "status": "NO RESULT",
                "detail": "SMB ports are open, but smb-security-mode returned no result; SMB1 may be unavailable or negotiation failed.",
                "raw_output": "",
            }
        return None

    values = script_values(script)
    raw_output = script.attrib.get("output", "")
    vulnerable = encryption_not_required(values, raw_output)
    if not vulnerable and not show_all:
        return None

    auth_level = values.get("authentication_level", "unknown")
    challenge = values.get("challenge_response", "unknown")

    reasons = []
    if auth_level.lower().startswith("share"):
        reasons.append("share-level authentication uses plaintext share passwords")
    if any(
        marker in challenge.lower()
        for marker in ("not supported", "unsupported", "disabled", "not required")
    ):
        reasons.append("challenge/response password protection is not required")
    if any(
        marker in raw_output.lower()
        for marker in (
            "plaintext passwords",
            "plain text passwords",
            "unencrypted passwords",
            "password encryption: disabled",
            "password encryption: not required",
            "encrypted passwords: disabled",
            "encrypted passwords: not required",
        )
    ):
        reasons.append("SMB response explicitly permits unencrypted passwords")

    return {
        "ip": ip,
        "ports": ",".join(str(port) for port in sorted(open_ports)) or "-",
        "auth_level": auth_level.upper(),
        "challenge_response": challenge.upper(),
        "status": "VULNERABLE" if vulnerable else "NOT DETECTED",
        "detail": (
            "; ".join(reasons)
            if reasons
            else "SMB responded, but no plaintext-password indicator was detected."
        ),
        "raw_output": re.sub(r"\s+", " ", raw_output).strip(),
    }


async def scan_one(ip, timeout, show_all):
    return parse_xml(await run_nmap(ip, timeout), show_all=show_all)


async def run_all(targets, workers, timeout, show_all):
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
                row = await scan_one(ip, timeout, show_all)
                if row:
                    results.append(row)

                completed += 1
                sys.stdout.write(
                    f"\rScanning SMB password encryption: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Vulnerable: {len(results)} | Current: {ip}".ljust(135)
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
        print("No SMB servers with password encryption not required were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["ports"], 10),
            cell(row["auth_level"], 14),
            cell(row["challenge_response"], 21),
            cell(row["status"], 14),
            cell(row["detail"], 80),
        ])
        print(paint(line, colors) if row["status"] == "VULNERABLE" else line)


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "ports",
                "auth_level",
                "challenge_response",
                "status",
                "detail",
                "raw_output",
            ],
        )
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
        for row in sorted(vulnerable, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find SMB servers that do not require password encryption."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all hosts where smb-security-mode returned a result",
    )
    parser.add_argument(
        "--csv",
        default="smb_password_encryption_not_required.csv",
        help="CSV output",
    )
    parser.add_argument(
        "--list",
        default="smb_password_encryption_not_required_ips.txt",
        help="Vulnerable IP list",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Ports          : 139,445/TCP")
    print("Nmap script    : smb-security-mode")
    print(
        "Showing        : "
        + ("all SMB security-mode responses" if args.show_all else "password encryption not required only")
    )

    rows = asyncio.run(run_all(targets, workers, args.timeout, args.show_all))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    vulnerable_count = sum(1 for row in rows if row["status"] == "VULNERABLE")
    print(f"Vulnerable hosts : {vulnerable_count}")
    print(f"CSV written      : {args.csv}")
    print(f"IP list written  : {args.list}")

    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

