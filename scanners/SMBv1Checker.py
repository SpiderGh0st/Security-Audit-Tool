#!/usr/bin/env python3
"""
SMBv1 checker using nmap smb-protocols.

Examples:
  python3 SMBv1Checker.py 198.51.100.31
  python3 SMBv1Checker.py 198.51.100.0/24 --workers 32
  python3 SMBv1Checker.py -f smb_open_ips.txt --csv smbv1_results.csv
  python3 SMBv1Checker.py -f smb_open_ips.txt --no-color

Affected = SMBv1 dialect "NT LM 0.12" is accepted.
Secure   = SMB service responds but SMBv1 was not listed.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
from pathlib import Path


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 16),
    ("PORTS", 12),
    ("SMBv1", 10),
    ("STATUS", 12),
    ("DETAIL", 70),
]


def paint(text, code, enabled):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:width].ljust(width)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]


def load_targets(args):
    targets = []
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
            targets.extend(expand_target(line))
    for item in args.targets:
        targets.extend(expand_target(item))

    seen = set()
    unique = []
    for target in targets:
        if target not in seen:
            unique.append(target)
            seen.add(target)
    if not unique:
        raise SystemExit("No targets supplied. Provide an IP/CIDR or use -f targets.txt")
    return unique


def ip_sort(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return value


async def run_nmap(ip, ports, timeout):
    cmd = [
        "nmap",
        "-Pn",
        "-p",
        ports,
        "--script",
        "smb-protocols",
        ip,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {
                "ip": ip,
                "ports": ports,
                "smbv1": "UNKNOWN",
                "status": "TIMEOUT",
                "detail": f"nmap timed out after {timeout}s",
            }
    except FileNotFoundError:
        raise SystemExit("nmap was not found in PATH.")

    text = stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
    return parse_result(ip, ports, text)


def parse_result(ip, ports, text):
    open_smb_ports = sorted(set(re.findall(r"^(139|445)/tcp\s+open\b", text, re.M)))
    smbv1 = bool(re.search(r"\bNT LM 0\.12\b|\bSMBv1\b", text, re.I))

    if smbv1:
        return {
            "ip": ip,
            "ports": ",".join(open_smb_ports) if open_smb_ports else ports,
            "smbv1": "ENABLED",
            "status": "AFFECTED",
            "detail": 'SMBv1 dialect "NT LM 0.12" was accepted.',
        }

    if open_smb_ports:
        dialects = re.findall(r"^\|\s+([0-9]:[0-9]:[0-9])", text, re.M)
        detail = "SMB service open; SMBv1 not listed."
        if dialects:
            detail += " Dialects: " + ", ".join(dialects[:8])
        return {
            "ip": ip,
            "ports": ",".join(open_smb_ports),
            "smbv1": "DISABLED",
            "status": "SECURE",
            "detail": detail,
        }

    if re.search(r"Host is up", text):
        return {
            "ip": ip,
            "ports": "-",
            "smbv1": "UNKNOWN",
            "status": "NO SMB",
            "detail": "Host up, but no SMB port reported open.",
        }

    return {
        "ip": ip,
        "ports": "-",
        "smbv1": "UNKNOWN",
        "status": "NO RESPONSE",
        "detail": "No usable SMB protocol response.",
    }


async def run_all(targets, workers, ports, timeout):
    queue = asyncio.Queue()
    results = []
    for target in targets:
        await queue.put(target)

    async def worker():
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            row = await run_nmap(ip, ports, timeout)
            results.append(row)
            if row["status"] == "AFFECTED":
                print(paint(f"[!] {ip}: SMBv1 ENABLED", RED, True))
            elif row["status"] == "SECURE":
                print(paint(f"[+] {ip}: SMBv1 disabled", GREEN, True))
            else:
                print(paint(f"[-] {ip}: {row['status']}", YELLOW, True))
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    return results


def print_table(rows, colors):
    print()
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(rows, key=lambda r: ip_sort(r["ip"])):
        code = RED if row["status"] == "AFFECTED" else GREEN if row["status"] == "SECURE" else YELLOW
        line = " ".join(
            [
                cell(row["ip"], 16),
                cell(row["ports"], 12),
                cell(row["smbv1"], 10),
                cell(row["status"], 12),
                cell(row["detail"], 70),
            ]
        )
        print(paint(line, code, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "ports", "smbv1", "status", "detail"])
        writer.writeheader()
        for row in sorted(rows, key=lambda r: ip_sort(r["ip"])):
            writer.writerow(row)


def write_lists(prefix, rows):
    affected = [r["ip"] for r in rows if r["status"] == "AFFECTED"]
    secure = [r["ip"] for r in rows if r["status"] == "SECURE"]
    Path(f"{prefix}_affected.txt").write_text("\n".join(affected) + ("\n" if affected else ""), encoding="utf-8")
    Path(f"{prefix}_secure.txt").write_text("\n".join(secure) + ("\n" if secure else ""), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Check SMBv1 support and separate affected hosts.")
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR subnet")
    parser.add_argument("-f", "--file", help="Text file containing IPs, hostnames, or CIDR subnets")
    parser.add_argument("-p", "--ports", default="139,445", help="Ports to check, default: 139,445")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent nmap workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Timeout per target in seconds")
    parser.add_argument("--csv", default="smbv1_results.csv", help="CSV output path")
    parser.add_argument("--list-prefix", default="smbv1", help="Prefix for affected/secure txt lists")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found in PATH. Install nmap first.")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Ports          : {args.ports}")
    print(f"Workers        : {workers}")
    print('Detection      : SMBv1 dialect "NT LM 0.12"')

    rows = asyncio.run(run_all(targets, workers, args.ports, args.timeout))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_lists(args.list_prefix, rows)

    affected = sum(1 for r in rows if r["status"] == "AFFECTED")
    secure = sum(1 for r in rows if r["status"] == "SECURE")
    other = len(rows) - affected - secure
    print()
    print(paint(f"Affected SMBv1 enabled : {affected}", RED, not args.no_color))
    print(paint(f"Secure SMBv1 disabled  : {secure}", GREEN, not args.no_color))
    print(paint(f"Other/no response      : {other}", YELLOW, not args.no_color))
    print(f"CSV written            : {args.csv}")
    print(f"Affected list          : {args.list_prefix}_affected.txt")
    print(f"Secure list            : {args.list_prefix}_secure.txt")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())

