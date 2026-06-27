#!/usr/bin/env python3
"""
Check SNMP agents for default community strings: public and private.

Requires Net-SNMP tools:
    sudo apt install snmp

Examples:
    python3 SnmpDefaultCommunityScanner.py -f target_ips.txt
    python3 SnmpDefaultCommunityScanner.py 203.0.113.0/24 --workers 32
    python3 SnmpDefaultCommunityScanner.py -f target_ips.txt --version 1

Only hosts accepting at least one default community string are displayed.
Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 11),
    ("public", 12),
    ("private", 12),
    ("STATUS", 13),
    ("DETAIL", 68),
]


def paint(text, color, enabled=True):
    return f"{color}{text}{RESET}" if enabled else text


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
    value = re.sub(r":161(?:/udp)?$", "", value, flags=re.IGNORECASE)

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


async def check_community(ip, community, version, timeout, retries):
    command = [
        "snmpget",
        "-v",
        version,
        "-c",
        community,
        "-t",
        str(timeout),
        "-r",
        str(retries),
        "-Oqv",
        f"udp:{ip}:161",
        SYS_DESCR_OID,
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=max(2, timeout * (retries + 1) + 2),
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return False, ""
    except OSError:
        return False, ""

    output = stdout.decode("utf-8", errors="ignore").strip()
    error = stderr.decode("utf-8", errors="ignore").strip()

    rejected_markers = (
        "timeout",
        "no response",
        "authorizationerror",
        "unknown user",
        "authentication failure",
        "no such object",
    )
    combined = f"{output} {error}".lower()
    accepted = process.returncode == 0 and bool(output) and not any(
        marker in combined for marker in rejected_markers
    )
    return accepted, output if accepted else ""


async def scan_host(ip, version, timeout, retries):
    public_result, private_result = await asyncio.gather(
        check_community(ip, "public", version, timeout, retries),
        check_community(ip, "private", version, timeout, retries),
    )

    public_ok, public_detail = public_result
    private_ok, private_detail = private_result

    if not public_ok and not private_ok:
        return None

    accepted = []
    if public_ok:
        accepted.append("public")
    if private_ok:
        accepted.append("private")

    description = public_detail or private_detail
    detail = f"Default community accepted: {', '.join(accepted)}"
    if description:
        detail += f"; sysDescr: {description}"

    return {
        "ip": ip,
        "port": "161/UDP",
        "public": "ACCEPTED" if public_ok else "REJECTED",
        "private": "ACCEPTED" if private_ok else "REJECTED",
        "status": "VULNERABLE",
        "detail": detail,
    }


async def run_all(targets, workers, version, timeout, retries):
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
                row = await scan_host(ip, version, timeout, retries)
                if row:
                    results.append(row)

                completed += 1
                sys.stdout.write(
                    f"\rScanning SNMP: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Vulnerable: {len(results)} | Current: {ip}".ljust(120)
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
        print("No SNMP agents accepting public/private community strings were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        prefix = " ".join([
            cell(row["ip"], 18),
            cell(row["port"], 11),
        ])
        public = cell(row["public"], 12)
        private = cell(row["private"], 12)
        suffix = " ".join([
            cell(row["status"], 13),
            cell(row["detail"], 68),
        ])

        if colors:
            public = paint(public, RED if row["public"] == "ACCEPTED" else GREEN)
            private = paint(private, RED if row["private"] == "ACCEPTED" else GREEN)
            suffix = paint(suffix, RED)

        print(f"{prefix} {public} {private} {suffix}")

    print("-" * len(header))
    if colors:
        accepted = paint("ACCEPTED", RED)
        rejected = paint("REJECTED", GREEN)
    else:
        accepted = "ACCEPTED"
        rejected = "REJECTED"
    print(f"Legend: {accepted}=default community valid | {rejected}=not accepted")


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "port", "public", "private", "status", "detail"],
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
        description="Find SNMP agents accepting default public/private community strings."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=32, help="Concurrent workers")
    parser.add_argument(
        "--version",
        choices=["1", "2c"],
        default="2c",
        help="SNMP version to test (default: 2c)",
    )
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds")
    parser.add_argument("-r", "--retries", type=int, default=0, help="SNMP retries")
    parser.add_argument("--csv", default="snmp_default_communities.csv", help="CSV output")
    parser.add_argument("--list", default="snmp_vulnerable_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("snmpget"):
        raise SystemExit(
            "snmpget was not found. Install it on Kali with: sudo apt install snmp"
        )

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"SNMP version   : {args.version}")
    print("Communities    : public, private")
    print("Showing        : accepted default communities only")

    rows = asyncio.run(
        run_all(targets, workers, args.version, args.timeout, args.retries)
    )
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

