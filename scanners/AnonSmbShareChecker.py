#!/usr/bin/env python3
"""
Anonymous SMB share access checker using smbmap.

Requirements:
  - smbmap installed and available in PATH
  - Network access to TCP/445 on target hosts

Examples:
  python3 AnonSmbShareChecker.py 198.51.100.31
  python3 AnonSmbShareChecker.py 198.51.100.0/24 --workers 32
  python3 AnonSmbShareChecker.py -f targets.txt --csv anon_smb_results.csv

Notes:
  - Uses anonymous credentials: -u '' -p ''
  - Runs smbmap checks concurrently in the background using asyncio workers
  - Reports shares that have READ, WRITE, READ/WRITE, or other accessible permissions
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
from pathlib import Path


COLS = [
    ("IP ADDRESS", 16),
    ("SHARE", 28),
    ("PERMISSION", 16),
    ("COMMENT", 55),
]

ACCESS_WORDS = ("READ", "WRITE", "READ, WRITE", "READ/WRITE", "WRITE, READ")


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


def parse_smbmap(ip, output):
    rows = []
    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        # smbmap table rows usually look like:
        # Disk    READ, WRITE    comment text
        # IPC$    NO ACCESS      Remote IPC
        match = re.match(r"^([^\s]+)\s{2,}([A-Z,\s/]+?)(?:\s{2,}(.*))?$", stripped)
        if not match:
            continue

        share = match.group(1).strip()
        perm = " ".join(match.group(2).strip().split())
        comment = (match.group(3) or "").strip()

        if share.lower() in {"disk", "permissions", "-----", "name"}:
            continue
        if share.endswith(":") or share.lower().startswith("[+]"):
            continue

        accessible = any(word in perm for word in ACCESS_WORDS) and "NO ACCESS" not in perm
        if accessible:
            rows.append(
                {
                    "ip": ip,
                    "share": share,
                    "permission": perm,
                    "comment": comment,
                }
            )
    return rows


async def run_smbmap(ip, timeout):
    cmd = ["smbmap", "-H", ip, "-u", "", "-p", ""]
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
            return ip, [], f"TIMEOUT after {timeout}s"

        text = stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
        return ip, parse_smbmap(ip, text), ""
    except FileNotFoundError:
        raise SystemExit("smbmap was not found in PATH.")
    except Exception as exc:
        return ip, [], str(exc)


async def worker(name, queue, results, errors, timeout):
    while True:
        ip = await queue.get()
        if ip is None:
            queue.task_done()
            return
        target, rows, error = await run_smbmap(ip, timeout)
        if rows:
            results.extend(rows)
            print(f"[+] {target}: {len(rows)} accessible share(s)")
        else:
            print(f"[-] {target}: no anonymous readable/writable shares")
        if error:
            errors.append({"ip": target, "error": error})
        queue.task_done()


async def run_all(targets, workers, timeout):
    queue = asyncio.Queue()
    results = []
    errors = []

    for target in targets:
        await queue.put(target)

    tasks = [
        asyncio.create_task(worker(f"worker-{i}", queue, results, errors, timeout))
        for i in range(workers)
    ]

    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    return results, errors


def print_table(rows):
    print()
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    if not rows:
        print("No anonymous SMB shares with read/write access were found.")
        return
    for row in sorted(rows, key=lambda r: (ip_sort(r["ip"]), r["share"])):
        print(
            " ".join(
                [
                    cell(row["ip"], 16),
                    cell(row["share"], 28),
                    cell(row["permission"], 16),
                    cell(row["comment"], 55),
                ]
            )
        )


def ip_sort(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return value


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "share", "permission", "comment"])
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (ip_sort(r["ip"]), r["share"])):
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Check anonymous SMB share read/write access with smbmap.")
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR subnet")
    parser.add_argument("-f", "--file", help="Text file containing IPs, hostnames, or CIDR subnets")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent smbmap workers")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Timeout per target in seconds")
    parser.add_argument("--csv", default="anonymous_smb_shares.csv", help="CSV output path")
    args = parser.parse_args()

    if not shutil.which("smbmap"):
        raise SystemExit("smbmap was not found in PATH. Install it first, then rerun this script.")

    targets = load_targets(args)
    workers = max(1, min(args.workers, len(targets)))
    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Auth mode      : anonymous (-u '' -p '')")

    rows, errors = asyncio.run(run_all(targets, workers, args.timeout))
    print_table(rows)
    write_csv(args.csv, rows)

    print()
    print(f"Accessible share rows : {len(rows)}")
    print(f"CSV written           : {args.csv}")
    if errors:
        print(f"Errors/timeouts       : {len(errors)}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

