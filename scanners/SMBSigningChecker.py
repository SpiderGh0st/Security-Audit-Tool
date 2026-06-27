#!/usr/bin/env python3
"""
Compact SMB signing checker using Nmap in concurrent background workers.

Reports only vulnerable hosts where SMB signing is:
  - DISABLED
  - ENABLED BUT NOT REQUIRED

Examples:
  python3 SMBSigningChecker.py 198.51.100.30
  python3 SMBSigningChecker.py 198.51.100.0/24 -w 32
  python3 SMBSigningChecker.py -f smb_open_ips.txt
  python3 SMBSigningChecker.py -f smb_open_ips.txt --no-color
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
from pathlib import Path


RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 15),
    ("PORT", 5),
    ("SMB1", 12),
    ("SMB2/3", 12),
    ("STATUS", 12),
    ("DETAIL", 45),
]


def paint(text, color, enabled=True):
    return f"{color}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:width].ljust(width)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []

    # Accept lines such as "198.51.100.30:445/tcp - microsoft-ds".
    value = value.split()[0]
    match = re.match(r"^([0-9.]+):\d+(?:/tcp)?$", value)
    if match:
        value = match.group(1)

    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [value]


def load_targets(args):
    targets = []
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise SystemExit(f"Target file not found: {path}")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            targets.extend(expand_target(line))

    for item in args.targets:
        targets.extend(expand_target(item))

    unique = []
    seen = set()
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


def signing_state(text):
    lower = text.lower()
    if "message signing enabled but not required" in lower:
        return "NOT REQUIRED"
    if "message signing enabled and required" in lower:
        return "REQUIRED"
    if re.search(r"message[_ ]signing\s*:\s*disabled", lower):
        return "DISABLED"
    if "message signing disabled" in lower:
        return "DISABLED"
    if "message signing required" in lower:
        return "REQUIRED"
    if re.search(r"message[_ ]signing\s*:\s*enabled", lower):
        return "ENABLED"
    return "N/A"


def script_block(text, script_name):
    lines = text.splitlines()
    captured = []
    active = False

    for line in lines:
        if re.search(rf"\b{re.escape(script_name)}\s*:", line):
            active = True
            captured.append(line)
            continue
        if active:
            if re.match(r"^\|[_ ]", line):
                captured.append(line)
                continue
            if line.startswith("|"):
                captured.append(line)
                continue
            break

    return "\n".join(captured)


def parse_result(ip, text):
    open_ports = sorted(set(re.findall(r"^(139|445)/tcp\s+open\b", text, re.M)))
    smb1_block = script_block(text, "smb-security-mode")
    smb2_block = script_block(text, "smb2-security-mode")

    smb1 = signing_state(smb1_block)
    smb2 = signing_state(smb2_block)

    vulnerable_states = {"DISABLED", "NOT REQUIRED"}
    affected = smb1 in vulnerable_states or smb2 in vulnerable_states

    states = []
    if smb1 in vulnerable_states:
        states.append(f"SMB1 {smb1.lower()}")
    if smb2 in vulnerable_states:
        states.append(f"SMB2/3 {smb2.lower()}")

    if "DISABLED" in (smb1, smb2):
        status = "DISABLED"
    elif "NOT REQUIRED" in (smb1, smb2):
        status = "NOT REQUIRED"
    elif "REQUIRED" in (smb1, smb2) and all(
        state in {"REQUIRED", "N/A"} for state in (smb1, smb2)
    ):
        status = "REQUIRED"
    else:
        status = "UNKNOWN"

    return {
        "ip": ip,
        "port": ",".join(open_ports) if open_ports else "-",
        "smb1": smb1,
        "smb2": smb2,
        "status": status,
        "detail": (
            "; ".join(states)
            if states
            else (
                "Signing is required for the reported SMB dialect(s)."
                if status == "REQUIRED"
                else "Nmap returned no conclusive SMB signing state."
            )
        ),
        "affected": affected,
    }


async def run_nmap(ip, ports, timeout):
    command = [
        "nmap",
        "-n",
        "-Pn",
        "-T4",
        "--max-retries",
        "1",
        "--script-timeout",
        "20s",
        "-p",
        ports,
        "--script",
        "smb-security-mode,smb2-security-mode",
        ip,
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise SystemExit("nmap was not found in PATH. Install Nmap first.")

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "ip": ip,
            "port": "-",
            "smb1": "N/A",
            "smb2": "N/A",
            "status": "TIMEOUT",
            "detail": f"Timed out after {timeout}s.",
            "affected": False,
        }

    text = stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")
    return parse_result(ip, text)


def show_progress(done, total, affected, current, colors):
    percent = done / total * 100 if total else 100
    message = (
        f"\rScanning SMB signing: {done}/{total} ({percent:5.1f}%)"
        f" | Vulnerable: {affected} | Current: {current}"
    )
    sys.stdout.write(paint(message[:120].ljust(120), CYAN, colors))
    sys.stdout.flush()


async def scan_targets(targets, workers, ports, timeout, colors):
    queue = asyncio.Queue()
    results = []
    completed = 0
    affected = 0
    lock = asyncio.Lock()

    for target in targets:
        await queue.put(target)

    show_progress(0, len(targets), 0, "-", colors)

    async def worker():
        nonlocal completed, affected
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return

            row = await run_nmap(ip, ports, timeout)
            results.append(row)

            async with lock:
                completed += 1
                if row["affected"]:
                    affected += 1
                show_progress(completed, len(targets), affected, ip, colors)

            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)

    sys.stdout.write("\n")
    return results


def print_table(rows, colors):
    affected = [row for row in rows if row["affected"]]
    print()
    if not affected:
        print("No hosts with SMB signing disabled or not required were detected.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(affected, key=lambda item: ip_sort(item["ip"])):
        line = " ".join(
            [
                cell(row["ip"], 15),
                cell(row["port"], 5),
                cell(row["smb1"], 12),
                cell(row["smb2"], 12),
                cell(row["status"], 12),
                cell(row["detail"], 45),
            ]
        )
        print(paint(line, RED, colors))


def write_outputs(csv_path, list_path, rows):
    affected = sorted(
        (row for row in rows if row["affected"]),
        key=lambda item: ip_sort(item["ip"]),
    )

    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "port", "smb1", "smb2", "status", "detail"],
        )
        writer.writeheader()
        for row in affected:
            writer.writerow({key: row[key] for key in writer.fieldnames})

    Path(list_path).write_text(
        "\n".join(row["ip"] for row in affected) + ("\n" if affected else ""),
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Find hosts where SMB signing is disabled or not required."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR subnet")
    parser.add_argument("-f", "--file", help="File containing IPs, hostnames, or CIDRs")
    parser.add_argument("-p", "--ports", default="139,445", help="SMB ports (default: 139,445)")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent Nmap workers")
    parser.add_argument("-t", "--timeout", type=int, default=40, help="Timeout per target")
    parser.add_argument(
        "--csv",
        default="smb_signing_vulnerable.csv",
        help="Affected-only CSV output",
    )
    parser.add_argument(
        "--affected",
        default="smb_signing_affected.txt",
        help="Affected IP list output",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found in PATH. Install Nmap first.")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))
    colors = not args.no_color

    print(f"Loaded targets : {len(targets)}")
    print(f"Ports          : {args.ports}")
    print(f"Workers        : {workers}")
    print("Checks         : SMB1/SMB2 signing disabled or not required")
    print("Display        : vulnerable hosts only")

    rows = asyncio.run(
        scan_targets(targets, workers, args.ports, args.timeout, colors)
    )
    print_table(rows, colors)
    write_outputs(args.csv, args.affected, rows)

    vulnerable = sum(1 for row in rows if row["affected"])
    print()
    print(f"Targets scanned     : {len(rows)}")
    print(f"Vulnerable hosts    : {vulnerable}")
    print(f"CSV written         : {args.csv}")
    print(f"Affected list       : {args.affected}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

