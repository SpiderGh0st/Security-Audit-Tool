#!/usr/bin/env python3
"""
Scan targets from Kali and print only hosts that appear to run unsupported
Windows versions.

Detection sources:
  - nmap smb-os-discovery on ports 139/445
  - nmap rdp-ntlm-info on port 3389
  - optional nmap OS detection with --os-detect, which adds -O

Examples:
  python3 UnsupportedWindowsScanner.py -f target_ips.txt
  sudo python3 UnsupportedWindowsScanner.py -f target_ips.txt --os-detect
  python3 UnsupportedWindowsScanner.py 192.0.2.0/24 --workers 32
  python3 UnsupportedWindowsScanner.py -f target_ips.txt --csv unsupported_windows.csv

Notes:
  - This is banner/version based. If a host hides OS details, it will not be
    reported unless nmap can identify an unsupported Windows version.
  - Windows Server 2012 / 2012 R2 are printed as unsupported unless your
    organization can prove paid ESU coverage is active.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys


COLS = [
    ("IP ADDRESS", 16),
    ("PORTS", 12),
    ("OS", 38),
    ("STATUS", 14),
    ("DETAIL", 80),
]

RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


UNSUPPORTED_PATTERNS = [
    (r"\bWindows\s+XP\b", "POTENTIAL EOL", "Windows XP was identified remotely; confirm the edition and asset inventory."),
    (r"\bWindows\s+Vista\b", "POTENTIAL EOL", "Windows Vista was identified remotely; confirm the edition and asset inventory."),
    (r"\bWindows\s+7\b", "POTENTIAL EOL", "Windows 7 was identified remotely; confirm edition and any exceptional support coverage."),
    (r"\bWindows\s+8(\b|[^.]|$)", "POTENTIAL EOL", "Windows 8 was identified remotely; confirm the exact release."),
    (r"\bWindows\s+8\.1\b", "POTENTIAL EOL", "Windows 8.1 was identified remotely; confirm the exact release."),
    (r"\bWindows\s+10\b", "LIFECYCLE REVIEW", "Windows 10 was identified remotely; verify edition, LTSC/IoT status, and ESU coverage before reporting EOL."),
    (r"\bWindows\s+Server\s+2003\b", "POTENTIAL EOL", "Windows Server 2003 was identified remotely; confirm in asset inventory."),
    (r"\bWindows\s+Server\s+2008\b", "POTENTIAL EOL", "Windows Server 2008/2008 R2 was identified remotely; confirm exact edition and coverage."),
    (r"\bWindows\s+Server\s+2012\b", "LIFECYCLE REVIEW", "Windows Server 2012/2012 R2 was identified remotely; verify ESU coverage before reporting EOL."),
]

VERSION_MAP = [
    (r"\b5\.1\.", "Windows XP", "POTENTIAL EOL", "NT 5.1 suggests Windows XP; confirm because remote OS fingerprints can be wrong."),
    (r"\b5\.2\.", "Windows Server 2003", "POTENTIAL EOL", "NT 5.2 suggests Server 2003; confirm because remote OS fingerprints can be wrong."),
    (r"\b6\.0\.", "Windows Vista / Server 2008", "POTENTIAL EOL", "NT 6.0 is ambiguous; confirm the exact operating system."),
    (r"\b6\.1\.", "Windows 7 / Server 2008 R2", "POTENTIAL EOL", "NT 6.1 is ambiguous; confirm the exact operating system."),
    (r"\b6\.2\.", "Windows 8 / Server 2012", "LIFECYCLE REVIEW", "NT 6.2 is ambiguous; confirm the exact operating system and support coverage."),
    (r"\b6\.3\.", "Windows 8.1 / Server 2012 R2", "LIFECYCLE REVIEW", "NT 6.3 is ambiguous; confirm the exact operating system and support coverage."),
]


def paint(text, color, enabled=True):
    return f"{color}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\t", " ").replace("\r", " ").replace("\n", " ")
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
    if ":" in value and re.match(r"^[0-9.]+:\d+$", value):
        ip, _port = value.split(":", 1)
        return [ip]
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
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                targets.extend(expand_target(line))
    for item in args.targets:
        targets.extend(expand_target(item))
    seen = set()
    unique = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    if not unique:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return unique


async def run_nmap(ip, timeout, os_detect):
    cmd = [
        "nmap",
        "-Pn",
        "-n",
        "--open",
        "-p",
        "135,139,445,3389",
        "--script",
        "smb-os-discovery,rdp-ntlm-info",
        "--host-timeout",
        f"{timeout}s",
    ]
    if os_detect:
        cmd.extend(["-O", "--osscan-guess"])
    cmd.append(ip)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode("utf-8", errors="ignore")


def extract_open_ports(text):
    ports = []
    for match in re.finditer(r"^(\d+)/tcp\s+open\b", text, flags=re.MULTILINE):
        ports.append(match.group(1))
    return ",".join(ports) if ports else "-"


def extract_os_strings(text):
    found = []
    patterns = [
        r"^\|\s+OS:\s*(.+)$",
        r"^\|\s+OS CPE:\s*(.+)$",
        r"^\|\s+Product_Version:\s*(.+)$",
        r"^\|\s+Target_Name:\s*(.+)$",
        r"^\|\s+NetBIOS_Computer_Name:\s*(.+)$",
        r"^OS details:\s*(.+)$",
        r"^Aggressive OS guesses:\s*(.+)$",
        r"^Running:\s*(.+)$",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.MULTILINE):
            value = match.group(1).strip()
            if value and value not in found:
                found.append(value)
    return found


def normalize_cpe(value):
    value = value.replace("cpe:/o:microsoft:", "").replace("_", " ")
    value = re.sub(r":.*$", "", value)
    return value.strip()


def classify(os_strings):
    joined = " | ".join(os_strings)
    normalized = " | ".join(normalize_cpe(item) for item in os_strings)
    haystack = f"{joined} | {normalized}"

    for pattern, status, detail in UNSUPPORTED_PATTERNS:
        if re.search(pattern, haystack, flags=re.IGNORECASE):
            os_name = re.search(pattern, haystack, flags=re.IGNORECASE).group(0)
            return os_name, status, detail

    for pattern, os_name, status, detail in VERSION_MAP:
        if re.search(pattern, haystack, flags=re.IGNORECASE):
            return os_name, status, detail

    return None, None, None


async def scan_one(ip, timeout, os_detect):
    text = await run_nmap(ip, timeout, os_detect)
    ports = extract_open_ports(text)
    os_strings = extract_os_strings(text)
    os_name, status, detail = classify(os_strings)
    if not status:
        return None
    if os_strings and os_name not in " | ".join(os_strings):
        os_display = f"{os_name} ({os_strings[0]})"
    else:
        os_display = os_strings[0] if os_strings else os_name
    return {
        "ip": ip,
        "ports": ports,
        "os": os_display,
        "status": status,
        "detail": detail,
    }


async def run_all(targets, workers, timeout, os_detect):
    queue = asyncio.Queue()
    results = []
    completed = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed
        while True:
            ip = await queue.get()
            try:
                row = await scan_one(ip, timeout, os_detect)
                if row:
                    results.append(row)
                completed += 1
                sys.stdout.write(
                    f"\rScanning Windows OS: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Unsupported: {len(results)} | Current: {ip}".ljust(120)
                )
                sys.stdout.flush()
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    sys.stdout.write("\n")
    return results


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No unsupported Windows OS fingerprints found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["ports"], 12),
            cell(row["os"], 38),
            cell(row["status"], 14),
            cell(row["detail"], 80),
        ])
        print(paint(line, RED if row["status"] == "POTENTIAL EOL" else YELLOW, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "ports", "os", "status", "detail"])
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(description="Print only unsupported Windows OS fingerprints.")
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="Input file containing IPs, CIDRs, or ip:port entries")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="nmap host timeout in seconds")
    parser.add_argument("--os-detect", action="store_true", help="Add nmap -O --osscan-guess fingerprinting. Run with sudo/root for best results")
    parser.add_argument("--csv", default="unsupported_windows.csv", help="CSV output path")
    parser.add_argument("--list", default="unsupported_windows_ips.txt", help="Unsupported IP list output path")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found in PATH. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Nmap scripts   : smb-os-discovery,rdp-ntlm-info")
    print(f"OS detection   : {'enabled (-O --osscan-guess)' if args.os_detect else 'disabled'}")
    print("Showing        : unsupported Windows fingerprints only")

    rows = asyncio.run(run_all(targets, workers, args.timeout, args.os_detect))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Unsupported found : {len(rows)}")
    print(f"CSV written       : {args.csv}")
    print(f"IP list written   : {args.list}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

