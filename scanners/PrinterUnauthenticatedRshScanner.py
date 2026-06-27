#!/usr/bin/env python3
"""
Find printer RSH services that disclose status or log information without
credentials.

The scanner:
  1. Finds TCP/514 (RSH) with Nmap.
  2. Opens a standard RSH session from a privileged source port.
  3. Runs only short read-only printer commands: status, lpq and log.
  4. Marks VULNERABLE only when meaningful status/log output is returned.

It does not submit jobs, cancel jobs, modify settings, upload files, or run
arbitrary user-supplied commands.

Requirements:
    sudo apt install nmap

Examples:
    sudo python3 PrinterUnauthenticatedRshScanner.py -f target_ips.txt
    sudo python3 PrinterUnauthenticatedRshScanner.py 192.0.2.0/24
    sudo python3 PrinterUnauthenticatedRshScanner.py -f target_ips.txt --show-all

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import os
import re
import shutil
import socket
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

RSH_PORT = 514
READ_ONLY_COMMANDS = ("status", "lpq", "log")

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("SERVICE", 28),
    ("COMMANDS", 20),
    ("DISCLOSURE", 20),
    ("STATUS", 16),
]

DENIED_PATTERNS = re.compile(
    r"(?:"
    r"permission denied|access denied|authentication failed|"
    r"login incorrect|not authorized|authorization failed|"
    r"unknown user|invalid user|connection refused|"
    r"command not found|unknown command|invalid command|"
    r"not recognized|usage:"
    r")",
    re.I,
)

STATUS_PATTERNS = re.compile(
    r"(?:"
    r"\bready\b|\bidle\b|\bprinting\b|\boffline\b|\bonline\b|"
    r"\bpaper\b|\btoner\b|\bink\b|\bqueue\b|\bjob\b|\bprinter\b|"
    r"\bstatus\b|\buptime\b|\bpages?\b|\berror\b|\bwarning\b"
    r")",
    re.I,
)

LOG_PATTERNS = re.compile(
    r"(?:"
    r"\blog\b|\bevent\b|\bhistory\b|\btimestamp\b|"
    r"\b(?:mon|tue|wed|thu|fri|sat|sun)\b|"
    r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b|"
    r"\b\d{1,2}:\d{2}:\d{2}\b"
    r")",
    re.I,
)


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
    value = re.sub(r":514(?:/tcp)?$", "", value, flags=re.I)
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
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "-p", str(RSH_PORT),
        "--host-timeout", f"{timeout}s",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_nmap(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    port_node = root.find(".//port[@protocol='tcp'][@portid='514']")
    if port_node is None:
        return None
    state = port_node.find("state")
    if state is None or state.attrib.get("state") != "open":
        return None
    service = port_node.find("service")
    parts = []
    if service is not None:
        parts = [
            service.attrib.get("name", ""),
            service.attrib.get("product", ""),
            service.attrib.get("version", ""),
            service.attrib.get("extrainfo", ""),
        ]
    return " ".join(part for part in parts if part) or "rsh"


def bind_privileged_source(sock):
    last_error = None
    for source_port in range(1023, 511, -1):
        try:
            sock.bind(("", source_port))
            return source_port
        except OSError as error:
            last_error = error
    raise OSError(f"Could not bind a privileged RSH source port: {last_error}")


def receive_limited(sock, max_bytes, timeout):
    chunks = []
    total = 0
    sock.settimeout(timeout)
    while total < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def rsh_read_only(ip, command, username, timeout, max_bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        bind_privileged_source(sock)
        sock.connect((ip, RSH_PORT))

        # Standard RSH request: no secondary stderr channel, local user,
        # remote user, command. No password field exists in this protocol.
        request = (
            b"0\x00"
            + username.encode("ascii", errors="ignore") + b"\x00"
            + username.encode("ascii", errors="ignore") + b"\x00"
            + command.encode("ascii") + b"\x00"
        )
        sock.sendall(request)
        first = sock.recv(1)
        output = receive_limited(sock, max_bytes, timeout)
        text = output.decode("utf-8", errors="ignore").replace("\x00", "")
        if first and first != b"\x00":
            text = first.decode("utf-8", errors="ignore") + text
            return False, text.strip(), "REJECTED"
        return True, text.strip(), "ACCEPTED"
    finally:
        sock.close()


def meaningful_output(command, text):
    clean = re.sub(r"\s+", " ", text).strip()
    if len(clean) < 4 or DENIED_PATTERNS.search(clean):
        return False, ""
    if command in {"status", "lpq"} and STATUS_PATTERNS.search(clean):
        return True, "PRINTER STATUS"
    if command == "log" and (
        LOG_PATTERNS.search(clean) or STATUS_PATTERNS.search(clean)
    ):
        return True, "STATUS / LOG"
    # Some embedded print servers return terse proprietary records. Require
    # multiple tokens to avoid treating an echo or generic success byte as
    # disclosed information.
    if len(clean.split()) >= 3 and len(clean) >= 16:
        return True, "PRINTER DATA"
    return False, ""


async def test_commands(ip, args):
    accepted = []
    disclosures = []
    evidence = []
    errors = []

    for command in READ_ONLY_COMMANDS[:args.max_commands]:
        try:
            success, output, result = await asyncio.to_thread(
                rsh_read_only,
                ip,
                command,
                args.user,
                args.rsh_timeout,
                args.max_bytes,
            )
        except (OSError, TimeoutError, socket.error) as error:
            errors.append(f"{command}: {type(error).__name__}: {error}")
            continue

        if success:
            accepted.append(command)
        disclosed, disclosure = meaningful_output(command, output)
        if disclosed:
            disclosures.append(disclosure)
            evidence.append(f"{command}: {output[:500]}")
        elif output:
            errors.append(f"{command} {result}: {output[:200]}")

    if disclosures:
        status = "VULNERABLE"
    elif accepted:
        status = "INCONCLUSIVE"
    else:
        status = "PROTECTED"

    return {
        "commands": accepted,
        "disclosures": sorted(set(disclosures)),
        "status": status,
        "evidence": " | ".join(evidence),
        "detail": " | ".join(errors),
    }


async def scan_host(ip, args):
    service = parse_nmap(await run_nmap(ip, args.nmap_timeout))
    if not service:
        return None
    result = await test_commands(ip, args)
    result.update({
        "ip": ip,
        "port": RSH_PORT,
        "protocol": "RSH/TCP",
        "service": service,
    })
    return result


async def run_all(targets, args):
    queue = asyncio.Queue()
    rows = []
    open_count = 0
    completed = 0
    rsh_lock = asyncio.Semaphore(args.rsh_workers)
    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, open_count
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                try:
                    # Privileged source ports are finite; keep active RSH
                    # sessions deliberately low.
                    async with rsh_lock:
                        result = await scan_host(ip, args)
                    if result:
                        open_count += 1
                        if args.show_all or result["status"] == "VULNERABLE":
                            rows.append(result)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning printer RSH: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"RSH open: {open_count} | Vulnerable: {vulnerable} | "
                    f"Current: {ip}".ljust(135)
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
    return rows, open_count


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No printer RSH status/log disclosure was confirmed.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell("514/TCP", 10),
            cell(row["protocol"], 12),
            cell(row["service"], 28),
            cell(",".join(row["commands"]) or "-", 20),
            cell(",".join(row["disclosures"]) or "-", 20),
            cell(row["status"], 16),
        ])
        code = RED if row["status"] == "VULNERABLE" else (
            GREEN if row["status"] == "PROTECTED" else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "service", "commands",
        "disclosures", "status", "evidence", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow({
                "ip": row["ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "service": row["service"],
                "commands": ",".join(row["commands"]),
                "disclosures": ",".join(row["disclosures"]),
                "status": row["status"],
                "evidence": row["evidence"],
                "detail": row["detail"],
            })


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            if row["status"] == "VULNERABLE":
                handle.write(f"{row['ip']}:514\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find unauthenticated printer RSH status/log disclosure."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host discovery")
    parser.add_argument("--rsh-workers", type=int, default=2, help="Concurrent RSH sessions")
    parser.add_argument("--nmap-timeout", type=int, default=25, help="Nmap timeout per host")
    parser.add_argument("--rsh-timeout", type=float, default=4.0, help="Timeout per RSH command")
    parser.add_argument("--max-commands", type=int, default=3, help="Read-only commands to try (1-3)")
    parser.add_argument("--max-bytes", type=int, default=16384, help="Maximum bytes read per command")
    parser.add_argument("--user", default="nobody", help="RSH username field; no password is sent")
    parser.add_argument("--show-all", action="store_true", help="Show protected and inconclusive RSH endpoints")
    parser.add_argument("--csv", default="printer_unauthenticated_rsh.csv", help="CSV output")
    parser.add_argument("--list", default="printer_unauthenticated_rsh_ips.txt", help="Vulnerable IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit(
            "Run with sudo because standard RSH requires a privileged source port."
        )

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))
    args.rsh_workers = max(1, min(args.rsh_workers, 8))
    args.max_commands = max(1, min(args.max_commands, len(READ_ONLY_COMMANDS)))
    args.max_bytes = max(1024, min(args.max_bytes, 65536))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", args.user):
        raise SystemExit("--user must contain only letters, numbers, dot, underscore or dash.")

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print("RSH port       : 514/TCP")
    print(f"Read-only probe: {','.join(READ_ONLY_COMMANDS[:args.max_commands])}")
    print(f"RSH user field : {args.user} (no password is sent)")
    print("Actions        : status/log queries only; no print or configuration commands")
    print(f"Showing        : {'all open RSH assessments' if args.show_all else 'confirmed disclosure only'}")

    rows, open_count = asyncio.run(run_all(targets, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(row["status"] == "VULNERABLE" for row in rows)
    print()
    print(f"RSH endpoints open : {open_count}")
    print(f"Vulnerable         : {vulnerable}")
    print(f"CSV written        : {args.csv}")
    print(f"IP list written    : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

