#!/usr/bin/env python3
"""
Scan RDP endpoints for BlueKeep (CVE-2019-0708) using rdpscan.

Examples:
    python3 BlueKeepStatusScanner.py 192.0.2.23 192.0.2.11
    python3 BlueKeepStatusScanner.py -f target_ips.txt
    python3 BlueKeepStatusScanner.py 192.0.2.23:3389

The report includes vulnerable, safe, closed, unknown, and error results.
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
YELLOW = "\033[93m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("BLUEKEEP", 14),
    ("DETAIL", 62),
]


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text[:width].ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


def expand_target(value, default_port):
    value = value.strip().rstrip("\\").strip()
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
        return []


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
        raise SystemExit("No valid targets supplied.")
    return unique


async def tcp_open(ip, port, timeout):
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def run_rdpscan(binary, ip, port, timeout):
    # The common hdmoore/rdpscan build expects a plain IP and always uses
    # TCP/3389. Passing IP:3389 makes it attempt DNS resolution of that string.
    if port == 3389:
        commands = [[binary, ip]]
    else:
        commands = [
            [binary, "--port", str(port), ip],
            [binary, "-p", str(port), ip],
        ]

    last_output = ""
    for command in commands:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            return "UNKNOWN", "rdpscan timed out"
        except OSError as error:
            return "ERROR", str(error)

        output = (
            stdout.decode("utf-8", errors="ignore")
            + "\n"
            + stderr.decode("utf-8", errors="ignore")
        ).strip()
        last_output = output

        # Retry only when this rdpscan build rejected the command syntax.
        if re.search(
            r"unknown option|usage:|invalid option|unrecognized option",
            output,
            re.I,
        ):
            continue
        return classify_output(output)

    return "ERROR", compact_detail(last_output) or "Unsupported rdpscan command syntax"


def compact_detail(output):
    lines = []
    for line in output.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if line:
            lines.append(line)
    return re.sub(r"\s+", " ", " ".join(lines))[:300]


def classify_output(output):
    clean = compact_detail(output)
    lower = clean.lower()

    if re.search(r"\bvulnerable\b|got appid", lower):
        detail = "BlueKeep vulnerable"
        if "got appid" in lower:
            detail += " - got appid"
        return "VULNERABLE", detail

    if re.search(r"\bsafe\b|appears patched|not vulnerable|patched", lower):
        return "SAFE", "Target appears patched"

    if re.search(r"connection refused|closed|no route|unreachable", lower):
        return "CLOSED", clean or "RDP port is closed or unreachable"

    if re.search(r"timeout|no response|unknown|error|failed", lower):
        return "UNKNOWN", clean or "No conclusive BlueKeep response"

    return "UNKNOWN", clean or "rdpscan returned no conclusive result"


async def scan_one(binary, ip, port, connect_timeout, scan_timeout):
    if not await tcp_open(ip, port, connect_timeout):
        return {
            "ip": ip,
            "port": port,
            "protocol": "TCP/RDP",
            "status": "CLOSED",
            "detail": "RDP port is closed, filtered, or unreachable",
        }

    status, detail = await run_rdpscan(binary, ip, port, scan_timeout)
    return {
        "ip": ip,
        "port": port,
        "protocol": "TCP/RDP",
        "status": status,
        "detail": detail,
    }


async def run_all(targets, args):
    queue = asyncio.Queue()
    rows = []
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
                try:
                    rows.append(
                        await scan_one(
                            args.rdpscan,
                            ip,
                            port,
                            args.connect_timeout,
                            args.scan_timeout,
                        )
                    )
                except Exception as error:
                    rows.append({
                        "ip": ip,
                        "port": port,
                        "protocol": "TCP/RDP",
                        "status": "ERROR",
                        "detail": f"{type(error).__name__}: {error}",
                    })

                completed += 1
                vulnerable = sum(
                    1 for row in rows if row["status"] == "VULNERABLE"
                )
                sys.stdout.write(
                    f"\rScanning BlueKeep: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Vulnerable: {vulnerable} | Current: {ip}:{port}".ljust(125)
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
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(
        rows,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
    ):
        line = " ".join([
            cell(row["ip"], 18),
            cell(f"{row['port']}/TCP", 10),
            cell(row["protocol"], 12),
            cell(row["status"], 14),
            cell(row["detail"], 62),
        ])
        code = {
            "VULNERABLE": RED,
            "SAFE": GREEN,
            "CLOSED": YELLOW,
            "UNKNOWN": YELLOW,
            "ERROR": YELLOW,
        }.get(row["status"], YELLOW)
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = ["ip", "port", "protocol", "status", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            writer.writerow(row)


def write_lists(prefix, rows):
    groups = {
        "vulnerable": "VULNERABLE",
        "safe": "SAFE",
        "unknown": "UNKNOWN",
        "closed": "CLOSED",
    }
    for suffix, status in groups.items():
        selected = [row for row in rows if row["status"] == status]
        with open(f"{prefix}_{suffix}.txt", "w", encoding="utf-8") as handle:
            for row in sorted(
                selected,
                key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
            ):
                handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Show BlueKeep status for every RDP endpoint."
    )
    parser.add_argument("targets", nargs="*", help="IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Default RDP port")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("--connect-timeout", type=int, default=3, help="TCP connection timeout")
    parser.add_argument("--scan-timeout", type=int, default=30, help="rdpscan timeout")
    parser.add_argument(
        "--rdpscan",
        default=shutil.which("rdpscan") or "rdpscan",
        help="Path to rdpscan binary",
    )
    parser.add_argument("--csv", default="bluekeep_status.csv", help="CSV output")
    parser.add_argument("--list-prefix", default="bluekeep", help="Output list prefix")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which(args.rdpscan) and not shutil.which("rdpscan"):
        raise SystemExit(
            "rdpscan was not found. Copy it to /usr/local/bin or use "
            "--rdpscan /full/path/to/rdpscan"
        )

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"Default port   : {args.port}/TCP")
    print(f"Scanner        : {args.rdpscan}")
    print("Protocol       : RDP")

    rows = asyncio.run(run_all(targets, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_lists(args.list_prefix, rows)

    counts = {
        status: sum(1 for row in rows if row["status"] == status)
        for status in ("VULNERABLE", "SAFE", "CLOSED", "UNKNOWN", "ERROR")
    }
    print()
    for status, count in counts.items():
        print(f"{status.title():<10}: {count}")
    print(f"CSV written: {args.csv}")
    return 1 if counts["VULNERABLE"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

