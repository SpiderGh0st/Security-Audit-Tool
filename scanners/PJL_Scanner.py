#!/usr/bin/env python3
"""
Find unauthenticated, read-only PJL access on HP printers.

The scanner sends only:
    Universal Exit Language (UEL)
    @PJL INFO ID
    UEL

It does NOT send print data, ENTER LANGUAGE, filesystem commands, configuration
changes, resets, or PJL job commands.

Examples:
    python3 HpUnauthenticatedPjlScanner.py -f target_ips.txt
    python3 HpUnauthenticatedPjlScanner.py 192.0.2.0/24
    python3 HpUnauthenticatedPjlScanner.py -f target_ips.txt -p 9100-9103

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import sys


RED = "\033[91m"
RESET = "\033[0m"

DEFAULT_PORTS = "9100-9103"
UEL = b"\x1b%-12345X"
PJL_INFO_ID = UEL + b"@PJL INFO ID\r\n" + UEL

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTOCOL", 13),
    ("PRODUCT", 38),
    ("PJL ACCESS", 14),
    ("STATUS", 14),
    ("DETAIL", 58),
]

HP_MARKERS = (
    "hewlett-packard",
    "hewlett packard",
    "hp laserjet",
    "hp color laserjet",
    "hp officejet",
    "hp pagewide",
    "hp designjet",
    "hp photosmart",
    "laserjet",
)


def paint(text, enabled=True):
    return f"{RED}{text}{RESET}" if enabled else text


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


def normalize_ports(value):
    ports = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start, end = item.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(item))
    valid = sorted(port for port in ports if 1 <= port <= 65535)
    if not valid:
        raise SystemExit("No valid TCP ports supplied.")
    return valid


def ports_label(ports):
    return ",".join(str(port) for port in ports)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    value = re.sub(r":\d+(?:/tcp)?$", "", value, flags=re.I)
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


def clean_response(data):
    text = data.decode("latin-1", errors="replace")
    text = text.replace("\x1b%-12345X", " ")
    text = text.replace("\x00", " ")
    return re.sub(r"\s+", " ", text).strip()


def extract_product(response):
    text = response.strip()
    text = re.sub(r"^@PJL\s+INFO\s+ID\s*[\r\n:=-]*", "", text, flags=re.I)
    quoted = re.search(r'"([^"]{2,200})"', text)
    if quoted:
        return quoted.group(1).strip()
    text = re.sub(r"^@PJL\s*", "", text, flags=re.I)
    return text[:200].strip(" :-")


def is_pjl_response(response):
    lower = response.lower()
    return (
        "@pjl" in lower
        or "info id" in lower
        or any(marker in lower for marker in HP_MARKERS)
    )


def is_hp_product(product, response):
    evidence = f"{product} {response}".lower()
    return any(marker in evidence for marker in HP_MARKERS)


async def probe_pjl(ip, port, connect_timeout, read_timeout):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=connect_timeout,
        )
        writer.write(PJL_INFO_ID)
        await writer.drain()

        chunks = []
        total = 0
        deadline = asyncio.get_running_loop().time() + read_timeout
        while total < 16384:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(min(4096, 16384 - total)),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            combined = b"".join(chunks)
            if b"@PJL" in combined.upper() and (
                b"\r\n" in combined or UEL in combined
            ):
                await asyncio.sleep(0.05)
                break

        response = clean_response(b"".join(chunks))
        if not response or not is_pjl_response(response):
            return None

        product = extract_product(response)
        if not is_hp_product(product, response):
            return None

        return {
            "ip": ip,
            "port": f"{port}/TCP",
            "protocol": "JetDirect/PJL",
            "product": product or "HP printer",
            "pjl_access": "ACCEPTED",
            "status": "VULNERABLE",
            "detail": "Unauthenticated read-only @PJL INFO ID command returned device information.",
            "evidence": response,
        }
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass


async def scan_host(ip, ports, connect_timeout, read_timeout):
    results = await asyncio.gather(
        *(
            probe_pjl(ip, port, connect_timeout, read_timeout)
            for port in ports
        )
    )
    return [result for result in results if result is not None]


async def run_all(targets, ports, workers, connect_timeout, read_timeout):
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
                rows.extend(
                    await scan_host(
                        ip,
                        ports,
                        connect_timeout,
                        read_timeout,
                    )
                )
                completed += 1
                sys.stdout.write(
                    f"\rScanning PJL: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Vulnerable: {len(rows)} | Current: {ip}".ljust(125)
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
    return rows


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No HP printers with confirmed unauthenticated PJL access were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        rows,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 10),
            cell(row["protocol"], 13),
            cell(row["product"], 38),
            cell(row["pjl_access"], 14),
            cell(row["status"], 14),
            cell(row["detail"], 58),
        ])
        print(paint(line, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "protocol",
        "product",
        "pjl_access",
        "status",
        "detail",
        "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
        ))


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted({row["ip"] for row in rows}, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find unauthenticated read-only PJL access on HP printers."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Raw printer TCP ports. Default: {DEFAULT_PORTS}",
    )
    parser.add_argument("-w", "--workers", type=int, default=32, help="Concurrent host workers")
    parser.add_argument("--connect-timeout", type=float, default=2.0, help="TCP connection timeout")
    parser.add_argument("--read-timeout", type=float, default=3.0, help="PJL response timeout")
    parser.add_argument("--csv", default="hp_unauthenticated_pjl.csv", help="CSV output path")
    parser.add_argument("--list", default="hp_unauthenticated_pjl_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Probe ports    : {ports_label(ports)}/TCP")
    print("PJL command    : @PJL INFO ID (read-only)")
    print("Print data     : never sent")
    print("Showing        : confirmed unauthenticated PJL access on HP printers only")

    rows = asyncio.run(
        run_all(
            targets,
            ports,
            workers,
            max(0.5, args.connect_timeout),
            max(0.5, args.read_timeout),
        )
    )
    print_table(rows, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Vulnerable endpoints : {len(rows)}")
    print(f"Vulnerable hosts     : {len({row['ip'] for row in rows})}")
    print(f"CSV written          : {args.csv}")
    print(f"IP list written      : {args.list}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

