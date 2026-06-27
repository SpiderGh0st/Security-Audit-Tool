#!/usr/bin/env python3
"""
gSOAP vulnerable version checker.

Checks HTTP/HTTPS service banners and response bodies for gSOAP versions, then
flags versions affected by CVE-2017-9765 ("Devil's Ivy"):
  - gSOAP 2.7.x
  - gSOAP 2.8.x before 2.8.48

Examples:
  python3 GsoapVersionChecker.py 198.51.100.82
  python3 GsoapVersionChecker.py 198.51.100.0/24 -p 80,631,3910,3911,8080,8289,8295,53048
  python3 GsoapVersionChecker.py -f gsoap_open_ips.txt --csv gsoap_results.csv
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import socket
import ssl
from pathlib import Path


DEFAULT_PORTS = "80,443,631,3910,3911,8080,8289,8295,53048"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 7),
    ("PROTO", 6),
    ("VERSION", 12),
    ("STATUS", 14),
    ("DETAIL", 76),
]


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
            seen.add(target)
            unique.append(target)
    if not unique:
        raise SystemExit("No targets supplied. Provide an IP/CIDR or use -f targets.txt")
    return unique


def parse_ports(value):
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = [int(x) for x in part.split("-", 1)]
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def ip_sort(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return value


async def grab(ip, port, proto, timeout):
    return await asyncio.to_thread(grab_sync, ip, port, proto, timeout)


def grab_sync(ip, port, proto, timeout):
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: gsoap-version-checker/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    sock = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        if proto == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.sendall(req)
        chunks = []
        total = 0
        while total < 8192:
            data = sock.recv(min(4096, 8192 - total))
            if not data:
                break
            chunks.append(data)
            total += len(data)
        return b"".join(chunks).decode("latin-1", errors="replace")
    except Exception:
        return ""
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def extract_gsoap(text):
    if not text:
        return None
    match = re.search(r"gSOAP\s*/\s*([0-9]+(?:\.[0-9]+){1,3})", text, re.I)
    if match:
        return match.group(1)
    if re.search(r"\bgSOAP\b", text, re.I):
        return "unknown"
    return None


def version_tuple(version):
    return tuple(int(x) for x in re.findall(r"\d+", version))


def classify(version):
    if not version:
        return "NOT DETECTED", "No gSOAP banner detected."
    if version == "unknown":
        return "UNKNOWN", "gSOAP detected, but version was not disclosed."

    nums = version_tuple(version)
    if len(nums) < 2:
        return "UNKNOWN", "gSOAP version format was not recognized."

    major, minor = nums[0], nums[1]
    if major == 2 and minor == 7:
        return "CVE CANDIDATE", "Version falls in the CVE-2017-9765 affected range; confirm vendor firmware and patch backports."
    if major == 2 and minor == 8 and nums < (2, 8, 48):
        return "CVE CANDIDATE", "Version falls in the CVE-2017-9765 affected range; confirm vendor firmware and patch backports."
    if major == 2 and minor == 8 and nums >= (2, 8, 48):
        return "NOT VULN", "gSOAP 2.8.48 or newer is not affected by CVE-2017-9765."
    return "REVIEW", "Version detected; verify against vendor firmware advisories."


async def check_one(ip, port, timeout):
    # Try likely protocol first by port, then fallback.
    protos = ["https", "http"] if port in (443, 8443) else ["http", "https"]
    for proto in protos:
        text = await grab(ip, port, proto, timeout)
        version = extract_gsoap(text)
        if version:
            status, detail = classify(version)
            return {
                "ip": ip,
                "port": port,
                "proto": proto,
                "version": version,
                "status": status,
                "detail": detail,
            }
    return {
        "ip": ip,
        "port": port,
        "proto": "-",
        "version": "-",
        "status": "NOT DETECTED",
        "detail": "No gSOAP banner detected on this port.",
    }


async def run_all(targets, ports, workers, timeout):
    queue = asyncio.Queue()
    results = []
    for ip in targets:
        for port in ports:
            await queue.put((ip, port))

    async def worker():
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            ip, port = item
            row = await check_one(ip, port, timeout)
            if row["status"] != "NOT DETECTED":
                print(f"[+] {ip}:{port} {row['proto']} gSOAP/{row['version']} {row['status']}")
            results.append(row)
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(max(1, workers))]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    return results


def print_table(rows, show_all):
    shown = [r for r in rows if show_all or r["status"] != "NOT DETECTED"]
    print()
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    if not shown:
        print("No gSOAP services were detected.")
        return
    for row in sorted(shown, key=lambda r: (ip_sort(r["ip"]), int(r["port"]))):
        print(
            " ".join(
                [
                    cell(row["ip"], 16),
                    cell(row["port"], 7),
                    cell(row["proto"], 6),
                    cell(row["version"], 12),
                    cell(row["status"], 14),
                    cell(row["detail"], 76),
                ]
            )
        )


def write_csv(path, rows, show_all):
    data = [r for r in rows if show_all or r["status"] != "NOT DETECTED"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "port", "proto", "version", "status", "detail"])
        writer.writeheader()
        for row in sorted(data, key=lambda r: (ip_sort(r["ip"]), int(r["port"]))):
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Check gSOAP banners for vulnerable versions.")
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR subnet")
    parser.add_argument("-f", "--file", help="Text file containing IPs, hostnames, or CIDR subnets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports to check, e.g. 80,631,3910-3911")
    parser.add_argument("-w", "--workers", type=int, default=64, help="Concurrent checks")
    parser.add_argument("-t", "--timeout", type=float, default=4.0, help="Timeout per connection in seconds")
    parser.add_argument("--csv", default="gsoap_version_results.csv", help="CSV output path")
    parser.add_argument("--show-all", action="store_true", help="Show ports where gSOAP was not detected")
    args = parser.parse_args()

    targets = load_targets(args)
    ports = parse_ports(args.ports)
    workers = min(max(1, args.workers), max(1, len(targets) * len(ports)))

    print(f"Loaded targets : {len(targets)}")
    print(f"Ports          : {','.join(str(p) for p in ports)}")
    print(f"Workers        : {workers}")
    print("Vuln rule      : gSOAP 2.7.x or 2.8.x before 2.8.48 => CVE-2017-9765")

    rows = asyncio.run(run_all(targets, ports, workers, args.timeout))
    print_table(rows, args.show_all)
    write_csv(args.csv, rows, args.show_all)

    detected = [r for r in rows if r["status"] != "NOT DETECTED"]
    vulnerable = [r for r in rows if r["status"] == "CVE CANDIDATE"]
    print()
    print(f"gSOAP services detected : {len(detected)}")
    print(f"Vulnerable services     : {len(vulnerable)}")
    print(f"CSV written             : {args.csv}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

