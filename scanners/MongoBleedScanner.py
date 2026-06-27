#!/usr/bin/env python3
"""
Find MongoDB servers running versions affected by MongoBleed
(CVE-2025-14847).

The scanner uses Nmap for service discovery and a normal, read-only MongoDB
buildInfo command to obtain the server version. It does not send malformed
compressed messages and does not attempt to disclose heap memory.

Affected MongoDB Server versions:
  - 3.6.x, 4.0.x and 4.2.x
  - 4.4.x before 4.4.30
  - 5.0.x before 5.0.32
  - 6.0.x before 6.0.27
  - 7.0.x before 7.0.28
  - 8.0.x before 8.0.17
  - 8.2.x before 8.2.3

Requirements:
    sudo apt install nmap

Examples:
    python3 MongoBleedScanner.py -f target_ips.txt
    python3 MongoBleedScanner.py 192.0.2.0/24 --show-all
    python3 MongoBleedScanner.py -f target_ips.txt --all-ports

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import socket
import ssl
import struct
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

CVE = "CVE-2025-14847"
DEFAULT_PORTS = "27017-27020,27080,27046,28017"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("MONGODB VERSION", 18),
    ("AUTH", 13),
    ("STATUS", 20),
    ("CVE", 16),
]

FIXED_RELEASES = {
    (4, 4): (4, 4, 30),
    (5, 0): (5, 0, 32),
    (6, 0): (6, 0, 27),
    (7, 0): (7, 0, 28),
    (8, 0): (8, 0, 17),
    (8, 2): (8, 2, 3),
}

FULLY_AFFECTED_BRANCHES = {
    (3, 6),
    (4, 0),
    (4, 2),
}


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
    return ",".join(str(port) for port in valid)


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


def version_tuple(value):
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(value or ""))
    if not match:
        return ()
    return tuple(int(part or 0) for part in match.groups())


def classify_version(version):
    numeric = version_tuple(version)
    if not numeric:
        return "VERSION UNKNOWN"

    branch = numeric[:2]
    if branch in FULLY_AFFECTED_BRANCHES:
        return "CVE CANDIDATE"
    if branch in FIXED_RELEASES:
        return (
            "CVE CANDIDATE"
            if numeric < FIXED_RELEASES[branch]
            else "NOT AFFECTED"
        )

    # The vendor advisory does not list other release branches. Avoid
    # extrapolating vulnerability status from an unlisted development branch.
    if numeric < (3, 6, 0):
        return "NOT LISTED"
    if numeric >= (8, 3, 0):
        return "NOT AFFECTED"
    return "NOT LISTED"


async def run_command(command):
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


async def discover_host(ip, ports, args):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "--host-timeout", args.host_timeout,
    ]
    if args.all_ports:
        command.extend(["-p-", "--min-rate", str(args.min_rate)])
    else:
        command.extend(["-p", ports])
    command.extend(["-oX", "-", ip])
    return parse_nmap(await run_command(command))


def service_text(service):
    if service is None:
        return ""
    return " ".join(
        value for value in (
            service.attrib.get("name", ""),
            service.attrib.get("product", ""),
            service.attrib.get("version", ""),
            service.attrib.get("extrainfo", ""),
            service.attrib.get("servicefp", ""),
        )
        if value
    )


def extract_nmap_version(text):
    patterns = (
        r"\bMongoDB(?:\s+Server)?\s*(?:version\s*)?(\d+\.\d+(?:\.\d+)?)",
        r"\bMongoDB[/_-](\d+\.\d+(?:\.\d+)?)",
        r"\bversion\s*[:=]\s*[\"']?(\d+\.\d+(?:\.\d+)?)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1)
    return ""


def parse_nmap(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    endpoints = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        service = port_node.find("service")
        text = service_text(service)
        name = service.attrib.get("name", "").lower() if service is not None else ""
        is_mongodb = (
            "mongodb" in text.lower()
            or name in {"mongodb", "mongod", "mongos"}
            or port in {27017, 27018, 27019, 27020, 27080, 28017}
        )
        if is_mongodb:
            endpoints.append({
                "port": port,
                "version": extract_nmap_version(text),
                "service": text or "MongoDB candidate",
                "tls_hint": bool(
                    service is not None
                    and service.attrib.get("tunnel", "").lower() in {"ssl", "tls"}
                ),
            })
    return endpoints


def bson_cstring(value):
    return value.encode("utf-8") + b"\x00"


def bson_document(values):
    elements = []
    for key, value in values.items():
        if isinstance(value, bool):
            elements.append(b"\x08" + bson_cstring(key) + (b"\x01" if value else b"\x00"))
        elif isinstance(value, int):
            elements.append(b"\x10" + bson_cstring(key) + struct.pack("<i", value))
        elif isinstance(value, str):
            raw = value.encode("utf-8") + b"\x00"
            elements.append(
                b"\x02" + bson_cstring(key) + struct.pack("<i", len(raw)) + raw
            )
        else:
            raise ValueError(f"Unsupported BSON value for {key}")
    payload = b"".join(elements) + b"\x00"
    return struct.pack("<i", len(payload) + 4) + payload


def build_info_message(request_id=1):
    document = bson_document({"buildInfo": 1, "$db": "admin"})
    body = struct.pack("<i", 0) + b"\x00" + document
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def receive_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("MongoDB closed the connection.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(sock, max_size=16 * 1024 * 1024):
    header = receive_exact(sock, 16)
    length, _, _, opcode = struct.unpack("<iiii", header)
    if length < 16 or length > max_size:
        raise ValueError("Invalid MongoDB response length.")
    return opcode, receive_exact(sock, length - 16)


def extract_bson_string(data, key):
    marker = b"\x02" + key.encode("utf-8") + b"\x00"
    position = data.find(marker)
    if position < 0:
        return ""
    length_pos = position + len(marker)
    if length_pos + 4 > len(data):
        return ""
    length = struct.unpack("<i", data[length_pos:length_pos + 4])[0]
    start = length_pos + 4
    end = start + max(0, length - 1)
    if length <= 1 or end > len(data):
        return ""
    return data[start:end].decode("utf-8", errors="ignore")


def response_text(data):
    return data.replace(b"\x00", b" ").decode("utf-8", errors="ignore")


def probe_build_info(ip, port, timeout, use_tls=False):
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if use_tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
            sock.settimeout(timeout)
        sock.sendall(build_info_message())
        opcode, data = receive_message(sock)
        text = response_text(data)
        version = extract_bson_string(data, "version")
        if version:
            return version, "NO AUTH", f"MongoDB buildInfo returned via opcode {opcode}."
        if re.search(
            r"(?:not authorized|requires authentication|unauthorized|authentication failed)",
            text,
            re.I,
        ):
            return "", "REQUIRED", "MongoDB rejected unauthenticated buildInfo."
        return "", "UNKNOWN", "MongoDB responded, but did not disclose an exact version."
    finally:
        try:
            sock.close()
        except OSError:
            pass


async def async_probe_build_info(ip, endpoint, timeout):
    attempts = [endpoint["tls_hint"]]
    if not endpoint["tls_hint"]:
        attempts.append(True)
    last_error = ""
    for use_tls in dict.fromkeys(attempts):
        try:
            version, auth, detail = await asyncio.to_thread(
                probe_build_info, ip, endpoint["port"], timeout, use_tls
            )
            if version or auth in {"NO AUTH", "REQUIRED"}:
                return version, auth, detail
        except (
            OSError,
            TimeoutError,
            ssl.SSLError,
            ConnectionError,
            ValueError,
            struct.error,
        ) as error:
            last_error = f"{type(error).__name__}: {error}"
    return "", "UNKNOWN", last_error or "No usable MongoDB protocol response."


async def scan_host(ip, ports, args):
    endpoints = await discover_host(ip, ports, args)
    rows = []
    for endpoint in endpoints:
        version, auth, detail = await async_probe_build_info(
            ip, endpoint, args.probe_timeout
        )
        version = version or endpoint["version"]
        status = classify_version(version)
        rows.append({
            "ip": ip,
            "port": endpoint["port"],
            "protocol": "MongoDB/TCP",
            "version": version,
            "auth": auth,
            "status": status,
            "cve": CVE,
            "service": endpoint["service"],
            "detail": detail,
        })
    return rows


async def run_all(targets, ports, args):
    queue = asyncio.Queue()
    rows = []
    found = 0
    completed = 0
    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, found
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                try:
                    findings = await scan_host(ip, ports, args)
                    found += len(findings)
                    rows.extend(
                        row for row in findings
                        if args.show_all or row["status"] == "CVE CANDIDATE"
                    )
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    row["status"] == "CVE CANDIDATE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning MongoBleed: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"MongoDB: {found} | Vulnerable: {vulnerable} | "
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
    return rows, found


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No MongoDB servers with versions affected by MongoBleed were found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 10),
            cell(row["protocol"], 12),
            cell(row["version"] or "UNKNOWN", 18),
            cell(row["auth"], 13),
            cell(row["status"], 20),
            cell(row["cve"], 16),
        ])
        code = RED if row["status"] == "CVE CANDIDATE" else (
            GREEN if row["status"] == "NOT AFFECTED" else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "version", "auth", "status",
        "cve", "service", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            writer.writerow({field: row.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            if row["status"] == "CVE CANDIDATE":
                handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find MongoDB versions affected by MongoBleed (CVE-2025-14847)."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="MongoDB TCP ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Discover MongoDB on all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="60s", help="Nmap timeout per host")
    parser.add_argument("--probe-timeout", type=float, default=5.0, help="MongoDB buildInfo timeout")
    parser.add_argument("--show-all", action="store_true", help="Show fixed and inconclusive MongoDB endpoints")
    parser.add_argument("--csv", default="mongobleed_results.csv", help="CSV output")
    parser.add_argument("--list", default="mongobleed_vulnerable_endpoints.txt", help="Vulnerable IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"MongoDB ports  : {'all TCP ports' if args.all_ports else ports}")
    print(f"Vulnerability  : MongoBleed / {CVE}")
    print("Verification   : exact MongoDB version compared with vendor-affected ranges")
    print("Probe          : normal read-only buildInfo; no malformed packets or memory retrieval")
    print(f"Showing        : {'all detected MongoDB endpoints' if args.show_all else 'affected versions only'}")

    rows, found = asyncio.run(run_all(targets, ports, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(row["status"] == "CVE CANDIDATE" for row in rows)
    print()
    print(f"MongoDB endpoints found : {found}")
    print(f"CVE version candidates  : {vulnerable}")
    print(f"CSV written             : {args.csv}")
    print(f"Endpoint list           : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

