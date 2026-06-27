#!/usr/bin/env python3
"""
Find HTTP/HTTPS servers and report their type and version.

Detection sources:
  - Nmap service/version detection
  - http-server-header
  - http-headers
  - http-title

Requirements:
    sudo apt install nmap

Examples:
    python3 HttpServerFingerprintScanner.py -f target_ips.txt
    python3 HttpServerFingerprintScanner.py 172.16.4.0/24
    python3 HttpServerFingerprintScanner.py -f target_ips.txt -p 80,443,8080
    python3 HttpServerFingerprintScanner.py -f target_ips.txt --all-ports

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET


CYAN = "\033[96m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "80,81,443,591,631,800,1080,3000,3910,3911,5000,5001,"
    "5300,5601,5800,5985,5986,6172,6443,7001,7002,7443,"
    "8000,8008,8080,8081,8088,8090,8181,8296,8443,8444,"
    "8543,8544,8545,8834,8888,9000,9043,9080,9090,9200,"
    "9402,9403,9404,9419,9443,10000,10443,20443,33034,"
    "33035,39110,47001,53048"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTO", 7),
    ("SERVER TYPE / VERSION", 42),
    ("TITLE", 38),
    ("SOURCE", 22),
]


def paint(text, enabled=True):
    return f"{CYAN}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text[:width].ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


def normalize_ports(value):
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    valid = sorted(port for port in ports if 1 <= port <= 65535)
    if not valid:
        raise SystemExit("No valid TCP ports supplied.")
    return ",".join(str(port) for port in valid)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    if re.match(r"^[0-9.]+:\d+$", value):
        value = value.rsplit(":", 1)[0]
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


async def run_nmap(ip, ports, all_ports, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "--host-timeout",
        timeout,
        "--script-timeout",
        "90s",
        "--script",
        "http-server-header,http-headers,http-title",
    ]
    command.extend(["-p-", "--min-rate", "500"] if all_ports else ["-p", ports])
    command.extend(["-oX", "-", ip])

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return (
        stdout.decode("utf-8", errors="ignore"),
        stderr.decode("utf-8", errors="ignore"),
    )


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "").strip() if script is not None else ""


def extract_server_header(port_node):
    candidates = [
        script_output(port_node, "http-server-header"),
        script_output(port_node, "http-headers"),
    ]
    for output in candidates:
        if not output:
            continue
        match = re.search(r"(?mi)^\s*Server\s*:\s*(.+?)\s*$", output)
        if match:
            return match.group(1).strip()

        clean = re.sub(r"\s+", " ", output).strip()
        if clean and "\n" not in output and len(clean) <= 160:
            return clean
    return ""


def service_fingerprint(service):
    if service is None:
        return ""
    parts = [
        service.attrib.get("product", ""),
        service.attrib.get("version", ""),
        service.attrib.get("extrainfo", ""),
    ]
    return " ".join(part for part in parts if part).strip()


def looks_like_http(port_node, service, server_header, title):
    name = service.attrib.get("name", "").lower() if service is not None else ""
    tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
    product = service_fingerprint(service).lower()
    script_present = any(
        port_node.find(f"script[@id='{script_id}']") is not None
        for script_id in ("http-server-header", "http-headers", "http-title")
    )
    return (
        "http" in name
        or name in {"www", "http-proxy", "https"}
        or tunnel in {"ssl", "tls"} and "http" in product
        or bool(server_header)
        or bool(title)
        or script_present
    )


def parse_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    rows = []
    for host_node in root.findall("host"):
        address = host_node.find("address[@addrtype='ipv4']")
        if address is None:
            address = host_node.find("address")
        if address is None:
            continue
        ip = address.attrib.get("addr", "")

        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            service = port_node.find("service")
            server_header = extract_server_header(port_node)
            title = re.sub(r"\s+", " ", script_output(port_node, "http-title")).strip()

            if not looks_like_http(port_node, service, server_header, title):
                continue

            fingerprint = service_fingerprint(service)
            sources = []
            if server_header:
                server_type = server_header
                sources.append("Server header")
            elif fingerprint:
                server_type = fingerprint
                sources.append("Nmap -sV")
            else:
                server_type = "HTTP server (version hidden)"
                sources.append("HTTP response")

            if fingerprint and server_header and fingerprint.lower() not in server_header.lower():
                server_type = f"{server_header} [{fingerprint}]"
                sources.append("Nmap -sV")

            tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
            service_name = service.attrib.get("name", "").lower() if service is not None else ""
            protocol = "HTTPS" if tunnel in {"ssl", "tls"} or service_name == "https" else "HTTP"
            port = int(port_node.attrib.get("portid", "0"))

            rows.append({
                "ip": ip,
                "port": f"{port}/TCP",
                "protocol": protocol,
                "server": server_type,
                "title": title or "-",
                "source": "+".join(sources),
            })

    return rows


async def scan_one(ip, ports, all_ports, timeout):
    xml_text, stderr = await run_nmap(ip, ports, all_ports, timeout)
    timed_out = bool(re.search(r"timed out|timeout|aborted", stderr, re.IGNORECASE))
    return parse_xml(xml_text), timed_out


async def run_all(targets, workers, ports, all_ports, timeout):
    queue = asyncio.Queue()
    results = []
    timed_out = []
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
                rows, timeout_hit = await scan_one(ip, ports, all_ports, timeout)
                results.extend(rows)
                if timeout_hit:
                    timed_out.append(ip)
                completed += 1
                sys.stdout.write(
                    f"\rScanning HTTP servers: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Services: {len(results)} | Current: {ip}".ljust(125)
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
    return results, timed_out


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No HTTP/HTTPS services were identified.")
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
            cell(row["port"], 9),
            cell(row["protocol"], 7),
            cell(row["server"], 42),
            cell(row["title"], 38),
            cell(row["source"], 22),
        ])
        print(paint(line, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "port", "protocol", "server", "title", "source"],
        )
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
        ):
            writer.writerow(row)


def write_text(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
        ):
            handle.write(
                f"{row['ip']}:{row['port'].split('/')[0]}\t"
                f"{row['protocol']}\t{row['server']}\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Find HTTP/HTTPS server types and versions."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="TCP ports/ranges")
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all 65535 TCP ports; considerably slower",
    )
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent workers")
    parser.add_argument("--host-timeout", default="5m", help="Nmap host timeout")
    parser.add_argument("--csv", default="http_server_fingerprints.csv", help="CSV output")
    parser.add_argument("--text", default="http_server_fingerprints.txt", help="Text output")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Ports          : {'1-65535' if args.all_ports else ports}")
    print("Detection      : Nmap -sV plus HTTP Server header/title scripts")

    rows, timed_out = asyncio.run(
        run_all(
            targets,
            workers,
            ports,
            args.all_ports,
            args.host_timeout,
        )
    )
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_text(args.text, rows)

    print()
    print(f"HTTP endpoints : {len(rows)}")
    print(f"HTTP hosts     : {len({row['ip'] for row in rows})}")
    print(f"Timed-out hosts: {len(set(timed_out))}")
    print(f"CSV written    : {args.csv}")
    print(f"Text written   : {args.text}")

    if timed_out:
        print("WARNING: Timed-out hosts may have incomplete results.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

