#!/usr/bin/env python3
"""
Check for missing or misconfigured security headers on HTTP/HTTPS servers.

Checks:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Server (disclosure)
  - X-Powered-By (disclosure)

Requirements:
    sudo apt install nmap

Examples:
    python3 SecurityHeadersScanner.py -f target_ips.txt
    python3 SecurityHeadersScanner.py 192.0.2.0/24
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

DEFAULT_PORTS = "80,443,8080,8443"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("MISSING HEADERS", 50),
    ("DISCLOSURES", 30),
]


def paint(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


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
    return ",".join(str(port) for port in valid) if valid else DEFAULT_PORTS


def normalize_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return [], None
    explicit_port = None
    if "://" in value:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return [], None
        value = parsed.hostname
        explicit_port = parsed.port
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)], explicit_port
        return [str(address) for address in network.hosts()], explicit_port
    except ValueError:
        return [value.rstrip(".")], explicit_port


def load_targets(args):
    targets = []
    url_ports = set()
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                expanded, port = normalize_target(line)
                targets.extend(expanded)
                if port:
                    url_ports.add(port)
    for value in args.targets:
        expanded, port = normalize_target(value)
        targets.extend(expanded)
        if port:
            url_ports.add(port)
    return list(dict.fromkeys(targets)), url_ports


async def run_nmap(ip, ports, timeout):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--open",
        "--host-timeout", timeout,
        "--script", "http-headers",
        "-p", ports,
        "-oX", "-", ip
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return "", f"Could not start Nmap: {exc}"
    stdout, stderr = await process.communicate()
    xml_text = stdout.decode("utf-8", errors="ignore")
    error_text = stderr.decode("utf-8", errors="ignore").strip()
    if process.returncode not in {0, 1}:
        return xml_text, f"Nmap exited with code {process.returncode}: {error_text}"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return xml_text, f"Invalid Nmap XML: {exc}"
    skipped = root.find(".//target[@status='skipped']")
    if skipped is not None:
        return xml_text, (
            f"Nmap skipped invalid target {skipped.attrib.get('specification', ip)!r}: "
            f"{error_text or skipped.attrib.get('reason', 'unknown reason')}"
        )
    if root.find("host") is None:
        return xml_text, f"Nmap returned no host result: {error_text or 'target was not tested'}"
    return xml_text, ""


def parse_headers(output):
    headers = {}
    for line in output.splitlines():
        match = re.match(r"^\s*([\w-]+)\s*:\s*(.+)$", line)
        if match:
            headers[match.group(1).lower()] = match.group(2).strip()
    return headers


def analyze_headers(headers, protocol):
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    missing = []
    for header, label in security_headers.items():
        if header not in headers:
            if header == "strict-transport-security" and protocol != "HTTPS":
                continue
            missing.append(label)

    disclosures = []
    if "server" in headers:
        disclosures.append(f"Server: {headers['server']}")
    if "x-powered-by" in headers:
        disclosures.append(f"X-Powered-By: {headers['x-powered-by']}")

    return missing, disclosures


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
            tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
            service_name = service.attrib.get("name", "").lower() if service is not None else ""
            protocol = "HTTPS" if tunnel in {"ssl", "tls"} or service_name == "https" else "HTTP"
            port = port_node.attrib.get("portid", "0")

            script = port_node.find("script[@id='http-headers']")
            if script is not None:
                headers = parse_headers(script.attrib.get("output", ""))
                missing, disclosures = analyze_headers(headers, protocol)
                if missing or disclosures:
                    rows.append({
                        "ip": ip,
                        "port": f"{port}/TCP",
                        "missing": ", ".join(missing),
                        "disclosures": ", ".join(disclosures),
                    })
    return rows


def inconclusive_http_reason(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "Invalid Nmap XML."
    open_ports = [
        port
        for port in root.findall(".//port")
        if (port.find("state") is not None)
        and port.find("state").attrib.get("state") == "open"
    ]
    for port in open_ports:
        script = port.find("script[@id='http-headers']")
        if script is None:
            return (
                f"TCP/{port.attrib.get('portid', '?')} is open, but "
                "Nmap http-headers returned no result."
            )
        if not script.attrib.get("output", "").strip():
            return (
                f"TCP/{port.attrib.get('portid', '?')} is open, but "
                "the HTTP header result was empty."
            )
    return ""


async def run_all(targets, workers, ports, timeout):
    queue = asyncio.Queue()
    results = []
    errors = []
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
                xml_text, error = await run_nmap(ip, ports, timeout)
                if error:
                    errors.append({"target": ip, "error": error})
                else:
                    inconclusive = inconclusive_http_reason(xml_text)
                    if inconclusive:
                        errors.append({"target": ip, "error": inconclusive})
                    else:
                        results.extend(parse_xml(xml_text))
                completed += 1
                sys.stdout.write(f"\rScanning headers: {completed}/{len(targets)} | Current: {ip}".ljust(100))
                sys.stdout.flush()
            finally:
                queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")
    return results, errors


def main():
    parser = argparse.ArgumentParser(description="Check for missing security headers.")
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="TCP ports")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent workers")
    parser.add_argument("--timeout", default="5m", help="Nmap host timeout")
    parser.add_argument("--csv", default="security_headers.csv", help="CSV output")
    args = parser.parse_args()

    targets, url_ports = load_targets(args)
    if not targets:
        print("No targets supplied.")
        return 2

    ports = normalize_ports(
        ",".join([args.ports, *(str(port) for port in sorted(url_ports))])
    )
    workers = min(max(1, args.workers), len(targets))

    results, errors = asyncio.run(run_all(targets, workers, ports, args.timeout))

    print("\n" + " ".join(cell(name, width) for name, width in COLS))
    print("-" * 110)
    for row in sorted(results, key=lambda x: ip_sort(x["ip"])):
        print(f"{cell(row['ip'], 16)} {cell(row['port'], 9)} {cell(row['missing'], 50)} {cell(row['disclosures'], 30)}")
    if errors:
        print("\nSCAN ERRORS / NOT TESTED")
        print("-" * 110)
        for error in errors:
            print(f"{error['target']}: {error['error']}")

    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "port", "missing", "disclosures"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nScan complete. Results saved to {args.csv}")
    print(f"Targets tested successfully: {len(targets) - len(errors)}/{len(targets)}")
    if errors:
        return 2
    return 1 if results else 0


if __name__ == "__main__":
    sys.exit(main())
