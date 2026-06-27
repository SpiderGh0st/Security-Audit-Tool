#!/usr/bin/env python3
"""
Find Oracle WebLogic Server versions outside the configured support baseline.

Detection sources:
  - Nmap service/version fingerprints
  - HTTP Server headers and page titles
  - read-only T3 protocol greeting

Built-in baseline:
  - WebLogic 12c: 12.2.1.4 only
  - WebLogic 14c and newer: 14.1.1 or newer

Oracle support can vary by contract and Sustaining Support. Use --policy to
override the built-in release policy for your organization.

Requirements:
    sudo apt install nmap

Examples:
    python3 UnsupportedWebLogicScanner.py -f target_ips.txt
    python3 UnsupportedWebLogicScanner.py -f target_ips.txt --show-all
    python3 UnsupportedWebLogicScanner.py 192.0.2.0/24 -p 7001,7002,9001

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "6000,6001,6002,6003,7001-7005,7101,7102,7201,7202,8001,8002,8101,8102,"
    "9001,9002,9101,9102,9501,9502,10001,10002"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTOCOL", 10),
    ("WEBLOGIC VERSION", 20),
    ("SUPPORT", 16),
    ("STATUS", 16),
    ("SOURCE", 16),
    ("DETAIL", 62),
]

VERSION_PATTERN = re.compile(
    r"(?<!\d)(\d{1,2}\.\d+\.\d+(?:\.\d+){0,2})(?!\d)"
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


def version_tuple(value):
    return tuple(int(part) for part in re.findall(r"\d+", value))


def normalize_release(value):
    numbers = re.findall(r"\d+", str(value or ""))
    if not numbers:
        return ""
    while len(numbers) > 1 and numbers[-1] == "0":
        numbers.pop()
    return ".".join(numbers)


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


def load_policy(path):
    if not path:
        return {
            "supported_exact": ["12.2.1.4"],
            "minimum_versions": ["14.1.1"],
        }
    try:
        with open(path, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Could not load policy: {error}")
    return policy


def evaluate_support(version, policy):
    normalized = normalize_release(version)
    if not normalized:
        return "UNKNOWN", "REVIEW", "Exact WebLogic version was not identified."

    current = version_tuple(normalized)
    exact = {
        normalize_release(item)
        for item in policy.get("supported_exact", [])
    }
    if normalized in exact:
        return "SUPPORTED LINE", "SUPPORTED", "Release matches the configured supported list."

    for minimum in policy.get("minimum_versions", []):
        minimum_normalized = normalize_release(minimum)
        minimum_tuple = version_tuple(minimum_normalized)
        if current and minimum_tuple and current[0] == minimum_tuple[0]:
            if current >= minimum_tuple:
                return "SUPPORTED LINE", "SUPPORTED", f"Release meets configured minimum {minimum_normalized}."

    return "OUT OF POLICY", "LIFECYCLE REVIEW", "Release does not match the configured supported WebLogic lines; confirm Oracle support entitlement."


async def run_nmap(ip, ports, timeout):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "-p", ports,
        "--script", "http-server-header,http-headers,http-title",
        "--script-timeout", "25s",
        "--host-timeout", f"{timeout}s",
        "-oX", "-", ip,
    ]
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
    return script.attrib.get("output", "") if script is not None else ""


def nmap_candidates(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    endpoints = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address")
        if address is None:
            continue
        ip = address.attrib.get("addr", "")
        for port_node in host.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            service = port_node.find("service")
            name = service.attrib.get("name", "") if service is not None else ""
            tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
            values = []
            if service is not None:
                values.extend([
                    service.attrib.get("product", ""),
                    service.attrib.get("version", ""),
                    service.attrib.get("extrainfo", ""),
                    service.attrib.get("servicefp", ""),
                ])
            values.extend([
                script_output(port_node, "http-server-header"),
                script_output(port_node, "http-headers"),
                script_output(port_node, "http-title"),
            ])
            evidence = "\n".join(values)
            endpoints.append({
                "ip": ip,
                "port": int(port_node.attrib.get("portid", "0")),
                "protocol": "HTTPS" if tunnel in {"ssl", "tls"} or name == "https" else "TCP",
                "evidence": evidence,
            })
    return endpoints


def extract_weblogic_version(evidence):
    patterns = [
        r"(?:Oracle\s+)?WebLogic(?:\s+Server)?[/\s:-]+(?:Version\s*)?(\d+(?:\.\d+){2,4})",
        r"\bWebLogicServer[/\s:-]+(\d+(?:\.\d+){2,4})",
        r"\bHELO:(\d+(?:\.\d+){2,4})(?:\.false)?",
    ]
    for pattern in patterns:
        match = re.search(pattern, evidence, re.I)
        if match:
            return normalize_release(match.group(1))
    if re.search(r"\bweblogic\b", evidence, re.I):
        match = VERSION_PATTERN.search(evidence)
        if match:
            return normalize_release(match.group(1))
    return ""


async def t3_probe(ip, port, timeout):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.write(
            b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        return data.decode("latin-1", errors="replace")
    except (OSError, asyncio.TimeoutError):
        return ""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass


async def analyze_endpoint(endpoint, policy, probe_timeout):
    version = extract_weblogic_version(endpoint["evidence"])
    source = "NMAP/HTTP" if version else ""
    weblogic_detected = bool(
        re.search(r"\b(?:oracle\s+)?weblogic\b", endpoint["evidence"], re.I)
    )

    if endpoint["protocol"] != "HTTPS":
        greeting = await t3_probe(
            endpoint["ip"], endpoint["port"], probe_timeout
        )
        if re.search(r"\b(?:HELO|weblogic|t3)\b", greeting, re.I):
            weblogic_detected = True
            t3_version = extract_weblogic_version(greeting)
            if t3_version:
                version = t3_version
            source = "T3" if not source else f"{source}+T3"

    if not weblogic_detected:
        return None

    support, status, detail = evaluate_support(version, policy)
    return {
        "ip": endpoint["ip"],
        "port": f"{endpoint['port']}/TCP",
        "protocol": "T3/HTTP" if endpoint["protocol"] != "HTTPS" else "HTTPS",
        "version": version or "HIDDEN",
        "support": support,
        "status": status,
        "source": source or "FINGERPRINT",
        "detail": detail,
    }


async def scan_one(ip, ports, nmap_timeout, probe_timeout, policy):
    xml_text, _ = await run_nmap(ip, ports, nmap_timeout)
    endpoints = nmap_candidates(xml_text)
    results = await asyncio.gather(
        *(
            analyze_endpoint(endpoint, policy, probe_timeout)
            for endpoint in endpoints
        )
    )
    return [result for result in results if result is not None]


async def run_all(
    targets, workers, ports, nmap_timeout, probe_timeout, policy
):
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
                    await scan_one(
                        ip, ports, nmap_timeout, probe_timeout, policy
                    )
                )
                completed += 1
                unsupported = sum(
                    row["status"] == "LIFECYCLE REVIEW" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning WebLogic: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Detected: {len(rows)} | Unsupported: {unsupported} | "
                    f"Current: {ip}".ljust(140)
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


def print_table(rows, show_all=False, colors=True):
    displayed = rows if show_all else [
        row for row in rows if row["status"] == "LIFECYCLE REVIEW"
    ]
    print()
    if not displayed:
        print("No Oracle WebLogic endpoints with confirmed unsupported versions were found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        displayed,
        key=lambda item: (
            ip_sort(item["ip"]),
            int(item["port"].split("/")[0]),
        ),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 9),
            cell(row["protocol"], 10),
            cell(row["version"], 20),
            cell(row["support"], 16),
            cell(row["status"], 16),
            cell(row["source"], 16),
            cell(row["detail"], 62),
        ])
        code = (
            RED if row["status"] == "LIFECYCLE REVIEW"
            else GREEN if row["status"] == "SUPPORTED"
            else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "version", "support",
        "status", "source", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (
                ip_sort(item["ip"]),
                int(item["port"].split("/")[0]),
            ),
        ))


def write_list(path, rows):
    endpoints = {
        f"{row['ip']}:{row['port'].split('/')[0]}"
        for row in rows if row["status"] == "LIFECYCLE REVIEW"
    }
    with open(path, "w", encoding="utf-8") as handle:
        for endpoint in sorted(endpoints):
            handle.write(f"{endpoint}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find unsupported Oracle WebLogic Server versions."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="WebLogic TCP ports/ranges")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host workers")
    parser.add_argument("--nmap-timeout", type=int, default=75, help="Nmap host timeout")
    parser.add_argument("--probe-timeout", type=float, default=3.0, help="T3 greeting timeout")
    parser.add_argument("--policy", help="JSON support-policy override")
    parser.add_argument("--show-all", action="store_true", help="Show supported and version-hidden WebLogic endpoints")
    parser.add_argument("--csv", default="unsupported_weblogic_results.csv", help="CSV output path")
    parser.add_argument("--list", default="unsupported_weblogic_endpoints.txt", help="Unsupported IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    policy = load_policy(args.policy)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Scan ports     : {ports}")
    print("Detection      : Nmap HTTP fingerprints plus read-only T3 greeting")
    print("Support policy : 12.2.1.4 and 14.1.1+ unless overridden")
    print(f"Showing        : {'all detected WebLogic endpoints' if args.show_all else 'confirmed unsupported versions only'}")

    rows = asyncio.run(
        run_all(
            targets,
            workers,
            ports,
            max(20, args.nmap_timeout),
            max(0.5, args.probe_timeout),
            policy,
        )
    )
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    unsupported = [row for row in rows if row["status"] == "LIFECYCLE REVIEW"]
    supported = [row for row in rows if row["status"] == "SUPPORTED"]
    review = [row for row in rows if row["status"] == "REVIEW"]
    print()
    print(f"WebLogic endpoints : {len(rows)}")
    print(f"Unsupported        : {len(unsupported)}")
    print(f"Supported lines    : {len(supported)}")
    print(f"Version review     : {len(review)}")
    print(f"CSV written        : {args.csv}")
    print(f"Endpoint list      : {args.list}")
    return 1 if unsupported else 0


if __name__ == "__main__":
    raise SystemExit(main())

