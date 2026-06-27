#!/usr/bin/env python3
"""
Find outdated THTTPD servers and list version-applicable CVEs from NVD.

The scanner:
  - fingerprints thttpd/x.y using Nmap and HTTP Server headers
  - retrieves the current release from https://www.acme.com/software/thttpd/
  - queries the NVD CVE API using the exact ACME thttpd CPE/version
  - caches NVD responses to avoid duplicate API requests

Requirements:
    sudo apt install nmap

Examples:
    python3 Acme_Thttpd_Scanner.py -f target_ips.txt
    python3 Acme_Thttpd_Scanner.py 192.0.2.0/24 --show-all
    python3 Acme_Thttpd_Scanner.py -f target_ips.txt --all-ports
    python3 Acme_Thttpd_Scanner.py -f target_ips.txt --nvd-api-key KEY

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from _common import (
    BLUE,
    GREEN,
    RED,
    RESET,
    WHITE,
    YELLOW,
    NVDCache,
    color,
    load_targets,
    query_nvd_sync,
    run_nmap,
    url_text,
)


THTTPD_DOWNLOAD = "https://www.acme.com/software/thttpd/"
FALLBACK_STABLE = "2.29"

DEFAULT_PORTS = (
    "80-90,443,444,591,593,631,3000,5000,5001,5601,5800,"
    "5985,5986,6172,6443,7001-7005,7070,7080,7443,7777,"
    "8000-8012,8020,8030,8040,8050,8060,8070,8080-8090,"
    "8100,8180,8181,8200,8280,8282,8300,8383,8442,8443,"
    "8444,8484,8500,8543,8544,8545,8585,8686,8787,8834,"
    "8880,8888,8983,8999,9000,9001,9043,9080,9090,9091,"
    "9200,9402,9403,9404,9419,9443,9990,9999,10000,10080,"
    "10443,18080,18081,18090,20443,28080,33034,33035,38080,"
    "47001,48080,53048,58080"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTO", 7),
    ("THTTPD VERSION", 16),
    ("STATUS", 14),
    ("MAX CVSS", 9),
    ("NVD CVES", 58),
]


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text[:width].ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


def version_tuple(value):
    numbers = re.findall(r"\d+", str(value or ""))
    return tuple(int(number) for number in numbers[:4])


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


def current_stable(timeout):
    try:
        html = url_text(THTTPD_DOWNLOAD, timeout)
        matches = re.findall(
            r"\bthttpd[-_/ ](?:version[-_/ ]*)?(\d+\.\d+(?:\.\d+)?[a-z]?)",
            html,
            re.I,
        )
        if matches:
            return max(matches, key=version_tuple), "acme.com"
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        pass
    return FALLBACK_STABLE, "fallback"


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "") if script is not None else ""


def extract_thttpd(port_node):
    service = port_node.find("service")
    values = []
    if service is not None:
        values.extend([
            service.attrib.get("name", ""),
            service.attrib.get("product", ""),
            service.attrib.get("version", ""),
            service.attrib.get("extrainfo", ""),
        ])
    values.extend([
        script_output(port_node, "http-server-header"),
        script_output(port_node, "http-headers"),
    ])
    evidence = "\n".join(values)
    version_match = re.search(
        r"\b(?:acme[\s/-]+)?thttpd[/\s-]+"
        r"(?:version[\s/-]+)?(\d+\.\d+(?:\.\d+)?[a-z]?)",
        evidence,
        re.I,
    )
    thttpd_present = bool(
        re.search(r"\b(?:acme[\s/-]+)?thttpd\b", evidence, re.I)
    )
    return thttpd_present, version_match.group(1) if version_match else "", evidence


def parse_nmap_xml(xml_text):
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
            detected, version, evidence = extract_thttpd(port_node)
            if not detected:
                continue

            service = port_node.find("service")
            name = service.attrib.get("name", "").lower() if service is not None else ""
            tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
            protocol = "HTTPS" if name == "https" or tunnel in {"ssl", "tls"} else "HTTP"
            port = int(port_node.attrib.get("portid", "0"))
            header = re.search(
                r"\b(?:acme[\s/-]+)?thttpd"
                r"(?:[/\s-]+(?:version[\s/-]+)?\d+\.\d+(?:\.\d+)?[a-z]?)?",
                evidence,
                re.I,
            )
            rows.append({
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "version": version,
                "evidence": header.group(0) if header else "thttpd",
            })
    return rows


async def discover_host(ip, args, ports):
    xml_text = await run_nmap(
        ip,
        ports,
        args.host_timeout,
        args.min_rate,
        ["--script", "http-server-header,http-headers"],
        all_ports=args.all_ports,
    )
    return parse_nmap_xml(xml_text)


async def discover_all(targets, args, ports):
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
                try:
                    rows.extend(await discover_host(ip, args, ports))
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} discovery failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rDiscovering THTTPD: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Endpoints: {len(rows)} | Current: {ip}".ljust(125)
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


def enrich_versions(rows, args):
    cache = NVDCache(args.nvd_cache)
    versions = sorted({row["version"] for row in rows if row["version"]}, key=version_tuple)
    enriched = {}

    for index, version in enumerate(versions, start=1):
        print(f"Querying NVD {index}/{len(versions)}: thttpd {version}", file=sys.stderr)
        cached = cache.get(version)
        if cached:
            enriched[version] = cached
            continue

        cpe = f"cpe:2.3:a:acme:thttpd:{version}:*:*:*:*:*:*:*"
        cves, error = query_nvd_sync(cpe, args.nvd_api_key, args.nvd_timeout)
        entry = {"cves": cves, "error": error, "queried": int(time.time())}
        cache.set(version, entry)
        enriched[version] = entry

        # NVD public rate limit is conservative without an API key.
        if index < len(versions):
            time.sleep(0.7 if args.nvd_api_key else 6.0)

    return enriched


def apply_results(rows, stable, enriched, show_all):
    output = []
    for row in rows:
        version = row["version"]
        if not version:
            row.update({
                "status": "VERSION HIDDEN",
                "max_cvss": 0.0,
                "cves": [],
                "nvd_error": "Exact version unavailable; NVD applicability cannot be determined.",
            })
        else:
            outdated = version_tuple(version) < version_tuple(stable)
            nvd = enriched.get(version, {"cves": [], "error": "NVD not queried"})
            cves = nvd.get("cves", [])
            if cves and outdated:
                status = "CVE CANDIDATE"
            elif cves:
                status = "CVE MATCH"
            elif outdated:
                status = "OUTDATED"
            else:
                status = "CURRENT"
            row.update({
                "status": status,
                "max_cvss": max((item["score"] for item in cves), default=0.0),
                "cves": cves,
                "nvd_error": nvd.get("error", ""),
            })

        if show_all or row["status"] in {"CVE CANDIDATE", "CVE MATCH", "OUTDATED"}:
            output.append(row)
    return output


def cve_ids(row):
    return ",".join(item["id"] for item in row["cves"]) or "-"


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No outdated or NVD-matched THTTPD endpoints were identified.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 9),
            cell(row["protocol"], 7),
            cell(row["version"] or "HIDDEN", 16),
            cell(row["status"], 14),
            cell(f"{row['max_cvss']:.1f}" if row["max_cvss"] else "-", 9),
            cell(cve_ids(row), 58),
        ])
        code = RED if row["status"] in {"CVE CANDIDATE", "CVE MATCH"} else (
            YELLOW if row["status"] in {"OUTDATED", "VERSION HIDDEN"} else GREEN
        )
        print(color(line, code, colors))
        if row["nvd_error"]:
            print(f"  NVD: {row['nvd_error']}")


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "version", "status", "max_cvss",
        "cve_ids", "cve_details", "evidence", "nvd_error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            cve_details = " | ".join(
                f"{item['id']} CVSS={item['score']:.1f} {item['severity']} "
                f"{item['url']} {item['description']}"
                for item in row["cves"]
            )
            writer.writerow({
                "ip": row["ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "version": row["version"],
                "status": row["status"],
                "max_cvss": row["max_cvss"],
                "cve_ids": cve_ids(row),
                "cve_details": cve_details,
                "evidence": row["evidence"],
                "nvd_error": row["nvd_error"],
            })


def write_list(path, rows):
    affected = [
        row for row in rows
        if row["status"] in {"CVE CANDIDATE", "CVE MATCH", "OUTDATED"}
    ]
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(affected, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find outdated THTTPD and version-based CVE candidates from NVD."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Web ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Scan all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="90s", help="Nmap host timeout")
    parser.add_argument("--show-all", action="store_true", help="Show current and version-hidden THTTPD too")
    parser.add_argument(
        "--nvd-api-key",
        default=os.environ.get("NVD_API_KEY", ""),
        help="NVD API key; defaults to NVD_API_KEY environment variable",
    )
    parser.add_argument("--nvd-timeout", type=int, default=30, help="NVD/acme.com request timeout")
    parser.add_argument("--nvd-cache", default="thttpd_nvd_cache.json", help="NVD response cache")
    parser.add_argument("--stable-version", help="Override current stable THTTPD version")
    parser.add_argument("--csv", default="thttpd_vulnerability_results.csv", help="CSV output")
    parser.add_argument("--list", default="thttpd_affected_endpoints.txt", help="Affected IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args.targets, args.file)
    if not targets:
        raise SystemExit("No targets supplied. Use an IP, hostname, CIDR, or -f targets.txt")
        
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))
    if args.stable_version:
        stable, stable_source = args.stable_version, "command line"
    else:
        stable, stable_source = current_stable(args.nvd_timeout)

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"Scan ports     : {'all TCP ports' if args.all_ports else args.ports}")
    print(f"THTTPD stable   : {stable} ({stable_source})")
    print("CVE source     : NVD CVE API 2.0 using exact thttpd CPE/version")

    discovered = asyncio.run(discover_all(targets, args, ports))
    enriched = enrich_versions(discovered, args)
    rows = apply_results(discovered, stable, enriched, args.show_all)

    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    affected = sum(
        1 for row in rows
        if row["status"] in {"CVE CANDIDATE", "CVE MATCH", "OUTDATED"}
    )
    print()
    print(f"THTTPD endpoints found : {len(discovered)}")
    print(f"Displayed endpoints   : {len(rows)}")
    print(f"Affected endpoints    : {affected}")
    print(f"CSV written           : {args.csv}")
    print(f"Endpoint list         : {args.list}")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())
