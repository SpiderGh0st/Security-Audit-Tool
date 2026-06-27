#!/usr/bin/env python3
"""
Find VMware ESXi hosts that appear vulnerable or unsupported.

Checks:
  - HTTPS /sdk/vimServiceVersions.xml to identify VMware SDK exposure
  - vSphere SOAP RetrieveServiceContent to extract ESXi fullName/version/build
  - Built-in EOL/legacy rules
  - Optional JSON rules for your own CVE fixed-build thresholds

Examples:
  python3 EsxiVulnScanner.py -f target_ips.txt
  python3 EsxiVulnScanner.py 192.0.2.0/24 --workers 32
  python3 EsxiVulnScanner.py -f target_ips.txt --show-all
  python3 EsxiVulnScanner.py -f target_ips.txt --flag-version 8.0.3
  python3 EsxiVulnScanner.py -f esxi_ips.txt --rules esxi_rules.json

Only vulnerable / affected rows are printed unless --show-all is used.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 6),
    ("VERSION", 14),
    ("BUILD", 12),
    ("STATUS", 14),
    ("DETAIL", 86),
]

DEFAULT_PORTS = [443, 9443]
HTTP_TIMEOUT = 8

RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


DEFAULT_RULES = [
    {
        "name": "ESXi 5.x or older",
        "version_regex": r"^(?:[0-5])(?:\.|$)",
        "status": "LIFECYCLE REVIEW",
        "detail": "Legacy VMware ESXi version detected; verify support entitlement and exact patch/build before reporting.",
    },
    {
        "name": "ESXi 6.x",
        "version_regex": r"^6(?:\.|$)",
        "status": "LIFECYCLE REVIEW",
        "detail": "VMware ESXi 6.x detected; verify support entitlement and exact patch/build before reporting.",
    },
    {
        "name": "ESXi 7.x",
        "version_regex": r"^7(?:\.|$)",
        "status": "LIFECYCLE REVIEW",
        "detail": "VMware ESXi 7.x detected; verify current support/patch entitlement and upgrade requirements.",
    },
]


SOAP_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vim25="urn:vim25">
  <soapenv:Body>
    <vim25:RetrieveServiceContent>
      <vim25:_this type="ServiceInstance">ServiceInstance</vim25:_this>
    </vim25:RetrieveServiceContent>
  </soapenv:Body>
</soapenv:Envelope>
"""


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
        ip, port = value.split(":", 1)
        return [(ip, int(port))]
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses == 1:
            return [(str(net.network_address), None)]
        return [(str(ip), None) for ip in net.hosts()]
    except ValueError:
        return [(value, None)]


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
    for ip, port in targets:
        ports = [port] if port else args.ports
        for current_port in ports:
            key = (ip, current_port)
            if key not in seen:
                seen.add(key)
                unique.append(key)
    if not unique:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return unique


def load_rules(path):
    rules = list(DEFAULT_RULES)
    if not path:
        return rules
    with open(path, "r", encoding="utf-8") as handle:
        custom = json.load(handle)
    if not isinstance(custom, list):
        raise SystemExit("Rules file must contain a JSON list.")
    rules.extend(custom)
    return rules


def version_tuple(value):
    nums = re.findall(r"\d+", str(value or ""))
    return tuple(int(item) for item in nums[:4])


def build_int(value):
    match = re.search(r"\d+", str(value or ""))
    return int(match.group(0)) if match else None


def http_request(ip, port, path, method="GET", body=None, headers=None):
    url = f"https://{ip}:{port}{path}"
    context = ssl._create_unverified_context()
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=context) as response:
        return response.read().decode("utf-8", errors="ignore")


async def async_http_request(ip, port, path, method="GET", body=None, headers=None):
    return await asyncio.to_thread(http_request, ip, port, path, method, body, headers)


def strip_ns(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_service_content(xml_text):
    info = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return info

    capture = {"fullName", "name", "version", "build", "apiVersion", "productLineId", "osType", "vendor"}
    for elem in root.iter():
        key = strip_ns(elem.tag)
        value = (elem.text or "").strip()
        if key in capture and value and key not in info:
            info[key] = value
    return info


def parse_versions_xml(xml_text):
    info = {}
    versions = sorted(set(re.findall(r"(?:vim\.version\.version|version)(\d+(?:\.\d+)*)", xml_text, re.I)), key=version_tuple)
    if versions:
        info["apiVersion"] = versions[-1]
    if "VMware" in xml_text or "vimServiceVersions" in xml_text:
        info["sdk"] = "present"
    return info


def detect_from_text(text):
    info = {}
    match = re.search(r"VMware\s+ESXi\s+([0-9.]+).*?build[-\s:]?([0-9]+)", text, re.I | re.S)
    if match:
        info["version"] = match.group(1)
        info["build"] = match.group(2)
        info["fullName"] = f"VMware ESXi {match.group(1)} build {match.group(2)}"
    elif re.search(r"VMware\s+ESXi", text, re.I):
        info["fullName"] = "VMware ESXi"
    return info


async def probe_target(ip, port):
    info = {"ip": ip, "port": port}

    try:
        versions_xml = await async_http_request(ip, port, "/sdk/vimServiceVersions.xml")
        info.update(parse_versions_xml(versions_xml))
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        pass

    try:
        soap = await async_http_request(
            ip,
            port,
            "/sdk",
            method="POST",
            body=SOAP_BODY,
            headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:vim25/6.7"},
        )
        info.update(parse_service_content(soap))
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        pass

    if "fullName" not in info and info.get("sdk") == "present":
        try:
            root_page = await async_http_request(ip, port, "/")
            info.update(detect_from_text(root_page))
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
            pass

    return info


def classify(info, rules):
    version = info.get("version") or info.get("apiVersion") or ""
    build = build_int(info.get("build"))
    haystack = " ".join(str(info.get(key, "")) for key in ["fullName", "name", "version", "build", "apiVersion", "productLineId", "osType"])

    if "esx" not in haystack.lower() and info.get("sdk") != "present":
        return None

    for rule in rules:
        version_regex = rule.get("version_regex")
        full_regex = rule.get("regex")
        min_build = rule.get("min_fixed_build")
        max_build = rule.get("max_vulnerable_build")

        matched = False
        if version_regex and re.search(version_regex, version, re.I):
            matched = True
        if full_regex and re.search(full_regex, haystack, re.I):
            matched = True
        if min_build is not None and build is not None and build < int(min_build):
            if not version_regex or re.search(version_regex, version, re.I):
                matched = True
        if max_build is not None and build is not None and build <= int(max_build):
            if not version_regex or re.search(version_regex, version, re.I):
                matched = True

        if matched:
            return {
                "status": rule.get("status", "CVE CANDIDATE"),
                "detail": rule.get("detail", rule.get("name", "Matched vulnerability rule.")),
            }

    return None


def detected_esxi(info):
    haystack = " ".join(str(info.get(key, "")) for key in ["fullName", "name", "version", "build", "apiVersion", "productLineId", "osType", "sdk"])
    return "esx" in haystack.lower() or info.get("sdk") == "present"


async def scan_one(ip, port, rules, show_all):
    info = await probe_target(ip, port)
    finding = classify(info, rules)
    if not finding and not (show_all and detected_esxi(info)):
        return None
    full_name = info.get("fullName") or info.get("name") or "VMware ESXi"
    version = info.get("version") or info.get("apiVersion") or full_name
    return {
        "ip": ip,
        "port": port,
        "version": version,
        "build": info.get("build", "-"),
        "status": finding["status"] if finding else "DETECTED",
        "detail": finding["detail"] if finding else "ESXi detected, but no vulnerability rule matched.",
        "full_name": full_name,
    }


async def run_all(targets, workers, rules, show_all):
    queue = asyncio.Queue()
    results = []
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
                row = await scan_one(ip, port, rules, show_all)
                if row:
                    results.append(row)
                completed += 1
                sys.stdout.write(
                    f"\rScanning ESXi: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Vulnerable: {len(results)} | Current: {ip}:{port}".ljust(120)
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
    return results


def print_table(rows, colors=True, show_all=False):
    print()
    if not rows:
        if show_all:
            print("No VMware ESXi hosts detected.")
        else:
            print("No vulnerable VMware ESXi findings found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), int(item["port"]))):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 6),
            cell(row["version"], 14),
            cell(row["build"], 12),
            cell(row["status"], 14),
            cell(row["detail"], 86),
        ])
        color = RED if row["status"].upper() == "VULNERABLE" else YELLOW
        print(paint(line, color, colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "port", "version", "build", "status", "detail", "full_name"])
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), int(item["port"]))):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), int(item["port"]))):
            handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(description="Print only vulnerable/affected VMware ESXi hosts.")
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="Input file containing IPs, CIDRs, or ip:port entries")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent workers")
    parser.add_argument("-p", "--ports", default="443,9443", help="HTTPS ports to check when target has no explicit port")
    parser.add_argument("--rules", help="Optional JSON rules file for CVE fixed-build thresholds")
    parser.add_argument("--flag-version", action="append", default=[], help="Treat this ESXi version prefix as AFFECTED, for example: --flag-version 8.0.3")
    parser.add_argument("--show-all", action="store_true", help="Show all detected ESXi hosts, including hosts with no matching vulnerability rule")
    parser.add_argument("--csv", default="vulnerable_esxi.csv", help="CSV output path")
    parser.add_argument("--list", default="vulnerable_esxi_hosts.txt", help="Vulnerable host:port list output path")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    args.ports = [int(port.strip()) for port in args.ports.split(",") if port.strip()]
    rules = load_rules(args.rules)
    for version in args.flag_version:
        rules.insert(0, {
            "name": f"Flagged ESXi {version}",
            "version_regex": "^" + re.escape(version),
            "status": "AFFECTED",
            "detail": f"ESXi version {version} matched a user-supplied flagged version rule.",
        })
    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))
    print(f"Loaded targets : {len(targets)} host/port checks")
    print(f"Workers        : {workers}")
    print("Probe          : /sdk/vimServiceVersions.xml and vSphere SOAP service content")
    print(f"Showing        : {'all detected ESXi hosts' if args.show_all else 'vulnerable / affected VMware ESXi only'}")

    rows = asyncio.run(run_all(targets, workers, rules, args.show_all))
    print_table(rows, colors=not args.no_color, show_all=args.show_all)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Vulnerable found : {len(rows)}")
    print(f"CSV written      : {args.csv}")
    print(f"Host list written: {args.list}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

