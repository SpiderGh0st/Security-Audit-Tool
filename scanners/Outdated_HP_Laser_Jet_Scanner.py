#!/usr/bin/env python3
"""
Inventory HP LaserJet printers, firmware, and exposed printer ports.

The scanner checks:
  - HTTP/HTTPS management: 80, 443, 631, 8080, 8443
  - JetDirect/PJL: 9100
  - LPD: 515
  - IPP: 631
  - SMB printing: 139, 445
  - SNMP: 161/UDP when snmpget is installed

Firmware is marked POTENTIALLY OUTDATED when a YYYYMMDD firmware date is older
than --max-age-years. This is an age-based audit signal, not proof that a
newer vendor firmware exists. Use --rules for model-specific minimum firmware.

Requirements:
    sudo apt install nmap snmp

Examples:
    python3 HpLaserJetOutdatedScanner.py -f target_ips.txt
    python3 HpLaserJetOutdatedScanner.py 192.0.2.0/24 --workers 16
    python3 HpLaserJetOutdatedScanner.py -f target_ips.txt --max-age-years 5
    python3 HpLaserJetOutdatedScanner.py -f target_ips.txt --rules hp_rules.json

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
from datetime import date, datetime
import http.client
import ipaddress
import json
import re
import shutil
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

TCP_PORTS = "80,443,515,631,8080,8443,9100,139,445"
WEB_PORTS = (80, 443, 631, 8080, 8443)
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
PRINTER_NAME_OID = "1.3.6.1.2.1.43.5.1.1.16.1"
PRINTER_SERIAL_OID = "1.3.6.1.2.1.43.5.1.1.17.1"

COLS = [
    ("IP ADDRESS", 16),
    ("PRODUCT", 34),
    ("SERIAL", 15),
    ("FIRMWARE", 12),
    ("AGE", 8),
    ("AFFECTED PORTS", 22),
    ("STATUS", 18),
]


def paint(text, color, enabled=True):
    return f"{color}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
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


def load_rules(path):
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as handle:
        rules = json.load(handle)
    if not isinstance(rules, list):
        raise SystemExit("Rules file must contain a JSON list.")
    return rules


async def run_nmap(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "--open",
        "-p",
        TCP_PORTS,
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_nmap(xml_text):
    result = {"ports": [], "fingerprints": []}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        service = port_node.find("service")
        name = service.attrib.get("name", "unknown") if service is not None else "unknown"
        result["ports"].append((port, name))
        if service is not None:
            fingerprint = " ".join(
                value
                for value in (
                    service.attrib.get("product", ""),
                    service.attrib.get("version", ""),
                    service.attrib.get("extrainfo", ""),
                )
                if value
            ).strip()
            if fingerprint:
                result["fingerprints"].append(fingerprint)
    return result


def http_fetch(ip, port, path, timeout, scheme):
    url = f"{scheme}://{ip}:{port}{path}"
    context = ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 HP-Printer-Audit"},
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        try:
            body_bytes = response.read(1024 * 1024)
        except http.client.IncompleteRead as error:
            # Older printer web servers often terminate chunked responses
            # incorrectly. Their partial HTML still contains useful inventory.
            body_bytes = error.partial
        body = body_bytes.decode("utf-8", errors="ignore")
        headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
        return url, response.geturl(), headers + "\n" + body


async def async_http_fetch(ip, port, path, timeout, scheme):
    try:
        return await asyncio.to_thread(http_fetch, ip, port, path, timeout, scheme)
    except (
        urllib.error.URLError,
        TimeoutError,
        ssl.SSLError,
        OSError,
        http.client.HTTPException,
        ValueError,
    ):
        return None


def strip_html(value):
    value = re.sub(r"<script\b.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = value.replace("&nbsp;", " ").replace("&amp;", "&")
    return re.sub(r"\s+", " ", value).strip()


def extract_web_details(text):
    plain = strip_html(text)
    result = {}
    patterns = {
        "serial": [
            r"Serial\s*(?:Number|No\.?)?\s*[:=]\s*([A-Z0-9-]{6,30})",
            r"Device\s+Serial\s+Number\s*[:=]\s*([A-Z0-9-]{6,30})",
        ],
        "firmware": [
            r"Firmware(?:\s+Datecode|\s+Version)?\s*[.:=]\s*([A-Z0-9_.-]{5,40})",
            r"Firmware\s+Revision\s*[.:=]\s*([A-Z0-9_.-]{5,40})",
            r"(?:Firmware\s+)?Datecode\s*[.:=]\s*([A-Z0-9_.-]{5,40})",
        ],
        "product": [
            r"Product\s+Name\s*[:=]\s*(HP\s+(?:LaserJet|Color LaserJet)[A-Z0-9 _.-]{0,70})",
            r"\b(HP\s+(?:LaserJet|Color LaserJet)[A-Z0-9 _.-]{0,70})",
        ],
    }
    for key, expressions in patterns.items():
        for expression in expressions:
            match = re.search(expression, plain, re.I)
            if match:
                result[key] = match.group(1).strip(" .:-")
                break
    if result.get("product"):
        result["product"] = re.split(
            r"\s+(?:Formatter\s+Number|Serial\s+Number|Service\s+ID|"
            r"Firmware(?:\s+Datecode|\s+Version)?|Type)\s*[:=]?",
            result["product"],
            maxsplit=1,
            flags=re.I,
        )[0].strip(" .:-")
    if not result.get("firmware"):
        dated = re.search(r"\b(20\d{6})\b", plain)
        if dated and re.search(r"firmware|datecode", plain, re.I):
            result["firmware"] = dated.group(1)
    return result


async def probe_web(ip, open_ports, timeout, deep_web=False, printer_hint=False):
    paths = (
        "/info_configuration.html",
        "/DevMgmt/ProductConfigDyn.xml",
        "/",
    )
    if deep_web:
        paths = (
            "/info_configuration.html",
            "/hp/device/DeviceInformation/View",
            "/DevMgmt/ProductConfigDyn.xml",
            "/",
        )
    async def probe_port(port):
        merged = {"port": port}
        preferred = "https" if port in (443, 8443) else "http"
        schemes = (preferred,)
        if deep_web:
            schemes = (preferred, "http" if preferred == "https" else "https")
        for scheme in schemes:
            for path in paths:
                fetched = await async_http_fetch(ip, port, path, timeout, scheme)
                if not fetched:
                    continue
                requested_url, final_url, text = fetched
                requested = urllib.parse.urlsplit(requested_url)
                final = urllib.parse.urlsplit(final_url)
                requested_port = requested.port or (443 if requested.scheme == "https" else 80)
                final_port = final.port or (443 if final.scheme == "https" else 80)

                # Do not credit a port with inventory obtained after redirecting
                # to another port or host.
                if final.hostname != requested.hostname or final_port != requested_port:
                    continue

                details = extract_web_details(text)
                if not details:
                    continue
                for key in ("product", "serial", "firmware"):
                    if details.get(key) and not merged.get(key):
                        merged[key] = details[key]
                merged["url"] = requested_url

        # Count an affected port only when that exact endpoint disclosed useful
        # printer inventory, not merely a generic HP/LaserJet page.
        if merged.get("product") and (
            merged.get("serial") or merged.get("firmware")
        ):
            return [merged]
        return []

    # Fast mode probes ports Nmap found open. If another protocol already
    # identifies a printer but Nmap found no web port, try the common ports.
    detected_web_ports = {port for port, _name in open_ports if port in WEB_PORTS}
    ports_to_probe = detected_web_ports
    if deep_web or (printer_hint and not detected_web_ports):
        ports_to_probe = detected_web_ports | set(WEB_PORTS)
    port_results = await asyncio.gather(
        *(probe_port(port) for port in sorted(ports_to_probe))
    )
    findings = []
    for port_findings in port_results:
        findings.extend(port_findings)
    return findings


def snmp_get(ip, community, oid, timeout):
    if not shutil.which("snmpget"):
        return ""
    command = [
        "snmpget", "-v2c", "-c", community, "-t", str(timeout), "-r", "0",
        "-Oqv", f"udp:{ip}:161", oid,
    ]
    try:
        import subprocess
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip().strip('"') if result.returncode == 0 else ""


async def probe_snmp(ip, timeout):
    values = await asyncio.gather(
        asyncio.to_thread(snmp_get, ip, "public", SYS_DESCR_OID, timeout),
        asyncio.to_thread(snmp_get, ip, "public", PRINTER_NAME_OID, timeout),
        asyncio.to_thread(snmp_get, ip, "public", PRINTER_SERIAL_OID, timeout),
    )
    description, product, serial = values
    joined = " ".join(values)
    if not re.search(r"\bHP\b|\bLaserJet\b|Hewlett", joined, re.I):
        return {}
    result = {"source": "SNMP"}
    if product:
        result["product"] = product
    elif description:
        match = re.search(r"(HP\s+.*?LaserJet[^,;]*)", description, re.I)
        result["product"] = match.group(1) if match else description
    if serial:
        result["serial"] = serial
    firmware_match = re.search(r"\b(20\d{6})\b", joined)
    if firmware_match:
        result["firmware"] = firmware_match.group(1)
    return result


def pjl_probe(ip, timeout):
    request = b"\x1b%-12345X@PJL INFO ID\r\n@PJL INFO CONFIG\r\n\x1b%-12345X"
    try:
        with socket.create_connection((ip, 9100), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            chunks = []
            while sum(len(chunk) for chunk in chunks) < 65536:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError:
        return {}
    text = b"".join(chunks).decode("latin-1", errors="ignore")
    if not text:
        return {}
    result = {"source": "PJL"}
    product = re.search(r'"([^"]*(?:HP|LaserJet)[^"]*)"', text, re.I)
    serial = re.search(r"(?:SERIAL|SERIALNUMBER)\s*=\s*\"?([A-Z0-9-]+)", text, re.I)
    firmware = re.search(r"(?:FIRMWARE|DATECODE)\s*=\s*\"?([A-Z0-9_.-]+)", text, re.I)
    if product:
        result["product"] = product.group(1)
    if serial:
        result["serial"] = serial.group(1)
    if firmware:
        result["firmware"] = firmware.group(1)
    return result


async def probe_pjl(ip, open_ports, timeout):
    if not any(port == 9100 for port, _name in open_ports):
        return {}
    return await asyncio.to_thread(pjl_probe, ip, timeout)


def firmware_date(value):
    if not value:
        return None
    match = re.search(r"\b(20\d{6})\b", value)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d").date()
    except ValueError:
        return None


def model_rule(product, firmware, rules):
    for rule in rules:
        pattern = rule.get("product_regex")
        if not pattern or not re.search(pattern, product or "", re.I):
            continue
        minimum = str(rule.get("minimum_firmware", ""))
        if minimum and firmware and firmware < minimum:
            return "OUTDATED", rule.get(
                "detail",
                f"Firmware is below configured minimum {minimum}.",
            )
        if minimum and firmware:
            return "CURRENT BY RULE", f"Firmware meets configured minimum {minimum}."
    return None


def classify(product, firmware, max_age_years, rules):
    rule_result = model_rule(product, firmware, rules)
    if rule_result:
        return rule_result

    parsed = firmware_date(firmware)
    if not parsed:
        if firmware:
            return (
                "REVIEW REQUIRED",
                "Firmware version was found but is not date-based; compare it with HP's model-specific current release.",
            )
        return "UNKNOWN", "Firmware date/version could not be identified."

    age_days = (date.today() - parsed).days
    age_years = age_days / 365.2425
    if age_years > max_age_years:
        return (
            "OUTDATED BY AGE",
            f"Firmware date is approximately {age_years:.1f} years old; verify against HP's latest model-specific release.",
        )
    return "WITHIN AGE LIMIT", f"Firmware date is approximately {age_years:.1f} years old."


def merge_details(nmap_info, web_findings, snmp_info, pjl_info):
    combined = {}
    sources = []
    affected_ports = set()

    ranked_web = sorted(
        web_findings,
        key=lambda item: (
            bool(re.search(r"\b(?:HP\s+)?(?:Color\s+)?LaserJet\b", item.get("product", ""), re.I)),
            bool(item.get("firmware")),
            bool(item.get("serial")),
        ),
        reverse=True,
    )
    ordered_findings = (
        [(item, "WEB") for item in ranked_web]
        + [(pjl_info, "PJL"), (snmp_info, "SNMP")]
    )
    for finding, source in ordered_findings:
        if not finding:
            continue
        sources.append(source)
        if source == "WEB" and finding.get("port"):
            affected_ports.add(int(finding["port"]))
        for key in ("product", "serial", "firmware", "url"):
            if finding.get(key) and not combined.get(key):
                combined[key] = finding[key]

    fingerprints = " ".join(nmap_info["fingerprints"])
    evidence_text = " ".join(
        [str(value) for value in combined.values()] + [fingerprints]
    )
    is_hp = bool(
        re.search(r"\b(?:HP\s+)?(?:Color\s+)?LaserJet\b", evidence_text, re.I)
    )
    if is_hp and not combined.get("product") and re.search(
        r"\bLaserJet\b", fingerprints, re.I
    ):
        combined["product"] = fingerprints
        sources.append("NMAP")

    combined["sources"] = sorted(set(sources))
    combined["affected_ports"] = sorted(affected_ports)
    combined["is_hp"] = is_hp
    return combined


async def scan_one(ip, args, rules):
    nmap_info = parse_nmap(await run_nmap(ip, args.timeout))

    snmp_info, pjl_info = await asyncio.gather(
        probe_snmp(ip, args.probe_timeout),
        probe_pjl(ip, nmap_info["ports"], args.probe_timeout),
    )
    nmap_text = " ".join(nmap_info["fingerprints"])
    printer_hint = bool(
        snmp_info
        or pjl_info
        or re.search(r"printer|laserjet|hewlett|\bhp\b|jetdirect", nmap_text, re.I)
    )
    web_findings = await probe_web(
        ip,
        nmap_info["ports"],
        args.probe_timeout,
        deep_web=args.deep_web,
        printer_hint=printer_hint,
    )
    details = merge_details(nmap_info, web_findings, snmp_info, pjl_info)
    if not details["is_hp"]:
        return None

    status, detail = classify(
        details.get("product", ""),
        details.get("firmware", ""),
        args.max_age_years,
        rules,
    )
    parsed = firmware_date(details.get("firmware", ""))
    age = f"{(date.today() - parsed).days / 365.2425:.1f}y" if parsed else "-"
    ports = ",".join(
        f"{port}/{name}" for port, name in sorted(nmap_info["ports"])
    ) or "web/SNMP discovery"
    return {
        "ip": ip,
        "product": details.get("product", "HP printer"),
        "serial": details.get("serial", "-"),
        "firmware": details.get("firmware", "-"),
        "age": age,
        "affected_ports": ",".join(
            str(port) for port in details.get("affected_ports", [])
        ) or "-",
        "ports": ports,
        "status": status,
        "source": ",".join(details["sources"]) or "NMAP",
        "detail": detail,
        "url": details.get("url", ""),
    }


async def run_all(targets, args, rules):
    queue = asyncio.Queue()
    results = []
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
                    row = await scan_one(ip, args, rules)
                    if row and (
                        args.show_all
                        or row["status"] in {"OUTDATED", "OUTDATED BY AGE"}
                    ):
                        results.append(row)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rScanning HP printers: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Findings: {len(results)} | Current: {ip}".ljust(125)
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
    return results


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No outdated HP LaserJet findings were identified.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["product"], 34),
            cell(row["serial"], 15),
            cell(row["firmware"], 12),
            cell(row["age"], 8),
            cell(row["affected_ports"], 22),
            cell(row["status"], 18),
        ])
        color = RED if row["status"] in {"OUTDATED", "OUTDATED BY AGE"} else YELLOW
        print(paint(line, color, colors))


def write_csv(path, rows):
    fields = [
        "ip", "product", "serial", "firmware", "age", "affected_ports", "ports",
        "status", "source", "detail", "url",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow(row)


def write_list(path, rows):
    affected = [
        row for row in rows
        if row["status"] in {"OUTDATED", "OUTDATED BY AGE"}
    ]
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(affected, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find potentially outdated HP LaserJet printers and exposed ports."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=90, help="Nmap host timeout")
    parser.add_argument("--probe-timeout", type=int, default=5, help="HTTP/SNMP/PJL timeout")
    parser.add_argument(
        "--deep-web",
        action="store_true",
        help="Probe every common printer web port with both HTTP and HTTPS; slower",
    )
    parser.add_argument(
        "--max-age-years",
        type=float,
        default=5.0,
        help="Flag dated firmware older than this many years",
    )
    parser.add_argument("--rules", help="Model-specific JSON minimum-firmware rules")
    parser.add_argument("--show-all", action="store_true", help="Show all detected HP printers")
    parser.add_argument("--csv", default="hp_laserjet_firmware.csv", help="CSV output")
    parser.add_argument("--list", default="outdated_hp_laserjet_ips.txt", help="Affected IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))
    rules = load_rules(args.rules)

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"TCP ports      : {TCP_PORTS}")
    print("UDP check      : 161/SNMP when snmpget is installed")
    print(f"Age threshold  : {args.max_age_years:g} years")
    print(f"Web probing    : {'deep/exhaustive' if args.deep_web else 'fast/selective'}")
    print(f"Showing        : {'all detected HP printers' if args.show_all else 'outdated findings only'}")

    rows = asyncio.run(run_all(targets, args, rules))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    affected = sum(
        1 for row in rows
        if row["status"] in {"OUTDATED", "OUTDATED BY AGE"}
    )
    print()
    print(f"Displayed printers : {len(rows)}")
    print(f"Outdated findings  : {affected}")
    print(f"CSV written        : {args.csv}")
    print(f"IP list written    : {args.list}")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())

