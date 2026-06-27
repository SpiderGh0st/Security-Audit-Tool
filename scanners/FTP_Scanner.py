#!/usr/bin/env python3
"""
Inventory FTP services and identify insecure access controls or known CVEs.

Checks:
  - open FTP/FTPS ports and service versions
  - anonymous FTP authentication using Nmap ftp-anon (read-only probe)
  - known CVEs using Nmap's vulners NSE script when installed
  - optional local minimum-version policy from a JSON rules file

Requirements:
    sudo apt install nmap

Examples:
    python3 FtpAccessVulnerabilityScanner.py -f target_ips.txt
    python3 FtpAccessVulnerabilityScanner.py 192.0.2.0/24 --vulnerable-only
    python3 FtpAccessVulnerabilityScanner.py -f target_ips.txt -p 21,990,2121
    python3 FtpAccessVulnerabilityScanner.py -f target_ips.txt --all-ports
    python3 FtpAccessVulnerabilityScanner.py -f target_ips.txt --rules ftp_version_rules.json

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = "21,990,2121,8021,2100,2101"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_CPE_PRODUCTS = [
    (r"\bvsftpd\b", "vsftpd_project", "vsftpd"),
]

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 7),
    ("FTP SERVER", 30),
    ("VERSION", 18),
    ("ANONYMOUS", 11),
    ("CVES", 49),
    ("STATUS", 12),
    ("DETAIL", 54),
]

# High-confidence product/version matches. This intentionally remains small:
# distribution backports and ambiguous Nmap ranges must not be called vulnerable.
KNOWN_VULNERABLE_VERSIONS = [
    {
        "product": r"\bvsftpd\b",
        "version": r"^2\.3\.4$",
        "cves": ["CVE-2011-2523"],
        "detail": "Known backdoored vsftpd 2.3.4 release.",
    },
]


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
    numbers = re.findall(r"\d+", str(value or ""))
    return tuple(int(number) for number in numbers[:4])


def exact_version(value):
    text = str(value or "").strip()
    if re.fullmatch(r"\d+(?:\.\d+){1,3}", text):
        return text
    return ""


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


def load_rules(path):
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Could not load version rules: {error}")
    if not isinstance(data, list):
        raise SystemExit("Version rules must be a JSON list.")
    return data


def has_vulners_script():
    try:
        result = subprocess.run(
            ["nmap", "--script-help", "vulners"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0 and "vulners" in result.stdout.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False


async def run_nmap(ip, ports, all_ports, min_rate, timeout, use_vulners):
    scripts = ["ftp-anon", "ftp-syst", "banner"]
    if use_vulners:
        scripts.append("vulners")
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "--script",
        ",".join(scripts),
        "--script-timeout",
        "20s",
        "--host-timeout",
        f"{timeout}s",
    ]
    if all_ports:
        command.extend(["-p-", "--min-rate", str(min_rate)])
    else:
        command.extend(["-p", ports])
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


async def read_ftp_reply(reader, timeout):
    first = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not first:
        return 0, ""
    text = first.decode("utf-8", errors="replace").strip()
    match = re.match(r"^(\d{3})([- ])", text)
    if not match:
        return 0, text
    code = int(match.group(1))
    if match.group(2) == "-":
        terminator = f"{code} "
        lines = [text]
        while len(lines) < 50:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").strip()
            lines.append(decoded)
            if decoded.startswith(terminator):
                break
        text = " ".join(lines)
    return code, text


async def direct_anonymous_probe(ip, port, timeout):
    # Implicit FTPS needs a TLS-specific client; avoid misclassifying it here.
    if port == 990:
        return "NOT TESTED", "Implicit FTPS was not directly tested."
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        banner_code, banner = await read_ftp_reply(reader, timeout)
        if banner_code and banner_code >= 400:
            return "NOT TESTED", f"FTP banner rejected connection: {banner}"

        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        user_code, user_reply = await read_ftp_reply(reader, timeout)
        if user_code == 230:
            return "ALLOWED", user_reply
        if user_code >= 400:
            return "REJECTED", user_reply

        writer.write(b"PASS anonymous@example.com\r\n")
        await writer.drain()
        pass_code, pass_reply = await read_ftp_reply(reader, timeout)
        if pass_code in {230, 202}:
            return "ALLOWED", pass_reply
        if pass_code >= 400:
            return "REJECTED", pass_reply
        return "NOT TESTED", pass_reply or user_reply
    except (OSError, asyncio.TimeoutError):
        return "NOT TESTED", "Direct anonymous login probe was inconclusive."
    finally:
        if writer is not None:
            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
            except (OSError, ConnectionError):
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "").strip() if script is not None else ""


def service_details(port_node):
    service = port_node.find("service")
    if service is None:
        return "", "", "", "", ""
    return (
        service.attrib.get("name", ""),
        service.attrib.get("product", ""),
        service.attrib.get("version", ""),
        service.attrib.get("extrainfo", ""),
        service.attrib.get("tunnel", ""),
    )


def refine_product_version(port_node, product, version):
    evidence = " ".join([
        product or "",
        version or "",
        script_output(port_node, "banner"),
        script_output(port_node, "ftp-syst"),
    ])
    patterns = [
        (r"\b(vsftpd)\s*(\d+(?:\.\d+){1,3})\b", "vsftpd"),
        (r"\b(Pure-FTPd)\s*(?:version\s*)?(\d+(?:\.\d+){1,3})\b", "Pure-FTPd"),
        (r"\b(ProFTPD)\s*(\d+(?:\.\d+){1,3}[a-z]?)\b", "ProFTPD"),
        (r"\b(oftpd)\s*(\d+(?:\.\d+){1,3})\b", "oftpd"),
        (r"\b(FileZilla Server)\s*(?:version\s*)?(\d+(?:\.\d+){1,3})\b", "FileZilla Server"),
    ]
    for pattern, canonical_product in patterns:
        match = re.search(pattern, evidence, re.I)
        if match:
            if not product or product.lower() in {"ftp", "unknown"}:
                product = canonical_product
            if not exact_version(version):
                version = match.group(2)
            break
    return product, version


def is_ftp_service(port_node):
    name, product, version, extra, tunnel = service_details(port_node)
    evidence = " ".join([
        name,
        product,
        version,
        extra,
        tunnel,
        script_output(port_node, "ftp-syst"),
        script_output(port_node, "ftp-anon"),
        script_output(port_node, "banner"),
    ]).lower()
    return (
        name in {"ftp", "ftps", "ftp-data"}
        or "ftp server" in evidence
        or bool(re.search(r"\b(?:vsftpd|proftpd|pure-ftpd|filezilla server)\b", evidence))
        or "220 " in evidence and "ftp" in evidence
    )


def anonymous_status(output):
    text = output.lower()
    accepted = (
        "anonymous ftp login allowed" in text
        or bool(re.search(r"\b(?:code|status)\s*230\b", text))
        or "login successful" in text
    )
    rejected = (
        "anonymous ftp login not allowed" in text
        or bool(re.search(r"\b(?:code|status)\s*(?:452|530|550)\b", text))
        or "login failed" in text
        or "login incorrect" in text
    )
    if accepted:
        return "ALLOWED"
    if rejected:
        return "REJECTED"
    return "NOT TESTED"


def extract_cves(output):
    cves = sorted(
        set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", output, re.I)),
        key=str.upper,
    )
    scores = []
    for match in re.finditer(
        r"(CVE-\d{4}-\d{4,7})\s+([0-9]+(?:\.[0-9]+)?)",
        output,
        re.I,
    ):
        try:
            scores.append(float(match.group(2)))
        except ValueError:
            pass
    return [value.upper() for value in cves], max(scores) if scores else None


def product_cpe(product, version):
    exact = exact_version(version)
    if not exact:
        return ""
    for pattern, vendor, cpe_product in NVD_CPE_PRODUCTS:
        if re.search(pattern, product or "", re.I):
            return f"cpe:2.3:a:{vendor}:{cpe_product}:{exact}:*:*:*:*:*:*:*"
    return ""


def nvd_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
    return None


def query_nvd(cpe, api_key, timeout):
    query = urllib.parse.urlencode({"cpeName": cpe})
    request = urllib.request.Request(
        f"{NVD_API}?{query}",
        headers={
            "Accept": "application/json",
            "User-Agent": "FTP-Access-Vulnerability-Scanner/2.0",
            **({"apiKey": api_key} if api_key else {}),
        },
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))

    cves = []
    scores = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id, re.I):
            cves.append(cve_id.upper())
        score = nvd_cvss(cve)
        if score is not None:
            scores.append(score)
    return sorted(set(cves)), max(scores) if scores else None


def enrich_from_nvd(rows, api_key, timeout):
    cache = {}
    query_rows = {}
    for row in rows:
        cpe = product_cpe(row["server"], row["version"])
        if cpe:
            query_rows.setdefault(cpe, []).append(row)

    total = len(query_rows)
    for index, (cpe, matching_rows) in enumerate(query_rows.items(), 1):
        label = f"{matching_rows[0]['server']} {matching_rows[0]['version']}"
        sys.stdout.write(f"\rQuerying NVD {index}/{total}: {label}".ljust(100))
        sys.stdout.flush()
        try:
            cache[cpe] = query_nvd(cpe, api_key, timeout)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, ValueError):
            cache[cpe] = None

        result = cache[cpe]
        for row in matching_rows:
            if result is None:
                row["cve_check"] = "NVD ERROR"
                row["detail"] = "Exact version detected, but the NVD query failed."
                continue

            nvd_cves, nvd_score = result
            existing = [] if row["cves"] == "-" else row["cves"].split(",")
            combined = sorted(set(existing + nvd_cves))
            if combined:
                row["cves"] = ",".join(combined)
                row["cve_check"] = f"{len(combined)} CVE(S)"
                if row["anonymous"] != "ALLOWED":
                    row["status"] = "REVIEW"
                if nvd_score is not None:
                    row["max_cvss"] = f"{nvd_score:.1f}"
                row["detail"] = (
                    f"Exact {row['server']} {row['version']} CPE matched "
                    f"{len(combined)} NVD CVE(s)."
                )
                if row["anonymous"] == "ALLOWED":
                    row["detail"] += " Anonymous FTP login also accepted."
            else:
                row["cves"] = "-"
                row["cve_check"] = "NVD NO MATCH"
                row["detail"] = (
                    "Exact version queried in NVD; no applicable CVE was returned."
                )

        if index < total:
            time.sleep(0.7 if api_key else 6.1)
    if total:
        sys.stdout.write("\n")
    return rows


def known_version_cves(product, version):
    exact = exact_version(version)
    if not exact:
        return [], ""
    for rule in KNOWN_VULNERABLE_VERSIONS:
        if (
            re.search(rule["product"], product or "", re.I)
            and re.fullmatch(rule["version"], exact, re.I)
        ):
            return list(rule["cves"]), rule["detail"]
    return [], ""


def evaluate_version(product, version, rules):
    if not product or not version:
        return "UNKNOWN", ""
    exact = exact_version(version)
    if not exact:
        return "UNKNOWN", "Nmap did not identify an exact version."
    current = version_tuple(exact)
    if not current:
        return "UNKNOWN", ""
    for rule in rules:
        pattern = str(rule.get("product_regex", ""))
        minimum = str(rule.get("minimum_version", ""))
        if not pattern or not minimum:
            continue
        try:
            matched = re.search(pattern, product, re.I)
        except re.error:
            continue
        if matched and current < version_tuple(minimum):
            detail = rule.get(
                "detail",
                f"Version is below configured minimum {minimum}.",
            )
            return "OUTDATED", str(detail)
        if matched:
            return "POLICY OK", f"Meets configured minimum {minimum}."
    return "UNASSESSED", "No matching local version policy rule."


def parse_xml(xml_text, rules):
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
            if not is_ftp_service(port_node):
                continue

            port = int(port_node.attrib.get("portid", "0"))
            name, product, version, extra, tunnel = service_details(port_node)
            product, version = refine_product_version(port_node, product, version)
            anonymous = anonymous_status(script_output(port_node, "ftp-anon"))
            vulners_output = script_output(port_node, "vulners")
            cves, max_cvss = extract_cves(vulners_output)
            built_in_cves, built_in_detail = known_version_cves(product, version)
            cves = sorted(set(cves + built_in_cves))
            version_risk, version_detail = evaluate_version(product, version, rules)

            protocol = "FTPS/TCP" if tunnel.lower() in {"ssl", "tls"} or name == "ftps" else "FTP/TCP"
            server = " ".join(value for value in [product, extra] if value).strip() or name or "FTP"

            reasons = []
            if anonymous == "ALLOWED":
                reasons.append("Anonymous FTP login accepted.")
            if cves:
                reasons.append(f"{len(cves)} high-confidence version-related CVE(s) matched.")
            if built_in_detail:
                reasons.append(built_in_detail)
            if version_risk == "OUTDATED":
                reasons.append(version_detail)

            if anonymous == "ALLOWED":
                status = "CONFIRMED ISSUE"
            elif cves or version_risk == "OUTDATED":
                status = "REVIEW"
            elif anonymous == "REJECTED" and version_risk == "POLICY OK":
                status = "SECURE"
            else:
                status = "REVIEW"

            if not reasons:
                reasons.append(version_detail or "FTP service detected; no confirmed issue identified.")
            if anonymous == "NOT TESTED":
                reasons.append("No anonymous-login verdict was returned.")

            if cves:
                cve_check = f"{len(cves)} CVE(S)"
            elif not exact_version(version):
                cve_check = "NO EXACT VERSION"
                reasons.append(
                    "CVE matching requires an exact product version; Nmap returned "
                    f"{version or 'no version'}."
                )
            else:
                cve_check = "NO MATCH"
                reasons.append(
                    "No CVE was returned for this exact fingerprint; this is not proof "
                    "that the software is fully patched."
                )

            rows.append({
                "ip": ip,
                "port": f"{port}/TCP",
                "protocol": protocol,
                "server": server,
                "version": version or "-",
                "anonymous": anonymous,
                "version_risk": version_risk,
                "status": status,
                "cve_check": cve_check,
                "max_cvss": f"{max_cvss:.1f}" if max_cvss is not None else "-",
                "cves": ",".join(cves) if cves else "-",
                "detail": " ".join(reasons),
            })
    return rows


async def scan_one(ip, ports, all_ports, min_rate, timeout, use_vulners, rules):
    xml_text, error = await run_nmap(
        ip, ports, all_ports, min_rate, timeout, use_vulners
    )
    rows = parse_xml(xml_text, rules)
    for row in rows:
        if row["anonymous"] != "NOT TESTED":
            continue
        port = int(row["port"].split("/", 1)[0])
        verdict, reply = await direct_anonymous_probe(
            ip,
            port,
            min(10, max(3, timeout)),
        )
        row["anonymous"] = verdict
        if verdict == "ALLOWED":
            row["status"] = "CONFIRMED ISSUE"
            row["detail"] = "Anonymous FTP login accepted by direct protocol check."
            if row["cves"] != "-":
                row["detail"] += " Version-related CVE match also present."
        elif verdict == "REJECTED":
            if row["status"] != "CONFIRMED ISSUE":
                row["status"] = "REVIEW"
            row["detail"] = (
                "Anonymous FTP login rejected. "
                + (f"Server reply: {reply}" if reply else "")
            ).strip()
    if not rows and error and "failed to resolve" not in error.lower():
        return []
    return rows


async def run_all(
    targets, workers, ports, all_ports, min_rate, timeout, use_vulners, rules
):
    queue = asyncio.Queue()
    results = []
    completed = 0
    vulnerable = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, vulnerable
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                rows = await scan_one(
                    ip, ports, all_ports, min_rate, timeout, use_vulners, rules
                )
                results.extend(rows)
                vulnerable += sum(row["status"] == "CONFIRMED ISSUE" for row in rows)
                completed += 1
                sys.stdout.write(
                    f"\rScanning FTP: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"FTP endpoints: {len(results)} | Vulnerable: {vulnerable} | Current: {ip}".ljust(145)
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


def print_table(rows, vulnerable_only=False, colors=True):
    displayed = [
        row for row in rows
        if not vulnerable_only or row["status"] == "CONFIRMED ISSUE"
    ]
    print()
    if not displayed:
        message = (
            "No vulnerable FTP endpoints were found."
            if vulnerable_only
            else "No FTP services were found on the selected ports."
        )
        print(message)
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        displayed,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 7),
            cell(row["server"], 30),
            cell(row["version"], 18),
            cell("-" if row["anonymous"] == "NOT TESTED" else row["anonymous"], 11),
            cell(row["cves"] if row["cves"] != "-" else row["cve_check"], 49),
            cell(row["status"], 12),
            cell(row["detail"], 54),
        ])
        code = RED if row["status"] == "CONFIRMED ISSUE" else YELLOW if row["status"] == "REVIEW" else GREEN
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "server", "version", "anonymous",
        "version_risk", "cve_check", "status", "max_cvss", "cves", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
        ))


def write_list(path, rows):
    vulnerable = {row["ip"] for row in rows if row["status"] == "CONFIRMED ISSUE"}
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted(vulnerable, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find FTP services, anonymous access, outdated versions, and known CVEs."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"TCP ports/ranges. Default: {DEFAULT_PORTS}")
    parser.add_argument("--all-ports", action="store_true", help="Scan all 65535 TCP ports for FTP")
    parser.add_argument("--min-rate", type=int, default=1000, help="Minimum packet rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host workers")
    parser.add_argument("-t", "--timeout", type=int, default=75, help="Nmap host timeout in seconds")
    parser.add_argument("--rules", help="JSON minimum-version policy file")
    parser.add_argument("--no-vulners", action="store_true", help="Do not run the vulners NSE script")
    parser.add_argument("--no-nvd", action="store_true", help="Do not query the NVD API for exact versions")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""), help="NVD API key or NVD_API_KEY environment variable")
    parser.add_argument("--nvd-timeout", type=int, default=30, help="NVD request timeout in seconds")
    parser.add_argument("--vulnerable-only", action="store_true", help="Display only directly confirmed issues")
    parser.add_argument("--csv", default="ftp_access_vulnerability_results.csv", help="CSV output path")
    parser.add_argument("--list", default="ftp_vulnerable_ips.txt", help="Vulnerable IP list path")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    rules = load_rules(args.rules)
    workers = min(max(1, args.workers), len(targets))
    use_vulners = not args.no_vulners and has_vulners_script()

    print(f"Loaded targets  : {len(targets)}")
    print(f"Workers         : {workers}")
    print(f"FTP ports       : {'1-65535/TCP' if args.all_ports else ports + '/TCP'}")
    print("Anonymous probe : ftp-anon (login/list only; no uploads)")
    print(f"CVE detection   : {'vulners NSE enabled' if use_vulners else 'not available/disabled'}")
    print(f"NVD lookup      : {'disabled' if args.no_nvd else 'exact product/version CPE'}")
    print(f"Version policy  : {args.rules if args.rules else 'none (use --rules for outdated-version thresholds)'}")
    print(f"Showing         : {'vulnerable only' if args.vulnerable_only else 'all detected FTP services'}")

    rows = asyncio.run(
        run_all(
            targets,
            workers,
            ports,
            args.all_ports,
            max(1, args.min_rate),
            args.timeout,
            use_vulners,
            rules,
        )
    )
    if not args.no_nvd:
        rows = enrich_from_nvd(
            rows,
            args.nvd_api_key,
            max(5, args.nvd_timeout),
        )
    print_table(rows, args.vulnerable_only, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable_rows = [row for row in rows if row["status"] == "CONFIRMED ISSUE"]
    anonymous_rows = [row for row in rows if row["anonymous"] == "ALLOWED"]
    cve_rows = [row for row in rows if row["cves"] != "-"]

    print()
    print(f"FTP endpoints found : {len(rows)}")
    print(f"Confirmed issues    : {len(vulnerable_rows)}")
    print(f"Anonymous allowed   : {len(anonymous_rows)}")
    print(f"Endpoints with CVEs : {len(cve_rows)}")
    print(f"Confirmed hosts     : {len({row['ip'] for row in vulnerable_rows})}")
    print(f"CSV written         : {args.csv}")
    print(f"IP list written     : {args.list}")
    return 1 if vulnerable_rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

