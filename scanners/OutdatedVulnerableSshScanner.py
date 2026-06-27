#!/usr/bin/env python3
"""
Find outdated SSH server versions and version-applicable CVEs from NVD.

The scanner performs read-only SSH service identification. It does not
authenticate, guess passwords, or execute commands.

Requirements:
    sudo apt install nmap

Examples:
    python3 OutdatedVulnerableSshScanner.py -f target_ips.txt
    python3 OutdatedVulnerableSshScanner.py 192.0.2.0/24 --show-all
    python3 OutdatedVulnerableSshScanner.py -f target_ips.txt --all-ports
    python3 OutdatedVulnerableSshScanner.py -f target_ips.txt --nvd-api-key KEY
    python3 OutdatedVulnerableSshScanner.py -f target_ips.txt --rules ssh_version_rules_example.json

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

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OPENSSH_RELEASES = "https://www.openssh.com/releasenotes.html"
FALLBACK_OPENSSH = "10.3p1"
DEFAULT_PORTS = "22,222,2222,2022,2200,8022,10022,22222"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PRODUCT", 14),
    ("VERSION", 14),
    ("LATEST", 14),
    ("STATUS", 17),
    ("MAX CVSS", 9),
    ("NVD CVES", 52),
]

CPE_PRODUCTS = {
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "libssh": ("libssh", "libssh"),
}


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "-").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return text[:width].ljust(width)


def ip_sort(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except Exception:
        return (999, value)


def version_tuple(value):
    text = str(value or "").lower()
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:p(\d+))?", text)
    if not match:
        return ()
    return tuple(int(part or 0) for part in match.groups())


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


def url_text(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SSH-Version-Audit/1.0"},
    )
    with urllib.request.urlopen(
        request, timeout=timeout, context=ssl.create_default_context()
    ) as response:
        return response.read().decode("utf-8", errors="replace")


def url_json(url, timeout, api_key=""):
    headers = {
        "User-Agent": "SSH-Version-Audit/1.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(
        request, timeout=timeout, context=ssl.create_default_context()
    ) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def current_openssh(timeout):
    try:
        page = url_text(OPENSSH_RELEASES, timeout)
        match = re.search(
            r"OpenSSH\s+(\d+(?:\.\d+){1,2})\s*/\s*(\d+(?:\.\d+){1,2}p\d+)",
            page,
            re.I,
        )
        if match:
            return match.group(2), "openssh.com"
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        pass
    return FALLBACK_OPENSSH, "fallback"


def load_rules(path):
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Could not load rules file: {error}")
    rules = {}
    for name, rule in payload.get("products", {}).items():
        if isinstance(rule, dict):
            rules[name.lower()] = rule
    return rules


async def run_nmap(ip, ports, all_ports, timeout, min_rate):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "--host-timeout", timeout,
        "--script", "banner",
    ]
    if all_ports:
        command.extend(["-p-", "--min-rate", str(min_rate)])
    else:
        command.extend(["-p", ports])
    command.extend(["-oX", "-", ip])
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "") if script is not None else ""


def identify_ssh(evidence, service):
    patterns = [
        ("OpenSSH", "openssh", r"\bOpenSSH[_/\s-]*(\d+(?:\.\d+){1,2}(?:p\d+)?)"),
        ("Dropbear", "dropbear", r"\bdropbear[_/\s-]*(\d{4}\.\d+|\d+(?:\.\d+){1,2})"),
        ("libssh", "libssh", r"\blibssh[_/\s-]*(\d+(?:\.\d+){1,3})"),
        ("Bitvise", "bitvise", r"\bBitvise(?:\s+SSH\s+Server)?[_/\s-]*(\d+(?:\.\d+){1,3})"),
    ]
    for display, key, pattern in patterns:
        match = re.search(pattern, evidence, re.I)
        if match:
            return display, key, match.group(1)

    product = service.attrib.get("product", "").strip() if service is not None else ""
    version = service.attrib.get("version", "").strip() if service is not None else ""
    lower = product.lower()
    for display, key, _ in patterns:
        if key in lower or display.lower() in lower:
            return display, key, version
    return product or "SSH server", "other", version


def parse_nmap(xml_text):
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
            fields = []
            if service is not None:
                fields.extend([
                    service.attrib.get("name", ""),
                    service.attrib.get("product", ""),
                    service.attrib.get("version", ""),
                    service.attrib.get("extrainfo", ""),
                    service.attrib.get("servicefp", ""),
                ])
            fields.append(script_output(port_node, "banner"))
            evidence = " ".join(value for value in fields if value)
            name = service.attrib.get("name", "").lower() if service is not None else ""
            if name != "ssh" and not re.search(
                r"\bSSH-\d+\.\d+|openssh|dropbear|libssh|bitvise", evidence, re.I
            ):
                continue
            product, product_key, version = identify_ssh(evidence, service)
            banner_match = re.search(r"SSH-\d+\.\d+-[^\s\\]+", evidence, re.I)
            rows.append({
                "ip": ip,
                "port": int(port_node.attrib.get("portid", "0")),
                "protocol": "SSH/TCP",
                "product": product,
                "product_key": product_key,
                "version": version,
                "banner": banner_match.group(0) if banner_match else evidence[:180],
            })
    return rows


async def discover_one(ip, args, ports):
    xml_text = await run_nmap(
        ip, ports, args.all_ports, args.host_timeout, args.min_rate
    )
    return parse_nmap(xml_text)


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
                    rows.extend(await discover_one(ip, args, ports))
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} discovery failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rDiscovering SSH: {completed}/{len(targets)} "
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


def metric_score(cve):
    metrics = cve.get("metrics", {})
    for group in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(group, [])
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if score is not None:
            return float(score), str(severity or "")
    return 0.0, ""


def english_description(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def query_nvd(product_key, version, api_key, timeout, rule):
    cpe_info = CPE_PRODUCTS.get(product_key)
    if rule.get("cpe_vendor") and rule.get("cpe_product"):
        cpe_info = (rule["cpe_vendor"], rule["cpe_product"])
    if not cpe_info:
        return [], "No exact NVD CPE mapping is configured for this SSH product."

    vendor, product = cpe_info
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    params = urllib.parse.urlencode({
        "cpeName": cpe,
        "resultsPerPage": "2000",
    })
    url = f"{NVD_API}?{params}&isVulnerable&noRejected"
    try:
        payload = url_json(url, timeout, api_key)
    except urllib.error.HTTPError as error:
        return [], f"NVD HTTP {error.code}"
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as error:
        return [], f"NVD unavailable: {error}"

    results = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve.get("vulnStatus", "").lower() == "rejected":
            continue
        score, severity = metric_score(cve)
        results.append({
            "id": cve_id,
            "score": score,
            "severity": severity,
            "description": english_description(cve),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    results.sort(key=lambda item: (-item["score"], item["id"]))
    return results, ""


def load_cache(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(path, cache):
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(cache, handle, indent=2, sort_keys=True)


def enrich_versions(rows, args, rules):
    cache = load_cache(args.nvd_cache)
    keys = sorted({
        (row["product_key"], row["version"])
        for row in rows if row["version"]
    })
    enriched = {}
    if args.skip_nvd:
        for product_key, version in keys:
            enriched[f"{product_key}:{version}"] = {
                "cves": [],
                "error": "NVD lookup skipped by --skip-nvd.",
            }
        return enriched, 0

    queried = 0
    for index, (product_key, version) in enumerate(keys, start=1):
        cache_key = f"{product_key}:{version}"
        print(
            f"Querying NVD {index}/{len(keys)}: {product_key} {version}",
            file=sys.stderr,
        )
        if cache_key in cache:
            enriched[cache_key] = cache[cache_key]
            continue
        cves, error = query_nvd(
            product_key, version, args.nvd_api_key, args.nvd_timeout,
            rules.get(product_key, {}),
        )
        entry = {"cves": cves, "error": error, "queried": int(time.time())}
        enriched[cache_key] = entry
        if not error or error.startswith("No exact"):
            cache[cache_key] = entry
        queried += 1
        if index < len(keys) and not error:
            time.sleep(0.7 if args.nvd_api_key else 6.0)
    save_cache(args.nvd_cache, cache)
    return enriched, queried


def assess(rows, openssh_latest, enriched, rules, show_all):
    output = []
    for row in rows:
        key = row["product_key"]
        version = row["version"]
        rule = rules.get(key, {})
        latest = rule.get("latest", "")
        minimum = rule.get("minimum_supported", "")
        if key == "openssh":
            latest = latest or openssh_latest
            minimum = minimum or latest

        nvd = enriched.get(
            f"{key}:{version}",
            {"cves": [], "error": "Exact version unavailable; NVD was not queried."},
        )
        cves = nvd.get("cves", []) if version else []
        old = bool(version and minimum and version_tuple(version) < version_tuple(minimum))

        if not version:
            status = "VERSION HIDDEN"
        elif cves:
            status = "VULNERABLE?"
        elif old:
            status = "OUTDATED BANNER"
        elif minimum:
            status = "CURRENT"
        else:
            status = "DETECTED"

        notes = []
        if old:
            notes.append(f"Banner version is older than configured baseline {minimum}.")
        if cves:
            notes.append("NVD returned version-applicable CVE candidates.")
        if key == "openssh" and (old or cves):
            notes.append(
                "Verify the installed OS package/advisory because vendors may backport fixes "
                "without changing the OpenSSH banner."
            )
        if status == "DETECTED":
            notes.append("No lifecycle baseline is configured for this product.")
        if status == "VERSION HIDDEN":
            notes.append("SSH was detected, but an exact product version was not exposed.")

        row.update({
            "latest": latest,
            "status": status,
            "max_cvss": max((item["score"] for item in cves), default=0.0),
            "cves": cves,
            "nvd_error": nvd.get("error", "") if version else nvd["error"],
            "detail": " ".join(notes),
        })
        if show_all or status in {"VULNERABLE?", "OUTDATED BANNER"}:
            output.append(row)
    return output


def cve_ids(row):
    return ",".join(item["id"] for item in row["cves"]) or "-"


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No outdated SSH banners or NVD version matches were identified.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 9),
            cell(row["product"], 14),
            cell(row["version"] or "HIDDEN", 14),
            cell(row["latest"], 14),
            cell(row["status"], 17),
            cell(f"{row['max_cvss']:.1f}" if row["max_cvss"] else "-", 9),
            cell(cve_ids(row), 52),
        ])
        code = RED if row["status"] == "VULNERABLE?" else (
            YELLOW if row["status"] in {"OUTDATED BANNER", "VERSION HIDDEN", "DETECTED"}
            else GREEN
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "product", "version", "latest",
        "status", "max_cvss", "cve_ids", "cve_details", "banner",
        "detail", "nvd_error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            writer.writerow({
                "ip": row["ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "product": row["product"],
                "version": row["version"],
                "latest": row["latest"],
                "status": row["status"],
                "max_cvss": row["max_cvss"],
                "cve_ids": cve_ids(row),
                "cve_details": " | ".join(
                    f"{item['id']} CVSS={item['score']:.1f} {item['severity']} "
                    f"{item['url']} {item['description']}"
                    for item in row["cves"]
                ),
                "banner": row["banner"],
                "detail": row["detail"],
                "nvd_error": row["nvd_error"],
            })


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            if row["status"] in {"VULNERABLE?", "OUTDATED BANNER"}:
                handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find outdated SSH server banners and retrieve exact-version CVEs from NVD."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="SSH ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Discover SSH on all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="90s", help="Nmap timeout per host")
    parser.add_argument("--show-all", action="store_true", help="Show every detected SSH endpoint")
    parser.add_argument("--rules", help="Optional JSON lifecycle/CPE policy")
    parser.add_argument("--openssh-latest", help="Override latest OpenSSH portable version")
    parser.add_argument(
        "--nvd-api-key",
        default=os.environ.get("NVD_API_KEY", ""),
        help="NVD API key; defaults to NVD_API_KEY",
    )
    parser.add_argument("--nvd-timeout", type=int, default=30, help="Web request timeout")
    parser.add_argument("--nvd-cache", default="ssh_nvd_cache.json", help="NVD cache file")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip online CVE lookups")
    parser.add_argument("--csv", default="ssh_version_results.csv", help="CSV output")
    parser.add_argument("--list", default="ssh_affected_endpoints.txt", help="Affected IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    rules = load_rules(args.rules)
    args.workers = min(max(1, args.workers), len(targets))
    if args.openssh_latest:
        openssh_latest, latest_source = args.openssh_latest, "command line"
    else:
        openssh_latest, latest_source = current_openssh(args.nvd_timeout)

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"SSH ports      : {'all TCP ports' if args.all_ports else ports}")
    print(f"OpenSSH latest : {openssh_latest} ({latest_source})")
    print(
        "CVE source     : "
        + (
            "disabled (--skip-nvd)"
            if args.skip_nvd
            else "NVD CVE API 2.0 using recognized exact product/version CPEs"
        )
    )
    print("Probe          : SSH identification only; no authentication or commands")
    print(f"Showing        : {'all detected SSH endpoints' if args.show_all else 'outdated/CVE-matched endpoints only'}")

    discovered = asyncio.run(discover_all(targets, args, ports))
    enriched, _ = enrich_versions(discovered, args, rules)
    rows = assess(discovered, openssh_latest, enriched, rules, args.show_all)

    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    affected = sum(
        1 for row in rows if row["status"] in {"VULNERABLE?", "OUTDATED BANNER"}
    )
    print()
    print(f"SSH endpoints found : {len(discovered)}")
    print(f"Displayed endpoints : {len(rows)}")
    print(f"Affected candidates : {affected}")
    print(f"CSV written         : {args.csv}")
    print(f"Endpoint list       : {args.list}")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())

