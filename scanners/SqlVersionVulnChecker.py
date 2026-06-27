#!/usr/bin/env python3
"""
SQL/database version vulnerability checker.

What it does:
  - Accepts a single IP, CIDR, plain IP list, or ip:port list.
  - Runs nmap service/version detection against SQL/database ports.
  - Detects MSSQL, MySQL/MariaDB, Oracle Database/TNS, PostgreSQL, DB2,
    MongoDB, Redis, and Elasticsearch-style services.
  - Flags unsupported/end-of-life or clearly outdated versions.
  - Optionally queries NVD for CVEs matching the detected product/version.

Examples:
  python3 SqlVersionVulnChecker.py -f sql_open_ip_ports.txt --nvd
  python3 SqlVersionVulnChecker.py 198.51.100.25 -p 51748 --nvd
  python3 SqlVersionVulnChecker.py 198.51.100.0/24 -p 1433,3306,1521 --workers 32

Notes:
  - This script is non-exploitative. It performs banner/service detection.
  - NVD lookup requires internet access. Use --nvd-api-key for higher limits.
  - CVE matching from banners is best-effort; validate CVEs against exact build
    and vendor patch level before final reporting.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

DEFAULT_PORTS = "1433,1434,1521,2483,2484,3306,33060,5432,50000,50001,3050,27017,27018,27019,6379,9200,49726,61662,49720"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 7),
    ("PRODUCT", 28),
    ("VERSION", 16),
    ("STATUS", 14),
    ("CVES", 45),
    ("DETAIL", 62),
]


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:width].ljust(width)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    # Accept ip:port/tcp - service lines.
    value = value.split()[0]
    if ":" in value and re.match(r"^[0-9.]+:\d+", value):
        ip, port = value.split(":", 1)
        return [(ip, port.split("/", 1)[0])]
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses == 1:
            return [(str(net.network_address), None)]
        return [(str(ip), None) for ip in net.hosts()]
    except ValueError:
        return [(value, None)]


def load_targets(args):
    items = []
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
            items.extend(expand_target(line))
    for target in args.targets:
        items.extend(expand_target(target))

    grouped = {}
    for ip, port in items:
        grouped.setdefault(ip, set())
        if port:
            grouped[ip].add(str(port))

    if not grouped:
        raise SystemExit("No targets supplied. Provide an IP/CIDR or use -f targets.txt")
    return grouped


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
    return ",".join(str(p) for p in sorted(set(ports)))


def ip_sort(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return value


async def run_nmap(ip, ports, timeout, deep=False):
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-T4",
        "-p",
        ports,
        "-oX",
        "-",
        ip,
    ]
    if deep:
        cmd.insert(4, "--version-all")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return [{
            "ip": ip,
            "port": "-",
            "product": "-",
            "version": "-",
            "service": "-",
            "status": "TIMEOUT",
            "detail": f"nmap timed out after {timeout}s",
            "cves": [],
        }]

    xml = stdout.decode(errors="replace")
    if not xml.strip():
        return [{
            "ip": ip,
            "port": "-",
            "product": "-",
            "version": "-",
            "service": "-",
            "status": "ERROR",
            "detail": stderr.decode(errors="replace").strip()[:180],
            "cves": [],
        }]
    return parse_nmap_xml(ip, xml)


def parse_nmap_xml(ip, xml):
    rows = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        return [{
            "ip": ip,
            "port": "-",
            "product": "-",
            "version": "-",
            "service": "-",
            "status": "ERROR",
            "detail": f"Failed to parse nmap XML: {exc}",
            "cves": [],
        }]

    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = port_el.attrib.get("portid", "")
        svc = port_el.find("service")
        if svc is None:
            continue
        service = svc.attrib.get("name", "")
        product = svc.attrib.get("product", "")
        version = svc.attrib.get("version", "")
        extrainfo = svc.attrib.get("extrainfo", "")
        cpes = [cpe.text or "" for cpe in svc.findall("cpe")]

        if not is_database_service(port, service, product, extrainfo, cpes):
            continue

        normalized_product = normalize_product(service, product, extrainfo, cpes)
        normalized_version = normalize_version(normalized_product, version, extrainfo)
        status, detail = classify(normalized_product, normalized_version, extrainfo)
        rows.append({
            "ip": ip,
            "port": port,
            "product": normalized_product,
            "version": normalized_version or version or "-",
            "service": service,
            "status": status,
            "detail": detail,
            "cves": [],
        })

    if not rows:
        rows.append({
            "ip": ip,
            "port": "-",
            "product": "-",
            "version": "-",
            "service": "-",
            "status": "NO DB",
            "detail": "No SQL/database service detected on scanned ports.",
            "cves": [],
        })
    return rows


def is_database_service(port, service, product, extrainfo, cpes):
    hay = " ".join([port, service, product, extrainfo, " ".join(cpes)]).lower()
    terms = [
        "ms-sql", "mssql", "sql server", "mysql", "mariadb", "postgres",
        "oracle database", "oracle-tns", "tns listener", "db2", "firebird",
        "sybase", "informix", "mongodb", "redis", "elasticsearch",
    ]
    if any(term in hay for term in terms):
        return True
    return port in {"1433", "1434", "1521", "2483", "2484", "3306", "33060", "5432", "50000", "50001", "3050", "27017", "27018", "27019", "6379", "9200"}


def normalize_product(service, product, extrainfo, cpes):
    hay = " ".join([service, product, extrainfo, " ".join(cpes)]).lower()
    if "microsoft sql server" in hay or "ms-sql" in hay or "mssql" in hay:
        return "Microsoft SQL Server"
    if "mysql" in hay:
        return "MySQL"
    if "mariadb" in hay:
        return "MariaDB"
    if "postgres" in hay:
        return "PostgreSQL"
    if "oracle database" in hay or "oracle-tns" in hay or "tns listener" in hay:
        return "Oracle Database"
    if "db2" in hay:
        return "IBM DB2"
    if "mongodb" in hay:
        return "MongoDB"
    if "redis" in hay:
        return "Redis"
    if "elasticsearch" in hay:
        return "Elasticsearch"
    return product or service or "Database Service"


def normalize_version(product, version, extrainfo):
    text = " ".join([version or "", extrainfo or ""])
    if product == "Microsoft SQL Server":
        match = re.search(r"(\d{2})\.(\d{2})\.(\d+)\.(\d+)", text)
        if match:
            return match.group(0)
        year = re.search(r"\b(2008|2012|2014|2016|2017|2019|2022)\b", text)
        return year.group(1) if year else version
    match = re.search(r"\b(\d+(?:\.\d+){1,4})\b", text)
    return match.group(1) if match else version


def version_nums(version):
    return tuple(int(x) for x in re.findall(r"\d+", version or ""))


def classify(product, version, extrainfo):
    nums = version_nums(version)
    text = " ".join([product or "", version or "", extrainfo or ""]).lower()

    if product == "Microsoft SQL Server":
        # Major version mapping: 11=2012, 12=2014, 13=2016, 14=2017, 15=2019, 16=2022.
        major = nums[0] if nums else None
        if major == 11 or "2012" in text:
            return "LIFECYCLE REVIEW", "SQL Server 2012 detected; verify ESU/support entitlement and exact patch level."
        if major == 12 or "2014" in text:
            return "LIFECYCLE REVIEW", "SQL Server 2014 detected; verify support entitlement and exact patch level."
        if major == 13 or "2016" in text:
            return "REVIEW", "SQL Server 2016 is old; verify latest cumulative update and support status."
        if major == 14 or "2017" in text:
            if nums and len(nums) >= 3 and nums[2] <= 1000:
                return "PATCH REVIEW", "SQL Server 2017 base-like build detected; confirm the exact CU and vendor servicing state."
            return "REVIEW", "SQL Server 2017 detected; verify latest cumulative update and support status."
        if major in (15, 16):
            return "REVIEW", "Supported SQL Server generation detected; verify latest cumulative update."
        return "REVIEW", "Microsoft SQL Server detected; version/build could not be fully classified."

    if product in {"MySQL", "MariaDB"}:
        if nums and nums[0] < 8 and product == "MySQL":
            return "LIFECYCLE REVIEW", "MySQL major version before 8.0 detected; verify vendor/distribution support and backported fixes."
        if nums and nums[0] == 8:
            return "REVIEW", "MySQL 8.x detected; verify current patch level against vendor advisories."
        return "REVIEW", f"{product} detected; verify exact patch level against vendor advisories."

    if product == "Oracle Database":
        if nums and nums[0] < 19:
            return "LIFECYCLE REVIEW", "Oracle Database version appears older than 19c; verify the licensed support policy and CPU patch level."
        return "REVIEW", "Oracle Database/TNS detected; validate exact database version and CPU patch level."

    if product == "PostgreSQL":
        if nums and nums[0] < 13:
            return "LIFECYCLE REVIEW", "Older PostgreSQL major version detected; verify the current vendor lifecycle and packaged support."
        return "REVIEW", "PostgreSQL detected; verify minor release is fully patched."

    if product == "MongoDB":
        if nums and nums[0] < 6:
            return "PATCH REVIEW", "Older MongoDB major version detected; verify support status and exact patch level."
        return "REVIEW", "MongoDB detected; verify latest patch level and authentication exposure."

    if product == "Redis":
        if nums and nums[0] < 7:
            return "PATCH REVIEW", "Older Redis major version detected; verify support status and exact patch level."
        return "REVIEW", "Redis detected; verify latest patch level and authentication/bind settings."

    return "REVIEW", "Database service detected; validate exact product/version against vendor advisories."


def progress_line(done, total, found, flagged, current=""):
    pct = (done / total * 100) if total else 100
    msg = f"\rScanning: {done}/{total} ({pct:5.1f}%) | DB found: {found} | Flagged: {flagged}"
    if current:
        msg += f" | Current: {current}"
    sys.stdout.write(msg[:160].ljust(160))
    sys.stdout.flush()


async def run_all(target_map, default_ports, workers, timeout, deep=False):
    queue = asyncio.Queue()
    results = []
    total = len(target_map)
    completed = 0
    found_count = 0
    flagged_count = 0
    lock = asyncio.Lock()
    for ip, ports in target_map.items():
        port_string = ",".join(sorted(ports, key=lambda p: int(p))) if ports else default_ports
        await queue.put((ip, port_string))

    async def worker():
        nonlocal completed, found_count, flagged_count
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            ip, ports = item
            async with lock:
                progress_line(completed, total, found_count, flagged_count, ip)
            rows = await run_nmap(ip, ports, timeout, deep=deep)
            results.extend(rows)
            interesting = [r for r in rows if r["status"] not in {"NO DB", "ERROR", "TIMEOUT"}]
            flagged = [
                r for r in rows
                if r["status"] in {"LIFECYCLE REVIEW", "PATCH REVIEW"}
            ]
            async with lock:
                completed += 1
                found_count += len(interesting)
                flagged_count += len(flagged)
                progress_line(completed, total, found_count, flagged_count, ip)
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return results


def nvd_lookup(product, version, api_key=None, max_cves=8):
    if not product or product == "-":
        return []
    query = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
        "keywordSearch": query,
        "cvssV3Severity": "HIGH",
        "resultsPerPage": str(max_cves),
    })
    req = urllib.request.Request(url, headers={"User-Agent": "sql-version-vuln-checker/1.0"})
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return []
    found = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        score = None
        severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0]
                cvss = metric.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
                break
        if cve_id:
            found.append({"id": cve_id, "score": score, "severity": severity})
    return found


def enrich_with_nvd(rows, api_key=None, delay=0.7):
    cache = {}
    for row in rows:
        if row["status"] in {"NO DB", "ERROR", "TIMEOUT"}:
            continue
        key = (row["product"], row["version"])
        if key not in cache:
            cache[key] = nvd_lookup(row["product"], row["version"], api_key=api_key)
            time.sleep(delay)
        row["cves"] = cache[key]


def cve_text(cves):
    if not cves:
        return "-"
    parts = []
    for cve in cves[:6]:
        suffix = ""
        if cve.get("score"):
            suffix = f"({cve['score']})"
        parts.append(cve["id"] + suffix)
    return ", ".join(parts)


def print_table(rows, colors=True, show_all=False):
    shown = [r for r in rows if show_all or r["status"] not in {"NO DB", "ERROR", "TIMEOUT"}]
    print()
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(shown, key=lambda r: (ip_sort(r["ip"]), str(r["port"]))):
        code = RED if row["status"] in {"LIFECYCLE REVIEW", "PATCH REVIEW"} else YELLOW if row["status"] in {"REVIEW", "UNKNOWN"} else GREEN
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 7),
            cell(row["product"], 28),
            cell(row["version"], 16),
            cell(row["status"], 14),
            cell(cve_text(row["cves"]), 45),
            cell(row["detail"], 62),
        ])
        print(color(line, code, colors))


def write_csv(path, rows, show_all=False):
    shown = [r for r in rows if show_all or r["status"] not in {"NO DB", "ERROR", "TIMEOUT"}]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "port", "product", "version", "service", "status", "cves", "detail"])
        writer.writeheader()
        for row in sorted(shown, key=lambda r: (ip_sort(r["ip"]), str(r["port"]))):
            writer.writerow({
                "ip": row["ip"],
                "port": row["port"],
                "product": row["product"],
                "version": row["version"],
                "service": row["service"],
                "status": row["status"],
                "cves": cve_text(row["cves"]),
                "detail": row["detail"],
            })


def main():
    parser = argparse.ArgumentParser(description="Check SQL/database service versions for outdated/vulnerable builds.")
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port entry")
    parser.add_argument("-f", "--file", help="Input file with IPs, CIDRs, or ip:port lines")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports to scan when input has no explicit port")
    parser.add_argument("-w", "--workers", type=int, default=8, help="Concurrent nmap workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Timeout per host in seconds")
    parser.add_argument("--deep", action="store_true", help="Use slower nmap --version-all detection")
    parser.add_argument("--nvd", action="store_true", help="Query NVD for CVEs matching detected product/version")
    parser.add_argument("--nvd-api-key", help="NVD API key")
    parser.add_argument("--csv", default="sql_version_vuln_results.csv", help="CSV output path")
    parser.add_argument("--show-all", action="store_true", help="Show targets where no DB service was detected")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found in PATH. Install nmap first.")

    target_map = load_targets(args)
    ports = parse_ports(args.ports)
    workers = min(max(1, args.workers), len(target_map))

    explicit_targets = sum(1 for pset in target_map.values() if pset)
    mode = f"{explicit_targets} target(s) with explicit ports" if explicit_targets else "default SQL/database port set"
    print(f"Loaded targets : {len(target_map)}")
    print(f"Scan mode      : {mode}")
    print(f"Workers        : {workers}")
    print(f"NVD CVE lookup : {'enabled' if args.nvd else 'disabled'}")

    rows = asyncio.run(run_all(target_map, ports, workers, args.timeout, deep=args.deep))
    if args.nvd:
        print("Querying NVD for CVEs...")
        enrich_with_nvd(rows, api_key=args.nvd_api_key)

    print_table(rows, colors=not args.no_color, show_all=args.show_all)
    write_csv(args.csv, rows, show_all=args.show_all)

    flagged = sum(1 for r in rows if r["status"] in {"LIFECYCLE REVIEW", "PATCH REVIEW"})
    review = sum(1 for r in rows if r["status"] == "REVIEW")
    detected = sum(1 for r in rows if r["status"] not in {"NO DB", "ERROR", "TIMEOUT"})
    print()
    print(f"Database services detected : {detected}")
    print(f"Lifecycle/patch candidates : {flagged}")
    print(f"Review manually            : {review}")
    print(f"CSV written                : {args.csv}")
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())


