#!/usr/bin/env python3
"""
Find exposed and potentially vulnerable Apache Tomcat servers.

The scanner is non-exploitative. It uses:
  - Nmap service/version detection
  - HTTP GET/HEAD/OPTIONS requests
  - Tomcat headers, default pages, error pages, docs and Manager endpoints
  - Version-aware CVE candidate mapping
  - AJP exposure detection on common AJP ports

CVEs marked with "?" require configuration conditions that cannot be proven
remotely by version detection alone.

Requirements:
    sudo apt install nmap

Examples:
    python3 TomcatVulnerabilityScanner.py -f target_ips.txt
    python3 TomcatVulnerabilityScanner.py 192.0.2.0/24 --workers 16
    python3 TomcatVulnerabilityScanner.py -f target_ips.txt --show-all

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import http.client
import ipaddress
import re
import shutil
import ssl
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "80-90,443,444,591,593,631,7001-7005,7070,7080,7443,"
    "7777,7780,7800,8000-8012,8020,8030,8040,8050,8060,"
    "8070,8080-8090,8100,8180,8181,8200,8280,8282,8300,"
    "8383,8442,8443,8484,8500,8585,8686,8787,8880,8888,"
    "8983,8999,9000,9001,9009,9043,9080,9090,9091,9443,"
    "9990,9999,10000,10080,10443,18080,18081,18090,28080,"
    "38080,48080,58080"
)

HTTP_PATHS = (
    "/",
    "/manager/html",
    "/host-manager/html",
    "/docs/",
    "/examples/",
    "/__server_probe_7f31c9__",
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 6),
    ("PROTO", 6),
    ("VERSION", 13),
    ("RISK", 8),
    ("CVES", 46),
    ("EVIDENCE", 72),
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


def version_tuple(value):
    if not value:
        return ()
    return tuple(int(number) for number in re.findall(r"\d+", value)[:4])


def version_at_most(version, maximum):
    current = version_tuple(version)
    return bool(current) and current <= version_tuple(maximum)


def version_before(version, fixed):
    current = version_tuple(version)
    return bool(current) and current < version_tuple(fixed)


def branch(version):
    parts = version_tuple(version)
    if len(parts) < 2:
        return ""
    return f"{parts[0]}.{parts[1]}"


async def run_nmap(ip, ports, timeout, deep=False):
    command = [
        "nmap", "-Pn", "-n", "-sV",
        "--version-all" if deep else "--version-light",
        "--open",
        "-p", ports,
        "--host-timeout", timeout,
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


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
        service = port_node.find("service")
        attributes = service.attrib if service is not None else {}
        endpoint = {
            "port": int(port_node.attrib.get("portid", "0")),
            "service": attributes.get("name", ""),
            "product": attributes.get("product", ""),
            "version": attributes.get("version", ""),
            "extra": attributes.get("extrainfo", ""),
            "tunnel": attributes.get("tunnel", ""),
        }
        fingerprint = " ".join(
            endpoint[key] for key in ("service", "product", "version", "extra")
        )
        endpoint["tomcat_hint"] = bool(
            re.search(r"tomcat|coyote|apache jserv|ajp13?", fingerprint, re.I)
        )
        endpoints.append(endpoint)
    return endpoints


def request_url(ip, port, scheme, path, method, timeout):
    url = f"{scheme}://{ip}:{port}{path}"
    request = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": "Mozilla/5.0 Tomcat-Security-Audit"},
    )
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            try:
                body_bytes = response.read(512 * 1024)
            except http.client.IncompleteRead as error:
                body_bytes = error.partial
            body = body_bytes.decode("utf-8", errors="ignore")
            headers = dict(response.headers.items())
            return {
                "url": url,
                "status": response.status,
                "headers": headers,
                "body": body,
            }
    except urllib.error.HTTPError as error:
        try:
            body_bytes = error.read(512 * 1024)
        except http.client.IncompleteRead as incomplete:
            body_bytes = incomplete.partial
        body = body_bytes.decode("utf-8", errors="ignore")
        return {
            "url": url,
            "status": error.code,
            "headers": dict(error.headers.items()) if error.headers else {},
            "body": body,
        }
    except (
        urllib.error.URLError,
        TimeoutError,
        ssl.SSLError,
        OSError,
        http.client.HTTPException,
        ValueError,
    ):
        return None


async def async_request(ip, port, scheme, path, method, timeout):
    return await asyncio.to_thread(
        request_url, ip, port, scheme, path, method, timeout
    )


def extract_version(text):
    patterns = (
        r"Apache Tomcat[/\s-]+(\d+(?:\.\d+){1,3})",
        r"Apache-Coyote[/\s-]+(\d+(?:\.\d+){1,3})",
        r"Tomcat[/\s-]+(\d+(?:\.\d+){1,3})",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1)
    return ""


def analyze_responses(responses):
    evidence = []
    diagnostics = []
    versions = []
    detected = False
    manager = False
    host_manager = False
    docs = False
    examples = False
    put_advertised = False
    proto = "http"

    for response in responses:
        if not response:
            continue
        proto = response["url"].split(":", 1)[0]
        headers_text = "\n".join(
            f"{key}: {value}" for key, value in response["headers"].items()
        )
        combined = headers_text + "\n" + response["body"]
        version = extract_version(combined)
        if version:
            versions.append(version)

        server = response["headers"].get("Server", "")
        auth_realm = response["headers"].get("WWW-Authenticate", "")
        powered_by = response["headers"].get("X-Powered-By", "")
        set_cookie = response["headers"].get("Set-Cookie", "")
        if re.search(
            r"Apache\s+Tomcat|Apache-Coyote|"
            r"Tomcat Web Application Manager|Tomcat Host Manager",
            combined,
            re.I,
        ):
            detected = True
            if server:
                evidence.append(f"Server: {server}")
        if re.search(r"tomcat|apache-coyote", server, re.I):
            detected = True
            evidence.append(f"Server: {server}")
        if re.search(r"tomcat|servlet|jsp", powered_by, re.I):
            detected = True
            evidence.append(f"X-Powered-By: {powered_by}")

        url = response["url"]
        status = response["status"]
        body = response["body"]
        diagnostics.append(
            f"{url}={status}"
            + (f",Server={server}" if server else "")
            + (f",Realm={auth_realm}" if auth_realm else "")
            + (f",X-Powered-By={powered_by}" if powered_by else "")
        )
        if "/manager/html" in url and (
            re.search(r"Tomcat Web Application Manager|Manager Application", body, re.I)
            or re.search(r"Tomcat Manager|Manager Application", auth_realm, re.I)
        ):
            manager = True
            detected = True
            evidence.append(f"/manager/html returned Tomcat Manager ({status})")
        elif "/host-manager/html" in url and (
            re.search(r"Tomcat Host Manager|Host Manager", body, re.I)
            or re.search(r"Tomcat Host Manager|Host Manager", auth_realm, re.I)
        ):
            host_manager = True
            detected = True
            evidence.append(f"/host-manager/html exposed ({status})")
        elif "/docs/" in url and re.search(r"Apache Tomcat", body, re.I):
            docs = True
            detected = True
            evidence.append(f"/docs/ exposed ({status})")
        elif "/examples/" in url and re.search(r"Tomcat|Servlet|JSP", body, re.I):
            examples = True
            detected = True
            evidence.append(f"/examples/ exposed ({status})")

        allow = response["headers"].get("Allow", "")
        if re.search(r"\bPUT\b", allow, re.I):
            put_advertised = True
            evidence.append("OPTIONS/Allow advertises PUT")

        # JSESSIONID is supporting evidence only when another Java/Tomcat
        # indicator is present; many non-Tomcat Java servers also use it.
        if detected and "JSESSIONID" in set_cookie.upper():
            evidence.append("JSESSIONID cookie observed")

    return {
        "detected": detected,
        "version": sorted(versions, key=version_tuple)[-1] if versions else "",
        "manager": manager,
        "host_manager": host_manager,
        "docs": docs,
        "examples": examples,
        "put_advertised": put_advertised,
        "proto": proto,
        "evidence": list(dict.fromkeys(evidence)),
        "diagnostics": diagnostics,
    }


def cve_candidates(version, ajp_exposed, put_advertised):
    cves = []
    b = branch(version)

    if not version:
        return cves

    if (
        (b == "11.0" and version_before(version, "11.0.3"))
        or (b == "10.1" and version_before(version, "10.1.35"))
        or (b == "9.0" and version_before(version, "9.0.99"))
    ):
        cves.append("CVE-2025-24813?")

    if (
        (b == "11.0" and version_before(version, "11.0.2"))
        or (b == "10.1" and version_before(version, "10.1.34"))
        or (b == "9.0" and version_before(version, "9.0.98"))
    ):
        cves.extend(["CVE-2024-50379?", "CVE-2024-56337?"])

    if (
        (b == "8.0" and version_at_most(version, "8.0.46"))
        or (b == "8.5" and version_at_most(version, "8.5.22"))
        or (b == "9.0" and version_before(version, "9.0.1"))
    ):
        cves.append("CVE-2017-12617?" if not put_advertised else "CVE-2017-12617")

    if ajp_exposed and (
        (b == "8.5" and version_before(version, "8.5.51"))
        or (b == "9.0" and version_before(version, "9.0.31"))
        or b in {"6.0", "7.0", "8.0"}
    ):
        cves.append("CVE-2020-1938?")

    return list(dict.fromkeys(cves))


def risk_for(version, cves, manager, host_manager, ajp_exposed):
    if any(cve in cves for cve in ("CVE-2017-12617",)):
        return "CRITICAL"
    if cves or manager or host_manager:
        return "HIGH*"
    if ajp_exposed:
        return "MEDIUM*"
    if version:
        major = version_tuple(version)[0]
        if major <= 8:
            return "HIGH*"
    return "INFO"


async def probe_http_endpoint(ip, endpoint, timeout, deep=False):
    port = endpoint["port"]
    preferred = "https" if endpoint["tunnel"] in {"ssl", "tls"} or port in {
        443, 444, 7443, 8442, 8443, 9043, 9443, 10443
    } else "http"
    schemes = (preferred, "http" if preferred == "https" else "https")

    if not deep:
        schemes = (preferred,)

    paths = HTTP_PATHS if deep else (
        "/",
        "/manager/html",
        "/host-manager/html",
        "/__server_probe_7f31c9__",
    )

    for scheme in schemes:
        tasks = [
            async_request(ip, port, scheme, path, "GET", timeout)
            for path in paths
        ]
        if deep:
            tasks.append(async_request(ip, port, scheme, "/", "OPTIONS", timeout))
        responses = await asyncio.gather(*tasks)
        if any(responses):
            return analyze_responses(responses)
    return analyze_responses([])


async def scan_host(
    ip, ports, host_timeout, http_timeout, show_all, deep=False, diagnose=False
):
    endpoints = parse_nmap(await run_nmap(ip, ports, host_timeout, deep=deep))
    ajp_ports = [
        endpoint["port"]
        for endpoint in endpoints
        if endpoint["service"].lower().startswith("ajp")
        or re.search(r"apache jserv|ajp", endpoint["product"], re.I)
        or endpoint["port"] in {8009, 9009}
        and endpoint["tomcat_hint"]
    ]
    rows = []

    known_web_ports = {
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        443, 444, 591, 593, 631, 7001, 7002, 7003, 7004, 7005,
        7070, 7080, 7443, 7777, 7780, 7800, 8000, 8001, 8002,
        8003, 8004, 8005, 8006, 8007, 8008, 8010, 8011, 8012,
        8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081, 8082,
        8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8100,
        8180, 8181, 8200, 8280, 8282, 8300, 8383, 8442, 8443,
        8484, 8500, 8585, 8686, 8787, 8880, 8888, 8983, 8999,
        9000, 9001, 9043, 9080, 9090, 9091, 9443, 9990, 9999,
        10000, 10080, 10443, 18080, 18081, 18090, 28080, 38080,
        48080, 58080,
    }
    likely_http = [
        endpoint for endpoint in endpoints
        if (
            "http" in endpoint["service"].lower()
            or endpoint["tunnel"] in {"ssl", "tls"}
            or endpoint["tomcat_hint"]
            or endpoint["port"] in known_web_ports
        )
    ]

    analyses = await asyncio.gather(
        *(
            probe_http_endpoint(ip, endpoint, http_timeout, deep=deep)
            for endpoint in likely_http
        )
    )
    for endpoint, analysis in zip(likely_http, analyses):
        nmap_text = " ".join(
            endpoint[key] for key in ("product", "version", "extra")
        )
        nmap_version = extract_version(nmap_text)
        detected = analysis["detected"] or endpoint["tomcat_hint"]
        if not detected:
            if diagnose and analysis["diagnostics"]:
                rows.append({
                    "ip": ip,
                    "port": endpoint["port"],
                    "proto": analysis["proto"],
                    "version": "NOT DETECTED",
                    "risk": "DIAG",
                    "cves": "-",
                    "evidence": " | ".join(analysis["diagnostics"]),
                })
            continue

        version = analysis["version"] or nmap_version or endpoint["version"]
        ajp_exposed = bool(ajp_ports)
        cves = cve_candidates(version, ajp_exposed, analysis["put_advertised"])
        risk = risk_for(
            version, cves, analysis["manager"], analysis["host_manager"], ajp_exposed
        )

        evidence = list(analysis["evidence"])
        if endpoint["tomcat_hint"]:
            product = " ".join(
                value for value in (
                    endpoint["product"], endpoint["version"], endpoint["extra"]
                ) if value
            )
            evidence.append(f"Nmap: {product or endpoint['service']}")
        if ajp_exposed:
            evidence.append("AJP open: " + ",".join(str(port) for port in ajp_ports))
        if not version:
            evidence.append("Tomcat version not disclosed")

        if show_all or risk != "INFO":
            rows.append({
                "ip": ip,
                "port": endpoint["port"],
                "proto": analysis["proto"],
                "version": version or "UNKNOWN",
                "risk": risk,
                "cves": ",".join(cves) or "-",
                "evidence": "; ".join(dict.fromkeys(evidence)) or "Tomcat detected",
            })

    # Report an exposed AJP connector even if no HTTP connector was identified.
    if ajp_ports and not rows:
        for port in ajp_ports:
            rows.append({
                "ip": ip,
                "port": port,
                "proto": "ajp",
                "version": "UNKNOWN",
                "risk": "MEDIUM*",
                "cves": "CVE-2020-1938?",
                "evidence": "AJP connector exposed; version/configuration not confirmed",
            })
    return rows


async def run_all(targets, args, ports):
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
                    findings = await scan_host(
                        ip,
                        ports,
                        args.host_timeout,
                        args.http_timeout,
                        args.show_all,
                        deep=args.deep,
                        diagnose=args.diagnose,
                    )
                    rows.extend(findings)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rScanning Tomcat: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Findings: {len(rows)} | Current: {ip}".ljust(125)
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


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No vulnerable or exposed Tomcat findings were identified.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 6),
            cell(row["proto"], 6),
            cell(row["version"], 13),
            cell(row["risk"], 8),
            cell(row["cves"], 46),
            cell(row["evidence"], 72),
        ])
        color = RED if row["risk"] in {"CRITICAL", "HIGH*"} else YELLOW
        print(paint(line, color, colors))


def write_csv(path, rows):
    fields = ["ip", "port", "proto", "version", "risk", "cves", "evidence"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            writer.writerow(row)


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted({row["ip"] for row in rows}, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find exposed and potentially vulnerable Apache Tomcat servers."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="TCP ports/ranges")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent workers")
    parser.add_argument("--host-timeout", default="90s", help="Nmap host timeout")
    parser.add_argument("--http-timeout", type=int, default=3, help="HTTP request timeout")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Use exhaustive Nmap probes, both HTTP schemes, all paths and OPTIONS",
    )
    parser.add_argument("--show-all", action="store_true", help="Show informational Tomcat detections too")
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Show HTTP status and identity headers for web endpoints not identified as Tomcat",
    )
    parser.add_argument("--csv", default="tomcat_vulnerability_results.csv", help="CSV output")
    parser.add_argument("--list", default="tomcat_vulnerable_ips.txt", help="Finding IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets  : {len(targets)}")
    print(f"Workers         : {args.workers}")
    print(f"Scan ports      : {args.ports}")
    print(
        "Detection       : "
        + (
            "deep Nmap/HTTP, Manager/docs/examples, OPTIONS, AJP"
            if args.deep
            else "fast Nmap/HTTP, root/error/Manager signatures, AJP"
        )
    )
    print("CVE marker '?'  : version/configuration candidate, not confirmed exploitation")

    rows = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    print()
    print(f"Tomcat findings : {len(rows)}")
    print(f"Tomcat hosts    : {len({row['ip'] for row in rows})}")
    print(f"CSV written     : {args.csv}")
    print(f"IP list written : {args.list}")
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())

