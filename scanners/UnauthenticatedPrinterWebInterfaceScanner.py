#!/usr/bin/env python3
"""
Find printer web pages accessible without credentials.

The scanner performs read-only HTTP/HTTPS GET requests. It does not submit
credentials, change settings, access print queues, or send print jobs.

Requirements:
    sudo apt install nmap

Examples:
    python3 UnauthenticatedPrinterWebInterfaceScanner.py -f target_ips.txt
    python3 UnauthenticatedPrinterWebInterfaceScanner.py 192.0.2.0/24
    python3 UnauthenticatedPrinterWebInterfaceScanner.py -f target_ips.txt --show-all

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
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "80-82,443,631,8000,8008,8080,8081,8088,8090,8181,"
    "8296,8443,8444,8888,9090,3910,3911,53048"
)

CHECK_PATHS = (
    "/wcd/system.xml",
    "/info_configuration.html?tab=Home&menu=DevConfig",
    "/info_config_network.html?tab=Networking&menu=NetConfig",
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTO", 7),
    ("VENDOR", 18),
    ("MODEL / INTERFACE", 36),
    ("ACCESSIBLE PATHS", 58),
    ("STATUS", 18),
]

VENDOR_PATTERNS = (
    ("HP", (
        r"\bHP\s+(?:LaserJet|OfficeJet|PageWide|DesignJet|DeskJet|Color LaserJet)\b",
        r"\bHP\s+Embedded\s+Web\s+Server\b",
        r"\bJetDirect\b",
    )),
    ("Canon", (
        r"\bCanon\b.*\b(?:imageRUNNER|imageCLASS|imagePRESS|LBP|MF\d|iR-?ADV)\b",
        r"\bRemote\s+UI\b.*\bCanon\b",
    )),
    ("Epson", (
        r"\bEPSON[- ]HTTP\b",
        r"\bEpsonNet\b",
        r"\bEpson\b.*\b(?:WorkForce|EcoTank|SureColor|AcuLaser|Stylus|printer)\b",
    )),
    ("Brother", (
        r"\bBrother\b.*\b(?:HL-|MFC-|DCP-|printer|Web Based Management)\b",
    )),
    ("Xerox", (
        r"\bXerox\b.*\b(?:CentreWare|WorkCentre|VersaLink|AltaLink|Phaser)\b",
        r"\bCentreWare\s+Internet\s+Services\b",
    )),
    ("Ricoh", (
        r"\bRICOH\b",
        r"\bWeb\s+Image\s+Monitor\b",
    )),
    ("Konica Minolta", (
        r"\bKONICA\s+MINOLTA\b",
        r"\bbizhub\b",
        r"\bPageScope\b",
    )),
    ("Kyocera", (
        r"\bKYOCERA\b",
        r"\bCommand\s+Center\s+RX\b",
    )),
    ("Lexmark", (r"\bLexmark\b",)),
    ("Sharp", (r"\bSHARP\b.*\b(?:MX-|BP-|printer|MFP)\b",)),
    ("Samsung", (
        r"\bSamsung\b.*\b(?:SyncThru|printer|CLP-|CLX-|ML-|SCX-|SL-)\b",
        r"\bSyncThru\s+Web\s+Service\b",
    )),
    ("OKI", (r"\bOKI(?:DATA)?\b",)),
    ("Zebra", (r"\bZebra(?:Net)?\b",)),
    ("Toshiba", (
        r"\bTOSHIBA\b.*\b(?:e-STUDIO|TopAccess)\b",
        r"\bTopAccess\b",
    )),
    ("FujiFilm / Fuji Xerox", (r"\b(?:FUJIFILM|Fuji\s+Xerox)\b",)),
    ("CUPS", (
        r"\bCUPS(?:/\d[\w.-]*)?\b",
        r"\bCommon\s+UNIX\s+Printing\s+System\b",
    )),
)

PRINTER_MARKERS = re.compile(
    r"\b(?:printer|laserjet|officejet|pagewide|designjet|deskjet|"
    r"imagerunner|imageclass|imagepress|workcentre|versalink|altalink|"
    r"phaser|bizhub|taskalfa|ecosys|aficio|centreware|syncthru|"
    r"jetdirect|epsonnet|zebranet|topaccess|cups|multifunction|mfp|"
    r"embedded web server|web image monitor|command center rx|pagescope)\b",
    re.I,
)

CONFIG_MARKERS = re.compile(
    r"(?:"
    r"product\s*(?:name|model)|model\s*(?:name|number)|"
    r"serial\s*(?:number|no)|firmware\s*(?:version|datecode|revision)|"
    r"device\s+configuration|network\s+(?:configuration|summary|settings)|"
    r"ip\s+(?:address|configuration)|subnet\s+mask|default\s+gateway|"
    r"host\s*name|mac\s+address|hardware\s+address|"
    r"<(?:ProductName|ModelName|SerialNumber|FirmwareVersion|DeviceInfo)\b"
    r")",
    re.I,
)

LOGIN_MARKERS = re.compile(
    r"(?:"
    r"<form[^>]+(?:login|signin|auth)|"
    r"<input[^>]+type\s*=\s*[\"']?password|"
    r"<input[^>]+name\s*=\s*[\"']?(?:password|passwd|username|userid)|"
    r"\b(?:administrator\s+login|authentication\s+required)\b"
    r")",
    re.I | re.S,
)


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def normalize_status(value):
    status = str(value or "").strip().upper()
    if status in {"PUBLIC PAGE", "UNAUTH ACCESS"}:
        return "UNAUTH ACCESS"
    return status


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


async def run_command(command):
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


async def discover_ports(ip, ports, args):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "--host-timeout", args.host_timeout,
    ]
    if args.all_ports:
        command.extend(["-p-", "--min-rate", str(args.min_rate)])
    else:
        command.extend(["-p", ports])
    command.extend(["-oX", "-", ip])
    return parse_nmap(await run_command(command))


def parse_nmap(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    endpoints = []
    known_web_ports = {
        80, 81, 82, 443, 631, 8000, 8008, 8080, 8081, 8088, 8090,
        8181, 8296, 8443, 8444, 8888, 9090, 3910, 3911, 53048,
    }
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        if port == 9100:
            continue
        service = port_node.find("service")
        name = service.attrib.get("name", "").lower() if service is not None else ""
        tunnel = service.attrib.get("tunnel", "").lower() if service is not None else ""
        parts = []
        if service is not None:
            parts = [
                service.attrib.get("product", ""),
                service.attrib.get("version", ""),
                service.attrib.get("extrainfo", ""),
            ]
        fingerprint = " ".join(part for part in parts if part)
        is_web = (
            "http" in name
            or name in {"www", "https", "ipp"}
            or tunnel in {"ssl", "tls"}
            or port in known_web_ports
        )
        if is_web:
            endpoints.append({
                "port": port,
                "name": name,
                "fingerprint": fingerprint,
                "tls": tunnel in {"ssl", "tls"} or name == "https" or port in {443, 8443, 8444},
            })
    return endpoints


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        old_port = old.port or (443 if old.scheme == "https" else 80)
        new_port = new.port or (443 if new.scheme == "https" else 80)
        if (
            new.hostname
            and (new.hostname != old.hostname or new_port != old_port)
        ):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_fetch(ip, port, scheme, path, timeout):
    url = f"{scheme}://{ip}:{port}{path}"
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        SameHostRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 Printer-Unauthenticated-Audit/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
        },
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    try:
        try:
            raw = response.read(512 * 1024)
        except http.client.IncompleteRead as error:
            raw = error.partial
        content_type = response.headers.get("Content-Type", "")
        charset_match = re.search(r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.I)
        charset = charset_match.group(1) if charset_match else ""
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            charset = "utf-16"
        try:
            body = raw.decode(charset or "utf-8", errors="ignore")
        except LookupError:
            body = raw.decode("utf-8", errors="ignore")
        body = body.replace("\x00", "")
        return {
            "url": url,
            "final_url": response.geturl(),
            "code": getattr(response, "status", getattr(response, "code", 0)),
            "headers": "\n".join(
                f"{key}: {value}" for key, value in response.headers.items()
            ),
            "body": body,
        }
    finally:
        response.close()


async def async_fetch(ip, port, scheme, path, timeout):
    try:
        return await asyncio.to_thread(
            http_fetch, ip, port, scheme, path, timeout
        )
    except (
        urllib.error.URLError,
        TimeoutError,
        ssl.SSLError,
        OSError,
        http.client.HTTPException,
        ValueError,
    ):
        return None


def strip_html(text):
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(
        r"\s+", " ",
        text.replace("&nbsp;", " ").replace("&amp;", "&")
    ).strip()


def identify_vendor(text):
    for vendor, patterns in VENDOR_PATTERNS:
        if any(re.search(pattern, text, re.I | re.S) for pattern in patterns):
            return vendor
    return ""


def extract_model(text, vendor):
    plain = strip_html(text)
    patterns = (
        r"(?:Product|Model|Device)\s*(?:Name|Model)?\s*[:=]\s*([A-Z0-9][A-Z0-9 _./()+-]{2,90})",
        r"\b(HP\s+(?:LaserJet|OfficeJet|PageWide|DesignJet|DeskJet|Color LaserJet)[A-Z0-9 _./()+-]{1,70})",
        r"\b(Canon\s+(?:imageRUNNER|imageCLASS|imagePRESS|LBP|MF)[A-Z0-9 _./()+-]{1,55})",
        r"\b(Brother\s+(?:HL|MFC|DCP)-[A-Z0-9-]+)\b",
        r"\b(Xerox\s+(?:WorkCentre|VersaLink|AltaLink|Phaser)[A-Z0-9 _-]{1,45})",
        r"\b(KONICA\s+MINOLTA\s+bizhub\s+[A-Z0-9-]+)\b",
        r"\b(KYOCERA\s+(?:ECOSYS|TASKalfa)\s+[A-Z0-9-]+)\b",
        r"\b(RICOH\s+(?:Aficio|IM|MP)\s+[A-Z0-9-]+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, plain, re.I)
        if match:
            value = re.sub(r"\s+", " ", match.group(1)).strip(" .:-")
            value = re.split(
                r"\s+(?:Serial|Firmware|Device Status|Network Summary)\b",
                value,
                maxsplit=1,
                flags=re.I,
            )[0]
            return value[:100]
    return f"{vendor} Printer Web Interface" if vendor else "Printer Web Interface"


def auth_challenge(response):
    return bool(re.search(
        r"(?mi)^WWW-Authenticate\s*:",
        response["headers"],
    ))


def classify_response(endpoint, response, requested_path=""):
    code = response["code"]
    body = response["body"]
    headers = response["headers"]
    final_path = urllib.parse.urlsplit(response["final_url"]).path.lower()
    combined = "\n".join([endpoint["fingerprint"], headers, body])
    vendor = identify_vendor(combined)
    printer = bool(vendor or PRINTER_MARKERS.search(combined))
    body_vendor = identify_vendor(body)
    body_printer = bool(body_vendor or PRINTER_MARKERS.search(body))
    config = bool(CONFIG_MARKERS.search(body))
    login = bool(
        LOGIN_MARKERS.search(body)
        or re.search(r"(?:login|signin|auth)", final_path, re.I)
        or auth_challenge(response)
    )
    login_only = login and not body_printer and not config
    requested_url = urllib.parse.urlsplit(requested_path)
    final_url = urllib.parse.urlsplit(response["final_url"])
    requested_endpoint_returned = (
        requested_url.path.lower() in {
            "/wcd/system.xml",
            "/info_configuration.html",
            "/info_config_network.html",
        }
        and final_url.path.lower() == requested_url.path.lower()
        and 200 <= code < 300
        and bool(body.strip())
        and not auth_challenge(response)
        and not login_only
    )

    if code in {401, 403, 407} or auth_challenge(response):
        state = "AUTH REQUIRED"
    elif requested_endpoint_returned:
        # These are known printer status/configuration endpoints. A direct,
        # non-empty 2xx response confirms anonymous access even when the
        # response schema has no recognizable vendor or model strings.
        state = "UNAUTH ACCESS"
        printer = True
    elif 200 <= code < 300 and printer and not login_only:
        # A recognized printer page is anonymously accessible even when it
        # also contains a sign-in control or exposes only general status.
        state = "UNAUTH ACCESS"
    elif login_only:
        state = "AUTH REQUIRED"
    else:
        state = "NO ACCESS"

    return {
        "state": state,
        "vendor": vendor or ("Generic / Unknown" if printer else ""),
        "model": extract_model(combined, vendor) if printer else "",
        "code": code,
        "final_url": response["final_url"],
    }


async def probe_endpoint(ip, endpoint, args):
    preferred = "https" if endpoint["tls"] else "http"
    schemes = (preferred, "http" if preferred == "https" else "https")
    checks = []

    for scheme in schemes:
        responded = False
        useful = False
        for path in CHECK_PATHS:
            response = await async_fetch(
                ip, endpoint["port"], scheme, path, args.http_timeout
            )
            if not response:
                continue
            responded = True
            result = classify_response(endpoint, response, path)
            result.update({"path": path, "scheme": scheme})
            checks.append(result)
            if result["state"] in {"UNAUTH ACCESS", "AUTH REQUIRED"}:
                useful = True
        if responded and useful:
            break

    accessible = [item for item in checks if item["state"] == "UNAUTH ACCESS"]
    protected = [item for item in checks if item["state"] == "AUTH REQUIRED"]

    if accessible:
        best = accessible[0]
        status = "UNAUTH ACCESS"
        selected = accessible
    elif protected:
        best = protected[0]
        status = "AUTH REQUIRED"
        selected = protected
    elif checks:
        best = checks[0]
        status = "NO ACCESS"
        selected = checks
    else:
        return None

    status = normalize_status(status)
    if status != "UNAUTH ACCESS":
        return None

    return {
        "ip": ip,
        "port": endpoint["port"],
        "protocol": best["scheme"].upper(),
        "vendor": best["vendor"] or "-",
        "model": best["model"] or "-",
        "paths": ",".join(dict.fromkeys(item["path"] for item in selected)),
        "status": status,
        "http_codes": ",".join(str(item["code"]) for item in selected),
        "urls": ";".join(item["final_url"] for item in selected),
    }


async def scan_host(ip, args, ports):
    endpoints = await discover_ports(ip, ports, args)
    if not endpoints:
        return []
    semaphore = asyncio.Semaphore(args.endpoint_workers)

    async def limited(endpoint):
        async with semaphore:
            return await probe_endpoint(ip, endpoint, args)

    results = await asyncio.gather(
        *(limited(endpoint) for endpoint in endpoints),
        return_exceptions=True,
    )
    return [result for result in results if isinstance(result, dict)]


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
                    findings = await scan_host(ip, args, ports)
                    rows.extend(
                        row for row in findings
                        if normalize_status(row.get("status")) == "UNAUTH ACCESS"
                    )
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    row["status"] == "UNAUTH ACCESS" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning printer access: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Unauthenticated: {vulnerable} | Current: {ip}".ljust(130)
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
    rows = [
        row for row in rows
        if normalize_status(row.get("status")) == "UNAUTH ACCESS"
    ]
    print()
    if not rows:
        print("No printer configuration interfaces with confirmed unauthenticated access were found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        status = normalize_status(row.get("status"))
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 10),
            cell(row["protocol"], 7),
            cell(row["vendor"], 18),
            cell(row["model"], 36),
            cell(row["paths"], 58),
            cell(status, 18),
        ])
        code = RED if status == "UNAUTH ACCESS" else (
            GREEN if status == "AUTH REQUIRED" else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "vendor", "model", "paths",
        "status", "http_codes", "urls",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        findings = [
            row for row in rows
            if normalize_status(row.get("status")) == "UNAUTH ACCESS"
        ]
        for row in sorted(findings, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            row = dict(row)
            row["status"] = "UNAUTH ACCESS"
            writer.writerow({field: row.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        findings = [
            row for row in rows
            if normalize_status(row.get("status")) == "UNAUTH ACCESS"
        ]
        for row in sorted(findings, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            for url in row["urls"].split(";"):
                if url:
                    handle.write(f"{url}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find printer web pages accessible without credentials."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Printer web ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Discover web services on all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--endpoint-workers", type=int, default=3, help="Concurrent endpoint probes per host")
    parser.add_argument("--host-timeout", default="60s", help="Nmap timeout per host")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP timeout per request")
    parser.add_argument("--csv", default="printer_unauthenticated_web_access.csv", help="CSV output")
    parser.add_argument("--list", default="printer_unauthenticated_urls.txt", help="Accessible URL list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))
    args.endpoint_workers = max(1, args.endpoint_workers)

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"Web ports      : {'all TCP ports' if args.all_ports else ports}")
    print(f"Paths checked  : {','.join(CHECK_PATHS)}")
    print("Verification   : recognized printer content returned without login or auth challenge")
    print("Actions        : read-only HTTP/HTTPS GET requests")
    print("Showing        : UNAUTH ACCESS only (PUBLIC PAGE is included as UNAUTH ACCESS)")

    rows = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(row["status"] == "UNAUTH ACCESS" for row in rows)
    hosts = len({
        row["ip"] for row in rows if row["status"] == "UNAUTH ACCESS"
    })
    print()
    print(f"Unauthenticated endpoints : {vulnerable}")
    print(f"Affected printer hosts    : {hosts}")
    print(f"CSV written               : {args.csv}")
    print(f"URL list written          : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

