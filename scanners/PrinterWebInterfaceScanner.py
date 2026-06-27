#!/usr/bin/env python3
"""
Discover printer web interfaces from multiple vendors.

Detection uses read-only Nmap service identification and HTTP/HTTPS GET
requests. The scanner does not authenticate, submit print jobs, inspect
queues, or change printer settings.

Recognized families include HP, Canon, Epson, Brother, Xerox, Ricoh,
Konica Minolta, Kyocera, Lexmark, Sharp, Samsung, OKI, Zebra, Toshiba,
FujiFilm/Fuji Xerox, Dell printers, CUPS and generic print servers.

Requirements:
    sudo apt install nmap

Examples:
    python3 PrinterWebInterfaceScanner.py -f target_ips.txt
    python3 PrinterWebInterfaceScanner.py 192.0.2.0/24 --show-all
    python3 PrinterWebInterfaceScanner.py -f target_ips.txt --all-ports

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


GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "80-82,443,631,8000,8008,8080,8081,8088,8090,8181,"
    "8296,8443,8444,8888,9090,3910,3911,53048"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTO", 7),
    ("VENDOR", 18),
    ("MODEL / INTERFACE", 38),
    ("SERVER", 30),
    ("STATUS", 18),
]

DETAIL_PATHS = (
    "/info_configuration.html",
    "/DevMgmt/ProductConfigDyn.xml",
    "/hp/device/DeviceInformation/View",
    "/web/guest/en/websys/webArch/mainFrame.cgi",
    "/web/entry/en/websys/webArch/mainFrame.cgi",
    "/startwlm/Start_Wlm.htm",
    "/dvcinfo/dvcconfig/DvcConfig_Config.htm",
    "/general/status.html",
)

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
        r"\bBrother\s+Web\s+Based\s+Management\b",
    )),
    ("Xerox", (
        r"\bXerox\b.*\b(?:CentreWare|WorkCentre|VersaLink|AltaLink|Phaser|printer)\b",
        r"\bCentreWare\s+Internet\s+Services\b",
    )),
    ("Ricoh", (
        r"\bRICOH\b.*\b(?:Aficio|IM\s*[A-Z]?\d|MP\s*[A-Z]?\d|printer)\b",
        r"\bWeb\s+Image\s+Monitor\b",
    )),
    ("Konica Minolta", (
        r"\bKONICA\s+MINOLTA\b",
        r"\bbizhub\b",
    )),
    ("Kyocera", (
        r"\bKYOCERA\b.*\b(?:ECOSYS|TASKalfa|FS-|printer)\b",
        r"\bCommand\s+Center\s+RX\b",
    )),
    ("Lexmark", (
        r"\bLexmark\b.*\b(?:printer|Embedded\s+Web\s+Server|[A-Z]{1,3}\d{3,4})\b",
    )),
    ("Sharp", (
        r"\bSHARP\b.*\b(?:MX-|BP-|printer|MFP)\b",
    )),
    ("Samsung", (
        r"\bSamsung\b.*\b(?:SyncThru|printer|CLP-|CLX-|ML-|SCX-|SL-)\b",
        r"\bSyncThru\s+Web\s+Service\b",
    )),
    ("OKI", (
        r"\bOKI(?:DATA)?\b.*\b(?:printer|C\d{3,4}|MC\d{3,4}|B\d{3,4})\b",
    )),
    ("Zebra", (
        r"\bZebra\b.*\b(?:printer|PrintServer|ZD\d|ZT\d|GK\d|GX\d|QLn)\b",
        r"\bZebraNet\b",
    )),
    ("Toshiba", (
        r"\bTOSHIBA\b.*\b(?:e-STUDIO|TopAccess|printer)\b",
        r"\bTopAccess\b",
    )),
    ("FujiFilm / Fuji Xerox", (
        r"\b(?:FUJIFILM|Fuji\s+Xerox)\b.*\b(?:Apeos|DocuCentre|printer)\b",
    )),
    ("Dell", (
        r"\bDell\b.*\b(?:Laser|Color|Multifunction)\s+Printer\b",
    )),
    ("CUPS", (
        r"\bCUPS(?:/\d[\w.-]*)?\b",
        r"\bCommon\s+UNIX\s+Printing\s+System\b",
    )),
)

PRINTER_TERMS = re.compile(
    r"\b(?:printer|printing|laserjet|officejet|pagewide|designjet|deskjet|"
    r"imagerunner|imageclass|imagepress|workcentre|versalink|altalink|"
    r"phaser|bizhub|taskalfa|ecosys|aficio|centreware|syncThru|"
    r"jetdirect|epsonnet|zebranet|topaccess|cups|embedded web server|"
    r"web image monitor|command center rx|multifunction|mfp)\b",
    re.I,
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


async def discover_ports(ip, args, ports):
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
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
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
        web_hint = (
            "http" in name
            or name in {"www", "https", "ipp"}
            or tunnel in {"ssl", "tls"}
            or port in {80, 81, 82, 443, 631, 8000, 8008, 8080, 8081, 8088,
                        8090, 8181, 8296, 8443, 8444, 8888, 9090, 3910, 3911,
                        53048}
        )
        printer_hint = bool(PRINTER_TERMS.search(f"{name} {fingerprint}"))
        # Never send HTTP requests merely because a non-web service looks
        # printer-related. In particular, raw JetDirect/9100 must not be
        # probed because arbitrary bytes could be interpreted as print data.
        if web_hint and port != 9100:
            endpoints.append({
                "port": port,
                "name": name,
                "fingerprint": fingerprint,
                "tls": tunnel in {"ssl", "tls"} or name == "https" or port in {443, 8443, 8444},
                "printer_hint": printer_hint,
            })
    return endpoints


class NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if new.hostname and new.hostname != old.hostname:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_fetch(ip, port, scheme, path, timeout):
    url = f"{scheme}://{ip}:{port}{path}"
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        NoCrossHostRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 Printer-Web-Inventory/1.0",
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
        body = raw.decode("utf-8", errors="ignore")
        headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
        return {
            "url": url,
            "final_url": response.geturl(),
            "status_code": getattr(response, "status", getattr(response, "code", 0)),
            "headers": headers,
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
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
    )
    return re.sub(r"\s+", " ", text).strip()


def title_from_html(body):
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return strip_html(match.group(1))[:160] if match else ""


def server_from_headers(headers):
    match = re.search(r"(?mi)^Server\s*:\s*(.+?)\s*$", headers)
    return match.group(1).strip() if match else ""


def identify_vendor(text):
    for vendor, patterns in VENDOR_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text, re.I | re.S):
                return vendor
    return ""


def clean_model(value):
    value = re.sub(r"\s+", " ", strip_html(value)).strip(" .:-|")
    value = re.split(
        r"\s+(?:Serial\s+(?:Number|No)|Firmware|Device\s+Status|Supplies|"
        r"Network\s+Summary|Sign\s+In|Login)\b",
        value,
        maxsplit=1,
        flags=re.I,
    )[0]
    return value[:120]


def extract_model(text, vendor, title):
    patterns = (
        r"(?:Product|Model|Device)\s*(?:Name|Model)?\s*[:=]\s*([A-Z0-9][A-Z0-9 _./()+-]{2,90})",
        r"\b(HP\s+(?:LaserJet|OfficeJet|PageWide|DesignJet|DeskJet|Color LaserJet)[A-Z0-9 _./()+-]{1,70})",
        r"\b(Canon\s+(?:imageRUNNER|imageCLASS|imagePRESS|LBP|MF)[A-Z0-9 _./()+-]{1,55})",
        r"\b(EPSON\s+[A-Z]{1,5}[- ]?[A-Z0-9]{2,12})\b",
        r"\b(Brother\s+(?:HL|MFC|DCP)-[A-Z0-9-]+)\b",
        r"\b(Xerox\s+(?:WorkCentre|VersaLink|AltaLink|Phaser)[A-Z0-9 _-]{1,45})",
        r"\b(KONICA\s+MINOLTA\s+bizhub\s+[A-Z0-9-]+)\b",
        r"\b(KYOCERA\s+(?:ECOSYS|TASKalfa)\s+[A-Z0-9-]+)\b",
        r"\b(RICOH\s+(?:Aficio|IM|MP)\s+[A-Z0-9-]+)\b",
        r"\b(TOSHIBA\s+e-STUDIO[A-Z0-9-]+)\b",
        r"\b(Zebra\s+(?:ZD|ZT|GK|GX|QLn)[A-Z0-9-]+)\b",
    )
    plain = strip_html(text)
    for pattern in patterns:
        match = re.search(pattern, plain, re.I)
        if match:
            model = clean_model(match.group(1))
            if model:
                return model
    if title and (
        PRINTER_TERMS.search(title)
        or vendor.lower() in title.lower()
    ):
        return clean_model(title)
    interface_names = {
        "CUPS": "CUPS Web Interface",
        "Ricoh": "Web Image Monitor",
        "Kyocera": "Command Center RX",
        "Xerox": "CentreWare Internet Services",
        "Samsung": "SyncThru Web Service",
        "Toshiba": "TopAccess",
    }
    return interface_names.get(vendor, "Printer Web Interface")


def analyze_response(endpoint, response):
    body = response["body"]
    headers = response["headers"]
    title = title_from_html(body)
    server = server_from_headers(headers) or endpoint["fingerprint"]
    evidence = "\n".join([
        endpoint["fingerprint"], headers, title, body[:400000]
    ])
    vendor = identify_vendor(evidence)
    printer_terms = bool(PRINTER_TERMS.search(evidence))
    confirmed = bool(vendor and (printer_terms or vendor in {"CUPS", "Konica Minolta"}))
    if not confirmed and printer_terms and PRINTER_TERMS.search(title):
        vendor = vendor or "Generic / Unknown"
        confirmed = True
    if not confirmed and endpoint["printer_hint"] and printer_terms:
        vendor = vendor or "Generic / Unknown"
        confirmed = True
    if not confirmed:
        return None
    return {
        "vendor": vendor or "Generic / Unknown",
        "model": extract_model(evidence, vendor or "Generic / Unknown", title),
        "server": server or "Version hidden",
        "title": title,
        "url": response["final_url"],
        "status_code": response["status_code"],
    }


async def probe_endpoint(ip, endpoint, args):
    preferred = "https" if endpoint["tls"] else "http"
    schemes = (preferred, "http" if preferred == "https" else "https")
    paths = ("/",)
    if endpoint["printer_hint"] or args.deep:
        paths += DETAIL_PATHS

    best_response = None
    for scheme in schemes:
        for path in paths:
            response = await async_fetch(
                ip, endpoint["port"], scheme, path, args.http_timeout
            )
            if not response:
                continue
            if best_response is None:
                best_response = response
            finding = analyze_response(endpoint, response)
            if finding:
                finding.update({
                    "ip": ip,
                    "port": endpoint["port"],
                    "protocol": scheme.upper(),
                    "status": "PRINTER FOUND",
                })
                return finding
        if best_response:
            break

    if args.show_all and best_response:
        return {
            "ip": ip,
            "port": endpoint["port"],
            "protocol": preferred.upper(),
            "vendor": "-",
            "model": title_from_html(best_response["body"]) or "Unclassified web interface",
            "server": server_from_headers(best_response["headers"]) or endpoint["fingerprint"] or "Version hidden",
            "status": "UNCLASSIFIED",
            "title": title_from_html(best_response["body"]),
            "url": best_response["final_url"],
            "status_code": best_response["status_code"],
        }
    return None


async def scan_host(ip, args, ports):
    endpoints = await discover_ports(ip, args, ports)
    if not endpoints:
        return []
    limit = asyncio.Semaphore(args.endpoint_workers)

    async def limited_probe(endpoint):
        async with limit:
            return await probe_endpoint(ip, endpoint, args)

    results = await asyncio.gather(
        *(limited_probe(endpoint) for endpoint in endpoints),
        return_exceptions=True,
    )
    return [
        result for result in results
        if isinstance(result, dict)
    ]


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
                    rows.extend(await scan_host(ip, args, ports))
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                printers = sum(row["status"] == "PRINTER FOUND" for row in rows)
                sys.stdout.write(
                    f"\rScanning printer web interfaces: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Interfaces: {printers} | Current: {ip}".ljust(135)
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
        print("No printer web interfaces were identified.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 10),
            cell(row["protocol"], 7),
            cell(row["vendor"], 18),
            cell(row["model"], 38),
            cell(row["server"], 30),
            cell(row["status"], 18),
        ])
        code = GREEN if row["status"] == "PRINTER FOUND" else YELLOW
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "vendor", "model", "server",
        "status", "title", "url", "status_code",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            writer.writerow({field: row.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: (ip_sort(item["ip"]), item["port"])):
            if row["status"] == "PRINTER FOUND":
                handle.write(f"{row['url']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Discover and identify printer HTTP/HTTPS management interfaces."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Web ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Discover web interfaces on all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--endpoint-workers", type=int, default=4, help="Concurrent HTTP probes per host")
    parser.add_argument("--host-timeout", default="60s", help="Nmap timeout per host")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP timeout per request")
    parser.add_argument("--deep", action="store_true", help="Try vendor information paths on every web endpoint")
    parser.add_argument("--show-all", action="store_true", help="Also show unclassified responding web interfaces")
    parser.add_argument("--csv", default="printer_web_interfaces.csv", help="CSV output")
    parser.add_argument("--list", default="printer_web_interface_urls.txt", help="Printer interface URL list")
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
    print("Detection      : Nmap service fingerprint plus read-only HTTP/HTTPS signatures")
    print("Printer action : none; no jobs, queues, authentication, or configuration changes")
    print(f"Showing        : {'printer and unclassified web interfaces' if args.show_all else 'identified printer web interfaces only'}")

    rows = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    printers = sum(row["status"] == "PRINTER FOUND" for row in rows)
    hosts = len({row["ip"] for row in rows if row["status"] == "PRINTER FOUND"})
    print()
    print(f"Printer interfaces : {printers}")
    print(f"Printer hosts      : {hosts}")
    print(f"CSV written        : {args.csv}")
    print(f"URL list written   : {args.list}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

