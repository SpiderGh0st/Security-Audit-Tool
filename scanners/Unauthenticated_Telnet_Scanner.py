#!/usr/bin/env python3
"""
Find unauthenticated Telnet administrative access on HP printers.

The scanner:
  1. Uses Nmap to find plaintext Telnet services.
  2. Connects and handles basic Telnet option negotiation.
  3. Sends only blank lines to reveal the login or administrative prompt.

It does NOT submit usernames/passwords or issue menu, configuration, reset,
filesystem, printing, or administrative commands.

Requirements:
    sudo apt install nmap

Examples:
    python3 HpUnauthenticatedTelnetScanner.py -f target_ips.txt
    python3 HpUnauthenticatedTelnetScanner.py 192.0.2.0/24
    python3 HpUnauthenticatedTelnetScanner.py -f target_ips.txt --show-all
    python3 HpUnauthenticatedTelnetScanner.py -f target_ips.txt -p 23,2323,8023

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = "23,2323,8023"

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTOCOL", 12),
    ("DEVICE", 32),
    ("ACCESS", 17),
    ("STATUS", 14),
    ("DETAIL", 62),
]

HP_PATTERNS = (
    r"\bhp jetdirect\b",
    r"\bhewlett[- ]packard\b",
    r"\bhp laserjet\b",
    r"\bhp color laserjet\b",
    r"\bhp officejet\b",
    r"\bhp pagewide\b",
    r"\bhp designjet\b",
    r"\bjetdirect\b",
    r"\bjetadmin\b",
)

AUTH_PATTERNS = (
    r"\busername\s*:",
    r"\buser\s*name\s*:",
    r"\blogin\s*:",
    r"\bpassword\s*:",
    r"\bpasscode\s*:",
    r"\bauthentication required\b",
    r"\bauthorization required\b",
    r"\baccess denied\b",
)

ADMIN_PATTERNS = (
    r"\bplease type ['\"]?menu['\"]?\b",
    r"\bmenu system\b",
    r"\bmain menu\b",
    r"\bconfiguration menu\b",
    r"\bjetdirect configuration\b",
    r"\btype ['\"]?\?['\"]? for help\b",
    r"\btype help for help\b",
    r"(?:^|\s)[>#]\s*$",
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
    value = re.sub(r":\d+(?:/tcp)?$", "", value, flags=re.I)
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


async def run_nmap(ip, ports, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "-p",
        ports,
        "--script",
        "banner,telnet-encryption",
        "--script-timeout",
        "15s",
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


def script_output(port_node, script_id):
    script = port_node.find(f"script[@id='{script_id}']")
    return script.attrib.get("output", "").strip() if script is not None else ""


def parse_telnet_ports(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    ports = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port_node.find("service")
        if service is None:
            continue

        name = service.attrib.get("name", "").lower()
        product = service.attrib.get("product", "")
        version = service.attrib.get("version", "")
        extra = service.attrib.get("extrainfo", "")
        tunnel = service.attrib.get("tunnel", "").lower()
        banner = script_output(port_node, "banner")
        encryption = script_output(port_node, "telnet-encryption")
        evidence = " ".join(
            [name, product, version, extra, banner, encryption]
        ).lower()

        telnet = name == "telnet" or bool(re.search(r"\btelnet\b", evidence))
        encrypted = tunnel in {"ssl", "tls"} or name in {"telnets", "ssl/telnet"}
        if not telnet or encrypted:
            continue

        device = " ".join(
            value for value in [product, version, extra] if value
        ).strip()
        ports.append({
            "port": int(port_node.attrib.get("portid", "0")),
            "device": device,
            "nmap_banner": banner,
        })
    return ports


def process_telnet_bytes(data):
    plain = bytearray()
    replies = bytearray()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte != IAC:
            plain.append(byte)
            index += 1
            continue
        if index + 1 >= len(data):
            break
        command = data[index + 1]
        if command == IAC:
            plain.append(IAC)
            index += 2
        elif command in {DO, DONT, WILL, WONT}:
            if index + 2 >= len(data):
                break
            option = data[index + 2]
            if command in {DO, DONT}:
                replies.extend([IAC, WONT, option])
            else:
                replies.extend([IAC, DONT, option])
            index += 3
        elif command == SB:
            end = data.find(bytes([IAC, SE]), index + 2)
            index = len(data) if end < 0 else end + 2
        else:
            index += 2
    return bytes(plain), bytes(replies)


async def read_prompt(reader, writer, timeout):
    chunks = []
    deadline = asyncio.get_running_loop().time() + timeout
    while sum(len(chunk) for chunk in chunks) < 16384:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except asyncio.TimeoutError:
            break
        if not data:
            break
        plain, replies = process_telnet_bytes(data)
        if replies:
            writer.write(replies)
            await writer.drain()
        if plain:
            chunks.append(plain)
    return b"".join(chunks)


def clean_text(data):
    text = data.decode("latin-1", errors="replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\x00", "")
    return re.sub(r"[ \t]+", " ", text).strip()


def matches_any(patterns, text):
    return any(re.search(pattern, text, re.I | re.M) for pattern in patterns)


def hp_identified(nmap_device, nmap_banner, response):
    evidence = " ".join([nmap_device, nmap_banner, response])
    return matches_any(HP_PATTERNS, evidence)


def classify_access(response):
    if matches_any(AUTH_PATTERNS, response):
        return "AUTH REQUIRED", "NOT AFFECTED"
    if matches_any(ADMIN_PATTERNS, response):
        return "UNAUTHENTICATED", "VULNERABLE"
    return "INCONCLUSIVE", "REVIEW"


def extract_device(nmap_device, response):
    if nmap_device:
        return nmap_device
    lines = [
        re.sub(r"\s+", " ", line).strip()
        for line in response.splitlines()
        if line.strip()
    ]
    for line in lines:
        if matches_any(HP_PATTERNS, line):
            return line[:160]
    return "HP printer"


async def probe_access(ip, finding, connect_timeout, read_timeout):
    port = finding["port"]
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=connect_timeout,
        )
        first = await read_prompt(reader, writer, read_timeout)
        writer.write(b"\r\n")
        await writer.drain()
        second = await read_prompt(reader, writer, read_timeout)
        response = clean_text(first + b"\n" + second)

        if not hp_identified(
            finding["device"],
            finding["nmap_banner"],
            response,
        ):
            return None

        access, status = classify_access(response)
        if status == "VULNERABLE":
            detail = "HP administrative Telnet prompt exposed without authentication."
        elif status == "NOT AFFECTED":
            detail = "Telnet service requested authentication before administrative access."
        else:
            detail = "HP Telnet service detected, but access control could not be confirmed."

        return {
            "ip": ip,
            "port": f"{port}/TCP",
            "protocol": "TELNET/TCP",
            "device": extract_device(finding["device"], response),
            "access": access,
            "status": status,
            "detail": detail,
            "evidence": response,
        }
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass


async def scan_one(ip, ports, nmap_timeout, connect_timeout, read_timeout):
    findings = parse_telnet_ports(await run_nmap(ip, ports, nmap_timeout))
    if not findings:
        return []
    results = await asyncio.gather(
        *(
            probe_access(ip, finding, connect_timeout, read_timeout)
            for finding in findings
        )
    )
    return [result for result in results if result is not None]


async def run_all(
    targets,
    ports,
    workers,
    nmap_timeout,
    connect_timeout,
    read_timeout,
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
                        ip,
                        ports,
                        nmap_timeout,
                        connect_timeout,
                        read_timeout,
                    )
                )
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning HP Telnet: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Vulnerable: {vulnerable} | Current: {ip}".ljust(130)
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
        row for row in rows if row["status"] == "VULNERABLE"
    ]
    print()
    if not displayed:
        print("No confirmed unauthenticated HP Telnet administrative access was found.")
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
            cell(row["port"], 9),
            cell(row["protocol"], 12),
            cell(row["device"], 32),
            cell(row["access"], 17),
            cell(row["status"], 14),
            cell(row["detail"], 62),
        ])
        code = (
            RED if row["status"] == "VULNERABLE"
            else GREEN if row["status"] == "NOT AFFECTED"
            else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "protocol",
        "device",
        "access",
        "status",
        "detail",
        "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"].split("/")[0])),
        ))


def write_list(path, rows):
    vulnerable = {row["ip"] for row in rows if row["status"] == "VULNERABLE"}
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted(vulnerable, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find unauthenticated Telnet administrative access on HP printers."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Telnet TCP ports/ranges. Default: {DEFAULT_PORTS}",
    )
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host workers")
    parser.add_argument("--nmap-timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument("--connect-timeout", type=float, default=3.0, help="TCP connection timeout")
    parser.add_argument("--read-timeout", type=float, default=2.0, help="Prompt read timeout")
    parser.add_argument("--show-all", action="store_true", help="Show authentication-required and inconclusive HP Telnet services")
    parser.add_argument("--csv", default="hp_unauthenticated_telnet.csv", help="CSV output path")
    parser.add_argument("--list", default="hp_unauthenticated_telnet_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Telnet ports   : {ports}/TCP")
    print("Discovery      : Nmap plaintext Telnet fingerprint")
    print("Access probe   : Telnet negotiation plus blank line only")
    print("Commands       : no login, configuration, printing, or admin commands")
    print(f"Showing        : {'all HP Telnet results' if args.show_all else 'confirmed vulnerable only'}")

    rows = asyncio.run(
        run_all(
            targets,
            ports,
            workers,
            max(10, args.nmap_timeout),
            max(0.5, args.connect_timeout),
            max(0.5, args.read_timeout),
        )
    )
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    auth_required = [row for row in rows if row["status"] == "NOT AFFECTED"]
    review = [row for row in rows if row["status"] == "REVIEW"]
    print()
    print(f"HP Telnet endpoints : {len(rows)}")
    print(f"Vulnerable          : {len(vulnerable)}")
    print(f"Authentication req. : {len(auth_required)}")
    print(f"Inconclusive        : {len(review)}")
    print(f"Vulnerable hosts    : {len({row['ip'] for row in vulnerable})}")
    print(f"CSV written         : {args.csv}")
    print(f"IP list written     : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

