#!/usr/bin/env python3
"""
Find OpenSSL ChangeCipherSpec Injection (CVE-2014-0224).

The scanner uses Nmap's safe ssl-ccs-injection NSE script. It sends only TLS
handshake records required to determine whether an out-of-order
ChangeCipherSpec message is accepted. It sends no credentials or application
data.

Requirements:
    sudo apt install nmap

Examples:
    python3 OpenSslCcsInjectionScanner.py -f target_ips.txt
    python3 OpenSslCcsInjectionScanner.py 192.0.2.0/24 --show-all
    python3 OpenSslCcsInjectionScanner.py -f target_ips.txt -p 443,8443,3389
    python3 OpenSslCcsInjectionScanner.py -f target_ips.txt --all-ports

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

CVE = "CVE-2014-0224"

DEFAULT_PORTS = (
    "21,25,110,143,443,444,465,587,591,593,631,636,989,990,"
    "993,995,1433,1521,2376,3389,5061,5432,5800,5986,6172,"
    "6443,7001-7005,7070,7080,7443,7777,8000-8012,8020,8030,"
    "8040,8050,8060,8070,8080-8090,8100,8180,8181,8200,8280,"
    "8282,8300,8383,8442,8443,8444,8484,8500,8543,8544,8545,"
    "8585,8686,8787,8834,8880,8888,8983,8999,9000,9001,9043,"
    "9080,9090,9091,9200,9402,9403,9404,9419,9443,9990,9999,"
    "10000,10080,10443,18080,18081,18090,20443,28080,33034,"
    "33035,38080,47001,48080,49720,49726,53048,58080,61662"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("SERVICE", 18),
    ("PROTOCOL", 10),
    ("CCS INJECTION", 18),
    ("STATUS", 18),
    ("CVE", 16),
    ("DETAIL", 64),
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


def has_nse_script():
    try:
        result = subprocess.run(
            ["nmap", "--script-help", "ssl-ccs-injection"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return (
            result.returncode == 0
            and "ssl-ccs-injection" in result.stdout
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


async def run_nmap(ip, ports, all_ports, min_rate, host_timeout, script_timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "--script",
        "ssl-ccs-injection",
        "--script-args",
        "vulns.showall=true",
        "--host-timeout",
        host_timeout,
        "--script-timeout",
        script_timeout,
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


def script_node(port_node):
    return port_node.find("script[@id='ssl-ccs-injection']")


def script_state(script):
    output = script.attrib.get("output", "").strip()
    for element in script.iter("elem"):
        if element.attrib.get("key", "").lower() != "state":
            continue
        value = (element.text or "").strip().upper()
        if "NOT VULNERABLE" in value:
            return "NOT VULNERABLE", output
        if "VULNERABLE" in value:
            return "VULNERABLE", output

    upper = output.upper()
    if re.search(r"\bSTATE\s*:\s*NOT VULNERABLE\b", upper):
        return "NOT VULNERABLE", output
    if re.search(r"\bSTATE\s*:\s*VULNERABLE\b", upper):
        return "VULNERABLE", output
    if "NO REPLY FROM SERVER" in upper or "TIMEOUT" in upper:
        return "TIMEOUT", output
    if "VULNERABLE:" in upper and "CCS INJECTION" in upper:
        return "VULNERABLE", output
    return "INCONCLUSIVE", output


def service_details(port_node):
    service = port_node.find("service")
    if service is None:
        return "TLS", "TLS"
    name = service.attrib.get("name", "TLS")
    product = service.attrib.get("product", "")
    version = service.attrib.get("version", "")
    extra = service.attrib.get("extrainfo", "")
    tunnel = service.attrib.get("tunnel", "").lower()
    fingerprint = " ".join(
        value for value in [product, version, extra] if value
    )
    protocol = (
        "TLS"
        if tunnel in {"ssl", "tls"} or name.lower() in {"https", "ssl"}
        else "STARTTLS/TLS"
    )
    return fingerprint or name.upper(), protocol


def parse_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    rows = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address")
        if address is None:
            continue
        ip = address.attrib.get("addr", "")

        for port_node in host.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            script = script_node(port_node)
            if script is None:
                continue

            result, raw_output = script_state(script)
            service, protocol = service_details(port_node)
            port = int(port_node.attrib.get("portid", "0"))

            if result == "VULNERABLE":
                ccs = "ACCEPTED"
                status = "VULNERABLE"
                detail = "Server accepted an invalid early ChangeCipherSpec sequence."
            elif result == "NOT VULNERABLE":
                ccs = "REJECTED"
                status = "NOT VULNERABLE"
                detail = "Server rejected the invalid ChangeCipherSpec sequence."
            elif result == "TIMEOUT":
                ccs = "NO VERDICT"
                status = "TIMEOUT"
                detail = "TLS service did not return a conclusive CCS probe response."
            else:
                ccs = "NO VERDICT"
                status = "INCONCLUSIVE"
                detail = "The CCS NSE script ran but returned no conclusive state."

            rows.append({
                "ip": ip,
                "port": f"{port}/TCP",
                "service": service,
                "protocol": protocol,
                "ccs": ccs,
                "status": status,
                "cve": CVE,
                "detail": detail,
                "evidence": re.sub(r"\s+", " ", raw_output).strip(),
            })
    return rows


async def scan_one(
    ip,
    ports,
    all_ports,
    min_rate,
    host_timeout,
    script_timeout,
):
    xml_text, stderr = await run_nmap(
        ip,
        ports,
        all_ports,
        min_rate,
        host_timeout,
        script_timeout,
    )
    return parse_xml(xml_text), bool(
        re.search(r"timed out|timeout|aborted", stderr, re.I)
    )


async def run_all(
    targets,
    workers,
    ports,
    all_ports,
    min_rate,
    host_timeout,
    script_timeout,
):
    queue = asyncio.Queue()
    rows = []
    timeout_hosts = set()
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
                findings, timed_out = await scan_one(
                    ip,
                    ports,
                    all_ports,
                    min_rate,
                    host_timeout,
                    script_timeout,
                )
                rows.extend(findings)
                if timed_out:
                    timeout_hosts.add(ip)
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning OpenSSL CCS: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Tested: {len(rows)} | Vulnerable: {vulnerable} | "
                    f"Current: {ip}".ljust(140)
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
    return rows, timeout_hosts


def print_table(rows, show_all=False, colors=True):
    displayed = rows if show_all else [
        row for row in rows if row["status"] == "VULNERABLE"
    ]
    print()
    if not displayed:
        print("No TLS endpoints confirmed vulnerable to OpenSSL CCS Injection were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        displayed,
        key=lambda item: (
            ip_sort(item["ip"]),
            int(item["port"].split("/")[0]),
        ),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 10),
            cell(row["service"], 18),
            cell(row["protocol"], 10),
            cell(row["ccs"], 18),
            cell(row["status"], 18),
            cell(row["cve"], 16),
            cell(row["detail"], 64),
        ])
        code = (
            RED if row["status"] == "VULNERABLE"
            else GREEN if row["status"] == "NOT VULNERABLE"
            else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "service",
        "protocol",
        "ccs",
        "status",
        "cve",
        "detail",
        "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (
                ip_sort(item["ip"]),
                int(item["port"].split("/")[0]),
            ),
        ))


def write_list(path, rows):
    endpoints = {
        f"{row['ip']}:{row['port'].split('/')[0]}"
        for row in rows
        if row["status"] == "VULNERABLE"
    }
    with open(path, "w", encoding="utf-8") as handle:
        for endpoint in sorted(
            endpoints,
            key=lambda item: (
                ip_sort(item.rsplit(":", 1)[0]),
                int(item.rsplit(":", 1)[1]),
            ),
        ):
            handle.write(f"{endpoint}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find OpenSSL CCS Injection (CVE-2014-0224)."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="TCP TLS/STARTTLS ports and ranges")
    parser.add_argument("--all-ports", action="store_true", help="Scan all 65535 TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Minimum Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent host workers")
    parser.add_argument("--host-timeout", default="5m", help="Nmap host timeout")
    parser.add_argument("--script-timeout", default="90s", help="NSE script timeout")
    parser.add_argument("--show-all", action="store_true", help="Show all endpoints tested by the CCS script")
    parser.add_argument("--csv", default="openssl_ccs_injection_results.csv", help="CSV output path")
    parser.add_argument("--list", default="openssl_ccs_vulnerable_endpoints.txt", help="Vulnerable IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    if not has_nse_script():
        raise SystemExit(
            "Nmap script ssl-ccs-injection was not found. "
            "Run: sudo nmap --script-updatedb"
        )

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Scan ports     : {'1-65535/TCP' if args.all_ports else ports}")
    print("Nmap script    : ssl-ccs-injection")
    print(f"Vulnerability  : OpenSSL CCS Injection ({CVE})")
    print("Probe          : TLS handshake records only; no application data")
    print(f"Showing        : {'all tested TLS endpoints' if args.show_all else 'confirmed vulnerable only'}")

    rows, timeout_hosts = asyncio.run(
        run_all(
            targets,
            workers,
            ports,
            args.all_ports,
            max(1, args.min_rate),
            args.host_timeout,
            args.script_timeout,
        )
    )
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    safe = [row for row in rows if row["status"] == "NOT VULNERABLE"]
    inconclusive = [
        row for row in rows
        if row["status"] in {"INCONCLUSIVE", "TIMEOUT"}
    ]
    print()
    print(f"TLS endpoints tested : {len(rows)}")
    print(f"Vulnerable           : {len(vulnerable)}")
    print(f"Not vulnerable       : {len(safe)}")
    print(f"Inconclusive/timeout : {len(inconclusive)}")
    print(f"Host-level timeouts  : {len(timeout_hosts)}")
    print(f"CSV written          : {args.csv}")
    print(f"Endpoint list        : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

