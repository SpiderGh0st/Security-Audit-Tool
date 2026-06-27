
#!/usr/bin/env python3
"""
Find Java JMX agents that allow unauthenticated management connections.

Workflow:
  1. Nmap finds open candidate JMX/RMI ports.
  2. JmxReadOnlyProbe connects with no credentials and no client certificate.
  3. The helper reads only default domain, domain names, and MBean count.

No MBean attributes are changed, no operations are invoked, and no serialized
gadget payloads are sent.

Requirements:
    sudo apt install nmap default-jdk-headless

Examples:
    python3 UnauthenticatedJmxAgentScanner.py -f target_ips.txt
    python3 UnauthenticatedJmxAgentScanner.py 203.0.113.21 -p 6101,6102
    python3 UnauthenticatedJmxAgentScanner.py -f target_ips.txt --show-all

Keep JmxReadOnlyProbe.java in the same directory as this script.
Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import base64
import csv
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "1090-1100,1199,2099,4444,4445,5555,6101,6102,7091,"
    "7199,8686,8999,9010,9998,9999,10001,11099,12345,50000"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTOCOL", 12),
    ("PASSWORD AUTH", 15),
    ("CLIENT CERT", 13),
    ("MBEANS", 8),
    ("DOMAINS", 9),
    ("STATUS", 16),
    ("DETAIL", 62),
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


def decode64(value):
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except (ValueError, base64.binascii.Error):
        return value


def compile_helper(source, build_dir):
    command = [
        "javac",
        "-d",
        str(build_dir),
        str(source),
    ]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            "Failed to compile JmxReadOnlyProbe.java:\n" + result.stderr.strip()
        )


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
        "rmi-dumpregistry",
        "--script-timeout",
        "20s",
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        ip,
    ]
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


def parse_open_ports(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    ports = []
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
            service = port_node.find("service")
            name = service.attrib.get("name", "") if service is not None else ""
            fingerprint = " ".join(
                value
                for value in (
                    service.attrib.get("product", "") if service is not None else "",
                    service.attrib.get("version", "") if service is not None else "",
                    service.attrib.get("extrainfo", "") if service is not None else "",
                )
                if value
            )
            script = port_node.find("script[@id='rmi-dumpregistry']")
            registry = script.attrib.get("output", "") if script is not None else ""
            ports.append({
                "ip": ip,
                "port": int(port_node.attrib.get("portid", "0")),
                "service": fingerprint or name.upper() or "unknown",
                "registry": re.sub(r"\s+", " ", registry).strip(),
            })
    return ports


async def probe_jmx(ip, port, build_dir, timeout):
    command = [
        "java",
        "-Dsun.rmi.transport.tcp.handshakeTimeout=5000",
        "-Dsun.rmi.transport.tcp.connectionTimeout=5000",
        "-Dsun.rmi.transport.tcp.responseTimeout=8000",
        "-cp",
        str(build_dir),
        "JmxReadOnlyProbe",
        ip,
        str(port),
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "probe": "TIMEOUT",
            "default_domain": "",
            "mbeans": 0,
            "domains": [],
            "error": "Read-only JMX connection timed out.",
        }

    output = stdout.decode("utf-8", errors="replace").strip()
    error = stderr.decode("utf-8", errors="replace").strip()
    result_line = next(
        (line for line in output.splitlines() if line.startswith("RESULT\t")),
        "",
    )
    if not result_line:
        return {
            "probe": "FAILED",
            "default_domain": "",
            "mbeans": 0,
            "domains": [],
            "error": re.sub(r"\s+", " ", error or output).strip()[:300],
        }

    parts = result_line.split("\t", 5)
    while len(parts) < 6:
        parts.append("")
    _prefix, status, default64, mbeans, domain_count, final64 = parts
    final = decode64(final64)
    domains = [item for item in final.split(",") if item]
    try:
        mbean_count = int(mbeans)
    except ValueError:
        mbean_count = 0
    return {
        "probe": status,
        "default_domain": decode64(default64),
        "mbeans": mbean_count,
        "domain_count": int(domain_count) if domain_count.isdigit() else len(domains),
        "domains": domains,
        "error": final if status != "CONNECTED" else "",
    }


async def scan_one(ip, ports, nmap_timeout, probe_timeout, build_dir):
    xml_text, _ = await run_nmap(ip, ports, nmap_timeout)
    endpoints = parse_open_ports(xml_text)
    rows = []
    for endpoint in endpoints:
        result = await probe_jmx(
            endpoint["ip"],
            endpoint["port"],
            build_dir,
            probe_timeout,
        )
        if result["probe"] == "CONNECTED":
            status = "VULNERABLE"
            password = "NOT REQUIRED"
            client_cert = "NOT REQUIRED"
            detail = (
                "Connected to JMX and read management metadata without "
                "credentials or a client certificate."
            )
            if result["default_domain"]:
                detail += f" Default domain: {result['default_domain']}."
        elif result["probe"] == "AUTH_REQUIRED":
            status = "AUTH REQUIRED"
            password = "REQUIRED"
            client_cert = "UNKNOWN"
            detail = "The JMX endpoint rejected the credential-free connection."
        else:
            status = "NOT JMX/FAILED"
            password = "UNKNOWN"
            client_cert = "UNKNOWN"
            detail = result["error"] or "Open port did not accept the standard jmxrmi connection."

        rows.append({
            "ip": endpoint["ip"],
            "port": f"{endpoint['port']}/TCP",
            "protocol": "JMX/RMI",
            "password_auth": password,
            "client_cert": client_cert,
            "mbeans": result.get("mbeans", 0) or "-",
            "domains": result.get("domain_count", len(result.get("domains", []))) or "-",
            "status": status,
            "detail": detail,
            "service": endpoint["service"],
            "domain_names": ",".join(result.get("domains", [])),
            "registry_evidence": endpoint["registry"],
        })
    return rows


async def run_all(
    targets,
    workers,
    ports,
    nmap_timeout,
    probe_timeout,
    build_dir,
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
                        probe_timeout,
                        build_dir,
                    )
                )
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning unauthenticated JMX: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Tested: {len(rows)} | Vulnerable: {vulnerable} | "
                    f"Current: {ip}".ljust(145)
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
        print("No JMX agents allowing unauthenticated management access were found.")
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
            cell(row["port"], 9),
            cell(row["protocol"], 12),
            cell(row["password_auth"], 15),
            cell(row["client_cert"], 13),
            cell(row["mbeans"], 8),
            cell(row["domains"], 9),
            cell(row["status"], 16),
            cell(row["detail"], 62),
        ])
        code = (
            RED if row["status"] == "VULNERABLE"
            else GREEN if row["status"] == "AUTH REQUIRED"
            else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "protocol",
        "password_auth",
        "client_cert",
        "mbeans",
        "domains",
        "status",
        "detail",
        "service",
        "domain_names",
        "registry_evidence",
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
        for endpoint in sorted(endpoints):
            handle.write(f"{endpoint}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find JMX agents that allow credential-free management access."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Candidate JMX/RMI TCP ports")
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent host workers")
    parser.add_argument("--nmap-timeout", type=int, default=60, help="Nmap host timeout")
    parser.add_argument("--probe-timeout", type=int, default=15, help="Read-only JMX connection timeout")
    parser.add_argument("--show-all", action="store_true", help="Show authentication-required and failed candidates")
    parser.add_argument("--csv", default="unauthenticated_jmx_agents.csv", help="CSV output path")
    parser.add_argument("--list", default="unauthenticated_jmx_endpoints.txt", help="Vulnerable host:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    for command in ("nmap", "java", "javac"):
        if not shutil.which(command):
            raise SystemExit(
                f"{command} was not found. Install dependencies with: "
                "sudo apt install nmap default-jdk-headless"
            )

    script_dir = Path(__file__).resolve().parent
    helper_source = script_dir / "JmxReadOnlyProbe.java"
    if not helper_source.exists():
        raise SystemExit(
            f"Missing helper source: {helper_source}. Keep it beside this script."
        )

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Scan ports     : {ports}")
    print("JMX proof      : empty credentials + read-only domain/MBean metadata")
    print("Client cert    : none supplied")
    print("Write actions  : none; no MBean operations invoked")
    print(f"Showing        : {'all candidates' if args.show_all else 'confirmed vulnerable only'}")

    with tempfile.TemporaryDirectory(prefix="jmx-readonly-") as temp:
        build_dir = Path(temp)
        compile_helper(helper_source, build_dir)
        rows = asyncio.run(
            run_all(
                targets,
                workers,
                ports,
                max(20, args.nmap_timeout),
                max(5, args.probe_timeout),
                build_dir,
            )
        )

    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    auth_required = [row for row in rows if row["status"] == "AUTH REQUIRED"]
    failed = [row for row in rows if row["status"] == "NOT JMX/FAILED"]
    print()
    print(f"Open candidates : {len(rows)}")
    print(f"Vulnerable      : {len(vulnerable)}")
    print(f"Auth required   : {len(auth_required)}")
    print(f"Not JMX/failed  : {len(failed)}")
    print(f"CSV written     : {args.csv}")
    print(f"Endpoint list   : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

