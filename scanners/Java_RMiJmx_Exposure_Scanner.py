#!/usr/bin/env python3
"""
Find exposed Java RMI registries and JMX/RMI serialization surfaces.

The scanner uses Nmap service detection and the safe rmi-dumpregistry NSE
script. It does not invoke remote methods, submit serialized objects, load
classes, authenticate, or attempt code execution.

An exposed RMI/JMX service is an attack surface, not proof that a specific
deserialization gadget is exploitable. Results are therefore classified as:
  JMX EXPOSED    - an unauthenticated registry dump reveals JMX bindings
  RMI EXPOSED    - an unauthenticated registry dump reveals RMI objects
  RMI CANDIDATE  - an RMI-like port is open but enumeration was inconclusive

Requirements:
    sudo apt install nmap

Examples:
    python3 JavaRmiJmxExposureScanner.py -f target_ips.txt
    python3 JavaRmiJmxExposureScanner.py 192.0.2.0/24 --show-all
    python3 JavaRmiJmxExposureScanner.py -f target_ips.txt --all-ports

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
RESET = "\033[0m"

DEFAULT_PORTS = (
    "1090-1100,1199,2099,4444,4445,7091,7199,8686,8999,"
    "9010,9998,9999,10001,11099,12345,50000"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("PROTOCOL", 12),
    ("SERVICE", 25),
    ("ACCESS", 18),
    ("STATUS", 16),
    ("REMOTE PORTS", 22),
    ("DETAIL", 62),
]

JMX_MARKERS = (
    "jmxconnector",
    "jmxrmi",
    "javax.management.remote",
    "rmiconnection",
    "rmiserversocketfactory",
)

RMI_MARKERS = (
    "java.rmi.",
    "remoteobject",
    "remotestub",
    "unicastref",
    "rmiregistry",
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


def has_nse_script():
    try:
        result = subprocess.run(
            ["nmap", "--script-help", "rmi-dumpregistry"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return (
            result.returncode == 0
            and "rmi-dumpregistry" in result.stdout
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


async def run_nmap(ip, ports, all_ports, min_rate, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-all",
        "--open",
        "--script",
        "rmi-dumpregistry",
        "--script-timeout",
        "30s",
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


def script_output(port_node):
    script = port_node.find("script[@id='rmi-dumpregistry']")
    return script.attrib.get("output", "").strip() if script is not None else ""


def service_fingerprint(port_node):
    service = port_node.find("service")
    if service is None:
        return "unknown", ""
    name = service.attrib.get("name", "unknown")
    details = " ".join(
        value
        for value in (
            service.attrib.get("product", ""),
            service.attrib.get("version", ""),
            service.attrib.get("extrainfo", ""),
        )
        if value
    )
    return name, details


def is_rmi_candidate(port_node, output):
    name, details = service_fingerprint(port_node)
    evidence = f"{name} {details} {output}".lower()
    return bool(
        re.search(
            r"\b(?:java[- ]?rmi|rmiregistry|java object|jmxrmi|jmxconnector)\b",
            evidence,
        )
    )


def remote_endpoints(output, registry_port):
    endpoints = set()
    for match in re.finditer(
        r"@(?:\[([0-9a-f:]+)\]|([A-Za-z0-9_.:-]+)):(\d{1,5})",
        output,
        re.I,
    ):
        host = match.group(1) or match.group(2)
        port = int(match.group(3))
        if 1 <= port <= 65535 and port != registry_port:
            endpoints.add(f"{host}:{port}")
    return sorted(endpoints)


def binding_names(output):
    names = []
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("|_").strip()
        if not line or line.lower().startswith(
            ("extends", "implements", "custom data", "classpath")
        ):
            continue
        if re.search(r"@[A-Za-z0-9_.:\[\]-]+:\d+", line):
            continue
        if re.search(r"\b(?:java|javax|sun|com|org)\.[A-Za-z0-9_.$]+", line):
            continue
        if len(line) <= 120 and not line.endswith(":"):
            names.append(line)
    return list(dict.fromkeys(names))


def classify(port_node):
    output = script_output(port_node)
    name, details = service_fingerprint(port_node)
    port = int(port_node.attrib.get("portid", "0"))
    evidence = f"{name} {details} {output}".lower()

    if output:
        jmx = any(marker in evidence for marker in JMX_MARKERS)
        rmi = jmx or any(marker in evidence for marker in RMI_MARKERS)
        bindings = binding_names(output)
        remotes = remote_endpoints(output, port)
        if jmx:
            status = "JMX EXPOSED"
            access = "REGISTRY READABLE"
            detail = "Unauthenticated RMI registry enumeration exposed JMX bindings."
        elif rmi or bindings:
            status = "RMI EXPOSED"
            access = "REGISTRY READABLE"
            detail = "Unauthenticated RMI registry enumeration exposed remote objects."
        else:
            status = "RMI EXPOSED"
            access = "REGISTRY READABLE"
            detail = "The RMI registry returned data without authentication."
        if bindings:
            detail += f" Bindings: {', '.join(bindings[:4])}."
        return status, access, remotes, detail, output

    if is_rmi_candidate(port_node, output):
        return (
            "RMI CANDIDATE",
            "INCONCLUSIVE",
            [],
            "An RMI-like service is open, but registry enumeration returned no objects.",
            "",
        )
    return None


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
            result = classify(port_node)
            if result is None:
                continue
            status, access, remotes, detail, evidence = result
            name, service_details = service_fingerprint(port_node)
            port = int(port_node.attrib.get("portid", "0"))
            rows.append({
                "ip": ip,
                "port": f"{port}/TCP",
                "protocol": "JAVA RMI",
                "service": service_details or name.upper(),
                "access": access,
                "status": status,
                "remote_ports": ",".join(remotes) or "-",
                "detail": detail,
                "evidence": re.sub(r"\s+", " ", evidence).strip(),
            })
    return rows


async def scan_one(ip, ports, all_ports, min_rate, timeout):
    xml_text, stderr = await run_nmap(
        ip, ports, all_ports, min_rate, timeout
    )
    timed_out = bool(re.search(r"timed out|timeout|aborted", stderr, re.I))
    return parse_xml(xml_text), timed_out


async def run_all(targets, workers, ports, all_ports, min_rate, timeout):
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
                    ip, ports, all_ports, min_rate, timeout
                )
                rows.extend(findings)
                if timed_out:
                    timeout_hosts.add(ip)
                completed += 1
                exposed = sum(
                    row["status"] in {"JMX EXPOSED", "RMI EXPOSED"}
                    for row in rows
                )
                sys.stdout.write(
                    f"\rScanning Java RMI/JMX: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Endpoints: {len(rows)} | Exposed: {exposed} | "
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
    return rows, timeout_hosts


def print_table(rows, show_all=False, colors=True):
    displayed = rows if show_all else [
        row for row in rows
        if row["status"] in {"JMX EXPOSED", "RMI EXPOSED"}
    ]
    print()
    if not displayed:
        print("No unauthenticated Java RMI/JMX registry exposure was confirmed.")
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
            cell(row["service"], 25),
            cell(row["access"], 18),
            cell(row["status"], 16),
            cell(row["remote_ports"], 22),
            cell(row["detail"], 62),
        ])
        code = RED if row["status"] in {"JMX EXPOSED", "RMI EXPOSED"} else YELLOW
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "port",
        "protocol",
        "service",
        "access",
        "status",
        "remote_ports",
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
        if row["status"] in {"JMX EXPOSED", "RMI EXPOSED"}
    }
    with open(path, "w", encoding="utf-8") as handle:
        for endpoint in sorted(
            endpoints,
            key=lambda value: (
                ip_sort(value.rsplit(":", 1)[0]),
                int(value.rsplit(":", 1)[1]),
            ),
        ):
            handle.write(f"{endpoint}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find exposed Java RMI registries and JMX/RMI serialization surfaces."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="RMI/JMX TCP ports and ranges")
    parser.add_argument("--all-ports", action="store_true", help="Scan all 65535 TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Minimum Nmap rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host workers")
    parser.add_argument("-t", "--timeout", type=int, default=75, help="Nmap host timeout")
    parser.add_argument("--show-all", action="store_true", help="Also show inconclusive RMI candidates")
    parser.add_argument("--csv", default="java_rmi_jmx_exposure.csv", help="CSV output path")
    parser.add_argument("--list", default="java_rmi_jmx_exposed_endpoints.txt", help="Exposed IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    if not has_nse_script():
        raise SystemExit(
            "Nmap script rmi-dumpregistry was not found. "
            "Run: sudo nmap --script-updatedb"
        )

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Scan ports     : {'1-65535/TCP' if args.all_ports else ports}")
    print("Nmap script    : rmi-dumpregistry (safe/read-only)")
    print("Payloads       : no serialized gadgets, method calls, or class loading")
    print(f"Showing        : {'all RMI/JMX candidates' if args.show_all else 'confirmed registry exposure only'}")

    rows, timeout_hosts = asyncio.run(
        run_all(
            targets,
            workers,
            ports,
            args.all_ports,
            max(1, args.min_rate),
            max(20, args.timeout),
        )
    )
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    jmx = [row for row in rows if row["status"] == "JMX EXPOSED"]
    rmi = [row for row in rows if row["status"] == "RMI EXPOSED"]
    candidates = [row for row in rows if row["status"] == "RMI CANDIDATE"]
    print()
    print(f"JMX exposed       : {len(jmx)}")
    print(f"RMI exposed       : {len(rmi)}")
    print(f"RMI candidates    : {len(candidates)}")
    print(f"Host timeouts     : {len(timeout_hosts)}")
    print(f"CSV written       : {args.csv}")
    print(f"Endpoint list     : {args.list}")
    return 1 if jmx or rmi else 0


if __name__ == "__main__":
    raise SystemExit(main())

