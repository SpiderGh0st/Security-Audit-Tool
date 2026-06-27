#!/usr/bin/env python3
"""
Find Microsoft Message Queuing endpoints potentially affected by QueueJumper,
CVE-2023-21554.

The scanner performs service and OS-build identification only. It does not
send crafted MSMQ packets, create queues, submit messages, authenticate, or
attempt code execution.

Classification:
  POTENTIALLY AFFECTED  MSMQ TCP/1801 is open and an exposed Windows build is older
              than the April 2023 fixed build.
  PATCHED     MSMQ is open and the exposed build meets/exceeds that baseline.
  REVIEW      MSMQ is open, but patch applicability cannot be established
              remotely from the exposed version.

Requirements:
    sudo apt install nmap

Examples:
    python3 MsmqRceCve202321554Scanner.py -f target_ips.txt
    python3 MsmqRceCve202321554Scanner.py 192.0.2.0/24 --show-all
    sudo python3 MsmqRceCve202321554Scanner.py -f target_ips.txt --os-detect

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

CVE = "CVE-2023-21554"
CVSS = "9.8"
SCAN_PORTS = "135,139,445,1801,3389"

# Minimum Windows builds containing Microsoft's April 2023 fix.
# The comparison is major.minor.build.revision.
FIXED_BUILDS = {
    14393: 5850,   # Windows Server 2016 / Windows 10 1607
    17763: 4252,   # Windows Server 2019 / Windows 10 1809
    19042: 2846,   # Windows 10 20H2
    19044: 2846,   # Windows 10 21H2
    19045: 2846,   # Windows 10 22H2
    20348: 1668,   # Windows Server 2022
    22000: 1817,   # Windows 11 21H2
    22621: 1555,   # Windows 11 22H2
}

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("MSMQ SERVICE", 30),
    ("WINDOWS BUILD", 18),
    ("STATUS", 15),
    ("CVE", 16),
    ("CVSS", 6),
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


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    value = re.sub(r":1801(?:/tcp)?$", "", value, flags=re.I)
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


async def run_nmap(ip, args):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "-p", SCAN_PORTS,
        "--script", "smb-os-discovery,rdp-ntlm-info",
        "--script-timeout", args.script_timeout,
        "--host-timeout", args.host_timeout,
    ]
    if args.os_detect:
        command.extend(["-O", "--osscan-guess"])
    command.extend(["-oX", "-", ip])
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def script_evidence(host):
    outputs = []
    for script in host.findall(".//script"):
        script_id = script.attrib.get("id", "")
        if script_id in {"smb-os-discovery", "rdp-ntlm-info"}:
            outputs.append(script.attrib.get("output", ""))
            for elem in script.iter("elem"):
                key = elem.attrib.get("key", "")
                value = elem.text or ""
                outputs.append(f"{key}: {value}")
    return "\n".join(outputs)


def os_evidence(host):
    values = []
    for osmatch in host.findall("./os/osmatch"):
        values.append(osmatch.attrib.get("name", ""))
    for osclass in host.findall("./os/osmatch/osclass"):
        values.extend([
            osclass.attrib.get("vendor", ""),
            osclass.attrib.get("osfamily", ""),
            osclass.attrib.get("osgen", ""),
        ])
        values.extend(cpe.text or "" for cpe in osclass.findall("cpe"))
    return "\n".join(value for value in values if value)


def extract_build(text):
    patterns = (
        r"\b(?:Product_Version|product version|Windows version|Version)\s*:\s*"
        r"(10\.0\.\d{4,5}(?:\.\d+)?)",
        r"\b(10\.0\.\d{4,5}\.\d+)\b",
        r"\b(10\.0\.\d{4,5})\b",
        r"\b(6\.[123]\.\d{4}(?:\.\d+)?)\b",
        r"\b(6\.0\.600[23](?:\.\d+)?)\b",
    )
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, text, re.I))
    if not matches:
        return ""
    return max(matches, key=lambda value: (len(value.split(".")), len(value)))


def build_parts(value):
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return ()
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def classify_build(build):
    parts = build_parts(build)
    if not parts:
        return (
            "REVIEW",
            "MSMQ is reachable, but no Windows patch-level build was exposed.",
        )

    build_number = parts[2]
    revision = parts[3]
    fixed_revision = FIXED_BUILDS.get(build_number)
    if fixed_revision is not None:
        if revision == 0 and build.count(".") < 3:
            return (
                "REVIEW",
                "Windows build branch is known, but the update revision is hidden.",
            )
        if revision < fixed_revision:
            return (
                "POTENTIALLY AFFECTED",
                f"Build {build} is older than fixed baseline "
                f"{parts[0]}.{parts[1]}.{build_number}.{fixed_revision}.",
            )
        return (
            "PATCHED",
            f"Build {build} meets or exceeds the April 2023 fixed baseline.",
        )

    if build_number in {6002, 6003, 7601, 9200, 9600}:
        return (
            "REVIEW",
            "Legacy Windows release detected; the visible build does not expose "
            "the installed monthly security update level.",
        )

    if build_number > max(FIXED_BUILDS):
        return (
            "PATCHED",
            "Windows build branch postdates the affected April 2023 branches.",
        )
    return (
        "REVIEW",
        "Windows build is not covered by the scanner's remote comparison table.",
    )


def service_text(port_node):
    service = port_node.find("service")
    if service is None:
        return "Microsoft Message Queuing"
    parts = [
        service.attrib.get("name", ""),
        service.attrib.get("product", ""),
        service.attrib.get("version", ""),
        service.attrib.get("extrainfo", ""),
    ]
    return " ".join(part for part in parts if part) or "Microsoft Message Queuing"


def parse_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    host = root.find("host")
    if host is None:
        return None
    address = host.find("address[@addrtype='ipv4']")
    if address is None:
        address = host.find("address")
    if address is None:
        return None
    ip = address.attrib.get("addr", "")

    msmq_port = None
    for port_node in host.findall("./ports/port"):
        if port_node.attrib.get("portid") != "1801":
            continue
        state = port_node.find("state")
        if state is not None and state.attrib.get("state") == "open":
            msmq_port = port_node
            break
    if msmq_port is None:
        return None

    evidence = "\n".join([
        script_evidence(host),
        os_evidence(host),
        service_text(msmq_port),
    ])
    build = extract_build(evidence)
    status, detail = classify_build(build)
    return {
        "ip": ip,
        "port": 1801,
        "protocol": "MSMQ/TCP",
        "service": service_text(msmq_port),
        "build": build,
        "status": status,
        "cve": CVE,
        "cvss": CVSS,
        "detail": detail,
        "evidence": re.sub(r"\s+", " ", evidence).strip()[:1000],
    }


async def scan_host(ip, args):
    return parse_xml(await run_nmap(ip, args))


async def run_all(targets, args):
    queue = asyncio.Queue()
    rows = []
    discovered = 0
    completed = 0
    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, discovered
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                try:
                    result = await scan_host(ip, args)
                    if result:
                        discovered += 1
                        if args.show_all or result["status"] in {"POTENTIALLY AFFECTED", "REVIEW"}:
                            rows.append(result)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    row["status"] == "POTENTIALLY AFFECTED" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning MSMQ RCE: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"MSMQ: {discovered} | Candidates: {vulnerable} | "
                    f"Current: {ip}".ljust(135)
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
    return rows, discovered


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No potentially affected or review-required MSMQ endpoints were identified.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell("1801/TCP", 10),
            cell(row["protocol"], 12),
            cell(row["service"], 30),
            cell(row["build"] or "UNKNOWN", 18),
            cell(row["status"], 15),
            cell(row["cve"], 16),
            cell(row["cvss"], 6),
        ])
        code = RED if row["status"] == "POTENTIALLY AFFECTED" else (
            GREEN if row["status"] == "PATCHED" else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "service", "build", "status",
        "cve", "cvss", "detail", "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow({field: row.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            if row["status"] == "POTENTIALLY AFFECTED":
                handle.write(f"{row['ip']}:1801\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find MSMQ endpoints affected by CVE-2023-21554 QueueJumper."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="60s", help="Nmap timeout per host")
    parser.add_argument("--script-timeout", default="30s", help="Nmap script timeout")
    parser.add_argument("--os-detect", action="store_true", help="Add Nmap OS detection; normally requires sudo")
    parser.add_argument("--show-all", action="store_true", help="Also show remotely confirmed patched MSMQ endpoints")
    parser.add_argument("--csv", default="msmq_cve_2023_21554_results.csv", help="CSV output")
    parser.add_argument("--list", default="msmq_cve_2023_21554_candidates.txt", help="Potentially affected IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print("MSMQ port      : 1801/TCP")
    print(f"Vulnerability  : QueueJumper / {CVE} / CVSS {CVSS}")
    print("Verification   : MSMQ exposure plus remote Windows build comparison")
    print("Probe          : version identification only; no crafted MSMQ messages")
    print(f"Showing        : {'all MSMQ assessments' if args.show_all else 'potentially affected and review-required endpoints'}")

    rows, discovered = asyncio.run(run_all(targets, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(row["status"] == "POTENTIALLY AFFECTED" for row in rows)
    review = sum(row["status"] == "REVIEW" for row in rows)
    print()
    print(f"MSMQ endpoints found : {discovered}")
    print(f"Potentially affected : {vulnerable}")
    print(f"Review required      : {review}")
    print(f"CSV written          : {args.csv}")
    print(f"Endpoint list        : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

