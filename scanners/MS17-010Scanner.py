#!/usr/bin/env python3
"""
Scan SMB servers for MS17-010 / EternalBlue (CVE-2017-0143).

Uses Nmap's non-exploitative smb-vuln-ms17-010 NSE script.

Requirements:
    sudo apt install nmap

Examples:
    python3 MS17_010Scanner.py -f target_ips.txt
    python3 MS17_010Scanner.py 192.0.2.0/24
    python3 MS17_010Scanner.py 192.0.2.10 --show-all

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
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 16),
    ("PORTS", 10),
    ("PROTOCOL", 10),
    ("MS17-010", 14),
    ("CVE", 16),
    ("DETAIL", 72),
]


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


def expand_target(value):
    value = value.strip().rstrip("\\").strip()
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
        return []


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
        raise SystemExit("No valid targets supplied.")
    return unique


async def run_nmap(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "--open",
        "-p",
        "139,445",
        "--script",
        "smb-vuln-ms17-010",
        "--script-args",
        "vulns.showall=true",
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
        process.returncode,
        stdout.decode("utf-8", errors="ignore"),
        stderr.decode("utf-8", errors="ignore"),
    )


def script_text(script):
    parts = [script.attrib.get("output", "")]
    for node in script.iter():
        if node.text:
            parts.append(node.text)
        parts.extend(node.attrib.values())
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def structured_vuln_state(script):
    """Read the exact state emitted by Nmap's vulns library."""
    for node in script.iter():
        key = node.attrib.get("key", "").strip().lower()
        value = (node.text or "").strip().upper()
        if key == "state" and value:
            return value

    output = script.attrib.get("output", "")
    match = re.search(
        r"(?im)^\s*State\s*:\s*(VULNERABLE|NOT VULNERABLE|LIKELY VULNERABLE)\s*$",
        output,
    )
    return match.group(1).upper() if match else ""


def parse_xml(xml_text, stderr="", returncode=0):
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

    open_ports = []
    # FIX 1: collect script element references by id() to avoid duplicates
    # when the same script appears at both port-level and host-script level.
    scripts_seen = {}
    for port_node in host.findall("./ports/port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        open_ports.append(int(port_node.attrib.get("portid", "0")))
        script = port_node.find("script[@id='smb-vuln-ms17-010']")
        if script is not None:
            scripts_seen[id(script)] = script

    host_script = host.find("hostscript/script[@id='smb-vuln-ms17-010']")
    if host_script is not None:
        scripts_seen[id(host_script)] = host_script

    scripts = list(scripts_seen.values())

    ports = ",".join(str(port) for port in sorted(set(open_ports))) or "-"
    if not open_ports:
        return {
            "ip": ip,
            "ports": ports,
            "protocol": "SMB/TCP",
            "status": "NO SMB",
            "cve": "CVE-2017-0143",
            "detail": "Ports 139 and 445 were not reported open.",
        }

    if not scripts:
        diagnostic = re.sub(r"\s+", " ", stderr).strip()
        return {
            "ip": ip,
            "ports": ports,
            "protocol": "SMB/TCP",
            "status": "NOT TESTED",
            "cve": "CVE-2017-0143",
            "detail": (
                f"NSE returned no result: {diagnostic[:220]}"
                if diagnostic
                else "SMB is open, but the NSE script returned no conclusive result. SMBv1 may be disabled."
            ),
        }

    states = [structured_vuln_state(script) for script in scripts]
    states = [state for state in states if state]
    evidence = " ".join(script_text(script) for script in scripts)
    lower = evidence.lower()

    if any(state == "VULNERABLE" for state in states):
        status = "VULNERABLE"
        detail = "Nmap returned a structured VULNERABLE state for MS17-010."
    elif any(state == "LIKELY VULNERABLE" for state in states):
        status = "POTENTIAL"
        detail = "Nmap returned LIKELY VULNERABLE; confirm with patch inventory before reporting."
    elif any(state == "NOT VULNERABLE" for state in states):
        status = "SAFE"
        detail = "Nmap reports the target is not vulnerable to MS17-010."
    elif re.search(r"state\s*:\s*vulnerable", lower):
        status = "VULNERABLE"
        detail = "Remote SMB service appears vulnerable to MS17-010."
    elif re.search(r"state\s*:\s*not vulnerable|not vulnerable", lower):
        status = "SAFE"
        detail = "Target appears patched or not vulnerable."
    elif re.search(r"could not connect|could not negotiate|failed|error", lower):
        status = "NOT TESTED"
        detail = "SMB negotiation failed; vulnerability status is inconclusive."
    else:
        status = "NOT TESTED"
        detail = evidence[:300] or "No conclusive MS17-010 response."

    return {
        "ip": ip,
        "ports": ports,
        "protocol": "SMB/TCP",
        "status": status,
        "cve": "CVE-2017-0143",
        "detail": detail,
    }


async def scan_one(ip, timeout):
    returncode, stdout, stderr = await run_nmap(ip, timeout)
    if not stdout.strip():
        raise RuntimeError(
            f"Nmap returned no XML (exit {returncode}): "
            f"{re.sub(r'\\s+', ' ', stderr).strip()[:240]}"
        )
    return parse_xml(stdout, stderr=stderr, returncode=returncode)


async def run_all(targets, args):
    queue = asyncio.Queue()
    rows = []
    completed = 0
    # Lock to protect shared state (rows list, completed counter) across workers.
    lock = asyncio.Lock()

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
                row = None
                error_row = None
                try:
                    row = await scan_one(ip, args.timeout)
                except Exception as error:
                    if args.show_all:
                        error_row = {
                            "ip": ip,
                            "ports": "-",
                            "protocol": "SMB/TCP",
                            "status": "ERROR",
                            "cve": "CVE-2017-0143",
                            "detail": f"{type(error).__name__}: {error}",
                        }

                # FIX 2: always increment completed, whether scan succeeded or raised.
                async with lock:
                    completed += 1
                    if row and (
                        args.show_all or row["status"] in {"VULNERABLE", "POTENTIAL"}
                    ):
                        rows.append(row)
                    if error_row:
                        rows.append(error_row)
                    vulnerable = sum(1 for r in rows if r["status"] == "VULNERABLE")
                    sys.stdout.write(
                        f"\rScanning MS17-010: {completed}/{len(targets)} "
                        f"({completed / len(targets) * 100:.1f}%) | "
                        f"Confirmed: {vulnerable} | Current: {ip}".ljust(125)
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
        print("No confirmed or potential MS17-010 findings were identified.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["ports"], 10),
            cell(row["protocol"], 10),
            cell(row["status"], 14),
            cell(row["cve"], 16),
            cell(row["detail"], 72),
        ])
        code = {
            "VULNERABLE": RED,
            "POTENTIAL": YELLOW,
            "SAFE": GREEN,
            "NO SMB": GREEN,
            "NOT TESTED": YELLOW,
            "ERROR": YELLOW,
        }.get(row["status"], YELLOW)
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = ["ip", "ports", "protocol", "status", "cve", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow(row)


def write_lists(prefix, rows):
    # FIX 3: include all possible statuses so no rows are silently dropped.
    for suffix, status in (
        ("vulnerable", "VULNERABLE"),
        ("potential", "POTENTIAL"),
        ("safe", "SAFE"),
        ("no_smb", "NO SMB"),
        ("not_tested", "NOT TESTED"),
        ("error", "ERROR"),
    ):
        selected = [row for row in rows if row["status"] == status]
        with open(f"{prefix}_{suffix}.txt", "w", encoding="utf-8") as handle:
            for row in sorted(selected, key=lambda item: ip_sort(item["ip"])):
                handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find SMB servers vulnerable to MS17-010."
    )
    parser.add_argument("targets", nargs="*", help="IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show safe, no-SMB, and inconclusive targets too",
    )
    parser.add_argument("--csv", default="ms17_010_results.csv", help="CSV output")
    parser.add_argument("--list-prefix", default="ms17_010", help="Output list prefix")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print("Ports          : 139,445/TCP")
    print("Nmap script    : smb-vuln-ms17-010")
    print(f"Showing        : {'all target statuses' if args.show_all else 'confirmed and potential findings'}")

    rows = asyncio.run(run_all(targets, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_lists(args.list_prefix, rows)

    counts = {
        status: sum(1 for row in rows if row["status"] == status)
        for status in ("VULNERABLE", "POTENTIAL", "SAFE", "NO SMB", "NOT TESTED", "ERROR")
    }
    print()
    for status, count in counts.items():
        print(f"{status.title():<12}: {count}")
    print(f"CSV written : {args.csv}")
    return 1 if counts["VULNERABLE"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

