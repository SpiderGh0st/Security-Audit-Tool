#!/usr/bin/env python3
"""
Check RDP servers for weak encryption configuration.

Detection uses Nmap's rdp-enum-encryption NSE script and reports:
  - NLA/CredSSP support
  - Whether Native RDP security is accepted
  - 40-bit and 56-bit RC4 support

Requirements:
    sudo apt install nmap

Examples:
    python3 RdpWeakEncryptionScanner.py -f target_ips.txt
    python3 RdpWeakEncryptionScanner.py 192.0.2.0/24 --workers 24
    python3 RdpWeakEncryptionScanner.py -f target_ips.txt --show-secure

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


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 18),
    ("NLA", 16),
    ("NATIVE RDP", 16),
    ("WEAK CIPHERS", 30),
    ("STATUS", 14),
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


def expand_target(value, default_port):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    if re.match(r"^[0-9.]+:\d+$", value):
        ip, port = value.rsplit(":", 1)
        return [(ip, int(port))]
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [(str(network.network_address), default_port)]
        return [(str(address), default_port) for address in network.hosts()]
    except ValueError:
        return [(value, default_port)]


def load_targets(args):
    targets = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                targets.extend(expand_target(line, args.port))
    for value in args.targets:
        targets.extend(expand_target(value, args.port))
    unique = list(dict.fromkeys(targets))
    if not unique:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f target_ips.txt")
    return unique


async def run_nmap(ip, port, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-p",
        str(port),
        "--script",
        "rdp-enum-encryption",
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


def script_text(script):
    parts = [script.attrib.get("output", "")]
    for node in script.iter():
        if node.text:
            parts.append(node.text)
        key = node.attrib.get("key")
        if key:
            parts.append(key)
    return "\n".join(parts)


def success(text, label):
    return bool(
        re.search(
            rf"(?im)^\s*{re.escape(label)}\s*:\s*SUCCESS\b",
            text,
        )
    )


def parse_xml(xml_text, expected_port):
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

    port_node = None
    for candidate in host.findall("./ports/port"):
        if candidate.attrib.get("portid") == str(expected_port):
            port_node = candidate
            break
    if port_node is None:
        return None
    state = port_node.find("state")
    if state is None or state.attrib.get("state") != "open":
        return None

    script = port_node.find("script[@id='rdp-enum-encryption']")
    if script is None:
        return {
            "ip": ip,
            "port": expected_port,
            "nla": "UNKNOWN",
            "native_rdp": "UNKNOWN",
            "weak_ciphers": "-",
            "status": "NOT TESTED",
            "evidence": "RDP is open, but rdp-enum-encryption returned no result.",
        }

    text = script_text(script)
    credssp = success(text, "CredSSP (NLA)")
    early_auth = success(text, "CredSSP with Early User Auth")
    native_rdp = success(text, "Native RDP")
    rdstls = success(text, "RDSTLS")
    ssl_layer = success(text, "SSL")
    weak = []
    if success(text, "40-bit RC4"):
        weak.append("40-bit RC4")
    if success(text, "56-bit RC4"):
        weak.append("56-bit RC4")

    # rdp-enum-encryption confirms protocol acceptance, not Group Policy.
    # Native RDP success proves NLA is not exclusively enforced.
    if credssp and not native_rdp and not rdstls and not ssl_layer:
        nla = "ENFORCED"
    elif credssp or early_auth:
        nla = "SUPPORTED"
    else:
        nla = "NOT ENFORCED"

    if native_rdp:
        native_status = "ACCEPTED"
    else:
        native_status = "BLOCKED"

    vulnerable = bool(weak) or native_rdp or nla == "NOT ENFORCED"
    status = "VULNERABLE" if vulnerable else "SECURE"

    evidence = []
    if weak:
        evidence.append("weak RC4 accepted")
    if native_rdp:
        evidence.append("legacy Native RDP accepted")
    if credssp:
        evidence.append("CredSSP/NLA supported")
    if not evidence:
        evidence.append("no weak RDP mode detected")

    return {
        "ip": ip,
        "port": expected_port,
        "nla": nla,
        "native_rdp": native_status,
        "weak_ciphers": " ".join(weak) if weak else "NONE",
        "status": status,
        "evidence": "; ".join(evidence),
    }


async def scan_one(ip, port, timeout):
    return parse_xml(await run_nmap(ip, port, timeout), port)


async def run_all(targets, workers, timeout, show_secure):
    queue = asyncio.Queue()
    rows = []
    completed = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            ip, port = item
            try:
                try:
                    row = await scan_one(ip, port, timeout)
                    if row and (
                        show_secure
                        or row["status"] in {"VULNERABLE", "NOT TESTED"}
                    ):
                        rows.append(row)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip}:{port} failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                sys.stdout.write(
                    f"\rScanning RDP encryption: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | Findings: {len(rows)} | Current: {ip}:{port}".ljust(130)
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


def status_cell(value, width, good_values, colors):
    code = GREEN if value in good_values else RED
    if value in {"UNKNOWN", "NOT TESTED"}:
        code = YELLOW
    return color(cell(value, width), code, colors)


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No weak RDP encryption configurations were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))

    for row in sorted(
        rows,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
    ):
        port_label = f"TCP/{row['port']}/RDP"
        print(
            f"{cell(row['ip'], 18)} "
            f"{cell(port_label, 18)} "
            f"{status_cell(row['nla'], 16, {'ENFORCED'}, colors)} "
            f"{status_cell(row['native_rdp'], 16, {'BLOCKED'}, colors)} "
            f"{status_cell(row['weak_ciphers'], 30, {'NONE'}, colors)} "
            f"{status_cell(row['status'], 14, {'SECURE'}, colors)}"
        )


def write_csv(path, rows):
    fields = [
        "ip", "port", "nla", "native_rdp",
        "weak_ciphers", "status", "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            writer.writerow(row)


def write_list(path, rows):
    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(vulnerable, key=lambda item: ip_sort(item["ip"])):
            handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find RDP servers using weak encryption configurations."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="File containing IPs, CIDRs or ip:port")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Default RDP port")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="Nmap host timeout")
    parser.add_argument("--show-secure", action="store_true", help="Also display secure rows")
    parser.add_argument("--csv", default="rdp_weak_encryption.csv", help="CSV output")
    parser.add_argument("--list", default="rdp_weak_encryption_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"Default port   : TCP/{args.port}/RDP")
    print("Nmap script    : rdp-enum-encryption")
    print(f"Showing        : {'all RDP results' if args.show_secure else 'vulnerable/not-tested only'}")

    rows = asyncio.run(
        run_all(targets, workers, args.timeout, args.show_secure)
    )
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(1 for row in rows if row["status"] == "VULNERABLE")
    secure = sum(1 for row in rows if row["status"] == "SECURE")
    untested = sum(1 for row in rows if row["status"] == "NOT TESTED")
    print()
    print(f"Vulnerable : {vulnerable}")
    print(f"Secure     : {secure}")
    print(f"Not tested : {untested}")
    print(f"CSV written: {args.csv}")
    print(f"IP list    : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

