#!/usr/bin/env python3
"""
Find IPMI 2.0 Cipher Suite Zero authentication bypass on UDP/623.

The scanner uses Nmap's safe ipmi-cipher-zero and ipmi-version NSE scripts.
It does not authenticate, execute BMC commands, change configuration, or open
an administrator session.

Requirements:
    sudo apt install nmap

Examples:
    sudo python3 IpmiCipherZeroScanner.py -f target_ips.txt
    sudo python3 IpmiCipherZeroScanner.py 192.0.2.0/24
    sudo python3 IpmiCipherZeroScanner.py -f target_ips.txt --show-all

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

PORT = 623
IDENTIFIER = "CIPHER SUITE 0"

COLS = [
    ("IP ADDRESS", 18),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("IPMI VERSION", 14),
    ("CIPHER ZERO", 18),
    ("STATUS", 18),
    ("IDENTIFIER", 18),
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


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    value = re.sub(r":623(?:/udp)?$", "", value, flags=re.I)
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


def has_script(name):
    try:
        result = shutil.which("nmap")
        if not result:
            return False
        import subprocess
        completed = subprocess.run(
            ["nmap", "--script-help", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        return completed.returncode == 0 and name in completed.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


async def run_nmap(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sU",
        "-p",
        str(PORT),
        "--script",
        "ipmi-cipher-zero,ipmi-version",
        "--script-args",
        "vulns.showall=true",
        "--script-timeout",
        "30s",
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
        process.returncode,
    )


async def run_cipher_retry(ip, timeout):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sU",
        "-p",
        str(PORT),
        "--script",
        "ipmi-cipher-zero",
        "--script-args",
        "vulns.showall=true",
        "--script-timeout",
        "45s",
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
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def script_node(port_node, script_id):
    return port_node.find(f"script[@id='{script_id}']")


def script_output(port_node, script_id):
    node = script_node(port_node, script_id)
    return node.attrib.get("output", "").strip() if node is not None else ""


def structured_values(node):
    values = []
    if node is None:
        return values
    for element in node.iter():
        if element.tag == "elem" and element.text:
            key = element.attrib.get("key", "")
            values.append((key, element.text.strip()))
    return values


def cipher_zero_state(port_node):
    node = script_node(port_node, "ipmi-cipher-zero")
    output = script_output(port_node, "ipmi-cipher-zero")
    for key, value in structured_values(node):
        if key.lower() == "state":
            normalized = value.upper()
            if "NOT VULNERABLE" in normalized:
                return "NOT VULNERABLE", output
            if "VULNERABLE" in normalized:
                return "VULNERABLE", output

    upper = output.upper()
    if re.search(r"\bSTATE\s*:\s*NOT VULNERABLE\b", upper):
        return "NOT VULNERABLE", output
    if re.search(r"\bSTATE\s*:\s*VULNERABLE\b", upper):
        return "VULNERABLE", output
    if "VULNERABLE:" in upper and "CIPHER ZERO" in upper:
        return "VULNERABLE", output
    return "UNKNOWN", output


def ipmi_details(port_node):
    output = script_output(port_node, "ipmi-version")
    version = ""
    auth = []
    node = script_node(port_node, "ipmi-version")
    for key, value in structured_values(node):
        lower_key = key.lower()
        if lower_key == "version":
            version = value
        elif lower_key in {"userauth", "passauth", "level"}:
            auth.append(f"{key}: {value}")

    if not version:
        match = re.search(r"(?mi)^\s*Version\s*:\s*(.+?)\s*$", output)
        if match:
            version = match.group(1).strip()
    if not auth:
        for key in ("UserAuth", "PassAuth", "Level"):
            match = re.search(
                rf"(?mi)^\s*{key}\s*:\s*(.+?)\s*$",
                output,
            )
            if match:
                auth.append(f"{key}: {match.group(1).strip()}")
    return version or "-", "; ".join(auth)


def parse_xml(ip, xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {
            "ip": ip,
            "port": "623/UDP",
            "protocol": "IPMI/RMCP+",
            "version": "-",
            "cipher_zero": "NOT TESTED",
            "status": "ERROR",
            "identifier": IDENTIFIER,
            "detail": "Nmap XML output could not be parsed.",
        }

    port_node = root.find(f".//port[@protocol='udp'][@portid='{PORT}']")
    if port_node is None:
        return {
            "ip": ip,
            "port": "623/UDP",
            "protocol": "IPMI/RMCP+",
            "version": "-",
            "cipher_zero": "NO RESPONSE",
            "status": "NO RESPONSE",
            "identifier": IDENTIFIER,
            "detail": "No UDP/623 result was returned.",
        }

    state_node = port_node.find("state")
    port_state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
    version, auth_detail = ipmi_details(port_node)
    vuln_state, _ = cipher_zero_state(port_node)
    ipmi_detected = version != "-" or bool(script_output(port_node, "ipmi-version"))

    if vuln_state == "VULNERABLE":
        status = "VULNERABLE"
        cipher = "ENABLED"
        detail = "IPMI 2.0 accepted cipher suite 0 negotiation; authentication integrity is bypassable."
    elif vuln_state == "NOT VULNERABLE":
        status = "NOT VULNERABLE"
        cipher = "REJECTED"
        detail = "Nmap reports that IPMI cipher suite 0 was not accepted."
    elif ipmi_detected:
        status = "INCONCLUSIVE"
        cipher = "NOT CONFIRMED"
        detail = "IPMI responded, but the cipher-zero script returned no conclusive state."
    else:
        status = "NO RESPONSE"
        cipher = "NOT TESTED"
        detail = f"UDP/623 was {port_state}; no usable IPMI protocol response was received."

    if auth_detail:
        detail += f" {auth_detail}."

    return {
        "ip": ip,
        "port": "623/UDP",
        "protocol": "IPMI/RMCP+",
        "version": version,
        "cipher_zero": cipher,
        "status": status,
        "identifier": IDENTIFIER,
        "detail": detail,
    }


async def scan_one(ip, timeout, cipher_retries):
    xml_text, error, returncode = await run_nmap(ip, timeout)
    if returncode != 0 and not xml_text.strip():
        return {
            "ip": ip,
            "port": "623/UDP",
            "protocol": "IPMI/RMCP+",
            "version": "-",
            "cipher_zero": "NOT TESTED",
            "status": "ERROR",
            "identifier": IDENTIFIER,
            "detail": re.sub(r"\s+", " ", error).strip()[:200] or "Nmap failed.",
        }
    row = parse_xml(ip, xml_text)
    if row["status"] != "INCONCLUSIVE":
        return row

    for _ in range(cipher_retries):
        retry_xml = await run_cipher_retry(ip, timeout)
        retry_row = parse_xml(ip, retry_xml)
        if retry_row["status"] in {"VULNERABLE", "NOT VULNERABLE"}:
            retry_row["version"] = row["version"]
            retry_row["detail"] += " Result confirmed by a dedicated retry."
            return retry_row
    row["detail"] += (
        f" Dedicated cipher-zero retries returned no verdict: {cipher_retries}."
    )
    return row


async def run_all(targets, workers, timeout, cipher_retries):
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
                row = await scan_one(ip, timeout, cipher_retries)
                rows.append(row)
                completed += 1
                vulnerable = sum(
                    item["status"] == "VULNERABLE" for item in rows
                )
                sys.stdout.write(
                    f"\rScanning IPMI Cipher Zero: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Vulnerable: {vulnerable} | Current: {ip}".ljust(140)
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


def print_table(rows, show_all=False, show_no_response=False, colors=True):
    if show_no_response:
        displayed = rows
    elif show_all:
        displayed = [
            row for row in rows
            if row["status"] not in {"NO RESPONSE", "ERROR"}
        ]
    else:
        displayed = [
            row for row in rows if row["status"] == "VULNERABLE"
        ]
    print()
    if not displayed:
        if show_no_response:
            print("No scan results were available.")
        elif show_all:
            print("No IPMI responders were identified.")
        else:
            print("No hosts confirmed vulnerable to IPMI Cipher Zero were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(displayed, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 18),
            cell(row["port"], 10),
            cell(row["protocol"], 12),
            cell(row["version"], 14),
            cell(row["cipher_zero"], 18),
            cell(row["status"], 18),
            cell(row["identifier"], 18),
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
        "protocol",
        "version",
        "cipher_zero",
        "status",
        "identifier",
        "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda item: ip_sort(item["ip"])))


def write_list(path, rows):
    vulnerable = {row["ip"] for row in rows if row["status"] == "VULNERABLE"}
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted(vulnerable, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find IPMI Cipher Zero authentication bypass on UDP/623."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent host workers")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Nmap host timeout")
    parser.add_argument("--cipher-retries", type=int, default=2, help="Dedicated retries when IPMI responds but cipher result is inconclusive")
    parser.add_argument("--show-all", action="store_true", help="Show vulnerable, not-vulnerable, and inconclusive IPMI responders")
    parser.add_argument("--show-no-response", action="store_true", help="Also show closed, silent, and error results")
    parser.add_argument("--csv", default="ipmi_cipher_zero_results.csv", help="CSV output path")
    parser.add_argument("--list", default="ipmi_cipher_zero_vulnerable_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    missing = [
        script for script in ("ipmi-cipher-zero", "ipmi-version")
        if not has_script(script)
    ]
    if missing:
        raise SystemExit(
            "Missing Nmap NSE script(s): "
            + ", ".join(missing)
            + ". Run: sudo nmap --script-updatedb"
        )

    targets = load_targets(args)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print("Scan port      : 623/UDP")
    print("Nmap scripts   : ipmi-cipher-zero,ipmi-version")
    print("Probe          : IPMI session negotiation only; no BMC commands")
    if args.show_no_response:
        showing = "all targets including closed/no-response"
    elif args.show_all:
        showing = "IPMI responders only"
    else:
        showing = "confirmed vulnerable only"
    print(f"Cipher retries : {max(0, args.cipher_retries)}")
    print(f"Showing        : {showing}")

    rows = asyncio.run(
        run_all(
            targets,
            workers,
            max(20, args.timeout),
            max(0, args.cipher_retries),
        )
    )
    print_table(
        rows,
        args.show_all,
        args.show_no_response,
        not args.no_color,
    )
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    safe = [row for row in rows if row["status"] == "NOT VULNERABLE"]
    inconclusive = [row for row in rows if row["status"] == "INCONCLUSIVE"]
    no_response = [row for row in rows if row["status"] == "NO RESPONSE"]
    print()
    print(f"Vulnerable     : {len(vulnerable)}")
    print(f"Not vulnerable : {len(safe)}")
    print(f"Inconclusive   : {len(inconclusive)}")
    print(f"No response    : {len(no_response)}")
    print(f"CSV written    : {args.csv}")
    print(f"IP list        : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

