#!/usr/bin/env python3
"""
Discover SSH services and report weak SSH algorithms.

The scanner runs in two stages:
  1. Nmap service detection finds SSH on standard or custom ports.
  2. ssh2-enum-algos enumerates offered KEX, host-key, cipher and MAC algorithms.

Requirements:
    sudo apt install nmap

Examples:
    python3 SshWeakAlgorithmsScanner.py -f target_ips.txt
    python3 SshWeakAlgorithmsScanner.py 192.0.2.0/24 --all-ports
    python3 SshWeakAlgorithmsScanner.py -f target_ips.txt --show-secure

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

DEFAULT_PORTS = "22,222,2222,2022,2200,8022,10022,22222"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 9),
    ("SSH VERSION", 28),
    ("RISK", 10),
    ("WEAK KEX", 34),
    ("WEAK HOST KEYS", 26),
    ("WEAK CIPHERS", 34),
    ("WEAK MACS", 30),
]

KEX_EXACT = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "rsa1024-sha1",
}

HOST_KEY_EXACT = {
    "ssh-dss",
    "ssh-rsa",
    "x509v3-ssh-dss",
    "x509v3-ssh-rsa",
}

CIPHER_EXACT = {
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "des-cbc",
    "none",
    "rijndael-cbc@lysator.liu.se",
}

MAC_EXACT = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-ripemd160",
    "hmac-ripemd160@openssh.com",
    "umac-64@openssh.com",
    "umac-64-etm@openssh.com",
    "none",
}


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


def normalize_ports(value):
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
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


async def discover_ssh(ip, ports, all_ports, timeout, min_rate):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "--host-timeout", timeout,
    ]
    if all_ports:
        command.extend(["-p-", "--min-rate", str(min_rate)])
    else:
        command.extend(["-p", ports])
    command.extend(["-oX", "-", ip])
    return parse_ssh_ports(await run_command(command))


def service_version(service):
    if service is None:
        return "UNKNOWN"
    values = [
        service.attrib.get("product", ""),
        service.attrib.get("version", ""),
        service.attrib.get("extrainfo", ""),
    ]
    text = " ".join(value for value in values if value).strip()
    return text or "UNKNOWN"


def parse_ssh_ports(xml_text):
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
        name = service.attrib.get("name", "").lower() if service is not None else ""
        version = service_version(service)
        fingerprint = f"{name} {version}"
        if name == "ssh" or re.search(r"\bssh\b|openssh|dropbear", fingerprint, re.I):
            ports.append({
                "port": int(port_node.attrib.get("portid", "0")),
                "version": version,
            })
    return ports


async def enumerate_algorithms(ip, ssh_ports, timeout):
    port_string = ",".join(str(item["port"]) for item in ssh_ports)
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "-p", port_string,
        "--script", "ssh2-enum-algos",
        "--host-timeout", timeout,
        "-oX", "-", ip,
    ]
    return parse_algorithm_xml(await run_command(command), ip, ssh_ports)


def table_values(script, key):
    values = []
    for table in script.iter("table"):
        if table.attrib.get("key", "").lower() != key.lower():
            continue
        for node in table.iter("elem"):
            value = (node.text or "").strip()
            if value:
                values.append(value)
    return values


def output_values(script, heading):
    output = script.attrib.get("output", "")
    values = []
    active = False
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(rf"^{re.escape(heading)}(?:\s+\(\d+\))?\s*:$", stripped, re.I):
            active = True
            continue
        if active and re.match(r"^[a-z_]+(?:\s+\(\d+\))?\s*:$", stripped, re.I):
            break
        if active and stripped:
            values.append(stripped)
    return values


def get_algorithms(script, key):
    values = table_values(script, key)
    if values:
        return values
    return output_values(script, key)


def weak_kex(values):
    weak = []
    for value in values:
        lower = value.lower()
        if (
            lower in KEX_EXACT
            or "group1-sha1" in lower
            or "group14-sha1" in lower
            or "group-exchange-sha1" in lower
        ):
            weak.append(value)
    return sorted(set(weak))


def weak_host_keys(values):
    return sorted({
        value for value in values
        if value.lower() in HOST_KEY_EXACT
    })


def weak_ciphers(values):
    weak = []
    for value in values:
        lower = value.lower()
        if (
            lower in CIPHER_EXACT
            or lower.endswith("-cbc")
            or lower.startswith("arcfour")
        ):
            weak.append(value)
    return sorted(set(weak))


def weak_macs(values):
    weak = []
    for value in values:
        lower = value.lower()
        if (
            lower in MAC_EXACT
            or lower.startswith("hmac-md5")
            or lower.startswith("hmac-sha1")
            or lower.startswith("hmac-ripemd160")
            or lower.startswith("umac-64")
        ):
            weak.append(value)
    return sorted(set(weak))


def severity(kex, host_keys, ciphers, macs):
    critical_markers = {
        "diffie-hellman-group1-sha1",
        "ssh-dss",
        "3des-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "none",
    }
    all_weak = {
        value.lower()
        for value in kex + host_keys + ciphers + macs
    }
    if all_weak & critical_markers:
        return "CRITICAL"
    if all_weak:
        return "HIGH"
    return "SECURE"


def parse_algorithm_xml(xml_text, ip, discovered):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    versions = {item["port"]: item["version"] for item in discovered}
    rows = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        service = port_node.find("service")
        version = service_version(service)
        if version == "UNKNOWN":
            version = versions.get(port, "UNKNOWN")

        script = port_node.find("script[@id='ssh2-enum-algos']")
        if script is None:
            rows.append({
                "ip": ip,
                "port": port,
                "version": version,
                "risk": "NOT TESTED",
                "weak_kex": [],
                "weak_host_keys": [],
                "weak_ciphers": [],
                "weak_macs": [],
                "detail": "SSH is open, but ssh2-enum-algos returned no result.",
            })
            continue

        kex = weak_kex(get_algorithms(script, "kex_algorithms"))
        host_keys = weak_host_keys(
            get_algorithms(script, "server_host_key_algorithms")
        )
        encryption = (
            get_algorithms(script, "encryption_algorithms")
            + get_algorithms(script, "encryption_algorithms_server_to_client")
            + get_algorithms(script, "encryption_algorithms_client_to_server")
        )
        mac_values = (
            get_algorithms(script, "mac_algorithms")
            + get_algorithms(script, "mac_algorithms_server_to_client")
            + get_algorithms(script, "mac_algorithms_client_to_server")
        )
        ciphers = weak_ciphers(encryption)
        macs = weak_macs(mac_values)
        risk = severity(kex, host_keys, ciphers, macs)

        rows.append({
            "ip": ip,
            "port": port,
            "version": version,
            "risk": risk,
            "weak_kex": kex,
            "weak_host_keys": host_keys,
            "weak_ciphers": ciphers,
            "weak_macs": macs,
            "detail": "Weak algorithms offered by the SSH server." if risk != "SECURE" else "No configured weak algorithm matched.",
        })
    return rows


async def scan_one(ip, args, ports):
    discovered = await discover_ssh(
        ip, ports, args.all_ports, args.discovery_timeout, args.min_rate
    )
    if not discovered:
        return []
    return await enumerate_algorithms(ip, discovered, args.script_timeout)


async def run_all(targets, args, ports):
    queue = asyncio.Queue()
    rows = []
    completed = 0
    ssh_endpoints = 0

    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, ssh_endpoints
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                try:
                    findings = await scan_one(ip, args, ports)
                    ssh_endpoints += len(findings)
                    for row in findings:
                        if args.show_secure or row["risk"] != "SECURE":
                            rows.append(row)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    1 for row in rows if row["risk"] in {"HIGH", "CRITICAL"}
                )
                sys.stdout.write(
                    f"\rScanning SSH: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"SSH: {ssh_endpoints} | Weak: {vulnerable} | Current: {ip}".ljust(130)
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
    return rows, ssh_endpoints


def compact(values):
    return ",".join(values) if values else "NONE"


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No SSH services offering configured weak algorithms were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        rows,
        key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 9),
            cell(row["version"], 28),
            cell(row["risk"], 10),
            cell(compact(row["weak_kex"]), 34),
            cell(compact(row["weak_host_keys"]), 26),
            cell(compact(row["weak_ciphers"]), 34),
            cell(compact(row["weak_macs"]), 30),
        ])
        code = RED if row["risk"] in {"HIGH", "CRITICAL"} else (
            GREEN if row["risk"] == "SECURE" else YELLOW
        )
        print(color(line, code, colors))


def csv_row(row):
    return {
        "ip": row["ip"],
        "port": row["port"],
        "version": row["version"],
        "risk": row["risk"],
        "weak_kex": ";".join(row["weak_kex"]),
        "weak_host_keys": ";".join(row["weak_host_keys"]),
        "weak_ciphers": ";".join(row["weak_ciphers"]),
        "weak_macs": ";".join(row["weak_macs"]),
        "detail": row["detail"],
    }


def write_csv(path, rows):
    fields = [
        "ip", "port", "version", "risk", "weak_kex",
        "weak_host_keys", "weak_ciphers", "weak_macs", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            writer.writerow(csv_row(row))


def write_list(path, rows):
    affected = [
        row for row in rows if row["risk"] in {"HIGH", "CRITICAL"}
    ]
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(
            affected,
            key=lambda item: (ip_sort(item["ip"]), int(item["port"])),
        ):
            handle.write(f"{row['ip']}:{row['port']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Discover SSH services and identify weak SSH algorithms."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="SSH discovery ports/ranges")
    parser.add_argument("--all-ports", action="store_true", help="Discover SSH across all TCP ports")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap minimum packet rate with --all-ports")
    parser.add_argument("-w", "--workers", type=int, default=24, help="Concurrent hosts")
    parser.add_argument("--discovery-timeout", default="90s", help="SSH discovery timeout per host")
    parser.add_argument("--script-timeout", default="60s", help="Algorithm enumeration timeout per host")
    parser.add_argument("--show-secure", action="store_true", help="Also display SSH endpoints without matched weak algorithms")
    parser.add_argument("--csv", default="ssh_weak_algorithms.csv", help="CSV output")
    parser.add_argument("--list", default="ssh_weak_algorithm_endpoints.txt", help="Affected IP:port list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"SSH discovery  : {'all TCP ports' if args.all_ports else ports}")
    print("Nmap script    : ssh2-enum-algos")
    print(f"Showing        : {'all discovered SSH endpoints' if args.show_secure else 'weak/not-tested endpoints only'}")

    rows, ssh_count = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    weak_count = sum(1 for row in rows if row["risk"] in {"HIGH", "CRITICAL"})
    not_tested = sum(1 for row in rows if row["risk"] == "NOT TESTED")
    print()
    print(f"SSH endpoints discovered : {ssh_count}")
    print(f"Weak endpoints           : {weak_count}")
    print(f"Not tested               : {not_tested}")
    print(f"CSV written              : {args.csv}")
    print(f"Endpoint list            : {args.list}")
    return 1 if weak_count else 0


if __name__ == "__main__":
    raise SystemExit(main())

