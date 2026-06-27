#!/usr/bin/env python3
"""
Find iSCSI targets that permit login without authentication.

The scanner:
  1. Finds open iSCSI TCP ports with Nmap.
  2. Uses SendTargets discovery without credentials.
  3. Attempts a credential-free iSCSI login.
  4. Immediately logs out sessions created by this scanner.

It does not inspect LUNs, read blocks, mount filesystems, or write data.

Requirements:
    sudo apt install nmap open-iscsi
    sudo systemctl start iscsid

Examples:
    sudo python3 UnauthenticatedIscsiLoginScanner.py -f target_ips.txt
    sudo python3 UnauthenticatedIscsiLoginScanner.py 192.0.2.0/24
    sudo python3 UnauthenticatedIscsiLoginScanner.py -f target_ips.txt --show-all

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
import ipaddress
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = "3260,860"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 10),
    ("PROTOCOL", 12),
    ("TARGET IQN", 52),
    ("DISCOVERY", 13),
    ("LOGIN", 13),
    ("STATUS", 16),
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
    value = re.sub(r":(?:3260|860)(?:/tcp)?$", "", value, flags=re.I)
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


async def run_command(command, timeout):
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()
        return 124, stdout.decode(errors="ignore"), (
            stderr.decode(errors="ignore") + "\nCommand timed out."
        )
    return (
        process.returncode,
        stdout.decode("utf-8", errors="ignore"),
        stderr.decode("utf-8", errors="ignore"),
    )


async def find_open_ports(ip, ports, timeout):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "-p", ports, "--host-timeout", f"{timeout}s", "-oX", "-", ip,
    ]
    rc, stdout, _ = await run_command(command, timeout + 10)
    if rc not in {0, 1}:
        return []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return []

    found = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        service = port_node.find("service")
        values = []
        if service is not None:
            values = [
                service.attrib.get("name", ""),
                service.attrib.get("product", ""),
                service.attrib.get("version", ""),
                service.attrib.get("extrainfo", ""),
            ]
        found.append({
            "port": port,
            "service": " ".join(value for value in values if value) or "iSCSI",
        })
    return found


def parse_targets(text, expected_ip, expected_port):
    targets = []
    pattern = re.compile(r"^\s*(\S+),\d+\s+(\S+)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        portal, iqn = match.groups()
        portal_host = portal
        portal_port = expected_port
        if portal.startswith("[") and "]:" in portal:
            portal_host, raw_port = portal[1:].split("]:", 1)
            portal_port = int(raw_port) if raw_port.isdigit() else expected_port
        elif portal.count(":") == 1:
            portal_host, raw_port = portal.rsplit(":", 1)
            portal_port = int(raw_port) if raw_port.isdigit() else expected_port
        targets.append({
            "portal": f"{portal_host}:{portal_port}",
            "ip": portal_host or expected_ip,
            "port": portal_port,
            "iqn": iqn,
        })
    return list({
        (item["portal"], item["iqn"]): item for item in targets
    }.values())


async def current_sessions(timeout):
    rc, stdout, stderr = await run_command(
        ["iscsiadm", "-m", "session"], timeout
    )
    text = f"{stdout}\n{stderr}"
    if rc != 0 and "No active sessions" in text:
        return set()
    sessions = set()
    for line in text.splitlines():
        match = re.search(r"\[(?:\d+)\]\s+(\S+),\d+\s+(\S+)", line)
        if match:
            sessions.add((match.group(1), match.group(2)))
    return sessions


def target_session_present(sessions, portal, iqn):
    host_port = portal.split(",", 1)[0]
    return any(
        session_iqn == iqn and session_portal.split(",", 1)[0] == host_port
        for session_portal, session_iqn in sessions
    )


def compact_error(stdout, stderr):
    text = re.sub(r"\s+", " ", f"{stdout} {stderr}").strip()
    return text[:500]


async def discover_targets(ip, port, timeout, lock):
    async with lock:
        rc, stdout, stderr = await run_command(
            [
                "iscsiadm", "-m", "discovery", "-t", "sendtargets",
                "-p", f"{ip}:{port}",
            ],
            timeout,
        )
    return rc, parse_targets(stdout, ip, port), compact_error(stdout, stderr)


async def test_login(target, timeout, lock):
    portal = target["portal"]
    iqn = target["iqn"]
    async with lock:
        before = await current_sessions(timeout)
        if target_session_present(before, portal, iqn):
            return "SKIPPED", "A matching iSCSI session was already active; it was not changed."

        rc, stdout, stderr = await run_command(
            [
                "iscsiadm", "-m", "node", "-T", iqn,
                "-p", portal, "--login",
            ],
            timeout,
        )
        after = await current_sessions(timeout)
        logged_in = rc == 0 and target_session_present(after, portal, iqn)

        if logged_in:
            logout_rc, logout_out, logout_err = await run_command(
                [
                    "iscsiadm", "-m", "node", "-T", iqn,
                    "-p", portal, "--logout",
                ],
                timeout,
            )
            if logout_rc != 0:
                warning = compact_error(logout_out, logout_err)
                print(
                    f"\nWARNING: iSCSI login succeeded for {iqn} at {portal}, "
                    f"but automatic logout failed. Run: "
                    f"sudo iscsiadm -m node -T {iqn} -p {portal} --logout",
                    file=sys.stderr,
                )
                return "ALLOWED", f"Login succeeded; automatic logout failed: {warning}"
            return "ALLOWED", "Credential-free target login succeeded; session was logged out."

        error = compact_error(stdout, stderr).lower()
        if any(marker in error for marker in (
            "authorization failure", "authentication failure", "chap",
            "initiator failed authorization", "login failed",
        )):
            return "REJECTED", "Target rejected credential-free login."
        if rc == 124:
            return "INCONCLUSIVE", "Login attempt timed out."
        return "INCONCLUSIVE", compact_error(stdout, stderr) or "Login did not establish a session."


async def scan_host(ip, args, ports, iscsi_lock):
    rows = []
    open_ports = await find_open_ports(ip, ports, args.nmap_timeout)
    for endpoint in open_ports:
        port = endpoint["port"]
        rc, targets, discovery_detail = await discover_targets(
            ip, port, args.iscsi_timeout, iscsi_lock
        )
        if not targets:
            rows.append({
                "ip": ip,
                "port": port,
                "protocol": "iSCSI/TCP",
                "target": "-",
                "discovery": "REJECTED" if rc != 0 else "NO TARGETS",
                "login": "NOT RUN",
                "status": "REVIEW",
                "service": endpoint["service"],
                "detail": discovery_detail or "No target IQN was returned.",
            })
            continue

        for target in targets:
            login, detail = await test_login(
                target, args.iscsi_timeout, iscsi_lock
            )
            status = "VULNERABLE" if login == "ALLOWED" else (
                "PROTECTED" if login == "REJECTED" else "REVIEW"
            )
            rows.append({
                "ip": ip,
                "port": port,
                "protocol": "iSCSI/TCP",
                "target": target["iqn"],
                "discovery": "ALLOWED",
                "login": login,
                "status": status,
                "service": endpoint["service"],
                "detail": detail,
            })
    return rows


async def run_all(targets, args, ports):
    queue = asyncio.Queue()
    rows = []
    completed = 0
    iscsi_lock = asyncio.Lock()
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
                    findings = await scan_host(ip, args, ports, iscsi_lock)
                    rows.extend(
                        finding for finding in findings
                        if args.show_all or finding["status"] == "VULNERABLE"
                    )
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning iSCSI: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Vulnerable: {vulnerable} | Current: {ip}".ljust(125)
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
        print("No iSCSI targets permitting unauthenticated login were found.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        rows, key=lambda item: (ip_sort(item["ip"]), item["port"], item["target"])
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(f"{row['port']}/TCP", 10),
            cell(row["protocol"], 12),
            cell(row["target"], 52),
            cell(row["discovery"], 13),
            cell(row["login"], 13),
            cell(row["status"], 16),
        ])
        code = RED if row["status"] == "VULNERABLE" else (
            GREEN if row["status"] == "PROTECTED" else YELLOW
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "port", "protocol", "target", "discovery", "login",
        "status", "service", "detail",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(
            rows, key=lambda item: (ip_sort(item["ip"]), item["port"], item["target"])
        ):
            writer.writerow({field: row.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(
            rows, key=lambda item: (ip_sort(item["ip"]), item["port"], item["target"])
        ):
            if row["status"] == "VULNERABLE":
                handle.write(f"{row['ip']}:{row['port']} {row['target']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find iSCSI targets permitting login without authentication."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="iSCSI TCP ports")
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent Nmap host checks")
    parser.add_argument("--nmap-timeout", type=int, default=30, help="Nmap timeout per host")
    parser.add_argument("--iscsi-timeout", type=int, default=20, help="Discovery/login timeout")
    parser.add_argument("--show-all", action="store_true", help="Show protected and inconclusive results")
    parser.add_argument("--csv", default="iscsi_unauthenticated_login.csv", help="CSV output")
    parser.add_argument("--list", default="iscsi_unauthenticated_targets.txt", help="Vulnerable target list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")
    if not shutil.which("iscsiadm"):
        raise SystemExit(
            "iscsiadm was not found. Install it with: sudo apt install open-iscsi"
        )
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Run this scanner as root: sudo python3 ...")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"iSCSI ports    : {ports}/TCP")
    print("Authentication : credential-free SendTargets discovery and target login")
    print("Storage access : no LUN reads, mounts, or writes")
    print("Session cleanup: sessions created by this scanner are immediately logged out")
    print(f"Showing        : {'all iSCSI results' if args.show_all else 'confirmed vulnerable targets only'}")

    rows = asyncio.run(run_all(targets, args, ports))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = sum(row["status"] == "VULNERABLE" for row in rows)
    protected = sum(row["status"] == "PROTECTED" for row in rows)
    review = sum(row["status"] == "REVIEW" for row in rows)
    print()
    print(f"Vulnerable targets : {vulnerable}")
    if args.show_all:
        print(f"Protected targets  : {protected}")
        print(f"Review required    : {review}")
    print(f"CSV written        : {args.csv}")
    print(f"Target list        : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

