#!/usr/bin/env python3
"""
Find NFS exports that expose virtualization storage with unauthenticated
read/write permissions.

This scanner uses Nmap's safe NFS discovery scripts:
  - nfs-showmount: enumerate exports
  - nfs-ls: obtain NFSv3 ACCESS permissions and list a small number of entries
  - nfs-statfs: confirm accessible filesystems

No files are created, modified, uploaded, renamed, or deleted.

Requirements:
    sudo apt install nmap

Examples:
    python3 NfsVirtualizationStorageScanner.py -f target_ips.txt
    python3 NfsVirtualizationStorageScanner.py 192.0.2.0/24
    python3 NfsVirtualizationStorageScanner.py -f target_ips.txt --show-all

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

DEFAULT_PORTS = "111,2049"

COLS = [
    ("IP ADDRESS", 16),
    ("PORTS", 18),
    ("EXPORT", 34),
    ("READ", 9),
    ("WRITE", 21),
    ("STORAGE", 16),
    ("CLIENTS", 14),
    ("STATUS", 14),
    ("DETAIL", 60),
]

VIRTUALIZATION_PATTERNS = (
    r"\bvmware\b",
    r"\bvmfs\b",
    r"\bdatastore\b",
    r"\bvirtual[-_ ]?machine",
    r"\bvirtualization\b",
    r"\bhyper[-_ ]?v\b",
    r"\bproxmox\b",
    r"\blibvirt\b",
    r"\bopenstack\b",
    r"\bovirt\b",
    r"\bxen\b",
    r"\bkvm\b",
    r"\bveeam\b",
    r"\bhypervisor\b",
    r"\biso[-_ ]?(?:store|library|images?)\b",
    r"\b(?:vm|vms)[-_ /]",
    r"\.(?:vmdk|vmx|vmsd|vmsn|vmem|nvram|ova|ovf|qcow2?|vhdx?|avhdx?|vdi|xva)\b",
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
    value = re.sub(r":\d+(?:/(?:tcp|udp))?$", "", value, flags=re.I)
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


async def run_nmap(ip, ports, timeout, protocol):
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "--open",
        "-p",
        ports,
        "--script",
        "nfs-showmount,nfs-ls,nfs-statfs",
        "--script-args",
        "nfs.version=3,mount.version=3,ls.maxfiles=50,ls.maxdepth=1",
        "--script-timeout",
        "45s",
        "--host-timeout",
        f"{timeout}s",
    ]
    if protocol == "udp":
        command.insert(4, "-sU")
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


def script_outputs(root, script_id):
    return [
        script.attrib.get("output", "")
        for script in root.findall(f".//script[@id='{script_id}']")
        if script.attrib.get("output")
    ]


def parse_open_ports(root):
    ports = set()
    for node in root.findall(".//port"):
        state = node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = node.attrib.get("portid", "")
        protocol = node.attrib.get("protocol", "tcp").upper()
        if port:
            ports.add(f"{port}/{protocol}")
    return sorted(ports, key=lambda value: int(value.split("/")[0]))


def parse_showmount(outputs):
    exports = {}
    for output in outputs:
        for raw_line in output.splitlines():
            line = raw_line.strip().lstrip("|_").strip()
            match = re.match(r"^(/\S+)(?:\s+(.*))?$", line)
            if not match:
                continue
            path = match.group(1)
            clients = (match.group(2) or "").strip()
            exports[path] = clients
    return exports


def split_nfs_volumes(outputs):
    volumes = {}
    for output in outputs:
        current = None
        for raw_line in output.splitlines():
            line = raw_line.strip().lstrip("|_").strip()
            volume = re.match(r"^Volume\s+(.+?)\s*$", line, re.I)
            if volume:
                current = volume.group(1).strip()
                volumes.setdefault(current, {"access": "", "listing": []})
                continue
            if current is None:
                continue
            access = re.match(r"^access:\s*(.+)$", line, re.I)
            if access:
                volumes[current]["access"] = access.group(1).strip()
            elif line and not line.upper().startswith(
                ("PERMISSION ", "FILESYSTEM ", "1K-BLOCKS ")
            ):
                volumes[current]["listing"].append(line)
    return volumes


def access_flags(access):
    tokens = set(re.findall(r"\b(?:No)?[A-Za-z]+\b", access))
    read = "Read" in tokens and "Lookup" in tokens
    capabilities = [
        name for name in ("Modify", "Extend", "Delete") if name in tokens
    ]
    return read, capabilities


def unrestricted_clients(value):
    text = value.strip().lower()
    if not text:
        return "UNKNOWN"
    if re.search(
        r"(?:^|\s|\()"
        r"(?:\*|everyone|world|0\.0\.0\.0(?:/0)?|0\.0\.0\.0/0\.0\.0\.0)"
        r"(?:$|\s|\))",
        text,
    ):
        return "WORLD"
    return "CLIENT LIST"


def virtualization_evidence(path, listing):
    evidence = " ".join([path] + listing)
    matches = []
    for pattern in VIRTUALIZATION_PATTERNS:
        match = re.search(pattern, evidence, re.I)
        if match:
            matches.append(match.group(0))
    return sorted(set(matches), key=str.lower)


def parse_xml(ip, xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    open_ports = parse_open_ports(root)
    exports = parse_showmount(script_outputs(root, "nfs-showmount"))
    volumes = split_nfs_volumes(script_outputs(root, "nfs-ls"))
    statfs = "\n".join(script_outputs(root, "nfs-statfs"))

    for path in exports:
        volumes.setdefault(path, {"access": "", "listing": []})

    rows = []
    for path, data in volumes.items():
        read, write_capabilities = access_flags(data["access"])
        storage_matches = virtualization_evidence(path, data["listing"])
        storage = "VIRTUALIZATION" if storage_matches else "OTHER/UNKNOWN"
        clients = exports.get(path, "")
        exposure = unrestricted_clients(clients)
        write = bool(write_capabilities)

        if read and write and storage_matches:
            status = "VULNERABLE"
            detail = (
                "Unauthenticated NFS access allows Read/Lookup and "
                f"{'/'.join(write_capabilities)} on virtualization storage."
            )
        elif read and write:
            status = "REVIEW"
            detail = (
                "Unauthenticated read/write NFS access confirmed, but "
                "virtualization storage content was not identified."
            )
        elif read:
            status = "READABLE"
            detail = "Unauthenticated NFS listing/read access confirmed; write was not reported."
        else:
            status = "NOT CONFIRMED"
            detail = "NFS export found, but unauthenticated read/write access was not confirmed."

        if exposure == "WORLD":
            detail += " Export appears available to all clients."
        elif clients:
            detail += f" Export clients: {clients}."
        if storage_matches:
            detail += f" Evidence: {', '.join(storage_matches[:4])}."
        if path in statfs:
            detail += " Filesystem statistics were accessible."

        rows.append({
            "ip": ip,
            "ports": ",".join(open_ports) or "111/TCP,2049/TCP",
            "export": path,
            "read": "ALLOWED" if read else "NOT CONFIRMED",
            "write": "/".join(write_capabilities) if write else "NOT ALLOWED",
            "storage": storage,
            "clients": clients or "-",
            "status": status,
            "detail": detail,
            "access": data["access"] or "-",
            "evidence": " | ".join(data["listing"][:20]) or "-",
        })
    return rows


async def scan_one(ip, ports, timeout, udp_fallback):
    tcp_xml, _ = await run_nmap(ip, ports, timeout, "tcp")
    rows = parse_xml(ip, tcp_xml)
    if rows or not udp_fallback:
        return rows
    udp_xml, _ = await run_nmap(ip, ports, timeout, "udp")
    return parse_xml(ip, udp_xml)


async def run_all(targets, ports, workers, timeout, udp_fallback):
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
                    await scan_one(ip, ports, timeout, udp_fallback)
                )
                completed += 1
                vulnerable = sum(
                    row["status"] == "VULNERABLE" for row in rows
                )
                sys.stdout.write(
                    f"\rScanning NFS: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Exports: {len(rows)} | Vulnerable: {vulnerable} | "
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
    return rows


def print_table(rows, show_all=False, colors=True):
    displayed = rows if show_all else [
        row for row in rows if row["status"] == "VULNERABLE"
    ]
    print()
    if not displayed:
        print("No NFS virtualization exports with confirmed unauthenticated read/write access were found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(
        displayed,
        key=lambda item: (ip_sort(item["ip"]), item["export"]),
    ):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["ports"], 18),
            cell(row["export"], 34),
            cell(row["read"], 9),
            cell(row["write"], 21),
            cell(row["storage"], 16),
            cell(row["clients"], 14),
            cell(row["status"], 14),
            cell(row["detail"], 60),
        ])
        code = (
            RED if row["status"] == "VULNERABLE"
            else YELLOW if row["status"] in {"REVIEW", "READABLE"}
            else GREEN
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip",
        "ports",
        "export",
        "read",
        "write",
        "storage",
        "clients",
        "status",
        "detail",
        "access",
        "evidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(
            rows,
            key=lambda item: (ip_sort(item["ip"]), item["export"]),
        ))


def write_list(path, rows):
    vulnerable = {row["ip"] for row in rows if row["status"] == "VULNERABLE"}
    with open(path, "w", encoding="utf-8") as handle:
        for ip in sorted(vulnerable, key=ip_sort):
            handle.write(f"{ip}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find NFS virtualization storage with unauthenticated read/write access."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"RPC/NFS ports. Default: {DEFAULT_PORTS}")
    parser.add_argument("-w", "--workers", type=int, default=12, help="Concurrent host workers")
    parser.add_argument("-t", "--timeout", type=int, default=75, help="Nmap host timeout")
    parser.add_argument("--no-udp-fallback", action="store_true", help="Do not retry RPC/NFS over UDP")
    parser.add_argument("--show-all", action="store_true", help="Show all discovered NFS exports")
    parser.add_argument("--csv", default="nfs_virtualization_storage.csv", help="CSV output path")
    parser.add_argument("--list", default="nfs_virtualization_storage_ips.txt", help="Vulnerable IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {workers}")
    print(f"RPC/NFS ports  : {ports}/TCP" + (" with UDP fallback" if not args.no_udp_fallback else ""))
    print("Nmap scripts   : nfs-showmount,nfs-ls,nfs-statfs")
    print("Write test     : metadata ACCESS check only; no files created or changed")
    print(f"Showing        : {'all NFS exports' if args.show_all else 'confirmed vulnerable virtualization exports only'}")

    rows = asyncio.run(
        run_all(
            targets,
            ports,
            workers,
            max(20, args.timeout),
            not args.no_udp_fallback,
        )
    )
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    vulnerable = [row for row in rows if row["status"] == "VULNERABLE"]
    rw_exports = [
        row for row in rows
        if row["read"] == "ALLOWED" and row["write"] != "NOT ALLOWED"
    ]
    print()
    print(f"NFS exports found       : {len(rows)}")
    print(f"Read/write exports      : {len(rw_exports)}")
    print(f"Vulnerable virtualization: {len(vulnerable)}")
    print(f"Vulnerable hosts        : {len({row['ip'] for row in vulnerable})}")
    print(f"CSV written             : {args.csv}")
    print(f"IP list written         : {args.list}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())

