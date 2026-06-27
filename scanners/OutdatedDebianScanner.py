#!/usr/bin/env python3
"""
Find outdated Debian GNU/Linux releases from remote OS and service evidence.

Default output includes:
  - UNSUPPORTED: Debian release is beyond all listed support.
  - ELTS ONLY: only third-party paid Extended LTS remains.

Debian releases still covered by normal support or Debian LTS are shown only
with --show-all.

Detection sources:
  - Nmap service/version banners
  - HTTP headers/titles and safe banner collection
  - Optional Nmap OS detection with --os-detect (normally requires root)

Examples:
    python3 OutdatedDebianScanner.py -f target_ips.txt
    sudo python3 OutdatedDebianScanner.py -f target_ips.txt --os-detect
    python3 OutdatedDebianScanner.py 192.0.2.0/24 --show-all
    python3 OutdatedDebianScanner.py -f target_ips.txt --all-ports

Use only on systems you are authorized to assess.
"""

import argparse
import asyncio
import csv
from datetime import date
import ipaddress
import re
import shutil
import sys
import xml.etree.ElementTree as ET


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_PORTS = (
    "21,22,25,53,80-82,110,111,139,143,389,443,445,465,587,"
    "631,873,993,995,2049,2375,2376,3000,3306,5432,6379,"
    "8000,8080,8081,8443,8888,9090,9200,10000"
)

COLS = [
    ("IP ADDRESS", 16),
    ("PORTS", 20),
    ("DEBIAN RELEASE", 24),
    ("CODENAME", 12),
    ("SUPPORT", 18),
    ("CONFIDENCE", 12),
    ("SUPPORT END", 12),
]

RELEASES = {
    13: {
        "codename": "trixie",
        "eol": date(2028, 8, 9),
        "lts": date(2030, 6, 30),
        "elts": date(2035, 6, 30),
    },
    12: {
        "codename": "bookworm",
        "eol": date(2026, 6, 10),
        "lts": date(2028, 6, 30),
        "elts": date(2033, 6, 30),
    },
    11: {
        "codename": "bullseye",
        "eol": date(2024, 8, 14),
        "lts": date(2026, 8, 31),
        "elts": date(2031, 6, 30),
    },
    10: {
        "codename": "buster",
        "eol": date(2022, 9, 10),
        "lts": date(2024, 6, 30),
        "elts": date(2029, 6, 30),
    },
    9: {
        "codename": "stretch",
        "eol": date(2020, 7, 18),
        "lts": date(2022, 7, 1),
        "elts": date(2027, 6, 30),
    },
    8: {
        "codename": "jessie",
        "eol": date(2018, 6, 17),
        "lts": date(2020, 6, 30),
        "elts": date(2025, 6, 30),
    },
    7: {
        "codename": "wheezy",
        "eol": date(2016, 4, 25),
        "lts": date(2018, 5, 31),
        "elts": date(2020, 6, 30),
    },
    6: {
        "codename": "squeeze",
        "eol": date(2014, 5, 31),
        "lts": date(2016, 2, 29),
        "elts": None,
    },
    5: {
        "codename": "lenny",
        "eol": date(2012, 2, 6),
        "lts": None,
        "elts": None,
    },
    4: {
        "codename": "etch",
        "eol": date(2010, 2, 15),
        "lts": None,
        "elts": None,
    },
}

CODENAME_TO_VERSION = {
    info["codename"]: version for version, info in RELEASES.items()
}


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
    value = re.sub(r":\d+(?:/tcp)?$", "", value, flags=re.I)
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


async def run_nmap(ip, ports, args):
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-all", "--open",
        "--host-timeout", args.host_timeout,
        "--script-timeout", args.script_timeout,
        "--script", "banner,http-server-header,http-headers,http-title",
    ]
    if args.all_ports:
        command.extend(["-p-", "--min-rate", str(args.min_rate)])
    else:
        command.extend(["-p", ports])
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


def script_output(node):
    return node.attrib.get("output", "") if node is not None else ""


def service_evidence(port_node):
    service = port_node.find("service")
    parts = []
    if service is not None:
        parts.extend(
            service.attrib.get(key, "")
            for key in ("name", "product", "version", "extrainfo", "servicefp")
        )
        for cpe in service.findall("cpe"):
            parts.append(cpe.text or "")
    parts.extend(
        script_output(script) for script in port_node.findall("script")
    )
    return " ".join(part for part in parts if part)


def add_candidate(candidates, version, score, source, port=None):
    if version not in RELEASES:
        return
    item = candidates.setdefault(
        version,
        {"score": 0, "sources": [], "ports": set()},
    )
    item["score"] += score
    if source and source not in item["sources"]:
        item["sources"].append(source)
    if port:
        item["ports"].add(port)


def detect_candidates(text, candidates, source, port=None):
    lower = text.lower()

    # Direct release declarations are the strongest remote evidence.
    direct_patterns = (
        r"\bdebian\s+(?:gnu/)?linux\s+(\d{1,2})(?:\.\d+)?\b",
        r"\bdebian\s+(?:release|version)\s+(\d{1,2})(?:\.\d+)?\b",
        r"\bcpe:/o:debian:debian_linux:(\d{1,2})(?:\.\d+)?\b",
        r"\bdebian_linux:(\d{1,2})(?:\.\d+)?\b",
    )
    for pattern in direct_patterns:
        for match in re.finditer(pattern, lower, re.I):
            add_candidate(
                candidates, int(match.group(1)), 100,
                f"{source}: {match.group(0)}", port,
            )

    # Debian codenames are also unambiguous release evidence.
    for codename, version in CODENAME_TO_VERSION.items():
        if re.search(rf"\b{re.escape(codename)}\b", lower):
            add_candidate(
                candidates, version, 95,
                f"{source}: Debian codename {codename}", port,
            )

    # Package revisions such as 1:9.2p1-2+deb12u7 identify the Debian base
    # release, but score lower because banners can be copied or proxied.
    for match in re.finditer(r"(?:\+|~|-|\.)deb(\d{1,2})(?:u\d+)?\b", lower):
        add_candidate(
            candidates, int(match.group(1)), 65,
            f"{source}: package suffix {match.group(0)}", port,
        )


def parse_nmap(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    candidates = {}
    ip = ""
    open_ports = set()

    host = root.find("host")
    if host is None:
        return None
    address = host.find("address[@addrtype='ipv4']")
    if address is None:
        address = host.find("address")
    if address is not None:
        ip = address.attrib.get("addr", "")

    for port_node in host.findall("./ports/port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        open_ports.add(port)
        evidence = service_evidence(port_node)
        detect_candidates(evidence, candidates, f"TCP/{port}", port)

    for osmatch in host.findall("./os/osmatch"):
        name = osmatch.attrib.get("name", "")
        accuracy = int(osmatch.attrib.get("accuracy", "0") or 0)
        detect_candidates(
            name, candidates, f"Nmap OS {accuracy}%"
        )
        for osclass in osmatch.findall("osclass"):
            evidence = " ".join([
                osclass.attrib.get("vendor", ""),
                osclass.attrib.get("osfamily", ""),
                osclass.attrib.get("osgen", ""),
            ])
            for cpe in osclass.findall("cpe"):
                evidence += " " + (cpe.text or "")
            detect_candidates(
                evidence, candidates, f"Nmap OS class {accuracy}%"
            )

    if not candidates:
        return None

    ranked = sorted(
        candidates.items(),
        key=lambda item: (-item[1]["score"], -item[0]),
    )
    version, evidence = ranked[0]
    conflict = (
        len(ranked) > 1
        and ranked[1][1]["score"] >= evidence["score"] * 0.75
        and ranked[1][0] != version
    )
    confidence = (
        "CONFLICT" if conflict else
        "HIGH" if evidence["score"] >= 95 else
        "MEDIUM" if evidence["score"] >= 60 else
        "LOW"
    )
    return {
        "ip": ip,
        "version": version,
        "ports": sorted(evidence["ports"] or open_ports),
        "confidence": confidence,
        "evidence": " | ".join(evidence["sources"]),
        "conflicts": ",".join(str(item[0]) for item in ranked[1:]),
    }


def lifecycle(version, today=None):
    today = today or date.today()
    info = RELEASES[version]
    if info["eol"] and today <= info["eol"]:
        return "SUPPORTED", info["eol"]
    if info["lts"] and today <= info["lts"]:
        return "LTS", info["lts"]
    if info["elts"] and today <= info["elts"]:
        return "ELTS ONLY", info["elts"]
    support_end = info["elts"] or info["lts"] or info["eol"]
    return "UNSUPPORTED", support_end


async def scan_host(ip, ports, args):
    result = parse_nmap(await run_nmap(ip, ports, args))
    if not result:
        return None
    status, support_end = lifecycle(result["version"])
    result.update({
        "release": f"Debian {result['version']}",
        "codename": RELEASES[result["version"]]["codename"],
        "status": status,
        "support_end": support_end.isoformat() if support_end else "-",
    })
    if not args.show_all and status not in {"ELTS ONLY", "UNSUPPORTED"}:
        return None
    return result


async def run_all(targets, ports, args):
    queue = asyncio.Queue()
    rows = []
    completed = 0
    detected = 0
    for target in targets:
        await queue.put(target)

    async def worker():
        nonlocal completed, detected
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                try:
                    result = parse_nmap(await run_nmap(ip, ports, args))
                    if result:
                        detected += 1
                        status, support_end = lifecycle(result["version"])
                        result.update({
                            "release": f"Debian {result['version']}",
                            "codename": RELEASES[result["version"]]["codename"],
                            "status": status,
                            "support_end": support_end.isoformat() if support_end else "-",
                        })
                        if args.show_all or status in {"ELTS ONLY", "UNSUPPORTED"}:
                            rows.append(result)
                except Exception as error:
                    print(
                        f"\nWARNING: {ip} scan failed: "
                        f"{type(error).__name__}: {error}",
                        file=sys.stderr,
                    )
                completed += 1
                affected = sum(
                    row["status"] in {"ELTS ONLY", "UNSUPPORTED"} for row in rows
                )
                sys.stdout.write(
                    f"\rScanning Debian OS: {completed}/{len(targets)} "
                    f"({completed / len(targets) * 100:.1f}%) | "
                    f"Detected: {detected} | Outdated: {affected} | "
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
    return rows, detected


def ports_text(ports):
    return ",".join(str(port) for port in ports) or "-"


def print_table(rows, colors=True):
    print()
    if not rows:
        print("No Debian releases requiring ELTS or already unsupported were identified.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(ports_text(row["ports"]), 20),
            cell(row["release"], 24),
            cell(row["codename"], 12),
            cell(row["status"], 18),
            cell(row["confidence"], 12),
            cell(row["support_end"], 12),
        ])
        code = RED if row["status"] == "UNSUPPORTED" else (
            YELLOW if row["status"] in {"ELTS ONLY", "LTS"} else GREEN
        )
        print(color(line, code, colors))


def write_csv(path, rows):
    fields = [
        "ip", "ports", "release", "version", "codename", "status",
        "confidence", "support_end", "evidence", "conflicts",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            output = dict(row)
            output["ports"] = ports_text(row["ports"])
            writer.writerow({field: output.get(field, "") for field in fields})


def write_list(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            if row["status"] in {"ELTS ONLY", "UNSUPPORTED"}:
                handle.write(f"{row['ip']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Find outdated or unsupported Debian GNU/Linux releases."
    )
    parser.add_argument("targets", nargs="*", help="Single IP or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs or CIDRs")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="TCP ports/ranges used for evidence")
    parser.add_argument("--all-ports", action="store_true", help="Scan all TCP ports for Debian banners")
    parser.add_argument("--min-rate", type=int, default=500, help="Nmap rate with --all-ports")
    parser.add_argument("--os-detect", action="store_true", help="Add Nmap -O --osscan-guess; run with sudo")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent hosts")
    parser.add_argument("--host-timeout", default="90s", help="Nmap timeout per host")
    parser.add_argument("--script-timeout", default="30s", help="Nmap script timeout")
    parser.add_argument("--show-all", action="store_true", help="Show supported and LTS Debian releases too")
    parser.add_argument("--csv", default="outdated_debian_results.csv", help="CSV output")
    parser.add_argument("--list", default="outdated_debian_ips.txt", help="Outdated IP list")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install it with: sudo apt install nmap")

    targets = load_targets(args)
    ports = normalize_ports(args.ports)
    args.workers = min(max(1, args.workers), len(targets))

    print(f"Loaded targets : {len(targets)}")
    print(f"Workers        : {args.workers}")
    print(f"Evidence ports : {'all TCP ports' if args.all_ports else ports}")
    print(f"OS detection   : {'enabled (-O)' if args.os_detect else 'service/banner evidence only'}")
    print("Lifecycle      : Debian project EOL/LTS dates; ELTS is third-party paid support")
    print(f"Showing        : {'all detected Debian releases' if args.show_all else 'ELTS-only and unsupported Debian releases'}")

    rows, detected = asyncio.run(run_all(targets, ports, args))
    print_table(rows, colors=not args.no_color)
    write_csv(args.csv, rows)
    write_list(args.list, rows)

    affected = sum(
        row["status"] in {"ELTS ONLY", "UNSUPPORTED"} for row in rows
    )
    print()
    print(f"Debian hosts detected : {detected}")
    print(f"Outdated hosts        : {affected}")
    print(f"CSV written           : {args.csv}")
    print(f"IP list written       : {args.list}")
    return 1 if affected else 0


if __name__ == "__main__":
    raise SystemExit(main())

