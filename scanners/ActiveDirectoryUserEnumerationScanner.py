#!/usr/bin/env python3
"""
Discover Active Directory domains and enumerate valid usernames with Kerbrute.

The user supplies only an IP, hostname, CIDR, or target file. The scanner:
  1. Finds likely domain controllers with Nmap.
  2. Derives the AD DNS domain from LDAP RootDSE, SMB, RDP NTLM, service
     hostnames, or reverse DNS evidence.
  3. Builds and runs a Kerbrute userenum command against each confirmed KDC.
  4. Reports only Kerbrute's explicit "VALID USERNAME" results as confirmed.

Kerbrute user enumeration does not test passwords. It can still generate
Kerberos event 4768 and must only be used with authorization.
"""

import argparse
import asyncio
import csv
import ipaddress
import re
import shlex
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

DISCOVERY_PORTS = "53,88,135,139,389,445,464,636,3268,3269,3389"
SCRIPT_SET = "ldap-rootdse,smb-os-discovery,rdp-ntlm-info"
DEFAULT_USERS = Path(__file__).resolve().parent / "data" / "ad_usernames.txt"

COLS = [
    ("IP ADDRESS", 16),
    ("DOMAIN", 34),
    ("SOURCE", 20),
    ("USERS", 7),
    ("VALID ACCOUNTS", 48),
    ("STATUS", 19),
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
    value = re.sub(r":(?:88|389|636|3268|3269)(?:/(?:tcp|udp))?$", "", value, flags=re.I)
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
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f targets.txt")
    return unique


def normalize_domain(value):
    value = str(value or "").strip().strip(".").lower()
    if value.upper().startswith("DC="):
        labels = re.findall(r"(?:^|,)\s*DC=([^,]+)", value, re.I)
        value = ".".join(labels)
    value = value.replace("\\", ".")
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", value or ""):
        return ""
    try:
        ipaddress.ip_address(value)
        return ""
    except ValueError:
        pass
    if "." not in value or value.endswith((".localdomain", ".localhost")):
        return ""
    return value


def domain_from_hostname(value):
    value = str(value or "").strip().strip(".").lower()
    if "." not in value:
        return ""
    return normalize_domain(value.split(".", 1)[1])


def script_text(script):
    parts = [script.attrib.get("output", "")]
    for node in script.iter():
        if node.text:
            parts.append(node.text)
        parts.extend(node.attrib.values())
    return "\n".join(parts)


def add_candidate(candidates, value, source, score):
    domain = normalize_domain(value)
    if not domain:
        return
    current = candidates.get(domain)
    if current is None or score > current["score"]:
        candidates[domain] = {"domain": domain, "source": source, "score": score}


def extract_domain_candidates(root):
    candidates = {}
    for script in root.findall(".//script"):
        text = script_text(script)
        for pattern, source, score in (
            (r"(?mi)^\s*[|_ ]*defaultNamingContext\s*:\s*(DC=[^\r\n]+)", "LDAP RootDSE", 100),
            (r"(?mi)^\s*[|_ ]*rootDomainNamingContext\s*:\s*(DC=[^\r\n]+)", "LDAP RootDSE", 100),
            (r"(?mi)^\s*[|_ ]*DNS_Domain_Name\s*:\s*([^\s]+)", "RDP NTLM", 95),
            (r"(?mi)^\s*[|_ ]*Domain_DNS\s*:\s*([^\s]+)", "SMB OS", 95),
            (r"(?mi)^\s*[|_ ]*Forest\s*:\s*([^\s]+)", "SMB/LDAP forest", 90),
            (r"(?mi)^\s*[|_ ]*dnsHostName\s*:\s*([^\s]+)", "LDAP hostname", 85),
            (r"(?mi)^\s*[|_ ]*FQDN\s*:\s*([^\s]+)", "Nmap FQDN", 80),
        ):
            for match in re.finditer(pattern, text):
                value = match.group(1)
                if source in {"LDAP hostname", "Nmap FQDN"}:
                    value = domain_from_hostname(value)
                add_candidate(candidates, value, source, score)
        for node in script.iter():
            key = node.attrib.get("key", "").lower()
            value = (node.text or "").strip()
            if key in {"defaultnamingcontext", "rootdomainnamingcontext"}:
                add_candidate(candidates, value, "LDAP RootDSE", 100)
            elif key in {"dns_domain_name", "domain_dns", "forest"}:
                add_candidate(candidates, value, "Nmap script data", 90)
            elif key in {"dnshostname", "fqdn"}:
                add_candidate(
                    candidates,
                    domain_from_hostname(value),
                    "Nmap hostname data",
                    80,
                )

    for service in root.findall(".//service"):
        hostname = service.attrib.get("hostname", "")
        add_candidate(
            candidates,
            domain_from_hostname(hostname),
            "service hostname",
            70,
        )
    for hostname in root.findall(".//hostname"):
        add_candidate(
            candidates,
            domain_from_hostname(hostname.attrib.get("name", "")),
            "reverse/service DNS",
            65,
        )
    return sorted(candidates.values(), key=lambda item: (-item["score"], item["domain"]))


def parse_discovery_xml(xml_text, target):
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
    ip = address.attrib.get("addr", target) if address is not None else target

    open_ports = set()
    service_evidence = []
    for port_node in host.findall("./ports/port"):
        state = port_node.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port = int(port_node.attrib.get("portid", "0"))
        open_ports.add(port)
        service = port_node.find("service")
        if service is not None:
            service_evidence.extend(service.attrib.values())

    text = " ".join(service_evidence).lower()
    kerberos_open = 88 in open_ports
    ad_evidence = bool(
        kerberos_open
        or open_ports.intersection({389, 636, 3268, 3269})
        or re.search(r"active directory|microsoft.*ldap|kerberos", text)
    )
    domains = extract_domain_candidates(root)
    return {
        "ip": ip,
        "ports": sorted(open_ports),
        "kerberos_open": kerberos_open,
        "ad_evidence": ad_evidence,
        "domains": domains,
    }


async def run_command(command, timeout):
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()
        return 124, stdout.decode(errors="replace"), (
            stderr.decode(errors="replace") + "\nCommand timed out."
        )
    return (
        process.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


async def discover_target(target, timeout):
    command = [
        "nmap",
        "-Pn",
        "-sV",
        "--version-light",
        "--open",
        "-p",
        DISCOVERY_PORTS,
        "--script",
        SCRIPT_SET,
        "--script-timeout",
        "15s",
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        target,
    ]
    rc, stdout, stderr = await run_command(command, timeout + 20)
    result = parse_discovery_xml(stdout, target)
    if result is None:
        return {
            "ip": target,
            "ports": [],
            "kerberos_open": False,
            "ad_evidence": False,
            "domains": [],
            "error": re.sub(r"\s+", " ", stderr).strip()[:300],
        }
    result["error"] = "" if rc in {0, 1} else re.sub(r"\s+", " ", stderr).strip()[:300]
    if not result["domains"]:
        try:
            reverse = await asyncio.to_thread(socket.gethostbyaddr, result["ip"])
            domain = domain_from_hostname(reverse[0])
            if domain:
                result["domains"] = [
                    {"domain": domain, "source": "reverse DNS", "score": 60}
                ]
        except (OSError, socket.herror):
            pass
    return result


def find_kerbrute(value):
    if value:
        path = Path(value).expanduser()
        if path.is_file():
            return str(path.resolve())
        found = shutil.which(value)
        if found:
            return found
        raise SystemExit(f"Kerbrute was not found: {value}")
    for name in (
        "kerbrute",
        "kerbrute.exe",
        "kerbrute_linux_amd64",
        "kerbrute_windows_amd64.exe",
    ):
        found = shutil.which(name)
        if found:
            return found
        for folder in (Path(__file__).resolve().parent, Path.cwd()):
            candidate = folder / name
            if candidate.is_file():
                return str(candidate.resolve())
    raise SystemExit(
        "Kerbrute was not found. Install it from "
        "https://github.com/ropnop/kerbrute/releases or use --kerbrute PATH."
    )


def load_usernames(path):
    users = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#") or any(char.isspace() for char in value):
                continue
            if value not in users:
                users.append(value)
    if not users:
        raise SystemExit(f"No usernames were loaded from {path}")
    return users


def build_kerbrute_command(binary, ip, domain, user_file, args, log_path):
    command = [
        binary,
        "userenum",
        "--dc",
        ip,
        "-d",
        domain,
        "--safe",
        "-t",
        str(args.threads),
        "-o",
        str(log_path),
    ]
    if args.delay:
        command.extend(["--delay", str(args.delay)])
    command.append(str(user_file))
    return command


def parse_valid_users(text, domain):
    users = []
    pattern = re.compile(r"\[\+\]\s+VALID USERNAME:\s*([^\s]+)", re.I)
    for match in pattern.finditer(text):
        value = match.group(1).strip().rstrip(",")
        if "@" in value:
            username, result_domain = value.rsplit("@", 1)
            if normalize_domain(result_domain) != normalize_domain(domain):
                continue
        else:
            username = value
        if username and username not in users:
            users.append(username)
    return users


async def enumerate_dc(discovery, args, kerbrute, user_file, output_dir):
    if not discovery["kerberos_open"]:
        return {
            "ip": discovery["ip"],
            "domain": "-",
            "source": "-",
            "users": [],
            "status": "NO KERBEROS",
            "detail": "TCP/88 was not confirmed open.",
            "command": "",
        }
    if args.domain:
        selected = {
            "domain": args.domain,
            "source": "command line",
            "score": 1000,
        }
    elif discovery["domains"]:
        selected = discovery["domains"][0]
    else:
        return {
            "ip": discovery["ip"],
            "domain": "-",
            "source": "-",
            "users": [],
            "status": "DOMAIN UNKNOWN",
            "detail": "Kerberos is open, but no AD DNS domain was discovered.",
            "command": "",
        }

    domain = selected["domain"]
    log_path = output_dir / f"kerbrute_{discovery['ip'].replace(':', '_')}.log"
    command = build_kerbrute_command(
        kerbrute,
        discovery["ip"],
        domain,
        user_file,
        args,
        log_path,
    )
    printable = subprocess_command(command)
    if args.dry_run:
        return {
            "ip": discovery["ip"],
            "domain": domain,
            "source": selected["source"],
            "users": [],
            "status": "COMMAND READY",
            "detail": "Dry run; Kerbrute was not executed.",
            "command": printable,
        }

    rc, stdout, stderr = await run_command(command, args.kerbrute_timeout)
    combined = f"{stdout}\n{stderr}"
    users = parse_valid_users(combined, domain)
    if users:
        status = "VALID USERS"
        detail = f"Kerbrute explicitly confirmed {len(users)} username(s)."
    elif rc == 124:
        status = "TIMEOUT"
        detail = "Kerbrute timed out; results are incomplete."
    elif re.search(r"could not|unable|failed|error|no kdc|connection refused", combined, re.I):
        status = "ERROR"
        detail = re.sub(r"\s+", " ", combined).strip()[-350:]
    else:
        status = "NO VALID USERS"
        detail = "No username from the supplied candidate list was confirmed."
    return {
        "ip": discovery["ip"],
        "domain": domain,
        "source": selected["source"],
        "users": users,
        "status": status,
        "detail": detail,
        "command": printable,
    }


def subprocess_command(command):
    return subprocess_list2cmdline(command) if sys.platform == "win32" else shlex.join(command)


def subprocess_list2cmdline(command):
    return subprocess.list2cmdline(command)


async def run_all(targets, args, kerbrute, user_file, output_dir):
    semaphore = asyncio.Semaphore(args.workers)

    async def one(target):
        async with semaphore:
            discovery = await discover_target(target, args.nmap_timeout)
            return await enumerate_dc(
                discovery,
                args,
                kerbrute,
                user_file,
                output_dir,
            )

    rows = []
    tasks = [asyncio.create_task(one(target)) for target in targets]
    for completed, task in enumerate(asyncio.as_completed(tasks), 1):
        row = await task
        rows.append(row)
        confirmed = sum(len(item["users"]) for item in rows)
        sys.stdout.write(
            f"\rAD/Kerbrute: {completed}/{len(tasks)} "
            f"({completed / len(tasks) * 100:.1f}%) | "
            f"Valid users: {confirmed} | Current: {row['ip']}".ljust(140)
        )
        sys.stdout.flush()
    sys.stdout.write("\n")
    return rows


def users_text(users):
    return ",".join(users) if users else "-"


def print_table(rows, show_all=False, colors=True):
    displayed = [
        row for row in rows
        if show_all or row["status"] in {"VALID USERS", "COMMAND READY", "DOMAIN UNKNOWN"}
    ]
    print()
    if not displayed:
        print("No valid usernames were confirmed by Kerbrute.")
        return
    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(displayed, key=lambda item: ip_sort(item["ip"])):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["domain"], 34),
            cell(row["source"], 20),
            cell(len(row["users"]), 7),
            cell(users_text(row["users"]), 48),
            cell(row["status"], 19),
        ])
        code = RED if row["status"] == "VALID USERS" else (
            GREEN if row["status"] == "NO VALID USERS" else YELLOW
        )
        print(color(line, code, colors))
        if row["command"]:
            print(f"  Command: {row['command']}")
        if row["detail"]:
            print(f"  Detail : {row['detail']}")


def write_csv(path, rows):
    fields = [
        "ip", "domain", "domain_source", "valid_user_count",
        "valid_users", "status", "detail", "command",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=lambda item: ip_sort(item["ip"])):
            writer.writerow({
                "ip": row["ip"],
                "domain": row["domain"],
                "domain_source": row["source"],
                "valid_user_count": len(row["users"]),
                "valid_users": users_text(row["users"]),
                "status": row["status"],
                "detail": row["detail"],
                "command": row["command"],
            })


def write_users(path, rows):
    users = []
    for row in rows:
        for user in row["users"]:
            principal = f"{user}@{row['domain']}"
            if principal not in users:
                users.append(principal)
    with open(path, "w", encoding="utf-8") as handle:
        for user in users:
            handle.write(user + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Discover AD domains and enumerate valid usernames with Kerbrute."
    )
    parser.add_argument("targets", nargs="*", help="Single IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing IPs, hostnames, or CIDRs")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Concurrent target workers")
    parser.add_argument("--nmap-timeout", type=int, default=45)
    parser.add_argument("--kerbrute-timeout", type=int, default=300)
    parser.add_argument("--threads", type=int, default=10, help="Kerbrute threads")
    parser.add_argument("--delay", type=int, default=0, help="Delay between attempts in milliseconds")
    parser.add_argument("--kerbrute", help="Kerbrute executable path or command name")
    parser.add_argument("--domain", help="Override automatic AD DNS domain discovery")
    parser.add_argument("--users", help="Custom username candidate file")
    parser.add_argument("--dry-run", action="store_true", help="Discover domain and print command without running Kerbrute")
    parser.add_argument("--show-all", action="store_true")
    parser.add_argument("--output-dir", default="ad_kerbrute_output")
    parser.add_argument("--csv", default="ad_kerbrute_results.csv")
    parser.add_argument("--valid-users", default="ad_valid_users.txt")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found. Install Nmap first.")
    kerbrute = (
        args.kerbrute or "kerbrute"
        if args.dry_run
        else find_kerbrute(args.kerbrute)
    )
    user_file = Path(args.users).expanduser() if args.users else DEFAULT_USERS
    if not user_file.is_file():
        raise SystemExit(f"Username candidate file was not found: {user_file}")
    usernames = load_usernames(user_file)
    targets = load_targets(args)
    args.workers = min(max(1, args.workers), len(targets))
    args.threads = min(max(1, args.threads), 100)
    args.delay = max(0, args.delay)
    if args.domain:
        args.domain = normalize_domain(args.domain)
        if not args.domain:
            parser.error("--domain must be a DNS domain such as corp.example.com")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loaded targets : {len(targets)}")
    print(f"Nmap ports     : {DISCOVERY_PORTS}")
    print(f"Domain sources : LDAP RootDSE, SMB, RDP NTLM, DNS")
    print(f"Kerbrute       : {kerbrute}")
    print(f"Username list  : {user_file} ({len(usernames)} candidates)")
    print(f"Mode           : {'domain discovery and command preview' if args.dry_run else 'Kerbrute userenum'}")
    print("Confirmation   : only explicit Kerbrute VALID USERNAME lines")

    rows = asyncio.run(run_all(targets, args, kerbrute, user_file, output_dir))
    print_table(rows, args.show_all, not args.no_color)
    write_csv(args.csv, rows)
    write_users(args.valid_users, rows)

    valid = sum(len(row["users"]) for row in rows)
    dcs = sum(row["status"] not in {"NO KERBEROS", "ERROR"} for row in rows)
    print()
    print(f"Domain controllers assessed : {dcs}")
    print(f"Valid usernames confirmed   : {valid}")
    print(f"CSV written                 : {args.csv}")
    print(f"Valid-user list             : {args.valid_users}")
    return 1 if valid else 0


if __name__ == "__main__":
    raise SystemExit(main())
