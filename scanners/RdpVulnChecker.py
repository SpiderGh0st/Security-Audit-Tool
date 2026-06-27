#!/usr/bin/env python3
"""
RDP vulnerability checker with BlueKeep support.

Checks:
  - RDP service open
  - NLA/CredSSP-only enforcement using rdp-enum-encryption
  - Weak RDP security layers such as SSL/RDSTLS accepted alongside NLA
  - MS12-020 if the nmap NSE script is available
  - BlueKeep CVE-2019-0708 using rdpscan if installed, otherwise an available
    rdp-vuln-ms19-0708 / rdp-vuln-cve2019-0708 NSE script if present

Examples:
  python3 RdpVulnChecker_vulnerable_only.py -f rdp_open_ips.txt
  python3 RdpVulnChecker_vulnerable_only.py -f rdp_open_ip_ports.txt --csv rdp_results.csv
  python3 RdpVulnChecker_vulnerable_only.py 198.51.100.90
  python3 RdpVulnChecker_vulnerable_only.py 198.51.100.0/24 --workers 32

Notes:
  - This is non-exploitative and uses scanner checks only.
  - BlueKeep accuracy is best when rdpscan is installed.
  - If no BlueKeep-capable tool is found, the script reports BLUEKEEP NOT TESTED.
  - Terminal output shows only affected / vulnerable rows by default.
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
from pathlib import Path


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

COLS = [
    ("IP ADDRESS", 16),
    ("PORT", 7),
    ("RDP", 8),
    ("NLA ONLY", 10),
    ("BLUEKEEP", 16),
    ("STATUS", 13),
    ("DETAIL", 88),
]


def paint(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def cell(value, width):
    text = str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return text[:width].ljust(width)


def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    value = value.split()[0]
    if ":" in value and re.match(r"^[0-9.]+:\d+", value):
        ip, port = value.split(":", 1)
        return [(ip, port.split("/", 1)[0])]
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses == 1:
            return [(str(net.network_address), None)]
        return [(str(ip), None) for ip in net.hosts()]
    except ValueError:
        return [(value, None)]


def load_targets(args):
    items = []
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
            items.extend(expand_target(line))
    for item in args.targets:
        items.extend(expand_target(item))

    grouped = {}
    for ip, port in items:
        grouped.setdefault(ip, set())
        if port:
            grouped[ip].add(port)

    if not grouped:
        raise SystemExit("No targets supplied. Provide an IP/CIDR or use -f targets.txt")
    return grouped


def ip_sort(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return value


def find_nse_script(names):
    if not shutil.which("nmap"):
        return None
    search_dirs = [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        str(Path.home() / ".nmap" / "scripts"),
    ]
    for directory in search_dirs:
        for name in names:
            if Path(directory, name).exists():
                return Path(name).stem
    return None


def progress(done, total, findings, current="", colors=True):
    pct = (done / total * 100) if total else 100
    msg = f"\rScanning RDP: {done}/{total} ({pct:5.1f}%) | Findings: {findings} | Current: {current}"
    sys.stdout.write(paint(msg[:150].ljust(150), CYAN, colors))
    sys.stdout.flush()


async def run_cmd(cmd, timeout):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 124, "", f"timeout after {timeout}s"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def run_nmap(ip, port, timeout, scripts):
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-T4",
        "-p",
        str(port),
        "--script",
        scripts,
        "-oX",
        "-",
        ip,
    ]
    code, out, err = await run_cmd(cmd, timeout)
    if code == 124:
        return {"timeout": True, "error": err, "xml": ""}
    return {"timeout": False, "error": err, "xml": out}


async def run_bluekeep(ip, port, timeout, bluekeep_script):
    if shutil.which("rdpscan"):
        # rdpscan supports target:port syntax in common builds.
        target = f"{ip}:{port}" if str(port) != "3389" else ip
        code, out, err = await run_cmd(["rdpscan", target], timeout)
        text = out + "\n" + err
        return parse_bluekeep_text(text, tool="rdpscan")

    if bluekeep_script and shutil.which("nmap"):
        code, out, err = await run_cmd([
            "nmap", "-Pn", "-p", str(port), "--script", bluekeep_script, ip
        ], timeout)
        return parse_bluekeep_text(out + "\n" + err, tool=bluekeep_script)

    return "NOT TESTED", "No rdpscan or BlueKeep NSE script found."


def parse_bluekeep_text(text, tool):
    low = text.lower()
    if "vulnerable" in low and "not vulnerable" not in low:
        return "VULNERABLE", f"BlueKeep check by {tool} reported vulnerable."
    if "not vulnerable" in low or "safe" in low or "not appear vulnerable" in low:
        return "NOT VULN", f"BlueKeep check by {tool} did not report vulnerability."
    if "patched" in low:
        return "NOT VULN", f"BlueKeep check by {tool} reported patched/not vulnerable."
    if "credssp" in low and "nla" in low and "required" in low:
        return "NOT VULN", f"BlueKeep check by {tool} indicates NLA required."
    return "UNKNOWN", f"BlueKeep check by {tool} was inconclusive."


def parse_nmap_xml(ip, port, xml, timeout=False, error=""):
    row = {
        "ip": ip,
        "port": str(port),
        "rdp": "UNKNOWN",
        "nla_only": "UNKNOWN",
        "bluekeep": "NOT TESTED",
        "status": "UNKNOWN",
        "detail": "",
        "findings": [],
    }
    if timeout:
        row.update({"rdp": "UNKNOWN", "status": "TIMEOUT", "detail": error})
        return row

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        row.update({"status": "ERROR", "detail": f"Failed to parse nmap XML: {exc}"})
        return row

    port_el = root.find(".//port")
    if port_el is None:
        row.update({"rdp": "NO", "status": "NO RDP", "detail": "No port result returned."})
        return row

    state = port_el.find("state")
    if state is None or state.attrib.get("state") != "open":
        row.update({"rdp": "NO", "status": "NO RDP", "detail": "RDP port is not open."})
        return row

    service = port_el.find("service")
    service_text = ""
    if service is not None:
        service_text = " ".join([
            service.attrib.get("name", ""),
            service.attrib.get("product", ""),
            service.attrib.get("extrainfo", ""),
        ]).strip()

    row["rdp"] = "OPEN"
    scripts = {s.attrib.get("id", ""): s.attrib.get("output", "") for s in port_el.findall("script")}
    combined = "\n".join(scripts.values())
    low = combined.lower()

    credssp = bool(re.search(r"credssp.*success|nla\):\s*success", combined, re.I))
    ssl_layer = bool(re.search(r"ssl:\s*success", combined, re.I))
    rdstls = bool(re.search(r"rdstls:\s*success", combined, re.I))
    native_rdp = bool(re.search(r"native rdp:\s*success|standard rdp security:\s*success", combined, re.I))

    details = []
    findings = []

    if "rdp-enum-encryption" in scripts:
        if credssp and not (ssl_layer or rdstls or native_rdp):
            row["nla_only"] = "YES"
            details.append("NLA/CredSSP appears to be the only accepted security layer.")
        elif credssp and (ssl_layer or rdstls or native_rdp):
            row["nla_only"] = "NO"
            findings.append("NLA not enforced exclusively")
            layers = []
            if ssl_layer:
                layers.append("SSL")
            if rdstls:
                layers.append("RDSTLS")
            if native_rdp:
                layers.append("Native RDP")
            details.append("CredSSP/NLA is supported, but weaker RDP layers also succeeded: " + ", ".join(layers) + ".")
        elif not credssp:
            row["nla_only"] = "NO"
            findings.append("NLA not supported/enforced")
            details.append("CredSSP/NLA was not reported as successful.")
        else:
            row["nla_only"] = "UNKNOWN"
    else:
        details.append("rdp-enum-encryption output not available.")

    if "40-bit" in low or "56-bit" in low or "low" in low and "encryption" in low:
        findings.append("Weak RDP encryption")
        details.append("Weak/legacy RDP encryption indicators were reported.")

    for script_id, output in scripts.items():
        out_low = output.lower()
        if "rdp-vuln-ms12-020" in script_id and "vulnerable" in out_low:
            findings.append("MS12-020")
            details.append("Nmap reported MS12-020 vulnerability indicators.")

    row["findings"] = sorted(set(findings))
    if row["findings"]:
        row["status"] = "AFFECTED"
    else:
        row["status"] = "OK"
        if not details:
            details.append(f"RDP service open ({service_text or 'service detected'}); no configured RDP script finding reported.")
    row["detail"] = " ".join(details)
    return row


async def check_target(ip, ports, timeout, scripts, bluekeep_script, bluekeep_timeout):
    rows = []
    for port in sorted(ports, key=lambda p: int(p)):
        result = await run_nmap(ip, port, timeout, scripts)
        row = parse_nmap_xml(ip, port, result["xml"], timeout=result["timeout"], error=result["error"])
        if row["rdp"] == "OPEN":
            bk_status, bk_detail = await run_bluekeep(ip, port, bluekeep_timeout, bluekeep_script)
            row["bluekeep"] = bk_status
            if bk_status == "VULNERABLE":
                row["status"] = "CRITICAL"
                row["findings"].append("BlueKeep CVE-2019-0708")
            if bk_detail:
                row["detail"] = (row["detail"] + " " + bk_detail).strip()
        rows.append(row)
    return rows


async def run_all(target_map, workers, timeout, scripts, bluekeep_script, bluekeep_timeout, colors=True):
    queue = asyncio.Queue()
    results = []
    total = 0
    for ip, ports in target_map.items():
        port_set = ports or {"3389"}
        await queue.put((ip, port_set))
        total += len(port_set)

    done = 0
    finding_count = 0
    lock = asyncio.Lock()

    async def worker():
        nonlocal done, finding_count
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            ip, ports = item
            async with lock:
                progress(done, total, finding_count, ip, colors)
            rows = await check_target(ip, ports, timeout, scripts, bluekeep_script, bluekeep_timeout)
            results.extend(rows)
            async with lock:
                done += len(ports)
                finding_count += sum(1 for r in rows if r["status"] in {"AFFECTED", "CRITICAL"})
                progress(done, total, finding_count, ip, colors)
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return results


def row_color(row):
    if row["status"] == "CRITICAL" or row["bluekeep"] == "VULNERABLE":
        return RED
    if row["status"] == "AFFECTED":
        return YELLOW
    if row["status"] == "OK":
        return GREEN
    return YELLOW


def is_vulnerable_row(row):
    return row["status"] in {"AFFECTED", "CRITICAL"} or row["bluekeep"] == "VULNERABLE"


def print_table(rows, colors=True, show_all=False):
    shown = rows if show_all else [r for r in rows if is_vulnerable_row(r)]
    print()
    if not shown:
        print("No vulnerable RDP / BlueKeep findings found.")
        return

    header = " ".join(cell(name, width) for name, width in COLS)
    print(header)
    print("-" * len(header))
    for row in sorted(shown, key=lambda r: (ip_sort(r["ip"]), int(r["port"]) if str(r["port"]).isdigit() else 0)):
        line = " ".join([
            cell(row["ip"], 16),
            cell(row["port"], 7),
            cell(row["rdp"], 8),
            cell(row["nla_only"], 10),
            cell(row["bluekeep"], 16),
            cell(row["status"], 13),
            cell(row["detail"], 88),
        ])
        print(paint(line, row_color(row), colors))


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "port", "rdp", "nla_only", "bluekeep", "status", "findings", "detail"])
        writer.writeheader()
        for row in sorted(rows, key=lambda r: (ip_sort(r["ip"]), int(r["port"]) if str(r["port"]).isdigit() else 0)):
            writer.writerow({
                "ip": row["ip"],
                "port": row["port"],
                "rdp": row["rdp"],
                "nla_only": row["nla_only"],
                "bluekeep": row["bluekeep"],
                "status": row["status"],
                "findings": "; ".join(row["findings"]),
                "detail": row["detail"],
            })


def write_lists(prefix, rows):
    affected = [r["ip"] for r in rows if is_vulnerable_row(r)]
    bluekeep = [r["ip"] for r in rows if r["bluekeep"] == "VULNERABLE"]
    Path(f"{prefix}_affected.txt").write_text("\n".join(sorted(set(affected), key=ip_sort)) + ("\n" if affected else ""), encoding="utf-8")
    Path(f"{prefix}_bluekeep.txt").write_text("\n".join(sorted(set(bluekeep), key=ip_sort)) + ("\n" if bluekeep else ""), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Check RDP vulnerabilities and BlueKeep status.")
    parser.add_argument("targets", nargs="*", help="Single IP, CIDR, or ip:port")
    parser.add_argument("-f", "--file", help="Input file containing IPs, CIDRs, or ip:port entries")
    parser.add_argument("-w", "--workers", type=int, default=16, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=45, help="nmap timeout per target in seconds")
    parser.add_argument("--bluekeep-timeout", type=int, default=25, help="BlueKeep check timeout per target")
    parser.add_argument("--csv", default="rdp_vuln_results.csv", help="CSV output path")
    parser.add_argument("--list-prefix", default="rdp", help="Prefix for affected/bluekeep/ok txt lists")
    parser.add_argument("--show-all", action="store_true", help="Print all rows, including OK and not-tested hosts")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if not shutil.which("nmap"):
        raise SystemExit("nmap was not found in PATH. Install nmap first.")

    target_map = load_targets(args)
    workers = min(max(1, args.workers), len(target_map))

    optional_scripts = ["rdp-enum-encryption", "rdp-ntlm-info"]
    if find_nse_script(["rdp-vuln-ms12-020.nse"]):
        optional_scripts.append("rdp-vuln-ms12-020")
    scripts = ",".join(optional_scripts)
    bluekeep_script = find_nse_script(["rdp-vuln-ms19-0708.nse", "rdp-vuln-cve2019-0708.nse", "rdp-vuln-bluekeep.nse"])

    colors = not args.no_color
    bluekeep_mode = "rdpscan" if shutil.which("rdpscan") else bluekeep_script or "not available"
    print(f"Loaded targets : {len(target_map)}")
    print(f"Workers        : {workers}")
    print(f"Nmap scripts   : {scripts}")
    print(f"BlueKeep check : {bluekeep_mode}")

    rows = asyncio.run(run_all(target_map, workers, args.timeout, scripts, bluekeep_script, args.bluekeep_timeout, colors=colors))
    print_table(rows, colors=colors, show_all=args.show_all)
    write_csv(args.csv, rows)
    write_lists(args.list_prefix, rows)

    critical = sum(1 for r in rows if r["status"] == "CRITICAL")
    affected = sum(1 for r in rows if r["status"] == "AFFECTED")
    ok = sum(1 for r in rows if r["status"] == "OK")
    other = len(rows) - critical - affected - ok
    print()
    print(paint(f"Critical / BlueKeep : {critical}", RED, colors))
    print(paint(f"Affected            : {affected}", YELLOW, colors))
    print(paint(f"OK                  : {ok}", GREEN, colors))
    print(paint(f"Other               : {other}", YELLOW, colors))
    print(f"CSV written         : {args.csv}")
    print(f"Affected list       : {args.list_prefix}_affected.txt")
    print(f"BlueKeep list       : {args.list_prefix}_bluekeep.txt")
    return 1 if (critical + affected) else 0


if __name__ == "__main__":
    raise SystemExit(main())

