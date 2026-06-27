#!/usr/bin/env python3
"""
Check for VNC services without authentication.

Examples:
    python3 VNC_Unauth_Scanner.py 192.0.2.80
    python3 VNC_Unauth_Scanner.py -f targets.txt
"""

import argparse
import asyncio
import ipaddress
import re
import sys
import xml.etree.ElementTree as ET
import shutil

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def expand_target(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [value]

def load_targets(args):
    targets = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                targets.extend(expand_target(line))
    for item in args.targets:
        targets.extend(expand_target(item))
    unique = list(dict.fromkeys(targets))
    if not unique:
        raise SystemExit("No targets supplied.")
    return unique

async def check_vnc(ip, timeout=10):
    if not shutil.which("nmap"):
        return "ERROR", "nmap not found"
    
    command = ["nmap", "-Pn", "-n", "-p5900", "--script", "vnc-info,vnc-brute", "-oX", "-", ip]
    try:
        process = await asyncio.create_subprocess_exec(
            *command, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout+30) # Nmap needs more time
        xml_text = stdout.decode("utf-8", errors="ignore")
        
        return parse_vnc_xml(xml_text)
    except Exception as e:
        return "ERROR", str(e)


def parse_vnc_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "ERROR", "Invalid XML from nmap"
    port = root.find(".//port[@protocol='tcp'][@portid='5900']")
    state = port.find("state") if port is not None else None
    if state is None or state.attrib.get("state") != "open":
        return "NOT TESTED", "TCP/5900 was not confirmed open"
    script = port.find("script[@id='vnc-info']")
    if script is None:
        return "INCONCLUSIVE", "VNC is open, but vnc-info returned no result"
    output = script.attrib.get("output", "")
    if re.search(
        r"\bNo authentication\b|security types?\s*:\s*[^\r\n]*\bNone\b",
        output,
        re.I,
    ):
        return "VULNERABLE", "The server explicitly offered no-authentication access"
    if re.search(r"VNC Authentication|security types?.*(?:2|VNC)", output, re.I | re.S):
        return "AUTH REQUIRED", "The server advertised an authentication security type"
    return "INCONCLUSIVE", "VNC responded, but authentication requirements were unclear"

async def run_all(targets, workers, timeout):
    queue = asyncio.Queue()
    results = []
    completed = 0
    for t in targets:
        await queue.put(t)

    async def worker():
        nonlocal completed
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                status, detail = await check_vnc(ip, timeout=timeout)
                results.append((ip, status, detail))
            except Exception as error:
                results.append((ip, "ERROR", str(error)))
            completed += 1
            sys.stdout.write(
                f"\rScanning: {completed}/{len(targets)} | Current: {ip}".ljust(100)
            )
            sys.stdout.flush()
            queue.task_done()

    tasks = [asyncio.create_task(worker()) for _ in range(workers)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    sys.stdout.write("\n")
    return results

def main():
    parser = argparse.ArgumentParser(description="Check for VNC services without authentication.")
    parser.add_argument("targets", nargs="*", help="Target IPs/CIDRs")
    parser.add_argument("-f", "--file", help="File with targets")
    parser.add_argument("-w", "--workers", type=int, default=10) # nmap is heavy, lower default workers
    parser.add_argument("-t", "--timeout", type=int, default=10)
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    args = parser.parse_args()

    global RED, YELLOW, GREEN, RESET
    if args.no_color:
        RED = YELLOW = GREEN = RESET = ""

    targets = load_targets(args)
    print(f"Loaded {len(targets)} targets.")
    
    workers = min(max(1, args.workers), len(targets))
    results = asyncio.run(run_all(targets, workers, max(1, args.timeout)))
    
    for ip, status, detail in sorted(results):
        if status == "VULNERABLE":
            print(f"{RED}[!] {status}: {ip} - VNC Unauth! ({detail}){RESET}")
        elif status in {"INCONCLUSIVE", "NOT TESTED"}:
            print(f"{YELLOW}[*] {status}: {ip} - VNC Unauth ({detail}){RESET}")
        elif status == "ERROR":
            print(f"{YELLOW}[*] {status}: {ip} - {detail}{RESET}")
        else:
            print(f"{GREEN}[-] {status}: {ip} - {detail}{RESET}")

    return 1 if any(status == "VULNERABLE" for _ip, status, _detail in results) else 0

if __name__ == "__main__":
    raise SystemExit(main())
