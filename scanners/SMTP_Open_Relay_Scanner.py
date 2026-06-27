#!/usr/bin/env python3
"""
Check for SMTP Open Relay vulnerability.

This scanner:
  - Connects to SMTP on TCP/25
  - Attempts to relay a message
  - Reports if the server allows relaying

Requirements:
    sudo apt install nmap

Examples:
    python3 SMTP_Open_Relay_Scanner.py 192.0.2.80
    python3 SMTP_Open_Relay_Scanner.py -f targets.txt
"""

import argparse
import asyncio
import sys
import xml.etree.ElementTree as ET

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


async def check_smtp(ip):
    command = [
        "nmap", "-Pn", "-n", "-p25", "--script", "smtp-open-relay",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_smtp(xml_text):
    if not xml_text.strip():
        return False, "No response from nmap"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False, "Invalid XML from nmap"
    script = root.find(".//script[@id='smtp-open-relay']")
    if script is None:
        return False, "SMTP not open or probe unavailable"
    output = script.attrib.get("output", "")
    if "Server is an open relay" in output:
        return True, output.strip()[:240]
    return False, "Not an open relay"


async def scan_targets(targets, workers):
    queue = asyncio.Queue()
    results = []

    for target in targets:
        await queue.put(target)

    async def worker():
        while True:
            ip = await queue.get()
            if ip is None:
                queue.task_done()
                return
            try:
                xml = await check_smtp(ip)
                vuln, detail = parse_smtp(xml)
                results.append((ip, vuln, detail))
            finally:
                queue.task_done()

    worker_count = min(max(1, workers), len(targets))
    tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await queue.join()
    for _ in tasks:
        await queue.put(None)
    await asyncio.gather(*tasks)
    return results


def main():
    parser = argparse.ArgumentParser(description="Check for SMTP open relay.")
    parser.add_argument("targets", nargs="*", help="Target IP, hostname, or CIDR")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-w", "--workers", type=int, default=10)
    args = parser.parse_args()

    targets = load_targets(args.targets, args.file)
    if not targets:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f targets.txt")

    results = asyncio.run(scan_targets(targets, args.workers))
    vulnerable = 0
    for ip, vuln, detail in sorted(results):
        if vuln:
            vulnerable += 1
            print(f"{RED}[!] VULNERABLE: {ip} - SMTP Open Relay! ({detail}){RESET}")
        else:
            print(f"{GREEN}[-] {ip} - SMTP Secure ({detail}){RESET}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
