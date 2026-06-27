#!/usr/bin/env python3
"""
Check for unauthenticated access to Rsync.

This scanner:
  - Connects to Rsync on TCP/873
  - Attempts to list modules
  - Reports only when unauthenticated module listing is confirmed

Requirements:
    sudo apt install nmap

Examples:
    python3 Rsync_Unauth_Scanner.py 192.0.2.80
    python3 Rsync_Unauth_Scanner.py -f targets.txt
"""

import argparse
import asyncio
import re
import sys
import xml.etree.ElementTree as ET

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

DENY_MARKERS = (
    "authentication required",
    "access denied",
    "not authorized",
    "permission denied",
    "refused",
    "failed to",
    "couldn't",
    "error",
)


async def check_rsync(ip):
    command = [
        "nmap", "-Pn", "-n", "-p873", "--script", "rsync-list-modules",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_rsync(xml_text):
    if not xml_text.strip():
        return False, "No response from nmap"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False, "Invalid XML from nmap"
    script = root.find(".//script[@id='rsync-list-modules']")
    if script is None:
        return False, "Rsync not open or probe unavailable"
    output = script.attrib.get("output", "").strip()
    if not output:
        return False, "Rsync probe returned no output"
    lower = output.lower()
    if any(marker in lower for marker in DENY_MARKERS):
        return False, output[:240]
    if re.search(r"@rsyncd", output, re.I):
        return True, output[:240]
    if re.search(r"^\s*\S+\s+\S", output, re.M):
        return True, output[:240]
    return False, "Rsync responded but unauthenticated module listing was not confirmed"


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
                xml = await check_rsync(ip)
                vuln, detail = parse_rsync(xml)
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
    parser = argparse.ArgumentParser(
        description="Check for unauthenticated Rsync module listing."
    )
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
            print(f"{RED}[!] VULNERABLE: {ip} - Rsync Unauth! ({detail}){RESET}")
        else:
            print(f"{GREEN}[-] {ip} - Rsync Secure ({detail}){RESET}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
