#!/usr/bin/env python3
"""
Check for SSH Terrapin Prefix Truncation vulnerability (CVE-2023-48795).

The scanner checks for:
  - Vulnerable encryption algorithms (chacha20-poly1305)
  - Vulnerable MAC algorithms (Encrypt-then-MAC / -etm)
  - Absence of the 'strict key exchange' countermeasure

Requirements:
    sudo apt install nmap

Examples:
    python3 SSH_Terrapin_Scanner.py 192.0.2.22
    python3 SSH_Terrapin_Scanner.py -f ssh_targets.txt
"""

import argparse
import asyncio
import sys
import xml.etree.ElementTree as ET

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


async def run_nmap_ssh(ip):
    command = [
        "nmap", "-Pn", "-n", "-p22", "--script", "ssh2-enum-algos",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_algos(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    algos = {"kex": [], "enc": [], "mac": []}
    script = root.find(".//script[@id='ssh2-enum-algos']")
    if script is None:
        return None

    output = script.attrib.get("output", "")
    current_key = None
    for line in output.splitlines():
        line = line.strip()
        if "kex_algorithms" in line:
            current_key = "kex"
        elif "encryption_algorithms" in line:
            current_key = "enc"
        elif "mac_algorithms" in line:
            current_key = "mac"
        elif current_key and line and not line.endswith(":"):
            algos[current_key].append(line.split()[0])
    return algos


def check_terrapin(algos):
    if not algos:
        return False, "No SSH algorithms found"

    vulnerable_enc = any("chacha20-poly1305" in item for item in algos["enc"])
    vulnerable_mac = any("-etm" in item for item in algos["mac"])
    strict_kex = any(
        "kex-strict-c-v00@openssh.com" in item
        or "kex-strict-s-v00@openssh.com" in item
        for item in algos["kex"]
    )

    if (vulnerable_enc or vulnerable_mac) and not strict_kex:
        detail = []
        if vulnerable_enc:
            detail.append("ChaCha20-Poly1305 enabled")
        if vulnerable_mac:
            detail.append("Encrypt-then-MAC enabled")
        return True, (
            "Potentially Vulnerable: "
            + " and ".join(detail)
            + " without strict KEX"
        )

    return False, "Strict KEX enabled or no vulnerable algorithms found"


async def scan_one(ip):
    xml = await run_nmap_ssh(ip)
    algos = parse_algos(xml)
    return check_terrapin(algos)


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
                vuln, detail = await scan_one(ip)
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
    parser = argparse.ArgumentParser(description="SSH Terrapin Vulnerability Scanner")
    parser.add_argument("targets", nargs="*", help="Target IPs, hostnames, or CIDRs")
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
            print(f"{RED}[!] VULNERABLE: {ip} - SSH Terrapin ({detail}){RESET}")
        else:
            print(f"{GREEN}[-] {ip} - SSH Terrapin: {detail}{RESET}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
