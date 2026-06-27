#!/usr/bin/env python3
"""
Check for DNS zone transfer (AXFR) vulnerability.

The scanner:
  - Identifies open DNS services (TCP/53)
  - Attempts AXFR for a user-supplied domain
  - Uses the nmap dns-zone-transfer script

Requirements:
    sudo apt install nmap

Examples:
    python3 DNS_Zone_Transfer_Scanner.py 192.0.2.53 --domain example.com
    python3 DNS_Zone_Transfer_Scanner.py -f dns_servers.txt --domain example.com
"""

import argparse
import asyncio
import re
import sys
import xml.etree.ElementTree as ET

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


async def run_nmap_axfr(ip, domain):
    command = [
        "nmap", "-Pn", "-n", "-p53",
        "--script", "dns-zone-transfer",
        "--script-args", f"dns-zone-transfer.domain={domain}",
        "-oX", "-", ip,
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")


def parse_axfr_result(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "INCONCLUSIVE", "Nmap returned invalid or incomplete XML."

    port = root.find(".//port[@protocol='tcp'][@portid='53']")
    state = port.find("state") if port is not None else None
    if state is None or state.attrib.get("state") != "open":
        return "NOT TESTED", "TCP/53 was not confirmed open."
    for script in root.findall(".//script[@id='dns-zone-transfer']"):
        output = script.attrib.get("output", "")
        if (
            "Zone transfer successful" in output
            or re.search(r"\b[1-9]\d*\s+records?\s+found\b", output, re.I)
        ):
            return "VULNERABLE", output
        if output:
            return "NOT CONFIRMED", output
    return "INCONCLUSIVE", "The dns-zone-transfer script returned no result."


def normalize_domain(value):
    domain = (value or "").strip().rstrip(".")
    if not domain:
        raise SystemExit(
            "Supply a DNS zone name with --domain example.com "
            "(a bare '.' is not a useful AXFR target)."
        )
    return domain


async def scan_one(ip, domain):
    print(f"[*] Testing AXFR on {ip} for domain {domain}...")
    xml_output = await run_nmap_axfr(ip, domain)
    return parse_axfr_result(xml_output)


def main():
    parser = argparse.ArgumentParser(description="Check for DNS zone transfer vulnerability.")
    parser.add_argument("targets", nargs="*", help="DNS server IPs")
    parser.add_argument("-f", "--file", help="File containing DNS server IPs")
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="DNS zone/domain name to request via AXFR",
    )
    args = parser.parse_args()

    targets = load_targets(args.targets, args.file)
    if not targets:
        raise SystemExit("No targets supplied. Use an IP/CIDR or -f targets.txt")

    domain = normalize_domain(args.domain)
    vulnerable = False
    for target in targets:
        status, detail = asyncio.run(scan_one(target, domain))
        if status == "VULNERABLE":
            vulnerable = True
            print(
                f"{RED}[!] VULNERABLE: Zone transfer successful on "
                f"{target} for {domain}{RESET}"
            )
            print(detail)
        else:
            color = GREEN if status == "NOT CONFIRMED" else CYAN
            print(f"{color}[-] {status}: {target} - {detail}{RESET}")

    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
