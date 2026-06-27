#!/usr/bin/env python3
"""
Detect Web Application Firewalls (WAF) using nmap.

Detection sources:
  - nmap http-waf-detect script
  - nmap http-waf-fingerprint script

Requirements:
    sudo apt install nmap

Examples:
    python3 WafDetectorScanner.py 192.0.2.80
    python3 WafDetectorScanner.py -f targets.txt
"""

import argparse
import asyncio
import sys
import xml.etree.ElementTree as ET


CYAN = "\033[96m"
RESET = "\033[0m"

async def run_nmap_waf(ip):
    command = ["nmap", "-Pn", "-n", "-p80,443", "--script", "http-waf-detect,http-waf-fingerprint", "-oX", "-", ip]
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", errors="ignore")

def parse_waf(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    findings = []
    for script in root.findall(".//script"):
        if script.attrib.get("id") in ["http-waf-detect", "http-waf-fingerprint"]:
            output = script.attrib.get("output", "").strip()
            if output and "IDS/WAF NOT detected" not in output:
                findings.append(output)
    return findings

async def scan_one(ip):
    xml = await run_nmap_waf(ip)
    waf = parse_waf(xml)
    if waf:
        print(f"{CYAN}[+] DISCOVERY: {ip} - WAF Detected! ({', '.join(waf)}){RESET}")
    else:
        print(f"[-] {ip} - No WAF detected via standard nmap scripts.")
    return bool(waf)

def main():
    parser = argparse.ArgumentParser(description="WAF Detector Scanner")
    parser.add_argument("targets", nargs="*")
    parser.add_argument("-f", "--file")
    args = parser.parse_args()

    targets = []
    if args.file:
        with open(args.file, "r") as f: targets.extend([l.strip() for l in f if l.strip()])
    targets.extend(args.targets)

    targets = list(dict.fromkeys(targets))
    if not targets:
        print("No targets supplied.")
        return 2

    detected = 0
    for completed, target in enumerate(targets, 1):
        detected += int(asyncio.run(scan_one(target)))
        print(f"Progress: {completed}/{len(targets)} | WAF detections: {detected}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
