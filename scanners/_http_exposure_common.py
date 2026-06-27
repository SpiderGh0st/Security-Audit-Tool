"""Shared conservative HTTP exposure scanner used by service wrappers."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

from _common import GREEN, RED, RESET, YELLOW, load_targets


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    port: int
    path: str
    scheme: str = "http"
    json_keys: tuple[str, ...] = ()
    text_patterns: tuple[str, ...] = ()
    description: str = ""


def nested_key(data, dotted):
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return current is not None


def evidence_matches(spec, body):
    parsed = None
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        pass
    if spec.json_keys and isinstance(parsed, dict):
        if all(nested_key(parsed, key) for key in spec.json_keys):
            return True, "JSON keys: " + ", ".join(spec.json_keys)
    for pattern in spec.text_patterns:
        if re.search(pattern, body, re.I | re.S):
            return True, f"response matched {pattern}"
    return False, ""


def request_sync(ip, spec, timeout):
    url = f"{spec.scheme}://{ip}:{spec.port}{spec.path}"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SecurityAuditTool/2.0",
            "Accept": "application/json,text/plain,text/html;q=0.8,*/*;q=0.2",
        },
    )
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=context,
        ) as response:
            body = response.read(1024 * 1024).decode("utf-8", errors="replace")
            matched, evidence = evidence_matches(spec, body)
            if response.status == 200 and matched:
                return {
                    "status": "CONFIRMED EXPOSED",
                    "detail": f"Unauthenticated GET returned service-specific evidence ({evidence}).",
                    "url": url,
                }
            if response.status == 200:
                return {
                    "status": "REVIEW",
                    "detail": "HTTP 200 returned, but service-specific evidence was absent.",
                    "url": url,
                }
            return {
                "status": "NOT CONFIRMED",
                "detail": f"HTTP status {response.status}.",
                "url": url,
            }
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            return {
                "status": "AUTH REQUIRED",
                "detail": f"HTTP {error.code} rejected the unauthenticated request.",
                "url": url,
            }
        return {
            "status": "NOT CONFIRMED",
            "detail": f"HTTP status {error.code}.",
            "url": url,
        }
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as error:
        return {
            "status": "NO RESPONSE",
            "detail": re.sub(r"\s+", " ", str(error))[:300],
            "url": url,
        }


async def scan_one(ip, spec, timeout):
    row = await asyncio.to_thread(request_sync, ip, spec, timeout)
    row["ip"] = ip
    return row


async def run_all(targets, spec, workers, timeout):
    semaphore = asyncio.Semaphore(workers)

    async def bounded(ip):
        async with semaphore:
            return await scan_one(ip, spec, timeout)

    rows = []
    tasks = [asyncio.create_task(bounded(ip)) for ip in targets]
    for completed, task in enumerate(asyncio.as_completed(tasks), 1):
        row = await task
        rows.append(row)
        findings = sum(item["status"] == "CONFIRMED EXPOSED" for item in rows)
        percent = completed / len(tasks) * 100
        sys.stdout.write(
            f"\rScanning {spec.name}: {completed}/{len(tasks)} "
            f"({percent:5.1f}%) | Confirmed: {findings} | "
            f"Current: {row['ip']}".ljust(140)
        )
        sys.stdout.flush()
    sys.stdout.write("\n")
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "url", "status", "detail"],
        )
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: row["ip"]))


def run_service(spec):
    parser = argparse.ArgumentParser(
        description=spec.description or f"Check unauthenticated {spec.name} exposure."
    )
    parser.add_argument("targets", nargs="*", help="Target IPs, hostnames, or CIDRs")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("-w", "--workers", type=int, default=20)
    parser.add_argument("-t", "--timeout", type=float, default=8.0)
    parser.add_argument("--show-all", action="store_true")
    parser.add_argument("--csv", default=f"{spec.name.lower().replace(' ', '_')}_results.csv")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    targets = load_targets(args.targets, args.file)
    if not targets:
        raise SystemExit("No targets supplied. Use an IP/CIDR, domain, or -f targets.txt")
    workers = min(max(1, args.workers), len(targets))
    rows = asyncio.run(run_all(targets, spec, workers, max(0.5, args.timeout)))
    displayed = [
        row for row in rows
        if args.show_all or row["status"] == "CONFIRMED EXPOSED"
    ]
    print()
    if not displayed:
        print(f"No confirmed unauthenticated {spec.name} exposure was found.")
    for row in sorted(displayed, key=lambda item: item["ip"]):
        code = RED if row["status"] == "CONFIRMED EXPOSED" else (
            GREEN if row["status"] == "AUTH REQUIRED" else YELLOW
        )
        text = f"{row['ip']:<40} {row['status']:<20} {row['url']} - {row['detail']}"
        print(f"{code}{text}{RESET}" if not args.no_color else text)
    write_csv(args.csv, rows)
    confirmed = sum(row["status"] == "CONFIRMED EXPOSED" for row in rows)
    print()
    print(f"Targets tested       : {len(rows)}")
    print(f"Confirmed exposures  : {confirmed}")
    print(f"CSV written          : {args.csv}")
    return 1 if confirmed else 0
