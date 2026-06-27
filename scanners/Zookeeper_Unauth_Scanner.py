#!/usr/bin/env python3
"""
Check for unauthenticated access to Zookeeper.

Examples:
    python3 Zookeeper_Unauth_Scanner.py 192.0.2.80
    python3 Zookeeper_Unauth_Scanner.py -f targets.txt
"""

import argparse
import asyncio
import ipaddress
import sys

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

async def check_zookeeper(ip, port=2181, timeout=10):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.write(b"envi\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
            
        if b"zookeeper.version" in response:
            return "VULNERABLE", "Zookeeper accessible and version info retrieved"
        return "INCONCLUSIVE", "Service responded, but no ZooKeeper version evidence was returned"
    except Exception as e:
        return "NO RESPONSE", str(e)

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
                status, detail = await check_zookeeper(ip, timeout=timeout)
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
    parser = argparse.ArgumentParser(description="Check for unauthenticated access to Zookeeper.")
    parser.add_argument("targets", nargs="*", help="Target IPs/CIDRs")
    parser.add_argument("-f", "--file", help="File with targets")
    parser.add_argument("-w", "--workers", type=int, default=20)
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
            print(f"{RED}[!] {status}: {ip} - Zookeeper Unauth! ({detail}){RESET}")
        elif status in {"INCONCLUSIVE", "NOT TESTED"}:
            print(f"{YELLOW}[*] {status}: {ip} - Zookeeper Unauth ({detail}){RESET}")
        elif status in {"ERROR", "NO RESPONSE"}:
            print(f"{YELLOW}[*] {status}: {ip} - {detail}{RESET}")
        else:
            print(f"{GREEN}[-] {status}: {ip} - {detail}{RESET}")

    return 1 if any(status == "VULNERABLE" for _ip, status, _detail in results) else 0

if __name__ == "__main__":
    raise SystemExit(main())
