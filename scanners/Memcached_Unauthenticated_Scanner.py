#!/usr/bin/env python3
"""
Check for unauthenticated access to Memcached servers.

This scanner attempts to connect to Memcached on TCP/11211 and 
execute the 'stats' command. If the server responds with 
statistical information without requiring authentication, 
it is flagged as VULNERABLE.

Requirements:
    - Network access to TCP/11211

Examples:
    python3 Memcached_Unauthenticated_Scanner.py 192.0.2.100
    python3 Memcached_Unauthenticated_Scanner.py -f memcached_targets.txt
"""

import argparse
import asyncio
import sys

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


async def check_memcached(ip, port=11211, timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"stats\r\n")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        if b"STAT pid" in response or b"STAT version" in response:
            version = "unknown"
            for line in response.decode(errors="ignore").splitlines():
                if "STAT version" in line:
                    version = line.split()[-1]
            return True, f"Version: {version}"
        return False, "Unexpected response"
    except Exception as error:
        return False, str(error)


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
                vuln, detail = await check_memcached(ip)
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
    parser = argparse.ArgumentParser(description="Memcached Unauthenticated Access Scanner")
    parser.add_argument("targets", nargs="*", help="Target IPs")
    parser.add_argument("-f", "--file", help="File with target IPs")
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
            print(
                f"{RED}[!] VULNERABLE: {ip}:11211 - "
                f"Unauthenticated Access! ({detail}){RESET}"
            )
        else:
            print(f"{GREEN}[-] {ip}:11211 - Secure or unreachable ({detail}){RESET}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
