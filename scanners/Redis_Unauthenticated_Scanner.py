#!/usr/bin/env python3
"""
Check for unauthenticated access to Redis servers.

This scanner attempts to connect to Redis on TCP/6379 and execute 
the 'INFO' command. If the server responds without requiring 
authentication, it is flagged as VULNERABLE.

Requirements:
    - Network access to TCP/6379

Examples:
    python3 Redis_Unauthenticated_Scanner.py 192.0.2.100
    python3 Redis_Unauthenticated_Scanner.py -f redis_targets.txt
"""

import argparse
import asyncio
import sys

from _common import load_targets


RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


async def check_redis(ip, port=6379, timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        if b"redis_version" in response:
            lines = response.decode(errors="ignore").splitlines()
            detail = lines[1] if len(lines) > 1 else "redis_version returned"
            return True, detail
        return False, "Authentication required or unexpected response"
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
                vuln, detail = await check_redis(ip)
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
    parser = argparse.ArgumentParser(description="Redis Unauthenticated Access Scanner")
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
                f"{RED}[!] VULNERABLE: {ip}:6379 - "
                f"Unauthenticated Access! ({detail}){RESET}"
            )
        else:
            print(f"{GREEN}[-] {ip}:6379 - Secure or unreachable ({detail}){RESET}")
    return 1 if vulnerable else 0


if __name__ == "__main__":
    raise SystemExit(main())
