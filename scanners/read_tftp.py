#!/usr/bin/env python3
"""Download explicitly named files from an authorized TFTP server."""

import argparse
import re
import sys
from pathlib import Path


def safe_local_name(remote_path):
    name = remote_path.strip().replace("\\", "/").strip("/")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name or "downloaded_file"


def main():
    parser = argparse.ArgumentParser(
        description="Download explicit files from an authorized TFTP server."
    )
    parser.add_argument("host", help="TFTP server hostname or IP address")
    parser.add_argument("remote", nargs="+", help="Remote file path(s) to download")
    parser.add_argument("-p", "--port", type=int, default=69, help="TFTP port")
    parser.add_argument("-o", "--output-dir", default="tftp_downloads")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--block-size", type=int, default=512)
    args = parser.parse_args()

    try:
        import tftpy
    except ImportError:
        print("Missing dependency: install with 'python -m pip install tftpy'.", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    client = tftpy.TftpClient(
        args.host,
        args.port,
        options={"blksize": args.block_size},
    )

    failures = 0
    for remote in args.remote:
        local = output_dir / safe_local_name(remote)
        try:
            client.download(remote, str(local), timeout=args.timeout)
            print(f"OK: {remote} -> {local}")
        except Exception as exc:
            failures += 1
            print(f"FAIL: {remote} -> {exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
