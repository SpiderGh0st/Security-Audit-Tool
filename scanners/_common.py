"""Shared utilities for security scanners."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def color(text, code, enabled=True):
    return f"{code}{text}{RESET}" if enabled else text


def expand_target(value):
    """Expand IP, CIDR, or return domain name."""
    value = value.strip()
    if not value or value.startswith("#"):
        return []
    # Strip whitespace/comments from line
    value = value.split()[0]
    # Remove port if present (e.g. 1.2.3.4:80)
    if re.match(r"^[0-9.]+:\d+$", value):
        value = value.rsplit(":", 1)[0]
    
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Likely a domain name
        return [value]


def load_targets(args_targets=None, args_file=None):
    """Load and unique targets from list and/or file."""
    targets = []
    if args_file:
        try:
            with open(args_file, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    targets.extend(expand_target(line))
        except OSError as exc:
            print(f"Warning: Could not read target file {args_file}: {exc}", file=sys.stderr)
            
    for value in args_targets or []:
        targets.extend(expand_target(value))
        
    # Maintain order but unique
    seen = set()
    return [x for x in targets if not (x in seen or seen.add(x))]


async def run_nmap(
    target,
    ports,
    timeout="90s",
    min_rate=500,
    extra_args=None,
    all_ports=False,
):
    """Run Nmap and return XML output."""
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not found in PATH")
        
    command = [
        "nmap", "-Pn", "-n", "-sV", "--version-light", "--open",
        "--host-timeout", str(timeout),
    ]
    if all_ports:
        command.append("-p-")
    elif ports:
        command.extend(["-p", str(ports)])
    if min_rate:
        command.extend(["--min-rate", str(min_rate)])
    if extra_args:
        command.extend(extra_args)
        
    command.extend(["-oX", "-", target])
    
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if stderr:
        # Log nmap errors to stderr
        sys.stderr.write(stderr.decode("utf-8", errors="replace"))
        
    return stdout.decode("utf-8", errors="replace")


def url_text(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityAuditTool/2.0"},
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read().decode("utf-8", errors="replace")


def url_json(url, timeout, api_key=""):
    headers = {
        "User-Agent": "SecurityAuditTool/2.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def get_cvss_score(cve):
    """Extract highest available CVSS score from NVD CVE data."""
    metrics = cve.get("metrics", {})
    # Preference order for CVSS versions
    candidates = (
        ("cvssMetricV40", "cvssData"),
        ("cvssMetricV31", "cvssData"),
        ("cvssMetricV30", "cvssData"),
        ("cvssMetricV2", "cvssData"),
    )
    for group, field in candidates:
        entries = metrics.get(group, [])
        if entries:
            # Sort by score descending within version if multiple entries
            data_list = [e.get(field, {}) for e in entries]
            scores = [float(d.get("baseScore", 0.0)) for d in data_list]
            if scores:
                max_idx = scores.index(max(scores))
                data = data_list[max_idx]
                severity = data.get("baseSeverity") or entries[max_idx].get("baseSeverity", "")
                return scores[max_idx], str(severity)
    return 0.0, ""


def query_nvd_sync(cpe_name, api_key="", timeout=30):
    """Synchronous NVD API query using a full CPE name."""
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": "2000",
        "isVulnerable": "",
        "noRejected": "",
    }
    
    encoded = urllib.parse.urlencode({k: v for k, v in params.items() if v != ""})
    url = f"{NVD_API}?{encoded}"
    
    headers = {
        "User-Agent": "SecurityAuditTool/2.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
        
    request = urllib.request.Request(url, headers=headers)
    context = ssl.create_default_context()
    
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return [], str(exc)

    results = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve.get("vulnStatus", "").lower() == "rejected":
            continue
            
        score, severity = get_cvss_score(cve)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
                
        results.append({
            "id": cve_id,
            "score": score,
            "severity": severity,
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    
    results.sort(key=lambda x: (-x["score"], x["id"]))
    return results, ""


class NVDCache:
    def __init__(self, cache_file):
        self.path = Path(cache_file)
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass
