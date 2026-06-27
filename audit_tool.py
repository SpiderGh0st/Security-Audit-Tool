#!/usr/bin/env python3
"""Unified launcher, catalog, validator, and environment checker."""

from __future__ import annotations

import argparse
import ast
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCANNERS = ROOT / "scanners"
REPORTS = ROOT / "reports"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CUSTOMER_PATTERNS = (
    re.compile(r"\bcustomer[ _-]name\b", re.I),
    re.compile(r"\bclient[ _-]name\b", re.I),
    re.compile(r"\binternal network\b", re.I),
)
TOOLS = (
    ("nmap", "most scanners"),
    ("openssl", "deprecated TLS scanner"),
    ("java", "unauthenticated JMX scanner"),
    ("javac", "unauthenticated JMX scanner"),
    ("kerbrute", "Active Directory username enumeration scanner"),
    ("smbmap", "anonymous SMB share scanner"),
    ("rdpscan", "dedicated BlueKeep scanner"),
    ("snmpget", "SNMP and printer firmware scanners"),
    ("iscsiadm", "unauthenticated iSCSI scanner"),
)
HELP_FLAGS = {"-h", "--help"}
FILE_FLAGS = {"-f", "--file"}

DIRECT_VERIFICATION = {
    "activedirectoryuserenumerationscanner",
    "anonsmbsharechecker",
    "bluekeepstatusscanner",
    "cookie_security_scanner",
    "couchdb_unauth_scanner",
    "deprecated_tls_scan",
    "dns_zone_transfer_scanner",
    "docker_api_scanner",
    "elasticsearch_unauth_scanner",
    "ftp_scanner",
    "git_exposure_scanner",
    "hadoop_unauth_scanner",
    "ipmi_cipher_zero_scanner",
    "java_jmx_no_authentication_scanner",
    "jenkins_unauth_scanner",
    "kibana_unauth_scanner",
    "kubernetes_api_scanner",
    "memcached_unauthenticated_scanner",
    "ms17_010scanner",
    "nfs_scanner",
    "openssl_ccs_mitm_scanner",
    "pjl_scanner",
    "printerunauthenticatedrshscanner",
    "rabbitmq_unauth_scanner",
    "rc4_nmap_scanner",
    "rdp_weak_encryption_scanner",
    "rdpmitmscanner",
    "rdpvulnchecker",
    "redis_unauthenticated_scanner",
    "rsync_unauth_scanner",
    "smtp_open_relay_scanner",
    "solr_unauth_scanner",
    "ssh_terrapin_scanner",
    "vnc_unauth_scanner",
    "smbpasswordencryptionscanner",
    "smbsigningchecker",
    "smbv1checker",
    "snmp_default_community_scanner",
    "ssh_weak_algo_scanner",
    "sweet32nmapscanner",
    "tlsdetector",
    "unauthenticated_telnet_scanner",
    "unauthenticatediscsiloginscanner",
    "unauthenticatedprinterwebinterfacescanner",
    "unencrypted_telnet_scanner",
    "zookeeper_unauth_scanner",
}

VERSION_ASSESSMENT = {
    "acme_thttpd_scanner",
    "esxivulnscanner",
    "gsoapversionchecker",
    "mongobleedscanner",
    "msmqrcecve202321554scanner",
    "oracle_weblogic_unsupported_version_scanner",
    "outdated_hp_laser_jet_scanner",
    "outdated_iis_scanner",
    "outdated_nginx_scanner",
    "outdateddebianscanner",
    "outdatedvulnerablesshscanner",
    "sqlversionvulnchecker",
    "security_headers_scanner",
    "tomcatvulnchecker",
    "unsupportedwindowsscanner",
}

NO_CONFIRMED_FROM_VERSION = {
    "Acme_Thttpd_Scanner.py",
    "GsoapVersionChecker.py",
    "MongoBleedScanner.py",
    "MsmqRceCve202321554Scanner.py",
    "Oracle_WebLogic_Unsupported_Version_Scanner.py",
    "Outdated_IIS_Scanner.py",
    "Outdated_Nginx_Scanner.py",
    "SqlVersionVulnChecker.py",
    "UnsupportedWindowsScanner.py",
}

STANDALONE_UTILITIES = {
    "read_tftp.py",  # Requires one or more explicit remote file paths.
}

BATCH_EXCLUDED = {
    "DNS_Zone_Transfer_Scanner.py",  # Requires --domain; not compatible with shared batch args.
}

ALL_PORTS_SCANNERS = {
    "acme_thttpd_scanner",
    "ftp_scanner",
    "http_server_scanner",
    "java_rmijmx_exposure_scanner",
    "mongobleedscanner",
    "openssl_ccs_mitm_scanner",
    "outdated_iis_scanner",
    "outdated_nginx_scanner",
    "outdateddebianscanner",
    "outdatedvulnerablesshscanner",
    "printerwebinterfacescanner",
    "ssh_weak_algo_scanner",
    "unauthenticatedprinterwebinterfacescanner",
}

DOMAIN_OPTION_SCANNERS = {
    "dns_zone_transfer_scanner",
}


def scanner_files():
    return sorted(
        (
            path
            for path in SCANNERS.iterdir()
            if (
                path.suffix.lower() == ".py"
                and not path.name.startswith("_")
                and path.name not in STANDALONE_UTILITIES
            )
        ),
        key=lambda path: path.name.lower(),
    )


def menu_scanners():
    order = {
        "windows": 0,
        "tls": 1,
        "web": 2,
        "remote-access": 3,
        "infrastructure": 4,
        "printer": 5,
        "other": 6,
    }
    return sorted(
        scanner_files(),
        key=lambda path: (order.get(category(path), 99), path.name.lower()),
    )


def batch_scanners():
    """Scanners safe to run with one shared target argument list."""
    excluded = BATCH_EXCLUDED
    return [path for path in menu_scanners() if path.name not in excluded]


def strip_option_with_value(arguments, option_names):
    names = set(option_names)
    filtered = []
    skip_next = False
    for token in arguments:
        if skip_next:
            skip_next = False
            continue
        if token in names:
            skip_next = True
            continue
        filtered.append(token)
    return filtered


def filter_scanner_args(path, arguments):
    """Drop scanner-specific flags that would break argparse in batch runs."""
    args = list(arguments)
    identity = scanner_id(path)
    if identity not in ALL_PORTS_SCANNERS:
        args = [token for token in args if token != "--all-ports"]
    if identity not in DOMAIN_OPTION_SCANNERS:
        args = strip_option_with_value(args, {"--domain", "-d"})
    return args


def scanner_id(path):
    return path.stem.lower().replace("-", "_")


def colors_enabled():
    return sys.stdout.isatty() and not bool(__import__("os").environ.get("NO_COLOR"))


def paint(text, code):
    return f"{code}{text}{RESET}" if colors_enabled() else text


def verification_profile(path):
    identity = scanner_id(path)
    if identity in DIRECT_VERIFICATION:
        return {
            "level": "VERIFY",
            "color": GREEN,
            "summary": "Active protocol/configuration verification",
            "guidance": "A positive result requires direct remote evidence.",
        }
    if identity in VERSION_ASSESSMENT:
        return {
            "level": "ASSESS",
            "color": YELLOW,
            "summary": "Version, banner, build, or lifecycle assessment",
            "guidance": (
                "Treat matches as review candidates; confirm vendor advisory, "
                "package backports, patch level, and configuration."
            ),
        }
    return {
        "level": "DISCOVER",
        "color": CYAN,
        "summary": "Service discovery or inventory",
        "guidance": "An open service is not itself a vulnerability.",
    }


def category(path):
    name = path.stem.lower()
    groups = (
        ("windows", ("rdp", "smb", "ms17", "bluekeep", "windows", "msmq", "kerberos", "active")),
        ("web", ("http", "iis", "nginx", "tomcat", "weblogic", "thttpd", "gsoap", "jenkins", "solr", "elastic", "kibana", "git", "waf")),
        ("tls", ("tls", "ssl", "rc4", "sweet32", "openssl")),
        ("printer", ("printer", "pjl", "laser")),
        ("remote-access", ("ssh", "telnet", "ftp", "rsh", "rsync", "vnc", "smtp")),
        ("infrastructure", ("esxi", "ipmi", "iscsi", "nfs", "snmp", "mongo", "sql", "jmx", "rmi", "dns", "redis", "memcached", "docker", "kubernetes", "couchdb", "hadoop", "zookeeper", "rabbitmq")),
    )
    for label, tokens in groups:
        if any(token in name for token in tokens):
            return label
    return "other"


def description(path):
    try:
        module = ast.parse(path.read_text(encoding="utf-8-sig"))
        doc = ast.get_docstring(module) or ""
        return next((line.strip() for line in doc.splitlines() if line.strip()), "")
    except (OSError, SyntaxError, UnicodeError):
        return ""


def catalog():
    return [
        {
            "id": scanner_id(path),
            "file": path.name,
            "category": category(path),
            "verification": verification_profile(path)["level"],
            "description": description(path),
            "batch_compatible": path.name not in BATCH_EXCLUDED,
        }
        for path in scanner_files()
    ]


def resolve_scanner(value):
    normalized = value.lower().replace("-", "_")
    matches = [
        path
        for path in scanner_files()
        if normalized in {scanner_id(path), path.name.lower(), path.stem.lower()}
    ]
    if not matches:
        raise ValueError(f"Unknown scanner: {value}. Use 'list' to see available IDs.")
    return matches[0]


def cmd_list(args):
    rows = catalog()
    if args.category:
        rows = [row for row in rows if row["category"] == args.category]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'ID':<46} {'CATEGORY':<16} {'MODE':<9} DESCRIPTION")
    print("-" * 118)
    for row in rows:
        print(
            f"{row['id']:<46} {row['category']:<16} "
            f"{row['verification']:<9} {row['description'][:42]}"
        )
    print(f"\n{len(rows)} scanner commands available.")
    return 0


def cmd_info(args):
    path = resolve_scanner(args.scanner)
    profile = verification_profile(path)
    print(f"Scanner     : {scanner_id(path)}")
    print(f"File        : {path.name}")
    print(f"Category    : {category(path)}")
    print(f"Mode        : {profile['level']} - {profile['summary']}")
    print(f"Accuracy    : {profile['guidance']}")
    print(f"Description : {description(path) or '-'}")
    print("\nOriginal scanner help:\n")
    return subprocess.run([sys.executable, str(path), "--help"], check=False).returncode


def cmd_run(args):
    path = resolve_scanner(args.scanner)
    scanner_args = list(args.scanner_args)
    if scanner_args and scanner_args[0] == "--":
        scanner_args.pop(0)
    return run_scanner(path, scanner_args, args.output_dir)


def cmd_run_all(args):
    scanner_args = list(args.scanner_args)
    if scanner_args and scanner_args[0] == "--":
        scanner_args.pop(0)
    scanner_args = validate_target_arguments(scanner_args)
    paths = batch_scanners()
    if BATCH_EXCLUDED:
        skipped = [name for name in BATCH_EXCLUDED if (SCANNERS / name).is_file()]
        if skipped:
            print(
                "Skipping batch-incompatible scanners "
                f"({', '.join(Path(name).stem for name in sorted(skipped))})."
            )
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    batch_root = (
        Path(args.output_dir)
        if args.output_dir
        else REPORTS / f"all-scanners-{stamp}"
    )
    
    num_workers = getattr(args, "workers", 4)
    print(f"Running all {len(paths)} scanners with up to {num_workers} parallel workers.")
    print(f"Batch reports: {batch_root.resolve()}")

    results = []
    import concurrent.futures

    def run_one(path_obj):
        output_dir = batch_root / scanner_id(path_obj)
        filtered_args = filter_scanner_args(path_obj, scanner_args)
        code = run_scanner_silent(path_obj, filtered_args, output_dir)
        return path_obj.stem, code

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_path = {executor.submit(run_one, p): p for p in paths}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_path):
            name, code = future.result()
            results.append((name, code))
            completed += 1
            print(f"[{completed}/{len(paths)}] {name}: {outcome_label(code)}")

    print("\nAll-scanner batch summary:")
    for name, code in sorted(results):
        print(f"  {name:<48} {outcome_label(code)}")
    return max((code for _name, code in results), default=0)


def run_scanner_silent(path, scanner_args, output_dir):
    """Run a scanner with minimal output for parallel execution."""
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(path), *scanner_args]
    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    try:
        process = subprocess.Popen(
            command,
            cwd=output_dir,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process.wait()
        return process.returncode
    except Exception:
        return 2


def run_scanner(path, scanner_args, output_dir=None):
    scanner_args = validate_target_arguments(scanner_args)
    scanner_args = filter_scanner_args(path, scanner_args)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(output_dir) if output_dir else REPORTS / f"{scanner_id(path)}-{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(path), *scanner_args]
    profile = verification_profile(path)
    print(paint("=" * 92, BLUE))
    print(paint(f" {path.stem}", BOLD + CYAN))
    print(paint("=" * 92, BLUE))
    print(f"Mode    : {paint(profile['level'], profile['color'])} - {profile['summary']}")
    print(f"Accuracy: {profile['guidance']}")
    print(f"Reports : {output_dir.resolve()}")
    print(f"Command : {subprocess.list2cmdline(command)}")
    print(paint("-" * 92, BLUE) + "\n")
    sys.stdout.flush()
    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=output_dir, env=environment)
    next_update = started + 2.0
    while process.poll() is None:
        now = time.monotonic()
        if now >= next_update:
            print(
                paint(
                    f"[progress] {path.stem} is running | "
                    f"elapsed {format_elapsed(now - started)}",
                    CYAN,
                ),
                flush=True,
            )
            next_update = now + 5.0
        time.sleep(0.1)
    print(
        paint(
            f"[complete] {path.stem} | {outcome_label(process.returncode)} | "
            f"elapsed {format_elapsed(time.monotonic() - started)}",
            GREEN if process.returncode == 0 else YELLOW,
        )
    )
    return process.returncode


def format_elapsed(seconds):
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def outcome_label(returncode):
    if returncode == 0:
        return "COMPLETED"
    if returncode == 1:
        return "ATTENTION (finding, notice, or scanner-specific condition)"
    if returncode in {130, -2}:
        return "CANCELLED"
    return f"ERROR (exit code {returncode})"


def read_input(prompt):
    try:
        return input(prompt)
    except EOFError:
        return "0"


def parse_scanner_args(value):
    tokens = shlex.split(value, posix=sys.platform != "win32")
    if sys.platform == "win32":
        tokens = [
            token[1:-1]
            if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}
            else token
            for token in tokens
        ]
    return tokens


def validate_direct_target(value):
    """Validate one literal IP address, CIDR subnet, or domain name."""
    target = value.strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    if any(character.isspace() for character in target):
        raise ValueError(f"Invalid target {value!r}: whitespace is not allowed.")
    
    # Try IP/CIDR first
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
        
    # Try domain name validation (simple check)
    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$", target):
        return target
        
    raise ValueError(
        f"Invalid target {value!r}. Enter an IPv4/IPv6 address, "
        "CIDR subnet, or domain name; URLs and host:port values are not allowed."
    )


def validate_ip_list_file(value):
    """Validate a readable text file containing only IP addresses."""
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValueError(f"IP list file not found: {value}")
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Could not read IP list file {value!r}: {exc}") from exc

    count = 0
    for line_number, line in enumerate(lines, 1):
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        try:
            ipaddress.ip_address(item)
        except ValueError:
            raise ValueError(
                f"Invalid IP in {value!r} at line {line_number}: {item!r}. "
                "IP list files may contain only IPv4 or IPv6 addresses."
            ) from None
        count += 1
    if not count:
        raise ValueError(f"IP list file contains no IP addresses: {value}")
    return path


def validate_target_arguments(arguments):
    """Validate target-first scanner arguments at the launcher boundary."""
    tokens = list(arguments)
    if not tokens:
        raise ValueError("Enter an IP, CIDR subnet, or -f/--file IP list.")
    if any(token in HELP_FLAGS for token in tokens):
        return tokens

    if tokens[0] in FILE_FLAGS:
        if len(tokens) < 2 or tokens[1].startswith("-"):
            raise ValueError("-f/--file requires an IP list file path.")
        path = validate_ip_list_file(tokens[1])
        tokens[1] = str(path.resolve())
        target_end = 2
    elif tokens[0].startswith("-"):
        raise ValueError(
            "Put the target first: IP, CIDR subnet, or -f/--file IP list."
        )
    else:
        target_end = next(
            (index for index, token in enumerate(tokens) if token.startswith("-")),
            len(tokens),
        )
        if target_end != 1:
            raise ValueError(
                "Enter one direct target. Use -f/--file for an IP list."
            )
        for target in tokens[:target_end]:
            validate_direct_target(target)

    trailing = tokens[target_end:]
    if any(token in FILE_FLAGS for token in trailing):
        raise ValueError(
            "Use either direct targets or one -f/--file IP list, not both."
        )
    return tokens


def print_menu(paths):
    term_width = 92
    print("\n" + paint("╔" + "═" * (term_width - 2) + "╗", BLUE))
    print(paint("║", BLUE) + paint("  SECURITY AUDIT CONSOLE".ljust(term_width - 2), BOLD + CYAN) + paint("║", BLUE))
    print(paint("║", BLUE) + f"  {len(paths)} scanners available | Standardized & Validated".ljust(term_width - 2) + paint("║", BLUE))
    print(paint("╚" + "═" * (term_width - 2) + "╝", BLUE))
    previous = None
    for number, path in enumerate(paths, start=1):
        group = category(path)
        if group != previous:
            print("\n" + paint(f"  ● {group.upper()}", BOLD + BLUE))
            previous = group
        label = path.stem.replace("_", " ")
        profile = verification_profile(path)
        mode = paint(f"[{profile['level']}]", profile["color"])
        print(f"  {number:>2}. {label:<47} {mode}")
    print("\n" + paint("─" * term_width, BLUE))


def interactive_menu():
    paths = menu_scanners()
    global_targets = ""
    results_summary = []
    while True:
        print_menu(paths)
        if global_targets:
            print(f"  {paint('Target Selection:', BOLD + YELLOW)} {global_targets}")
        
        if results_summary:
            print(f"\n  {paint('Last Session Summary:', BOLD + GREEN)}")
            for name, code in results_summary[-5:]:
                status = paint(
                    outcome_label(code),
                    GREEN if code == 0 else YELLOW if code == 1 else RED,
                )
                print(f"    - {name:<30} {status}")

        print("\n" + paint("─" * 92, BLUE))
        print("  " + paint("A", CYAN) + " Run All Scanners   " + paint("G", CYAN) + " Set Global Targets   " + paint("D", CYAN) + " Doctor   " + paint("V", CYAN) + " Validate   " + paint("0", CYAN) + " Exit")
        print("  " + paint("VERIFY", GREEN) + " = direct evidence   " + paint("ASSESS", YELLOW) + " = confirm manually   " + paint("DISCOVER", CYAN) + " = inventory")
        print(paint("─" * 92, BLUE))

        choice = read_input("Select #, category, or command: ").strip()
        if choice.lower() in {"0", "q", "quit", "exit"}:
            print("Goodbye.")
            return 0
        if choice.lower() == "d":
            cmd_doctor(None)
            read_input("\nPress Enter to return to the menu...")
            continue
        if choice.lower() == "v":
            cmd_validate(None)
            read_input("\nPress Enter to return to the menu...")
            continue
        if choice.lower() == "g":
            global_targets = read_input(
                "Enter one IP/CIDR subnet or -f IP-list file: "
            ).strip()
            if global_targets:
                try:
                    validate_target_arguments(parse_scanner_args(global_targets))
                except ValueError as exc:
                    print(f"Invalid target input: {exc}")
                    global_targets = ""
            continue

        selected_paths = []
        if choice.lower() in {"a", "all"}:
            selected_paths = batch_scanners()
            if BATCH_EXCLUDED:
                skipped = sorted(Path(name).stem for name in BATCH_EXCLUDED)
                print(
                    "Note: batch-incompatible scanners are skipped in Run All: "
                    + ", ".join(skipped)
                )
        elif "," in choice:
            for part in choice.split(","):
                part = part.strip()
                if part.isdigit() and 1 <= int(part) <= len(paths):
                    selected_paths.append(paths[int(part) - 1])
        elif choice.isdigit() and 1 <= int(choice) <= len(paths):
            selected_paths.append(paths[int(choice) - 1])
        else:
            # Check for category selection
            cat_matches = [p for p in paths if category(p) == choice.lower()]
            if cat_matches:
                selected_paths = cat_matches
            else:
                print(
                    "Invalid selection. Enter number(s), category, A, G, D, V, or 0."
                )
                continue

        if not selected_paths:
            continue

        print("\n" + "=" * 92)
        print(f"Selected Scanners: {', '.join(p.stem for p in selected_paths)}")
        print("=" * 92)

        scanner_args_list = []
        if len(selected_paths) == 1:
            path = selected_paths[0]
            print(f"Selected    : {path.stem}")
            print(f"Category    : {category(path)}")
            profile = verification_profile(path)
            print(f"Mode        : {profile['level']} - {profile['summary']}")
            print(f"Accuracy    : {profile['guidance']}")
            print(f"Description : {description(path) or '-'}")
            print("-" * 92)
            print("Enter the target and options exactly as you would after the scanner name.")
            if global_targets:
                print(f"Global targets [{global_targets}] will be used if you leave this empty.")
            print("Examples: 192.0.2.10 --no-color")
            print("          -f targets.txt --workers 16")
            print("Enter H for scanner help or B to return to the menu.")

            raw_args = read_input("Scanner arguments: ").strip()
            if raw_args.lower() in {"b", "back"}:
                continue
            if raw_args.lower() in {"h", "help", "?"}:
                run_scanner(path, ["--help"])
                read_input("\nPress Enter to return to the menu...")
                continue
            
            if not raw_args and global_targets:
                scanner_args = validate_target_arguments(
                    parse_scanner_args(global_targets)
                )
            elif not raw_args:
                scanner_args = ["--help"]
            else:
                try:
                    scanner_args = parse_scanner_args(raw_args)
                except ValueError as exc:
                    print(f"Could not parse arguments: {exc}")
                    read_input("\nPress Enter to return to the menu...")
                    continue
            scanner_args_list.append((path, scanner_args))
        else:
            print("Running multiple scanners.")
            if not global_targets:
                raw_args = read_input(
                    "Enter one IP/CIDR subnet or -f IP-list file: "
                ).strip()
                if not raw_args:
                    print("No targets provided. Returning to menu.")
                    continue
                args_to_use = validate_target_arguments(parse_scanner_args(raw_args))
            else:
                args_to_use = validate_target_arguments(
                    parse_scanner_args(global_targets)
                )
            
            for path in selected_paths:
                scanner_args_list.append(
                    (path, filter_scanner_args(path, args_to_use))
                )

        for path, s_args in scanner_args_list:
            exit_code = run_scanner(path, s_args)
            results_summary.append((path.stem, exit_code))
            print(f"\nScanner {path.stem}: {outcome_label(exit_code)}.")
        
        read_input("\nAll selected scans finished. Press Enter to return to the menu...")


def cmd_menu(_args):
    return interactive_menu()


def cmd_gui(_args):
    try:
        from gui import launch_gui
    except ImportError as exc:
        print(f"GUI unavailable: {exc}", file=sys.stderr)
        return 2
    return launch_gui()


def cmd_doctor(_args):
    print(f"Python      : {sys.version.split()[0]} ({sys.executable})")
    print(f"Scanner dir : {SCANNERS}")
    print(f"Scanners    : {len(scanner_files())}")
    print("\nExternal tools:")
    missing = 0
    for tool, purpose in TOOLS:
        found = shutil.which(tool)
        state = "OK: " + found if found else "NOT FOUND"
        print(f"  {tool:<11} {state}")
        print(f"  {'':<11} used by {purpose}")
        missing += int(found is None)

    helper = SCANNERS / "JmxReadOnlyProbe.java"
    print(
        f"  {'JMX helper':<11} "
        f"{'OK: ' + str(helper) if helper.is_file() else 'NOT FOUND'}"
    )
    missing += int(not helper.is_file())
    ad_users = SCANNERS / "data" / "ad_usernames.txt"
    print(
        f"  {'AD users':<11} "
        f"{'OK: ' + str(ad_users) if ad_users.is_file() else 'NOT FOUND'}"
    )
    missing += int(not ad_users.is_file())

    try:
        import tftpy  # noqa: F401

        print("  tftpy      OK")
        print(f"  {'':<11} used by TFTP downloader")
    except ImportError:
        print("  tftpy      NOT FOUND")
        print(f"  {'':<11} used by TFTP downloader")
        missing += 1
    print("\nMissing components affect only the scanners shown beside them.")
    return 1 if missing else 0


def cmd_validate(_args):
    syntax_errors = []
    customer_hits = []
    policy_errors = []
    hashes = {}
    project_files = sorted(
        {
            *ROOT.glob("*.py"),
            *SCANNERS.glob("*.py"),
            *SCANNERS.glob("*.PY"),
            *(ROOT / "tests").glob("*.py"),
        },
        key=lambda path: str(path).lower(),
    )
    scanner_paths = set(scanner_files())
    for path in project_files:
        text = path.read_text(encoding="utf-8-sig")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            syntax_errors.append(f"{path.name}:{exc.lineno}: {exc.msg}")
            tree = None
        if (
            tree is not None
            and path in scanner_paths
            and path.name in NO_CONFIRMED_FROM_VERSION
        ):
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and node.value == "VULNERABLE"
                ):
                    policy_errors.append(
                        f"{path.name}:{node.lineno}: version-only scanner uses VULNERABLE"
                    )
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in CUSTOMER_PATTERNS):
                customer_hits.append(f"{path.name}:{line_number}: {line.strip()}")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        hashes.setdefault(digest, []).append(path.name)

    duplicates = [names for names in hashes.values() if len(names) > 1]
    missing_companions = [
        relative
        for relative in (
            Path("JmxReadOnlyProbe.java"),
            Path("data") / "ad_usernames.txt",
        )
        if not (SCANNERS / relative).is_file()
    ]
    print(f"Project files parsed : {len(project_files)}")
    print(f"Scanner commands     : {len(scanner_paths)}")
    print(f"Syntax errors        : {len(syntax_errors)}")
    print(f"Customer-data hits   : {len(customer_hits)}")
    print(f"Exact duplicate sets : {len(duplicates)}")
    print(f"Missing companions   : {len(missing_companions)}")
    print(f"Verdict policy errors: {len(policy_errors)}")
    for title, items in (
        ("Syntax errors", syntax_errors),
        ("Customer-data hits", customer_hits),
        ("Exact duplicates", [", ".join(names) for names in duplicates]),
        ("Verdict policy errors", policy_errors),
    ):
        if items:
            print(f"\n{title}:")
            for item in items:
                print(f"  {item}")
    if missing_companions:
        print("\nMissing companions:")
        for relative in missing_companions:
            print(f"  scanners/{relative}")
    return 1 if (
        syntax_errors
        or customer_hits
        or duplicates
        or missing_companions
        or policy_errors
    ) else 0


def cmd_summary(args):
    """Aggregate all CSV results into one SUMMARY.md."""
    if not REPORTS.is_dir():
        print("No reports directory found.")
        return 1
    
    import csv
    all_rows = []
    # Find all CSV files in reports subdirectories
    for csv_path in REPORTS.glob("**/*.csv"):
        try:
            with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row["_scanner"] = csv_path.parent.name
                    all_rows.append(row)
        except Exception:
            continue

    if not all_rows:
        print("No results found in CSV files.")
        return 0

    summary_path = REPORTS / "SUMMARY.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Security Audit Summary\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Confirmed findings first
        confirmed = [r for r in all_rows if "status" in r and "CONFIRMED" in r["status"].upper()]
        if confirmed:
            f.write("## High-Confidence Findings\n\n")
            f.write("| Scanner | Target | Status | Detail |\n")
            f.write("|---------|--------|--------|--------|\n")
            for r in confirmed:
                target = r.get("ip") or r.get("target") or r.get("host", "unknown")
                detail = r.get("evidence") or r.get("cve_ids") or ""
                f.write(f"| {r['_scanner']} | {target} | {r['status']} | {detail[:100]} |\n")
            f.write("\n")
            
        f.write("## All Results\n\n")
        f.write("| Scanner | Target | Status | Port |\n")
        f.write("|---------|--------|--------|------|\n")
        for r in sorted(all_rows, key=lambda x: (x.get("status", ""), x.get("_scanner", ""))):
            target = r.get("ip") or r.get("target") or r.get("host", "unknown")
            f.write(f"| {r['_scanner']} | {target} | {r.get('status', '-')} | {r.get('port', '-')} |\n")
            
    print(f"Summary generated: {summary_path.resolve()}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="audit-tool",
        description="Unified interface for the cleaned security audit scanner collection.",
    )
    sub = parser.add_subparsers(dest="command")

    menu_parser = sub.add_parser("menu", help="Open the interactive numbered menu")
    menu_parser.set_defaults(func=cmd_menu)

    gui_parser = sub.add_parser("gui", help="Open the graphical scanner interface")
    gui_parser.set_defaults(func=cmd_gui)

    list_parser = sub.add_parser("list", help="List available scanners")
    list_parser.add_argument("--category")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_list)

    info_parser = sub.add_parser("info", help="Show scanner metadata and help")
    info_parser.add_argument("scanner")
    info_parser.set_defaults(func=cmd_info)

    run_parser = sub.add_parser("run", help="Run one scanner")
    run_parser.add_argument("scanner")
    run_parser.add_argument("--output-dir", help="Directory for generated reports")
    run_parser.add_argument("scanner_args", nargs=argparse.REMAINDER)
    run_parser.set_defaults(func=cmd_run)

    run_all_parser = sub.add_parser(
        "run-all", help="Run every scanner as one batch"
    )
    run_all_parser.add_argument(
        "--output-dir", help="Base directory for all generated reports"
    )
    run_all_parser.add_argument(
        "--workers", type=int, default=4, help="Number of parallel scanners"
    )
    run_all_parser.add_argument("scanner_args", nargs=argparse.REMAINDER)
    run_all_parser.set_defaults(func=cmd_run_all)

    doctor_parser = sub.add_parser("doctor", help="Check optional dependencies")
    doctor_parser.set_defaults(func=cmd_doctor)

    validate_parser = sub.add_parser("validate", help="Check syntax, duplicates, and customer labels")
    validate_parser.set_defaults(func=cmd_validate)

    summary_parser = sub.add_parser("summary", help="Aggregate all results into one report")
    summary_parser.set_defaults(func=cmd_summary)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        if not args.command:
            return interactive_menu()
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
