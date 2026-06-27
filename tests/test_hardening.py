#!/usr/bin/env python3
"""Regression tests for launcher and false-positive hardening."""

import json
import asyncio
import os
import tempfile
import runpy
import threading
import time
import unittest
import urllib.request
from pathlib import Path

import audit_tool
import gui


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = ROOT / "scanners"


def load(name):
    import sys

    scanner_dir = str(SCANNERS)
    if scanner_dir not in sys.path:
        sys.path.insert(0, scanner_dir)
    return runpy.run_path(str(SCANNERS / name))


class LauncherTests(unittest.TestCase):
    def test_run_all_command_accepts_scanner_arguments(self):
        args = audit_tool.build_parser().parse_args(
            ["run-all", "--", "192.0.2.10", "--timeout", "2"]
        )
        self.assertIs(args.func, audit_tool.cmd_run_all)
        self.assertEqual(
            args.scanner_args, ["--", "192.0.2.10", "--timeout", "2"]
        )

    def test_ip_only_catalog_excludes_non_batch_utilities(self):
        names = {path.name for path in audit_tool.scanner_files()}
        self.assertNotIn("read_tftp.py", names)

    def test_elapsed_format(self):
        self.assertEqual(audit_tool.format_elapsed(0), "00:00")
        self.assertEqual(audit_tool.format_elapsed(65), "01:05")
        self.assertEqual(audit_tool.format_elapsed(3661), "1:01:01")

    def test_exit_one_is_not_mislabeled_as_crash(self):
        label = audit_tool.outcome_label(1)
        self.assertIn("ATTENTION", label)
        self.assertNotIn("ERROR", label)

    def test_security_headers_are_assessment(self):
        path = SCANNERS / "Security_Headers_Scanner.py"
        self.assertEqual(audit_tool.verification_profile(path)["level"], "ASSESS")

    def test_waf_is_discovery(self):
        path = SCANNERS / "Waf_Detector_Scanner.py"
        self.assertEqual(audit_tool.verification_profile(path)["level"], "DISCOVER")

    def test_sweet32_accepts_positional_ip_domain_and_cidr(self):
        module = load("Sweet32NmapScanner.py")
        targets = module["load_targets"](
            direct_targets=["192.0.2.10", "scanner.example.com", "198.51.100.0/30"]
        )
        self.assertIn("192.0.2.10", targets)
        self.assertIn("scanner.example.com", targets)
        self.assertIn("198.51.100.1", targets)
        self.assertIn("198.51.100.2", targets)

    def test_rc4_accepts_positional_ip_domain_and_cidr(self):
        module = load("RC4_Nmap_Scanner.py")
        targets = module["load_targets"](
            direct_targets=["192.0.2.10", "scanner.example.com", "198.51.100.0/30"]
        )
        self.assertIn("192.0.2.10", targets)
        self.assertIn("scanner.example.com", targets)
        self.assertIn("198.51.100.1", targets)

    def test_tls_detector_accepts_positional_ip_domain_and_cidr(self):
        module = load("TLSDetector.py")
        targets = module["load_targets"](
            direct_targets=["192.0.2.10", "scanner.example.com", "198.51.100.0/30"]
        )
        self.assertIn("192.0.2.10", targets)
        self.assertIn("scanner.example.com", targets)
        self.assertIn("198.51.100.2", targets)

    def test_sweet32_missing_nmap_is_reported(self):
        module = load("Sweet32NmapScanner.py")
        code, stdout, stderr, _command = module["run_nmap"](
            "__missing_nmap_binary__",
            ["127.0.0.1"],
            "443",
            "-T3",
            "1s",
            [],
        )
        self.assertEqual(code, 127)
        self.assertFalse(stdout)
        self.assertTrue(stderr)

    def test_rc4_missing_nmap_is_reported(self):
        module = load("RC4_Nmap_Scanner.py")
        code, stdout, stderr, _command = module["run_nmap"](
            "__missing_nmap_binary__",
            ["127.0.0.1"],
            "443",
            "-T4",
            "1s",
            [],
        )
        self.assertEqual(code, 127)
        self.assertFalse(stdout)
        self.assertTrue(stderr)

    def test_tls_missing_nmap_is_reported(self):
        module = load("TLSDetector.py")
        code, stdout, stderr, _command = module["run_nmap"](
            "__missing_nmap_binary__",
            ["127.0.0.1"],
            "443",
            "-T4",
            "1s",
            [],
        )
        self.assertEqual(code, 127)
        self.assertFalse(stdout)
        self.assertTrue(stderr)

    def test_accepts_supported_direct_target_types(self):
        for target in (
            "192.0.2.10",
            "2001:db8::10",
            "198.51.100.0/24",
            "2001:db8::/64",
        ):
            self.assertEqual(audit_tool.validate_direct_target(target), target)

    def test_rejects_malformed_direct_targets(self):
        for target in (
            "../targets.txt",
            "bad_domain",
            "999.1.1.1",
            "ftp://example.com/",
            "https://user:pass@example.com/",
            "example.com:70000",
            "example.com:443",
            "192.0.2.10:8080",
            "[2001:db8::10]:443",
            "[2001:db8::10]:bad",
        ):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    audit_tool.validate_direct_target(target)

    def test_ip_list_file_accepts_only_ips(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory) / "valid.txt"
            valid.write_text("# approved\n192.0.2.1\n2001:db8::1\n", encoding="utf-8")
            audit_tool.validate_target_arguments(["-f", str(valid), "--workers", "2"])

            invalid = Path(directory) / "invalid.txt"
            invalid.write_text("192.0.2.1\nexample.com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                audit_tool.validate_target_arguments(["--file", str(invalid)])

    def test_ip_list_file_is_absolutized(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            try:
                os.chdir(directory)
                valid = Path("targets.txt")
                valid.write_text("192.0.2.1\n", encoding="utf-8")
                tokens = audit_tool.validate_target_arguments(["-f", "targets.txt"])
                self.assertTrue(Path(tokens[1]).is_absolute())
                self.assertEqual(Path(tokens[1]), valid.resolve())
            finally:
                os.chdir(original)

    def test_target_must_precede_scanner_options(self):
        with self.assertRaisesRegex(ValueError, "target first"):
            audit_tool.validate_target_arguments(["--workers", "2", "192.0.2.1"])

    def test_direct_targets_and_file_cannot_be_mixed(self):
        with self.assertRaisesRegex(ValueError, "not both"):
            audit_tool.validate_target_arguments(["192.0.2.1", "-f", "targets.txt"])

    def test_multiple_direct_targets_require_an_ip_list(self):
        with self.assertRaisesRegex(ValueError, "one direct target"):
            audit_tool.validate_target_arguments(["192.0.2.1", "192.0.2.2"])

    def test_batch_scanners_exclude_dns_axfr(self):
        names = {path.name for path in audit_tool.batch_scanners()}
        self.assertNotIn("DNS_Zone_Transfer_Scanner.py", names)
        self.assertIn("FTP_Scanner.py", names)

    def test_filter_scanner_args_strips_incompatible_flags(self):
        path = audit_tool.resolve_scanner("ftp_scanner")
        args = audit_tool.filter_scanner_args(
            path,
            ["-f", "C:/targets.txt", "--all-ports", "--domain", "example.com"],
        )
        self.assertEqual(args, ["-f", "C:/targets.txt", "--all-ports"])
        other = audit_tool.resolve_scanner("ms17_010scanner")
        filtered = audit_tool.filter_scanner_args(
            other,
            ["192.0.2.1", "--all-ports", "--domain", "example.com"],
        )
        self.assertEqual(filtered, ["192.0.2.1"])


class FalsePositiveGuardTests(unittest.TestCase):
    def test_smb_empty_script_output_is_unknown(self):
        module = load("SMBSigningChecker.py")
        row = module["parse_result"]("192.0.2.1", "")
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertFalse(row["affected"])

    def test_smb_explicit_required_is_required(self):
        module = load("SMBSigningChecker.py")
        text = """445/tcp open microsoft-ds
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
"""
        row = module["parse_result"]("192.0.2.1", text)
        self.assertEqual(row["status"], "REQUIRED")
        self.assertFalse(row["affected"])

    def test_dns_invalid_xml_is_inconclusive(self):
        module = load("DNS_Zone_Transfer_Scanner.py")
        status, _detail = module["parse_axfr_result"]("<broken")
        self.assertEqual(status, "INCONCLUSIVE")

    def test_dns_success_requires_explicit_script_evidence(self):
        module = load("DNS_Zone_Transfer_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="53">
          <state state="open"/>
          <script id="dns-zone-transfer" output="Zone transfer successful"/>
        </port></ports></host></nmaprun>
        """
        status, _detail = module["parse_axfr_result"](xml)
        self.assertEqual(status, "VULNERABLE")

    def test_rsync_denied_output_is_not_vulnerable(self):
        module = load("Rsync_Unauth_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="873">
          <state state="open"/>
          <script id="rsync-list-modules" output="ERROR: access denied"/>
        </port></ports></host></nmaprun>
        """
        vuln, _detail = module["parse_rsync"](xml)
        self.assertFalse(vuln)

    def test_rsync_module_list_is_vulnerable(self):
        module = load("Rsync_Unauth_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="873">
          <state state="open"/>
          <script id="rsync-list-modules" output="@RSYNCD: 2.3.4&#10;public          Public Folder"/>
        </port></ports></host></nmaprun>
        """
        vuln, _detail = module["parse_rsync"](xml)
        self.assertTrue(vuln)

    def test_vnc_open_without_script_is_inconclusive(self):
        module = load("VNC_Unauth_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="5900">
          <state state="open"/>
        </port></ports></host></nmaprun>
        """
        status, _detail = module["parse_vnc_xml"](xml)
        self.assertEqual(status, "INCONCLUSIVE")

    def test_vnc_no_auth_requires_explicit_evidence(self):
        module = load("VNC_Unauth_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="5900">
          <state state="open"/>
          <script id="vnc-info" output="Security types: None (No authentication)"/>
        </port></ports></host></nmaprun>
        """
        status, _detail = module["parse_vnc_xml"](xml)
        self.assertEqual(status, "VULNERABLE")

    def test_security_headers_normalizes_url_and_port(self):
        module = load("Security_Headers_Scanner.py")
        targets, port = module["normalize_target"](
            "https://testfire.net:8443/demo/index.jsp"
        )
        self.assertEqual(targets, ["testfire.net"])
        self.assertEqual(port, 8443)

    def test_cookie_scanner_normalizes_url_and_port(self):
        module = load("Cookie_Security_Scanner.py")
        targets, port = module["normalize_target"](
            "http://testfire.net:8080/"
        )
        self.assertEqual(targets, ["testfire.net"])
        self.assertEqual(port, 8080)

    def test_security_headers_open_port_without_script_is_inconclusive(self):
        module = load("Security_Headers_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="80">
          <state state="open"/>
        </port></ports></host></nmaprun>
        """
        self.assertIn("no result", module["inconclusive_http_reason"](xml))

    def test_cookie_open_port_without_script_is_inconclusive(self):
        module = load("Cookie_Security_Scanner.py")
        xml = """
        <nmaprun><host><ports><port protocol="tcp" portid="443">
          <state state="open"/>
        </port></ports></host></nmaprun>
        """
        self.assertIn("no result", module["inconclusive_http_reason"](xml))

    def test_cookie_runtime_collects_backend_error_without_traceback(self):
        module = load("Cookie_Security_Scanner.py")

        async def failed_nmap(_target, _ports, _timeout):
            return "", "simulated backend failure"

        module["run_nmap"].__globals__["run_nmap"] = failed_nmap
        results, errors = asyncio.run(
            module["run_all"](["127.0.0.1"], 1, "80", "1s")
        )
        self.assertEqual(results, [])
        self.assertEqual(errors[0]["target"], "127.0.0.1")
        self.assertIn("simulated", errors[0]["error"])


class BrowserGuiTests(unittest.TestCase):
    def setUp(self):
        self.server = gui.create_web_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request_json(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if data is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def test_page_and_catalog_load(self):
        with urllib.request.urlopen(self.base + "/", timeout=5) as response:
            page = response.read().decode("utf-8")
        self.assertIn("Run selected", page)
        self.assertIn("Run all scanners", page)
        self.assertIn("runAll", page)
        self.assertEqual(len(self.request_json("/api/catalog")), 69)
        self.assertFalse(self.request_json("/api/status")["running"])

    def test_browser_gui_runs_scanner_and_streams_output(self):
        self.request_json(
            "/api/run",
            {
                "scanners": ["port1801openscanner"],
                "arguments": "127.0.0.1 --timeout 1 --workers 1 --no-color",
            },
        )
        deadline = time.monotonic() + 15
        status = {}
        while time.monotonic() < deadline:
            status = self.request_json("/api/status")
            if not status["running"]:
                break
            time.sleep(0.1)
        self.assertFalse(status.get("running", True))
        self.assertEqual(status.get("status"), "Scan batch complete")
        self.assertEqual(status.get("progress"), 100)
        self.assertIn("port1801openscanner", status.get("output", ""))
        self.assertIn("COMPLETED", status.get("output", ""))

    def test_browser_gui_rejects_url_target(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.request_json(
                "/api/run",
                {
                    "scanners": ["port1801openscanner"],
                    "arguments": "https://example.com/",
                },
            )
        self.assertEqual(context.exception.code, 400)


class TerminalOutputTests(unittest.TestCase):
    def test_ansi_colors_are_removed(self):
        output_filter = gui.TerminalOutputFilter()
        text = output_filter.feed("\x1b[97mVULNERABLE\x1b[0m")
        self.assertEqual(text, "VULNERABLE")

    def test_split_ansi_sequence_is_not_leaked(self):
        output_filter = gui.TerminalOutputFilter()
        first = output_filter.feed("TLS 1.0: \x1b[")
        second = output_filter.feed("91mOFFERED\x1b[0")
        third = output_filter.feed("m\n")
        self.assertEqual(first + second + third, "TLS 1.0: OFFERED\n")
        self.assertNotIn("\x1b", first + second + third)

    def test_progress_carriage_return_is_preserved_for_gui_conversion(self):
        output_filter = gui.TerminalOutputFilter()
        self.assertEqual(output_filter.feed("Scanning 1/2\r"), "Scanning 1/2\r")

    def test_progress_parser_reads_percent(self):
        self.assertEqual(gui.progress_from_output("Scanning (42.7%)"), 42)

    def test_progress_parser_reads_fraction(self):
        self.assertEqual(gui.progress_from_output("Scanning: 3/10 | Current"), 30)

    def test_progress_parser_reserves_100_for_process_completion(self):
        self.assertEqual(gui.progress_from_output("Scanning: 10/10 (100.0%)"), 99)


if __name__ == "__main__":
    unittest.main()
