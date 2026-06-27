#!/usr/bin/env python3
"""Regression tests for conservative scanner verdicts."""

import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCANNERS = ROOT / "scanners"


def load(name):
    return runpy.run_path(str(SCANNERS / name))


class VerdictTests(unittest.TestCase):
    def test_gsoap_version_match_is_candidate(self):
        module = load("GsoapVersionChecker.py")
        self.assertEqual(module["classify"]("2.7.10")[0], "CVE CANDIDATE")
        self.assertEqual(module["classify"]("2.8.48")[0], "NOT VULN")

    def test_mongobleed_version_match_is_candidate(self):
        module = load("MongoBleedScanner.py")
        self.assertEqual(module["classify_version"]("4.4.10"), "CVE CANDIDATE")

    def test_iis_is_lifecycle_review(self):
        module = load("Outdated_IIS_Scanner.py")
        self.assertEqual(module["classify"]("7.5")[0], "LIFECYCLE REVIEW")
        self.assertEqual(module["classify"]("10.0")[0], "REVIEW OS")

    def test_sql_banner_is_not_proof(self):
        module = load("SqlVersionVulnChecker.py")
        status, _detail = module["classify"](
            "Microsoft SQL Server",
            "11.0.0.0",
            "",
        )
        self.assertEqual(status, "LIFECYCLE REVIEW")

    def test_ms17_likely_is_not_confirmed(self):
        module = load("MS17-010Scanner.py")
        xml = """
        <nmaprun><host>
          <address addr="192.0.2.1" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="445">
            <state state="open"/>
            <script id="smb-vuln-ms17-010"
                    output="State: LIKELY VULNERABLE"/>
          </port></ports>
        </host></nmaprun>
        """
        self.assertEqual(module["parse_xml"](xml)["status"], "POTENTIAL")

    def test_ms17_structured_vulnerable_is_confirmed(self):
        module = load("MS17-010Scanner.py")
        xml = """
        <nmaprun><host>
          <address addr="192.0.2.1" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="445">
            <state state="open"/>
            <script id="smb-vuln-ms17-010"
                    output="State: VULNERABLE"/>
          </port></ports>
        </host></nmaprun>
        """
        self.assertEqual(module["parse_xml"](xml)["status"], "VULNERABLE")

    def test_ad_domain_discovery_prefers_rootdse(self):
        module = load("ActiveDirectoryUserEnumerationScanner.py")
        xml = """
        <nmaprun><host>
          <address addr="192.0.2.10" addrtype="ipv4"/>
          <ports>
            <port protocol="tcp" portid="88"><state state="open"/></port>
            <port protocol="tcp" portid="389">
              <state state="open"/>
              <script id="ldap-rootdse"
                      output="defaultNamingContext: DC=corp,DC=example,DC=com">
                <table>
                  <elem key="defaultNamingContext">DC=corp,DC=example,DC=com</elem>
                  <elem key="dnsHostName">dc01.corp.example.com</elem>
                </table>
              </script>
            </port>
          </ports>
        </host></nmaprun>
        """
        result = module["parse_discovery_xml"](xml, "192.0.2.10")
        self.assertTrue(result["kerberos_open"])
        self.assertEqual(result["domains"][0]["domain"], "corp.example.com")
        self.assertEqual(result["domains"][0]["source"], "LDAP RootDSE")

    def test_ad_kerbrute_command_is_complete(self):
        module = load("ActiveDirectoryUserEnumerationScanner.py")
        args = SimpleNamespace(threads=8, delay=50)
        command = module["build_kerbrute_command"](
            "kerbrute",
            "192.0.2.10",
            "corp.example.com",
            Path("users.txt"),
            args,
            Path("kerbrute.log"),
        )
        self.assertEqual(command[1], "userenum")
        self.assertIn("--safe", command)
        self.assertEqual(command[command.index("--dc") + 1], "192.0.2.10")
        self.assertEqual(command[command.index("-d") + 1], "corp.example.com")
        self.assertEqual(command[-1], "users.txt")

    def test_ad_parses_only_explicit_valid_usernames(self):
        module = load("ActiveDirectoryUserEnumerationScanner.py")
        output = """
        [+] VALID USERNAME: alice@corp.example.com
        [-] alice2@corp.example.com - USERNAME DOES NOT EXIST
        [+] VALID USERNAME: bob@other.example.com
        """
        users = module["parse_valid_users"](output, "corp.example.com")
        self.assertEqual(users, ["alice"])


if __name__ == "__main__":
    unittest.main()
