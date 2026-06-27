# Verification Report

Test date: 2026-06-18

## Results

- Python scanner files parsed and compiled: 70/70
- Scanner `--help` interfaces: 70/70 passed
- Unified launcher catalog and dispatch: passed
- Launcher, GUI imports, and parser regression checks: passed
- Unhandled Python tracebacks: 0
- Runtime smoke-test timeouts: 0
- Customer-specific data hits: 0
- Exact duplicate scanner files: 0
- Required JMX companion source: present and successfully compiled
- Verdict, AD integration, target compatibility, backend-failure handling,
  terminal-output cleanup, launcher, browser-GUI, and false-positive
  URL-target and numeric-progress regression tests: 38/38 passed
- Version-only scanners using a confirmed `VULNERABLE` verdict: 0

## Accuracy-hardening pass

The interface now identifies each scanner as `VERIFY`, `ASSESS`, or
`DISCOVER`. Current distribution:

- Scanner modes are generated from the current catalog; run
  `python audit_tool.py list` for the current distribution.

The following misleading verdict patterns were corrected:

- NVD CPE and disclosed-version matches now report `CVE CANDIDATE` or
  `REVIEW`, not a confirmed vulnerability.
- FTP reports `CONFIRMED ISSUE` only when anonymous login is accepted by a
  direct protocol check.
- An MS17-010 `LIKELY VULNERABLE` result is now `POTENTIAL`; only a structured
  `VULNERABLE` state is confirmed.
- MSMQ build comparison reports `POTENTIALLY AFFECTED`.
- Windows, IIS, SQL/database, ESXi, and WebLogic lifecycle/banner findings use
  review verdicts that require inventory, support, edition, and patch
  confirmation.
- Automated validation now rejects future confirmed-vulnerability labels in
  designated version-only scanners.
- SMB signing no longer reports `SECURE` when Nmap supplied no signing state.
- DNS AXFR failures and malformed output remain `INCONCLUSIVE` or
  `NOT TESTED`, rather than being called not vulnerable.
- VNC and ZooKeeper unexpected responses remain inconclusive; only explicit
  no-authentication evidence is reported as vulnerable.
- Exit code 1 is shown as `ATTENTION`, because scanners may use it to signal a
  finding rather than a process failure.

## Active Directory Kerbrute update

`ActiveDirectoryUserEnumerationScanner.py` now:

- accepts only an IP, hostname, CIDR, or target file for normal operation;
- discovers KDC/AD services with Nmap;
- derives the DNS domain from LDAP RootDSE, SMB OS discovery, RDP NTLM data,
  service hostnames, or reverse DNS;
- automatically builds Kerbrute `userenum --dc IP -d DOMAIN --safe ...`;
- uses a bundled 44-name conservative candidate list by default;
- accepts a larger authorized list through `--users`;
- reports a username only when Kerbrute emits an explicit
  `VALID USERNAME` result for the discovered domain.

Nine verdict/domain/command/parser regression tests now pass. Kerbrute was not
installed on the Windows verification host, so live KDC enumeration could not
be performed there. Domain parsing, command construction, strict result
parsing, dry-run discovery, syntax, help, and launcher integration were tested.

The two scanners that exceeded the first broad smoke-test timeout
(`Http_Server_Scanner.py` and `OpenSSL_CCS_MiTM_Scanner.PY`) both passed when
run with a one-port test profile and explicit short Nmap timeouts. Their normal
defaults scan larger port sets and are expected to take longer.

## Runtime dependency limitations on this Windows test host

The following scanners stopped cleanly because their external dependency is
not installed:

| Scanner | Missing dependency |
|---|---|
| `ActiveDirectoryUserEnumerationScanner.py` | `ldapsearch` |
| `AnonSmbShareChecker.py` | `smbmap` |
| `BlueKeepStatusScanner.py` | `rdpscan` |
| `SNMP_Default_Community_Scanner.py` | `snmpget` |
| `UnauthenticatedIscsiLoginScanner.py` | `iscsiadm` |
| `read_tftp.py` | Python package `tftpy` |

These are environment limitations rather than Python crashes. Nmap, OpenSSL,
Java, and Javac were available and exercised successfully.

## Defect corrected during this pass

`Java_JMX_No_Authentication_Scanner.py` required
`scanners/JmxReadOnlyProbe.java`, but that companion file was absent from the
first package. It is now included. The Java helper compiles successfully, and
the scanner completed a localhost runtime test without errors.

## Scope

Runtime smoke tests used only `127.0.0.1` and closed/non-service ports. This
verifies startup, argument handling, dependency handling, subprocess
integration, report creation, and clean no-finding behavior. Confirming each
scanner's vulnerability-detection accuracy requires an authorized lab
containing deliberately vulnerable and patched target systems.
