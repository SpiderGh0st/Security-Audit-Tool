# Security Audit Tool

A customer-neutral, unified launcher for the cleaned Python security scanner
collection. Use it only on systems you own or are explicitly authorized to test.

## Quick start

```powershell
python main.py
```

Running the main script without arguments opens the graphical interface. It
supports search/category filtering, multi-selection, target files, live
scanner output, elapsed-time progress, cancellation, and direct access to the
report directory. Choose **Run all scanners** to execute every scanner one at
a time as a single batch.

Use `python audit_tool.py menu` for the numbered terminal interface, or
`python audit_tool.py gui` to open the GUI explicitly. The terminal launcher
also prints elapsed-time heartbeat messages while a scanner is running. Enter
`A` in the terminal menu to run all scanners.

For command-line automation, use:

```powershell
python audit_tool.py run-all -- 192.0.2.10
python audit_tool.py run-all -- -f targets.txt
```

The launcher intentionally excludes `DNS_Zone_Transfer_Scanner.py` because
AXFR requires a domain name, and excludes `read_tftp.py` because it requires
explicit remote filenames. Both remain in `scanners/` as standalone utilities,
but they are not included in the IP-only GUI, menu, catalog, or run-all batch.

The menu labels every scanner as:

- `VERIFY` for direct protocol/configuration evidence;
- `ASSESS` for version, build, CVE, and lifecycle candidates;
- `DISCOVER` for inventory-only checks.

See `ACCURACY_POLICY.md` before using results in a formal report. Version and
banner matches are deliberately not presented as confirmed vulnerabilities.

Run all regression tests with:

```powershell
python -m unittest discover -s tests -v
```

### Active Directory Kerbrute scanner

Install Kerbrute from its official releases and place it in `PATH`, beside the
scanner, or provide `--kerbrute PATH`:
[github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases).

```powershell
python main.py
# Select ActiveDirectoryUserEnumerationScanner, then enter:
192.0.2.10
```

The scanner discovers the AD domain automatically and runs Kerbrute `userenum`
with the bundled conservative candidate list. For a broader authorized list:

```powershell
python audit_tool.py run activedirectoryuserenumerationscanner -- 192.0.2.0/24 --users usernames.txt
```

The command-line interface is still available:

```powershell
python audit_tool.py validate
python audit_tool.py doctor
python audit_tool.py list
python audit_tool.py info smbsigningchecker
python audit_tool.py run smbsigningchecker -- 192.0.2.10 --no-color
```

See `TEST_REPORT.md` for the latest verification results and the dependencies
that were unavailable on the Windows test host.

Arguments after `--` are validated and then passed to the selected scanner.
By default, each run writes into a timestamped folder under `reports/`.

The GUI and launcher accept exactly one literal IPv4/IPv6 address or CIDR
subnet. Domains, URLs, and `host:port` values are rejected. For multiple
targets, use `-f` with a UTF-8 text file containing one IPv4 or IPv6 address
per line. Blank lines and `#` comments are ignored.

```powershell
python audit_tool.py run sweet32nmapscanner -- 192.0.2.10
python audit_tool.py run tlsdetector -- 192.0.2.0/28
python audit_tool.py run port1801openscanner -- 2001:db8::10
```

Malformed targets, domains, URLs, `host:port` values, mixed direct/file input,
and non-IP entries inside IP-list files are rejected before a scanner starts.

```powershell
python audit_tool.py run tlsdetector -- -f targets.txt --network-name "Authorized Network"
python audit_tool.py run rc4_nmap_scanner -- 192.0.2.0/24 --no-color
```

Use `info` to see the original scanner's complete arguments:

```powershell
python audit_tool.py info tlsdetector
```

## Dependencies

The launcher uses only the Python standard library. Individual scanners may
need tools such as Nmap, OpenSSL, Java/Javac, smbclient, smbmap, or showmount.
Run `python audit_tool.py doctor` for a local availability check.

`Java_JMX_No_Authentication_Scanner.py` compiles the included
`scanners/JmxReadOnlyProbe.java` helper into a temporary directory at runtime.

Only the TFTP helper requires a Python package:

```powershell
python -m pip install -r requirements.txt
```

## Cleanup performed

- Removed customer-branded default labels.
- Replaced internal/private IP examples with RFC 5737 documentation ranges.
- Reworked the hard-coded TFTP downloader to require an explicit host and file.
- Replaced an exact duplicate JMX implementation with a compatibility launcher.
- Added syntax, duplicate, and customer-label validation.
- Centralized scanner discovery, help, execution, report directories, and
  dependency checks in `audit_tool.py`.

## Directory structure

```text
security-audit-tool/
|-- audit_tool.py
|-- README.md
|-- requirements.txt
|-- reports/
`-- scanners/
    |-- Acme_Thttpd_Scanner.py
    |-- ActiveDirectoryUserEnumerationScanner.py
    |-- ...
    |-- TLSDetector.py
    `-- UnsupportedWindowsScanner.py
```
