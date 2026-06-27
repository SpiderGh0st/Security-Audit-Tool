# Audit Results

Audit completed on June 18, 2026.

## Input contract

The unified CLI launcher, desktop GUI, and browser GUI now accept only:

- one IPv4 or IPv6 address;
- one DNS domain or hostname;
- one IPv4 or IPv6 CIDR subnet; or
- one HTTP/HTTPS URL or `host:port` target; or
- `-f/--file` followed by an IP-list file.

An IP-list file must exist, be readable as UTF-8, and contain at least one
IPv4 or IPv6 address. Blank lines and `#` comment lines are allowed.
Malformed targets, unsupported URL schemes, URL credentials, invalid ports,
multiple direct targets, mixed direct/file inputs, and domains in IP-list
files are rejected before scanner execution.

## Verification

- 45 unit and integration tests passed.
- All 68 IP-only launcher scanner entry points completed their `--help` startup
  check. The DNS AXFR and explicit TFTP-download utilities remain standalone.
- All 76 Python project files parsed successfully.
- No syntax errors, exact duplicate scripts, missing companion files,
  customer-data labels, or verdict-policy violations were detected.
- CLI and browser API rejection paths were tested for invalid target input.

## Main changes

- Added centralized target and IP-list validation in `audit_tool.py`.
- Applied validation to CLI execution, desktop GUI input, and browser API
  requests.
- Kept scanner options separate from the desktop GUI target field.
- Added regression tests for IPv4, IPv6, domains, CIDR, IP-list files, URLs,
  malformed targets, mixed inputs, and multiple direct targets.
- Updated usage documentation to match the strict input contract.
