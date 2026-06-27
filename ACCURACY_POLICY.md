# Accuracy and Verdict Policy

This tool intentionally uses conservative language. Remote scanners cannot
guarantee zero false positives or false negatives.

## Verdict classes

- **VERIFY**: The scanner performs an active protocol or configuration check.
  A positive result requires direct remote evidence, such as an accepted
  unauthenticated login, an offered weak protocol/cipher, or a structured
  vulnerability-script result.
- **ASSESS**: The scanner compares a disclosed version, banner, build, or
  operating-system fingerprint with a policy or advisory. These results are
  candidates for review, not proof that a fix is absent.
- **DISCOVER**: The scanner inventories an exposed service or interface.
  Exposure alone is not labelled a vulnerability.

## Reporting rules

1. `VULNERABLE` is reserved for direct evidence from a purpose-built protocol
   check or structured vulnerability result.
2. Version and CPE matches use labels such as `CVE CANDIDATE`,
   `POTENTIALLY AFFECTED`, `PATCH REVIEW`, or `LIFECYCLE REVIEW`.
3. `SAFE` means the tested condition was not observed. It does not certify the
   entire host as secure.
4. Timeouts, missing versions, unsupported handshakes, and parser uncertainty
   remain `REVIEW`, `UNKNOWN`, `NOT TESTED`, or `INCONCLUSIVE`.
5. Before reporting an assessment finding, confirm:
   - the exact installed package/build;
   - vendor or distribution backported fixes;
   - current patch inventory;
   - product edition and support/ESU entitlement;
   - whether a proxy, load balancer, or banner override affected detection.

## Operational guidance

- Prefer authenticated patch/configuration evidence where available.
- Run from a network position representative of the real threat path.
- Repeat unexpected positives with packet capture or a second independent
  method.
- Keep raw CSV evidence and scanner output with the assessment record.
- Test against known-vulnerable and known-patched lab systems before relying on
  a scanner for production reporting.
