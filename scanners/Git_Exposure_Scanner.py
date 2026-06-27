#!/usr/bin/env python3
"""Check whether a Git repository configuration is publicly readable."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Git metadata", 80, "/.git/config", text_patterns=(r"(?m)^\s*\[core\]\s*$", r"(?m)^\s*repositoryformatversion\s*="), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
