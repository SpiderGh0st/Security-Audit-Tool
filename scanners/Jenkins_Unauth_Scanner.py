#!/usr/bin/env python3
"""Check for unauthenticated Jenkins API data access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Jenkins", 8080, "/api/json", json_keys=("jobs",), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
