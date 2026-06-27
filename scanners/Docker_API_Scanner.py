#!/usr/bin/env python3
"""Check for unauthenticated Docker Engine API access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Docker API", 2375, "/version", json_keys=("ApiVersion", "Version"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
