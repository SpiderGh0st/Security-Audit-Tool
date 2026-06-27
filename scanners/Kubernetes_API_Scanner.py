#!/usr/bin/env python3
"""Check for unauthenticated Kubernetes API discovery access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Kubernetes API", 6443, "/api", scheme="https", json_keys=("kind", "versions"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
