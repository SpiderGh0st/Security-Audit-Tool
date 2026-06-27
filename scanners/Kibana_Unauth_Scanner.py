#!/usr/bin/env python3
"""Check for unauthenticated Kibana status API access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Kibana", 5601, "/api/status", json_keys=("version.number", "status.overall"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
