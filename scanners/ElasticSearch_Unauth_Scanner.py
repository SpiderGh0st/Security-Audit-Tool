#!/usr/bin/env python3
"""Check for unauthenticated Elasticsearch node information."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Elasticsearch", 9200, "/", json_keys=("cluster_name", "version.number"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
