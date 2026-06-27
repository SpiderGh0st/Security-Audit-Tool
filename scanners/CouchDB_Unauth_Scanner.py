#!/usr/bin/env python3
"""Check for unauthenticated CouchDB database-list access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("CouchDB", 5984, "/_all_dbs", json_keys=(), text_patterns=(r"^\s*\[\s*(?:\"[^\"]*\"\s*,?\s*)*\]\s*$",), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
