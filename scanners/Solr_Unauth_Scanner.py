#!/usr/bin/env python3
"""Check for unauthenticated Apache Solr system-information access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Apache Solr", 8983, "/solr/admin/info/system?wt=json", json_keys=("lucene.solr-spec-version", "mode"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
