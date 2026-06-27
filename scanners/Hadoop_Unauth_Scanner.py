#!/usr/bin/env python3
"""Check for unauthenticated Hadoop NameNode web access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("Hadoop NameNode", 50070, "/dfshealth.html", text_patterns=(r"\bNameNode\b", r"\bHadoop\b"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
