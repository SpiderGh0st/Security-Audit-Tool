#!/usr/bin/env python3
"""Check for unauthenticated RabbitMQ Management API access."""
from _http_exposure_common import ServiceSpec, run_service

SPEC = ServiceSpec("RabbitMQ", 15672, "/api/overview", json_keys=("rabbitmq_version", "cluster_name"), description=__doc__)
if __name__ == "__main__":
    raise SystemExit(run_service(SPEC))
