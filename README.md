# Telemetry Correlation Assistant

**0.1.2a1 — experimental partial candidate, JY-S006-P001**

A pure Python library that assembles caller-supplied alert, topology, log, metric,
trace, and change records into a bounded evidence bundle. Every bundle contains
ranked excerpts, raw provenance, content digests, freshness, and explicit unknowns.
It performs no retrieval or remediation; all outputs are read-only drafts.

## Install and use

Python 3.10 or newer; no third-party runtime dependencies.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from telecorr.core import build_evidence_bundle

bundle = build_evidence_bundle(
    {"alert_id": "AL-1", "service": "api", "raised_at": 1000,
     "signal": "latency", "target_env": "prod"},
    {"topology": {"target_env": "prod", "edges": [{"from": "api", "to": "db"}]},
     "logs": [{"service": "db", "target_env": "prod", "t": 990,
               "level": "error", "message": "query timeout"}]},
    now=1010,
)
~~~

Missing sources appear in unknowns. Pass now explicitly for repeatable output.
Telemetry is included from the alert service and its immediate undirected
neighbors during [raised_at - window_s, raised_at]. Changes use twice that lookback.
Default window is 30 minutes; maximum is one day. Ranking is a provisional
heuristic favoring own-service errors and matching metrics, not causal inference.

## Provenance, scope, and freshness

Facts deduplicate within each source type; identical records across source types
retain both provenance entries. Changes also deduplicate. Equal-ranked records
sort by stable content identity. Topology has a detached raw snapshot and digest.
The bundle digest covers the complete body except the bundle_digest field itself.

When alert.target_env is supplied, records and topology must have the same
target_env. Records without it are excluded and reported as unknown; different
environments are excluded. Explicitly scoped sources require a scoped alert.
An edge may inherit the graph environment; its explicit environment must match.
Legacy unscoped inputs cannot prove isolation between environments; prefer explicit
scope. These labels are caller assertions, not authorization.

Freshness uses observed_at, falling back to t. Age greater than 3600 seconds
marks facts and changes stale, independent of the correlation window. Future
observation timestamps mark freshness unknown. Future alert timestamps are rejected.
Conflicting evidence is retained.

## Input boundaries and compatibility

Source lists and topology edges are limited to 5,000 records each. A record may
serialize to at most 256 KiB; all source JSON combined is limited to 16 MiB.
Labels are bounded to 512 characters. Timestamps accept finite numbers or numeric
strings between -1e12 and 1e12; booleans are rejected. Windows must be positive
and no more than 86,400 seconds. Malformed inputs raise ValueError.

Compared with 0.1.1-partial, validation is stricter, environment mixing is rejected
or excluded, deduplication and tie ordering change, and the bundle now includes
topology provenance. Existing bundle digests will change; rebuild derived bundles.
The schema identifier remains v1 with additive fields.

Raw provenance can contain secrets or personal data. Sanitize input before
sharing output. Source error text is reduced to known codes or a generic message.
SHA-256 identifies content and does not authenticate a source or prevent replacement.

## Validation and remaining scope

50 tests include 23 inherited checks and 27 hardening regressions. Source and
installed-wheel evidence is in [CHECK_RUNS](docs/CHECK_RUNS.json); see the
[audit](docs/AUDIT.md) and [security boundaries](SECURITY.md).
CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12.

This implements the original PAPER-CAP-01 slice. Live retrieval connectors,
service/storage layers, workflow orchestration, owner-approved acceptance values,
the original 1,073 item roadmap, and production release gates remain outside this
partial candidate.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party code is vendored.
