# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S006-P001 / 0.1.1-partial / run-0001 / product.
Reviewed the complete core and inherited tests. Original source remains separate.

## Repaired findings

- Deduplication used raw digest alone, dropping identical records from different
  source types. Identity now includes source type; changes also deduplicate.
- Duplicate facts could duplicate stale entries, and changes lacked freshness
  markers. Freshness is applied after deduplication to both facts and changes.
- Stale classification included an undocumented extra correlation window; future
  observations could appear fresh. The one-hour threshold now stands independently,
  and future observations are marked unknown.
- Tie ranking depended on input order. Content identity now breaks ties.
- Topology affected scope without appearing in provenance. Bundles now include
  its detached raw snapshot and digest.
- Environment scope was absent. Explicit alert, record, graph and edge boundaries
  now reject ambiguous scoped inputs and exclude mismatched/missing environments.
- Malformed records, invalid shapes, boolean timestamps, unsafe windows and
  unbounded source inputs now fail through bounded validation.
- Source errors could expose arbitrary credentials. Only recognized error codes
  are forwarded; other text is replaced with a generic reason. Raw provenance
  intentionally remains unredacted and is documented as potentially sensitive.

## Validation and release

23 inherited tests passed before changes. 50 source and installed-wheel tests
pass after repairs, including 27 regressions. Historical check evidence remains
separate. CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12.

Version 0.1.1-partial -> 0.1.2a1. Bundles must be regenerated because provenance,
ordering and freshness change digests. Input contracts are intentionally stricter.
Added packaging, pinned-action CI, Apache 2.0 LICENSE and NOTICE naming
RUSSELL PHILIP SMITHSON, README and security documentation.

No external runtime dependencies need upgrading. No build-tool vulnerability
scan is claimed. This release remains a partial prototype and does not complete
the original roadmap or certify production suitability.
