# Security boundaries

This stateless library assembles caller-supplied records. It does not authenticate
sources, authorize retrieval, enforce tenant ownership, or perform remediation.
Environment labels and topology are trusted assertions. Content hashes are not
signatures and do not prove authenticity. Missing sources remain explicit unknowns.

Raw provenance is deliberately retained and can contain secrets or personal data.
Sanitize records before building or distributing bundles. Validation errors omit
raw payloads, and source error details are not forwarded, but ordinary records are
not redacted. Read-only/draft flags describe library behavior, not downstream policy.

Limits cover serialized source data, record counts, labels, windows and timestamps.
They are not a process memory quota or protection against hostile in-process
Python code, concurrent mutation, or arbitrarily deep inputs. Exposed services
need request limits and process isolation before deserialization.

Freshness is based on caller timestamps, not verified clocks. Unknown freshness,
stale evidence, missing topology and source errors require human interpretation.
The ranking is heuristic and cannot establish causality, completeness or safety.

There are no third-party runtime dependencies. Build tooling is bounded in
pyproject.toml; no build-tool vulnerability scan is claimed.
Report defects privately to the owner with a synthetic, sanitized reproduction.
