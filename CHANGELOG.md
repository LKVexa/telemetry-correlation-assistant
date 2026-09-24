# 0.1.2a1 — 2026-09-23

- Preserve cross-source provenance and deterministic ordering; deduplicate changes.
- Repair freshness thresholds, mark future observations unknown, include topology.
- Enforce bounded input and consistent optional environment scope.
- Omit arbitrary source error text from bundles.
- Add 27 regression tests, packaging, Apache 2.0 LICENSE/NOTICE, README and CI.
- Compatibility: rebuild stored bundles; invalid and ambiguously scoped input fails.

# Changelog — Telemetry Correlation Assistant (JY-S006-P001)

## 0.1.1-partial — 2026-09-14 (maintenance audit A007)

Baseline fingerprint: build-0001 `product.zip`
sha256 `8eb02562f63b633b922e9cd5bdc9c725d809f8015bd18982a016568d0df9475d`
(baseline version 0.1.0-partial; baseline suite 15/15 PASS).
All findings below were reproduced on the unmodified baseline before
being fixed. Repairs only — patch bump; no public API removed.

### A007-F1 — provenance aliasing (fixed)
- Observed: `provenance.raw` in `telemetry_excerpts` and
  `recent_changes` stored the caller's live record object; mutating the
  source after bundle construction changed the bundle's "raw" evidence
  and broke the `raw_digest` match (digest no longer verified the
  stored record).
- Expected: provenance is an immutable snapshot; `raw_digest` always
  verifies `raw`.
- Fix: `copy.deepcopy(rec)` at capture time for both facts and changes.

### A007-F2 — unauthorized topology silently dropped (fixed)
- Observed: `sources["topology"] = {"error": "unauthorized"}` produced
  empty `related_services` with NO entry in `unknowns` (the error
  marker was truthy, so the "not supplied" branch never fired) —
  violating the "missing or unauthorized sources appear in unknowns"
  contract.
- Expected: `{"source": "topology", "reason": "unauthorized"}` in
  `unknowns`.
- Fix: topology error/missing markers handled explicitly like every
  other source; non-mapping topology raises ValueError.

### A007-F3 — error-contract leaks (fixed)
- Observed: malformed inputs escaped as bare KeyError ('t', 'from'),
  TypeError (non-numeric `t` / `raised_at`), and AttributeError
  (non-list source), while the documented contract raises ValueError.
- Fix: `_norm_ts`/`_rec_ts` validation raises ValueError with context;
  topology edges and source container types validated; `now` and
  `window_s` validated too.

### A007-F4 — NaN accepted, non-strict canonical digests (fixed)
- Observed: `raised_at=NaN` was accepted, yielding a NaN time window,
  a silently empty bundle, and a `bundle_digest` computed over
  non-interoperable JSON containing the bare `NaN` token
  (`json.dumps` default `allow_nan=True`).
- Fix: non-finite timestamps rejected with ValueError; `_digest` uses
  `allow_nan=False` (strict canonical JSON).

### Compatibility / rollback
- Compatible for all well-formed inputs: bundle schema, digests, and
  ranking are unchanged for valid data. Previously-crashing or
  silently-wrong inputs now raise ValueError or are recorded in
  `unknowns`. Rollback: redeploy build-0001 product.zip (fingerprint
  above); no data migration (pure in-memory function).

## 0.1.0-partial — build-0001
- Initial PAPER-CAP-01 slice.
