"""Bounded, read-only assembly of caller-supplied telemetry evidence.

Digests identify content; authorization and authentication remain caller duties.
"""
from __future__ import annotations
import hashlib
import json
import math
import time

VERSION = "0.1.2a1"
__version__ = VERSION
DEFAULT_WINDOW_S = 1800.0
STALENESS_LIMIT_S = 3600.0
MAX_WINDOW_S = 86400.0
MAX_RECORDS = 5000
MAX_RECORD_BYTES = 256 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
SOURCE_NAMES = ("topology", "logs", "metrics", "traces", "changes")

def _canonical(obj):
    try:
        value = json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise ValueError("record must be finite JSON data") from None
    if len(value) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the JSON size limit")
    return value

def _digest(obj) -> str:
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()

def _label(value, context):
    if type(value) is not str or not value.strip() or len(value) > 512:
        raise ValueError(f"{context} must be a nonempty bounded string")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{context} must be valid Unicode") from None
    if any(ord(c) < 32 for c in value):
        raise ValueError(f"{context} contains a control character")
    return value

def _norm_service(name: str) -> str:
    return _label(name, "service").strip().lower().replace("_", "-")

def _norm_ts(value, ctx="timestamp") -> float:
    if type(value) not in (str, int, float) or type(value) is bool:
        raise ValueError(f"invalid {ctx}")
    if isinstance(value, str) and len(value) > 64:
        raise ValueError(f"invalid {ctx}")
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"invalid {ctx}") from None
    if not math.isfinite(timestamp) or not -1e12 <= timestamp <= 1e12:
        raise ValueError(f"{ctx} must be finite and between -1e12 and 1e12")
    return timestamp

def _rec_ts(rec, kind):
    if type(rec) is not dict or "t" not in rec:
        raise ValueError(f"{kind} record must contain a timestamp")
    return _norm_ts(rec["t"], f"{kind} timestamp")

def related_services(topology: dict, service: str, hops: int = 1) -> list[str]:
    service = _norm_service(service)
    if type(topology) is not dict or type(hops) is not int or not 0 <= hops <= 4:
        raise ValueError("topology must be an object and hops an integer from 0 to 4")
    edges_in = topology.get("edges", [])
    if type(edges_in) is not list or len(edges_in) > MAX_RECORDS:
        raise ValueError("topology edges must be a bounded list")
    edges = {}
    topology_env = topology.get("target_env")
    if "target_env" in topology:
        _label(topology_env, "topology target_env")
    for edge in edges_in:
        if type(edge) is not dict or not {"from", "to"} <= set(edge):
            raise ValueError("topology edge requires from and to")
        if "target_env" in edge:
            _label(edge["target_env"], "edge target_env")
            if edge["target_env"] != topology_env:
                raise ValueError("edge environment must match the declared topology environment")
        left, right = _norm_service(edge["from"]), _norm_service(edge["to"])
        edges.setdefault(left, set()).add(right)
        edges.setdefault(right, set()).add(left)
    seen, frontier = {service}, {service}
    for _ in range(hops):
        frontier = {neighbor for node in frontier for neighbor in edges.get(node, set())} - seen
        seen |= frontier
    return sorted(seen - {service})

def build_evidence_bundle(alert: dict, sources: dict, now: float | None = None,
                          window_s: float = DEFAULT_WINDOW_S) -> dict:
    """Assemble a bounded draft. Pass now explicitly for repeatable digests."""
    if type(alert) is not dict or not {"alert_id", "service", "raised_at", "signal"} <= set(alert):
        raise ValueError("alert must contain identity, service, timestamp, and signal")
    if type(sources) is not dict or not set(sources) <= set(SOURCE_NAMES):
        raise ValueError("sources must be an object containing only supported source names")
    ident = _label(alert["alert_id"], "alert_id")
    signal = _label(alert["signal"], "signal")
    service = _norm_service(alert["service"])
    environment = alert.get("target_env")
    if "target_env" in alert:
        _label(environment, "target_env")
    now = _norm_ts(time.time() if now is None else now, "now")
    window_s = _norm_ts(window_s, "window_s")
    if not 0 < window_s <= MAX_WINDOW_S:
        raise ValueError("window_s must be positive and no more than one day")
    end = _norm_ts(alert["raised_at"], "alert raised_at")
    if end > now:
        raise ValueError("alert raised_at is after the bundle build time")
    start = end - window_s
    unknowns, stale, facts, changes = [], [], {}, {}
    total_bytes = 0

    def snapshot(value, *, topology=False):
        nonlocal total_bytes
        encoded = _canonical(value)
        if len(encoded) > (MAX_INPUT_BYTES if topology else MAX_RECORD_BYTES):
            raise ValueError("source record exceeds size limit")
        total_bytes += len(encoded)
        if total_bytes > MAX_INPUT_BYTES:
            raise ValueError("combined source data exceeds size limit")
        return json.loads(encoded)

    def unavailable(name, source):
        if source is None:
            unknowns.append({"source": name, "reason": "source not supplied"})
            return True
        if type(source) is dict and "error" in source:
            reason = _label(source["error"], "source error")
            # Error messages can contain credentials. Only forward known codes.
            if reason not in {"unauthorized", "unavailable", "timeout", "not found"}:
                reason = "source error (details omitted)"
            unknowns.append({"source": name, "reason": reason})
            return True
        return False

    topology_raw = sources.get("topology")
    topology_provenance = None
    related = []
    if not unavailable("topology", topology_raw):
        if type(topology_raw) is not dict:
            raise ValueError("topology must be an object")
        topology = snapshot(topology_raw, topology=True)
        if environment is None and "target_env" in topology:
            raise ValueError("alert environment required for scoped topology")
        if environment is not None and topology.get("target_env") != environment:
            unknowns.append({"source": "topology", "reason": "environment missing or different"})
        else:
            related = related_services(topology, service)
            topology_provenance = {"source": "topology", "raw": topology,
                                   "raw_digest": _digest(topology)}
    scope = {service, *related}

    def freshness(entry, record, kind):
        observed = _norm_ts(record.get("observed_at", record["t"]), kind+" observed_at")
        age = now - observed
        if age < 0:
            entry["freshness_unknown"] = True
            unknowns.append({"source": kind, "reason": "observation timestamp is in the future",
                             "raw_digest": entry["provenance"]["raw_digest"]})
        elif age > STALENESS_LIMIT_S:
            entry["stale"] = True
            stale.append({"kind": kind, "raw_digest": entry["provenance"]["raw_digest"],
                          "age_s": round(age, 1)})

    for kind in ("logs", "metrics", "traces", "changes"):
        records = sources.get(kind)
        if unavailable(kind, records):
            continue
        if type(records) not in (list, tuple) or len(records) > MAX_RECORDS:
            raise ValueError(f"{kind} must be a bounded record list")
        missing_environment = 0
        for original in records:
            if type(original) is not dict:
                raise ValueError(f"{kind} record must be an object")
            record = snapshot(original)
            timestamp = _rec_ts(record, kind)
            record_service = _norm_service(record.get("service"))
            if "observed_at" in record:
                _norm_ts(record["observed_at"], kind+" observed_at")
            if "target_env" in record:
                _label(record["target_env"], "record target_env")
                if environment is None:
                    raise ValueError("alert environment required for scoped records")
            if environment is not None and record.get("target_env") != environment:
                if "target_env" not in record:
                    missing_environment += 1
                continue
            if record_service not in scope or not (start - (window_s if kind == "changes" else 0)) <= timestamp <= end:
                continue
            raw_digest = _digest(record)
            provenance = {"source": kind, "raw": record, "raw_digest": raw_digest}
            if kind == "changes":
                if raw_digest in changes:
                    continue
                for field in ("kind", "version"):
                    if field in record and record[field] is not None:
                        _label(record[field], "change "+field)
                entry = {"service": record_service, "t": timestamp,
                         "kind": record.get("kind"), "version": record.get("version"),
                         "provenance": provenance}
                if environment is not None:
                    entry["target_env"] = environment
                freshness(entry, record, kind)
                changes[raw_digest] = entry
                continue
            key = (kind, raw_digest)
            if key in facts:
                continue
            for field in ("summary", "message", "name"):
                if field in record and record[field] is not None and type(record[field]) is not str:
                    raise ValueError(f"{kind} summary fields must be strings")
            if kind == "logs":
                level = record.get("level", "")
                if type(level) is not str:
                    raise ValueError("log level must be a string")
                relevance = 1.0 if record_service == service else 0.6
                if level.lower() in ("error", "critical"):
                    relevance = min(1.0, relevance + 0.3)
            elif kind == "metrics":
                if "metric" in record:
                    _label(record["metric"], "metric")
                relevance = (0.9 if record.get("metric") == signal else 0.5) - (0 if record_service == service else 0.2)
            else:
                status = record.get("status", "")
                if type(status) is not str:
                    raise ValueError("trace status must be a string")
                relevance = 0.7 if status.lower() == "error" else 0.4
            entry = {"kind": kind, "service": record_service, "t": timestamp,
                     "summary": record.get("summary") or record.get("message") or record.get("name"),
                     "relevance": round(relevance, 2), "provenance": provenance}
            if environment is not None:
                entry["target_env"] = environment
            freshness(entry, record, kind)
            facts[key] = entry
        if missing_environment:
            unknowns.append({"source": kind, "reason": "records without environment excluded",
                             "count": missing_environment})

    ranked = sorted(facts.values(), key=lambda item: (-item["relevance"], -item["t"],
                                                      item["kind"], item["provenance"]["raw_digest"]))
    recent = sorted(changes.values(), key=lambda item: (-item["t"], item["provenance"]["raw_digest"]))
    unknowns.sort(key=lambda item: (item["source"], item["reason"], item.get("raw_digest", "")))
    stale.sort(key=lambda item: (item["kind"], item["raw_digest"]))
    bundle = {"schema": "telecorr/evidence-bundle/v1", "assistant_version": VERSION,
              "alert": {"alert_id": ident, "service": service, "signal": signal, "raised_at": end},
              "time_window": {"start": start, "end": end, "seconds": window_s},
              "related_services": related, "topology_provenance": topology_provenance,
              "telemetry_excerpts": ranked, "recent_changes": recent,
              "unknowns": unknowns, "stale_inputs": stale,
              "freshness": {"built_at": now, "staleness_limit_s": STALENESS_LIMIT_S},
              "read_only": True, "draft_only": True,
              "note": "Raw-record digests identify canonical JSON content, not authenticity or authorization. Raw provenance may contain sensitive data."}
    if environment is not None:
        bundle["alert"]["target_env"] = environment
    bundle["bundle_digest"] = _digest(bundle)
    return bundle
