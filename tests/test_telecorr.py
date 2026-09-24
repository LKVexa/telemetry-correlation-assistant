import copy
import unittest

from telecorr.core import build_evidence_bundle, related_services

NOW = 100000.0
ALERT = {"alert_id": "AL-1", "service": "API", "raised_at": NOW - 60,
         "signal": "p99_ms"}

TOPOLOGY = {"edges": [{"from": "api", "to": "db"},
                      {"from": "web", "to": "api"},
                      {"from": "db", "to": "backup"}]}

SOURCES = {
    "topology": TOPOLOGY,
    "logs": [
        {"service": "api", "t": NOW - 120, "level": "error",
         "message": "timeout talking to db"},
        {"service": "db", "t": NOW - 200, "level": "warn",
         "message": "slow query"},
        {"service": "backup", "t": NOW - 100, "level": "error",
         "message": "unrelated 2-hop service"},          # outside 1-hop scope
        {"service": "api", "t": NOW - 90000, "level": "error",
         "message": "old, outside window"},
    ],
    "metrics": [
        {"service": "api", "t": NOW - 100, "metric": "p99_ms", "value": 900,
         "name": "p99_ms spike"},
        {"service": "api", "t": NOW - 100, "metric": "cpu", "value": 40,
         "name": "cpu nominal"},
    ],
    "traces": [
        {"service": "db", "t": NOW - 110, "status": "error",
         "name": "trace-77 db span failed"},
    ],
    "changes": [
        {"service": "db", "t": NOW - 2000, "kind": "deploy", "version": "9.1"},
        {"service": "web", "t": NOW - 500, "kind": "config", "version": "c3"},
        {"service": "db", "t": NOW - 900000, "kind": "deploy", "version": "8.0"},
    ],
}


class Topology(unittest.TestCase):
    def test_one_hop(self):
        self.assertEqual(related_services(TOPOLOGY, "API"), ["db", "web"])

    def test_two_hop(self):
        self.assertEqual(related_services(TOPOLOGY, "api", hops=2),
                         ["backup", "db", "web"])


class Bundle(unittest.TestCase):
    def setUp(self):
        self.b = build_evidence_bundle(ALERT, SOURCES, now=NOW)

    def test_schema_and_identity(self):
        self.assertEqual(self.b["schema"], "telecorr/evidence-bundle/v1")
        self.assertEqual(self.b["alert"]["service"], "api")   # normalized
        self.assertEqual(self.b["related_services"], ["db", "web"])

    def test_window_and_scope_filtering(self):
        summaries = [f["summary"] for f in self.b["telemetry_excerpts"]]
        self.assertIn("timeout talking to db", summaries)
        self.assertIn("slow query", summaries)
        self.assertNotIn("unrelated 2-hop service", summaries)
        self.assertNotIn("old, outside window", summaries)

    def test_ranking(self):
        top = self.b["telemetry_excerpts"][0]
        # own-service error log outranks everything else
        self.assertEqual(top["summary"], "timeout talking to db")
        rels = [f["relevance"] for f in self.b["telemetry_excerpts"]]
        self.assertEqual(rels, sorted(rels, reverse=True))
        sig = next(f for f in self.b["telemetry_excerpts"]
                   if f["summary"] == "p99_ms spike")
        cpu = next(f for f in self.b["telemetry_excerpts"]
                   if f["summary"] == "cpu nominal")
        self.assertGreater(sig["relevance"], cpu["relevance"])

    def test_provenance_on_every_fact(self):
        for f in self.b["telemetry_excerpts"]:
            self.assertTrue(f["provenance"]["raw_digest"].startswith("sha256:"))
            self.assertIn("raw", f["provenance"])
        for c in self.b["recent_changes"]:
            self.assertIn("raw_digest", c["provenance"])

    def test_recent_changes_bounded_and_sorted(self):
        versions = [c["version"] for c in self.b["recent_changes"]]
        self.assertIn("9.1", versions)
        self.assertIn("c3", versions)
        self.assertNotIn("8.0", versions)        # far outside lookback
        ts = [c["t"] for c in self.b["recent_changes"]]
        self.assertEqual(ts, sorted(ts, reverse=True))

    def test_dedup(self):
        doubled = copy.deepcopy(SOURCES)
        doubled["logs"] = doubled["logs"] + doubled["logs"]
        b2 = build_evidence_bundle(ALERT, doubled, now=NOW)
        self.assertEqual(len(b2["telemetry_excerpts"]),
                         len(self.b["telemetry_excerpts"]))

    def test_deterministic(self):
        self.assertEqual(self.b, build_evidence_bundle(ALERT, SOURCES, now=NOW))


class Fixtures(unittest.TestCase):
    """PAPER-CAP-01.5 — partial, stale, conflicting, unauthorized."""

    def test_partial_missing_sources_marked(self):
        b = build_evidence_bundle(ALERT, {"logs": SOURCES["logs"],
                                          "topology": TOPOLOGY}, now=NOW)
        missing = {u["source"] for u in b["unknowns"]}
        self.assertEqual(missing, {"metrics", "traces", "changes"})

    def test_unauthorized_source_marked_not_guessed(self):
        src = dict(SOURCES, metrics={"error": "unauthorized"})
        b = build_evidence_bundle(ALERT, src, now=NOW)
        self.assertIn({"source": "metrics", "reason": "unauthorized"},
                      b["unknowns"])
        self.assertFalse([f for f in b["telemetry_excerpts"]
                          if f["kind"] == "metrics"])

    def test_stale_input_marked(self):
        src = copy.deepcopy(SOURCES)
        src["logs"][0]["observed_at"] = NOW - 90000   # observed long ago
        b = build_evidence_bundle(ALERT, src, now=NOW)
        self.assertEqual(len(b["stale_inputs"]), 1)
        flagged = next(f for f in b["telemetry_excerpts"]
                       if f.get("stale"))
        self.assertEqual(flagged["summary"], "timeout talking to db")

    def test_conflicting_evidence_both_retained(self):
        src = copy.deepcopy(SOURCES)
        src["metrics"].append({"service": "api", "t": NOW - 99,
                               "metric": "p99_ms", "value": 100,
                               "name": "p99_ms nominal (conflicts)"})
        b = build_evidence_bundle(ALERT, src, now=NOW)
        names = [f["summary"] for f in b["telemetry_excerpts"]]
        self.assertIn("p99_ms spike", names)
        self.assertIn("p99_ms nominal (conflicts)", names)

    def test_read_only_draft_only_flags_and_api(self):
        b = build_evidence_bundle(ALERT, SOURCES, now=NOW)
        self.assertTrue(b["read_only"] and b["draft_only"])
        import telecorr.core as m
        for name in dir(m):
            for bad in ("execute", "remediate", "restart", "mutate", "write_"):
                self.assertNotIn(bad, name.lower())

    def test_malformed_alert_rejected(self):
        with self.assertRaises(ValueError):
            build_evidence_bundle({"alert_id": "x"}, SOURCES, now=NOW)


class Hardening(unittest.TestCase):
    """0.1.1-partial regression tests (findings A007-F1..F4)."""

    def test_f1_provenance_isolated_from_caller_mutation(self):
        src = copy.deepcopy(SOURCES)
        b = build_evidence_bundle(ALERT, src, now=NOW)
        from telecorr.core import _digest
        top = b["telemetry_excerpts"][0]
        self.assertIsNot(top["provenance"]["raw"], src["logs"][0])
        src["logs"][0]["message"] = "TAMPERED"
        src["changes"][0]["version"] = "EVIL"
        self.assertNotEqual(top["provenance"]["raw"].get("message"), "TAMPERED")
        self.assertEqual(_digest(top["provenance"]["raw"]),
                         top["provenance"]["raw_digest"])
        for c in b["recent_changes"]:
            self.assertNotEqual(c["provenance"]["raw"].get("version"), "EVIL")

    def test_f2_unauthorized_topology_recorded_in_unknowns(self):
        src = dict(SOURCES, topology={"error": "unauthorized"})
        b = build_evidence_bundle(ALERT, src, now=NOW)
        self.assertIn({"source": "topology", "reason": "unauthorized"},
                      b["unknowns"])
        self.assertEqual(b["related_services"], [])

    def test_f2_missing_topology_still_recorded(self):
        src = {k: v for k, v in SOURCES.items() if k != "topology"}
        b = build_evidence_bundle(ALERT, src, now=NOW)
        self.assertIn({"source": "topology", "reason": "source not supplied"},
                      b["unknowns"])

    def test_f3_malformed_records_raise_valueerror(self):
        cases = []
        s1 = copy.deepcopy(SOURCES); del s1["logs"][0]["t"]; cases.append(s1)
        s2 = copy.deepcopy(SOURCES); s2["logs"][0]["t"] = None; cases.append(s2)
        s3 = copy.deepcopy(SOURCES); s3["topology"] = {"edges": [{"to": "db"}]}
        cases.append(s3)
        s4 = copy.deepcopy(SOURCES); s4["logs"] = {"not": "a list"}
        cases.append(s4)
        s5 = copy.deepcopy(SOURCES); s5["changes"][0]["t"] = "soon"
        cases.append(s5)
        for src in cases:
            with self.assertRaises(ValueError):
                build_evidence_bundle(ALERT, src, now=NOW)

    def test_f3_non_numeric_raised_at_raises_valueerror(self):
        with self.assertRaises(ValueError):
            build_evidence_bundle(dict(ALERT, raised_at=None), SOURCES, now=NOW)

    def test_f4_non_finite_timestamps_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                build_evidence_bundle(dict(ALERT, raised_at=bad), SOURCES,
                                      now=NOW)
        src = copy.deepcopy(SOURCES)
        src["logs"][0]["t"] = float("nan")
        with self.assertRaises(ValueError):
            build_evidence_bundle(ALERT, src, now=NOW)

    def test_f4_digest_rejects_nan_payloads(self):
        from telecorr.core import _digest
        with self.assertRaises(ValueError):
            _digest({"x": float("nan")})

    def test_version_constant(self):
        import telecorr.core as m
        self.assertEqual(m.VERSION, "0.1.2a1")
        self.assertEqual(m.__version__, m.VERSION)


if __name__ == "__main__":
    unittest.main()
