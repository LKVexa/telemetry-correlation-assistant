import copy
import json
import unittest
from unittest.mock import patch

from telecorr.core import build_evidence_bundle, related_services, _digest
from tests.test_telecorr import ALERT, NOW, SOURCES


class SecurityRegressions(unittest.TestCase):
    def bundle(self, sources=None, **kwargs):
        return build_evidence_bundle(ALERT, SOURCES if sources is None else sources,
                                     now=NOW, **kwargs)

    def test_invalid_source_containers(self):
        for value in ([], None, 'credential', {'unknown': []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_evidence_bundle(ALERT, value, now=NOW)

    def test_invalid_record_shapes(self):
        for value in (None, [], 'credential', 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bundle({'logs': [value]})

    def test_invalid_services(self):
        for value in (None, [], True, '', 'a\n', 'a' * 513):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bundle({'logs': [{'service': value, 't': NOW - 100}]})

    def test_window_bounds(self):
        for value in (0, -1, True, float('nan'), float('inf'), 86401):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bundle(window_s=value)

    def test_future_alert_rejected(self):
        with self.assertRaises(ValueError):
            build_evidence_bundle(dict(ALERT, raised_at=NOW + 1), {}, now=NOW)

    def test_negative_historical_timestamps_are_valid(self):
        b = self.bundle({'logs': [{'service': 'api', 't': -100}]})
        self.assertEqual(b['telemetry_excerpts'], [])

    def test_bool_timestamps_rejected(self):
        for field in ('t', 'observed_at'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bundle({'logs': [dict({'service': 'api', 't': NOW-100}, **{field: True})]})

    def test_record_count_limit(self):
        with patch('telecorr.core.MAX_RECORDS', 1), self.assertRaises(ValueError):
            self.bundle({'logs': [{'service': 'api', 't': NOW-100}] * 2})

    def test_record_byte_limit(self):
        with patch('telecorr.core.MAX_RECORD_BYTES', 20), self.assertRaises(ValueError):
            self.bundle({'logs': [{'service': 'api', 't': NOW-100}]})

    def test_aggregate_byte_limit(self):
        record = {'service': 'api', 't': NOW-100, 'message': 'a' * 100}
        with patch('telecorr.core.MAX_INPUT_BYTES', 250), self.assertRaises(ValueError):
            self.bundle({'logs': [record, record]})

    def test_identical_records_in_different_sources_retain_provenance(self):
        record = {'service': 'api', 't': NOW-100}
        b = self.bundle({'logs': [record], 'metrics': [record], 'traces': [record]})
        self.assertEqual({x['provenance']['source'] for x in b['telemetry_excerpts']},
                         {'logs', 'metrics', 'traces'})

    def test_duplicate_changes_and_staleness_deduplicated(self):
        record = {'service': 'api', 't': NOW-100, 'observed_at': NOW-4000}
        b = self.bundle({'changes': [record, record]})
        self.assertEqual(len(b['recent_changes']), 1)
        self.assertEqual(len(b['stale_inputs']), 1)

    def test_duplicate_facts_and_staleness_deduplicated(self):
        record = {'service': 'api', 't': NOW-100, 'observed_at': NOW-4000}
        b = self.bundle({'logs': [record, record]})
        self.assertEqual(len(b['telemetry_excerpts']), 1)
        self.assertEqual(len(b['stale_inputs']), 1)

    def test_permuted_ties_are_deterministic(self):
        records = [{'service': 'api', 't': NOW-100, 'message': x} for x in ('a', 'b')]
        self.assertEqual(self.bundle({'logs': records, 'changes': records}),
                         self.bundle({'logs': records[::-1], 'changes': records[::-1]}))

    def test_future_observation_is_unknown(self):
        b = self.bundle({'logs': [{'service': 'api', 't': NOW-100, 'observed_at': NOW+1}]})
        self.assertTrue(b['telemetry_excerpts'][0]['freshness_unknown'])
        self.assertTrue(any('future' in x['reason'] for x in b['unknowns']))

    def test_stale_threshold_independent_of_window(self):
        b = self.bundle({'logs': [{'service': 'api', 't': NOW-100,
                                  'observed_at': NOW-3601}]}, window_s=10000)
        self.assertTrue(b['telemetry_excerpts'][0]['stale'])

    def test_stale_threshold_boundary(self):
        b = self.bundle({'logs': [{'service': 'api', 't': NOW-100,
                                  'observed_at': NOW-3600}]})
        self.assertEqual(b['stale_inputs'], [])

    def test_topology_provenance_is_detached(self):
        src = copy.deepcopy(SOURCES)
        b = self.bundle(src)
        src['topology']['edges'].clear()
        p = b['topology_provenance']
        self.assertEqual(len(p['raw']['edges']), 3)
        self.assertEqual(p['raw_digest'], _digest(p['raw']))

    def test_environment_filters_records(self):
        records = [{'service': 'api', 't': NOW-100, 'target_env': env} for env in ('prod', 'stage')]
        b = build_evidence_bundle(dict(ALERT, target_env='prod'), {'logs': records}, now=NOW)
        self.assertEqual(len(b['telemetry_excerpts']), 1)
        self.assertEqual(b['telemetry_excerpts'][0]['target_env'], 'prod')

    def test_missing_environment_is_unknown(self):
        b = build_evidence_bundle(dict(ALERT, target_env='prod'),
            {'logs': [{'service': 'api', 't': NOW-100}]}, now=NOW)
        self.assertEqual(b['telemetry_excerpts'], [])
        self.assertIn({'source': 'logs', 'reason': 'records without environment excluded', 'count': 1}, b['unknowns'])

    def test_scoped_records_require_alert_environment(self):
        with self.assertRaises(ValueError):
            self.bundle({'logs': [{'service': 'api', 't': NOW-100, 'target_env': 'prod'}]})

    def test_topology_environment_mismatch_excluded(self):
        b = build_evidence_bundle(dict(ALERT, target_env='prod'),
            {'topology': {'target_env': 'stage', 'edges': [{'from': 'api', 'to': 'db'}]},
             'logs': [{'service': 'db', 't': NOW-100, 'target_env': 'prod'}]}, now=NOW)
        self.assertEqual(b['related_services'], [])
        self.assertEqual(b['telemetry_excerpts'], [])

    def test_edge_scope_requires_consistent_topology_scope(self):
        for topology in ({}, {'target_env': 'stage'}):
            with self.subTest(topology=topology), self.assertRaises(ValueError):
                related_services(dict(topology, edges=[{'from': 'api', 'to': 'db', 'target_env': 'prod'}]), 'api')

    def test_source_errors_redact_details_and_skip_payload(self):
        b = self.bundle({'logs': {'error': 'Bearer credential-example', 'records': [1]}})
        self.assertNotIn('credential-example', json.dumps(b))
        self.assertEqual(b['telemetry_excerpts'], [])

    def test_validation_errors_do_not_echo_records(self):
        with self.assertRaises(ValueError) as caught:
            self.bundle({'logs': [{'service': 'api', 't': 'credential-example'}]})
        self.assertNotIn('credential-example', str(caught.exception))

    def test_nonstring_summary_rejected(self):
        with self.assertRaises(ValueError):
            self.bundle({'logs': [{'service': 'api', 't': NOW-100, 'message': {'nested': 'data'}}]})

    def test_bundle_digest_covers_full_body(self):
        b = self.bundle()
        digest = b.pop('bundle_digest')
        self.assertEqual(digest, _digest(b))
        b['related_services'].append('other')
        self.assertNotEqual(digest, _digest(b))
