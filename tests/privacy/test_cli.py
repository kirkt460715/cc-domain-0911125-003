import contextlib
import io
import json
import pathlib
from tests.support import Case
from rights_graph.cli import main

FIXTURE = pathlib.Path(__file__).resolve().parents[2] / 'fixtures' / 'privacy_demo.json'


class PrivacyCliTests(Case):
    def test_seeded_privacy_demo_is_reproducible(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--db', ':memory:', 'privacy-demo', '--fixture', str(FIXTURE), '--seed', '42'])
        self.assertEqual(code, 0)
        first = json.loads(output.getvalue())
        output.seek(0)
        output.truncate()
        with contextlib.redirect_stdout(output):
            main(['--db', ':memory:', 'privacy-demo', '--fixture', str(FIXTURE), '--seed', '42'])
        second = json.loads(output.getvalue())
        self.assertEqual(first['releases'], second['releases'])
        self.assertEqual(first['randomness'], 'injected_test_randomness')

    def test_demo_exercises_overlap_exhaustion_and_revocation(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(['--db', ':memory:', 'privacy-demo', '--fixture', str(FIXTURE), '--seed', '7'])
        result = json.loads(output.getvalue())
        self.assertTrue(result['overlap_reuse']['charged_zero_epsilon'])
        self.assertTrue(result['budget_exhaustion']['rejected'])
        self.assertTrue(result['budget_exhaustion']['spent_unchanged_after_refusal'])
        self.assertTrue(result['budget_exhaustion']['no_new_release'])
        self.assertFalse(result['revocation']['retrieval_authorized'])
        self.assertTrue(result['postprocessing']['nonnegative'])
        self.assertTrue(result['audit_does_not_leak_exact_values'])
        self.assertTrue(result['ordinary_delivery_entry_still_available'])
        self.assertEqual(result['domain']['epsilon_remaining'], 0.0)
        # every public group, including the empty one, appears in each release
        for release in result['releases']:
            groups = {cell['group'] for cell in release['cells']}
            self.assertIn('empty-isle', groups)

    def test_unseeded_demo_uses_system_randomness(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--db', ':memory:', 'privacy-demo', '--fixture', str(FIXTURE)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['randomness'], 'system_csprng_laplace')

    def test_ordinary_demo_still_runs_alongside_privacy_flow(self):
        ordinary = pathlib.Path(__file__).resolve().parents[2] / 'fixtures' / 'demo.json'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--db', ':memory:', 'demo', '--fixture', str(ordinary)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result['revocation_blocked_export'])
        self.assertTrue(result['integrity'])
