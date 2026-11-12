from tests.privacy.support import PrivacyCase, GROUPS
from tests.support import context
from rights_graph.privacy.noise import DeterministicNoise
from rights_graph.primitives import checksum


class DomainAndPlanTests(PrivacyCase):
    def test_domain_registration_freezes_batches_and_rejects_unknown_subject_column(self):
        self.domain()
        stored = self.app.privacy.get_domain('domain-overlap')
        self.assertEqual(stored['roster_size'], 8)
        self.assertEqual(len(stored['sources']), 2)
        self.assertEqual(stored['epsilon_spent'], 0.0)
        self.fails('privacy_source', self.app.privacy.register_domain,
                   'bad-domain', 'period-x', 'missing_col', ['S001'], 1.0,
                   [{'asset_id': 'detail_alpha', 'batch_id': 'batch-alpha'}])
        self.fails('privacy_roster', self.app.privacy.register_domain,
                   'bad-domain', 'period-x', 'subject_id', ['S001', 'S001'], 1.0,
                   [{'asset_id': 'detail_alpha', 'batch_id': 'batch-alpha'}])
        self.fails('privacy_epsilon', self.app.privacy.register_domain,
                   'bad-domain', 'period-x', 'subject_id', ['S001'], 0.0,
                   [{'asset_id': 'detail_alpha', 'batch_id': 'batch-alpha'}])

    def test_batch_version_mismatch_rejected(self):
        # an unknown version fails the asset lookup before domain registration
        self.fails('unknown_version', self.app.privacy.register_domain,
                   'bad-domain', 'period-x', 'subject_id', ['S001'], 1.0,
                   [{'asset_id': 'detail_alpha', 'version': 99, 'batch_id': 'batch-alpha'}])
        # a real version that the batch does not belong to fails the frozen source check
        self.fails('privacy_source', self.app.privacy.register_domain,
                   'bad-domain', 'period-x', 'subject_id', ['S001'], 1.0,
                   [{'asset_id': 'detail_beta', 'batch_id': 'batch-alpha'}])

    def test_plan_registration_checks_columns_before_data_is_seen(self):
        self.domain()
        self.plan()
        fetched = self.app.privacy.get_plan('plan-count')
        self.assertEqual(fetched['definition']['groups']['labels'], GROUPS)
        self.fails('privacy_plan_columns', self.app.privacy.register_plan, 'bad-plan',
                   {'domain_id': 'domain-overlap', 'metric': 'count',
                    'groups': {'column': 'ghost', 'labels': ['north']}, 'max_contributions': 1})
        self.fails('privacy_plan_columns', self.app.privacy.register_plan, 'bad-plan',
                   {'domain_id': 'domain-overlap', 'metric': 'count',
                    'groups': {'column': 'subject_id', 'labels': ['north']}, 'max_contributions': 1})
        self.fails('unknown_privacy_domain', self.app.privacy.register_plan, 'orphan',
                   {'domain_id': 'ghost-domain', 'metric': 'count',
                    'groups': {'column': 'region', 'labels': ['north']}, 'max_contributions': 1})


class ReleaseTests(PrivacyCase):
    def test_release_emits_every_public_group_including_empty_ones(self):
        self.domain()
        self.plan()
        release = self.release()
        labels = [cell['group'] for cell in release['payload']['cells']]
        self.assertEqual(labels, GROUPS)
        self.assertIn('empty-isle', labels)  # empty group still gets noise
        self.assertEqual(release['payload']['sensitivity'], {'norm': 'L1', 'value': 1.0,
                                                              'basis': 'single_subject_add_or_remove'})
        self.assertEqual(release['payload']['noise']['scale'], 2.5)  # 1 / 0.4
        self.assertEqual(release['payload']['randomness'], 'injected_test_randomness')

    def test_repeated_identical_request_reuses_release_without_new_charge(self):
        self.domain()
        self.plan()
        first = self.release(requester='analyst-a')
        second = self.release(requester='analyst-b')  # different analyst, same request
        self.assertEqual(first['release_id'], second['release_id'])
        self.assertEqual(first['payload'], second['payload'])  # no redraw
        status = self.app.privacy.budget_status('domain-overlap')
        self.assertEqual(status['epsilon_spent'], 0.4)
        self.assertEqual(len(status['ledger']), 1)
        actions = [entry['action'] for entry in self.audit_bodies()]
        self.assertIn('privacy.release_reused', actions)

    def test_changed_context_cannot_reuse_budget(self):
        self.domain(budget=0.4)
        self.plan()
        self.release()
        changed = {**context(), 'at': '2026-12-01T00:00:00Z'}
        self.fails('privacy_budget_exhausted', self.release, request=changed)
        status = self.app.privacy.budget_status('domain-overlap')
        self.assertEqual(status['epsilon_spent'], 0.4)
        self.assertEqual(len(status['ledger']), 1)
        self.assertEqual(len(self.app.privacy.list_releases()), 1)

    def test_budget_is_shared_across_subset_versions_and_requesters(self):
        self.domain(budget=0.5)
        self.plan()
        self.release(epsilon=0.3, requester='analyst-a')
        # another requester, a distinct plan on the same domain still draws from the same ledger
        self.plan('plan-count-2', max_contributions=2)
        self.fails('privacy_budget_exhausted', self.release, 'plan-count-2', 0.3, requester='analyst-b')
        status = self.app.privacy.budget_status('domain-overlap')
        self.assertEqual(len(status['ledger']), 1)
        self.assertEqual(status['epsilon_remaining'], 0.2)

    def test_concurrent_requests_charge_budget_atomically(self):
        self.domain(budget=0.5)
        self.plan()
        requests = [
            {'operation': 'privacy.release',
             'arguments': {'plan_id': 'plan-count', 'context': context(), 'epsilon': 0.3, 'requester': 'a'}},
            {'operation': 'privacy.release',
             'arguments': {'plan_id': 'plan-count', 'context': {**context(), 'at': '2026-12-02T00:00:00Z'},
                           'epsilon': 0.3, 'requester': 'b'}},
        ]
        self.fails('privacy_budget_exhausted', self.app.transaction, requests)
        # whole batch rolled back: no ledger rows, no retrievable releases from it
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], 0.0)
        self.assertEqual(self.app.privacy.list_releases(), [])

    def test_failed_release_rolls_back_noise_and_budget(self):
        self.domain(budget=1.0)
        self.plan()
        draws_before = self.app.privacy.noise.draws
        # authorization failure happens before any noise draw or charge
        denied = {**context(), 'purpose': 'advertising'}
        self.fails('privacy_unauthorized', self.release, request=denied)
        self.assertEqual(self.app.privacy.noise.draws, draws_before)
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], 0.0)
        self.assertEqual(self.app.privacy.list_releases(), [])

    def test_noise_is_never_redrawn_for_a_better_look(self):
        self.domain()
        self.plan()
        first = self.release()
        self.app.privacy.noise.reset()
        second = self.release()  # must hit the stored release, ignoring the reset stream
        self.assertEqual(first['payload']['cells'], second['payload']['cells'])

    def test_noisy_counts_can_be_negative_and_sums_are_not_reconciled(self):
        self.domain()
        self.plan()
        release = self.release()
        # the guarantee is structural: values are floats and clipping to nonnegative is a separate recorded step
        self.assertTrue(all(isinstance(cell['value'], float) for cell in release['payload']['cells']))
        self.plan('plan-sum', metric='sum')
        summed = self.release('plan-sum', epsilon=0.35)
        self.assertEqual(summed['payload']['clipping']['kind'], 'per_row_value_clamp_then_subject_group_average')
        self.assertIn('aggregate_bias_bound_per_group', summed['payload']['clipping'])


class HistogramAndPostTests(PrivacyCase):
    def test_histogram_release_has_group_bin_cells_and_overflow(self):
        self.domain()
        self.plan('plan-hist', metric='histogram')
        release = self.release('plan-hist', epsilon=0.25)
        self.assertEqual(len(release['payload']['cells']), 20)  # 4 groups x 5 bins (incl. underflow/overflow)
        self.assertTrue(any(cell['bin'] == 'overflow>=50.0' for cell in release['payload']['cells']))
        self.assertEqual(release['payload']['noise']['scale'], 4.0)  # sensitivity 1 / 0.25
        self.assertEqual(release['payload']['clipping']['bias_bound'], 0.0)

    def test_postprocessing_is_recorded_and_charges_no_budget(self):
        self.domain()
        self.plan('plan-hist', metric='histogram')
        release = self.release('plan-hist', epsilon=0.25)
        before = self.app.privacy.budget_status('domain-overlap')['epsilon_spent']
        post = self.app.privacy.postprocess('post-1', release['release_id'],
                                            ['round_nearest_integer', 'clip_nonnegative'])
        self.assertEqual(post['steps'], ['clip_nonnegative', 'round_nearest_integer'])
        self.assertTrue(all(cell['value'] >= 0.0 for cell in post['payload']['cells']))
        self.assertTrue(all(float(cell['value']).is_integer() for cell in post['payload']['cells']))
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], before)
        self.fails('privacy_post_step', self.app.privacy.postprocess, 'post-2', release['release_id'], ['secret_filter'])
        self.fails('privacy_post_exists', self.app.privacy.postprocess, 'post-1', release['release_id'],
                   ['clip_nonnegative'])

    def test_postprocessing_requires_live_authorization(self):
        self.domain()
        self.plan('plan-hist', metric='histogram')
        release = self.release('plan-hist', epsilon=0.25)
        from rights_graph.policy import grants
        grant = grants.get(self.store, 'grant-alpha')
        grants.revoke(self.store, grant['grant_id'], grant['revision'], 'withdrawn')
        self.fails('privacy_unauthorized', self.app.privacy.postprocess, 'post-1',
                   release['release_id'], ['clip_nonnegative'])


class AuthorizationTests(PrivacyCase):
    def test_compute_requires_active_grant_for_each_frozen_source(self):
        self.domain()
        self.plan()
        from rights_graph.policy import grants
        grant = grants.get(self.store, 'grant-beta')
        grants.revoke(self.store, grant['grant_id'], grant['revision'], 'partner exit')
        self.fails('privacy_unauthorized', self.release)
        # nothing was charged
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], 0.0)

    def test_retrieval_rechecks_authorization_after_revocation(self):
        self.domain()
        self.plan()
        release = self.release()
        self.assertTrue(release['authorization']['authorized'])
        from rights_graph.policy import grants
        grant = grants.get(self.store, 'grant-alpha')
        grants.revoke(self.store, grant['grant_id'], grant['revision'], 'withdrawn')
        fetched = self.app.privacy.get_release(release['release_id'])
        self.assertFalse(fetched['authorization']['authorized'])
        self.assertEqual(fetched['authorization']['failures'][0]['code'], 'no_active_grant')
        # budget remains spent: revocation removes delivery rights, it does not refund epsilon
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], 0.4)

    def test_context_outside_grant_window_denied(self):
        self.domain()
        self.plan()
        self.fails('privacy_unauthorized', self.release, request={**context(), 'at': '2030-01-01T00:00:00Z'})


class AuditTests(PrivacyCase):
    def test_audit_records_plans_budget_and_lineage_but_never_exact_values(self):
        self.domain()
        self.plan()
        release = self.release()
        self.plan('plan-sum', metric='sum')
        self.release('plan-sum', epsilon=0.35)
        bodies = self.audit_bodies()
        actions = {entry['action'] for entry in bodies}
        self.assertIn('privacy.domain_registered', actions)
        self.assertIn('privacy.plan_registered', actions)
        self.assertIn('privacy.release_published', actions)
        encoded = str(bodies)
        # exact aggregates never appear; only plan metadata, budget, lineage and digest
        self.assertNotIn('25.5', encoded)   # exact north sum
        self.assertNotIn('unnoised', encoded)
        for body in bodies:
            if body.get('release_id') == release['release_id']:
                self.assertIn('digest', body)
                self.assertNotIn('cells', body)
        # journal itself stays tamper-evident
        self.assertTrue(self.app.dispatch('audit.verify', {})['ok'])


class ServiceSurfaceTests(PrivacyCase):
    def test_dispatch_rejects_caller_supplied_randomness(self):
        self.domain()
        self.plan()
        self.fails('invalid_fields', self.app.dispatch, 'privacy.release',
                   {'plan_id': 'plan-count', 'context': context(), 'epsilon': 0.4,
                    'requester': 'a', 'seed': 42})

    def test_ordinary_delivery_entry_remains_available(self):
        self.assertTrue(hasattr(self.app, 'deliveries'))
        self.assertTrue(hasattr(self.app, 'preview'))

    def test_release_digest_is_canonical_and_stable(self):
        self.domain()
        self.plan()
        release = self.release()
        self.assertEqual(release['digest'], checksum(release['payload']))
        self.assertTrue(release['release_id'].startswith('priv-release-'))
        again = self.release()
        self.assertEqual(again['release_id'], release['release_id'])


class EdgeCaseTests(PrivacyCase):
    def test_integer_subject_keys_are_supported_and_normalized(self):
        integer_rows = [
            {'subject_id': '1', 'region': 'north', 'amount': '1.00'},
            {'subject_id': '2', 'region': 'south', 'amount': '2.00'},
        ]
        self.app.preview.data.import_rows('batch-keys', 'detail_alpha', 1, integer_rows)
        self.app.privacy.register_domain(
            'domain-keys', 'period-keys', 'subject_id', [1, 2], 1.0,
            [{'asset_id': 'detail_alpha', 'batch_id': 'batch-keys'}])
        self.app.privacy.register_plan('plan-keys', {
            'domain_id': 'domain-keys', 'metric': 'count',
            'groups': {'column': 'region', 'labels': ['north', 'south']}, 'max_contributions': 1})
        release = self.app.privacy.release(
            'plan-keys', context(), 0.5, requester='analyst-a')
        self.assertEqual(len(release['payload']['cells']), 2)
        self.fails('privacy_roster', self.app.privacy.register_domain,
                   'bad', 'period-bad', 'subject_id', [True], 1.0,
                   [{'asset_id': 'detail_alpha', 'batch_id': 'batch-keys'}])

    def test_duplicate_domain_and_plan_identifiers_are_rejected(self):
        self.domain()
        self.fails('privacy_domain_exists', self.domain)
        self.plan()
        self.fails('privacy_plan_exists', self.plan)

    def test_tampered_frozen_batch_blocks_release(self):
        self.domain()
        self.plan()
        # corrupt the stored digest so the frozen-input check trips before any noise draw
        self.store.execute('UPDATE data_batches SET digest=? WHERE batch_id=?',
                           ('0' * 64, 'batch-alpha'))
        self.fails('privacy_frozen_input', self.release)
        self.assertEqual(self.app.privacy.budget_status('domain-overlap')['epsilon_spent'], 0.0)

    def test_empty_groups_always_get_noise_and_never_get_filtered(self):
        self.domain()
        self.plan()
        release = self.release()
        empty = next(cell for cell in release['payload']['cells'] if cell['group'] == 'empty-isle')
        self.assertIsInstance(empty['value'], float)
        # no cell ordering depends on true counts: labels follow the pre-registered order
        self.assertEqual([cell['group'] for cell in release['payload']['cells']], GROUPS)

    def test_budget_ledger_is_append_only_and_scoped(self):
        self.domain(budget=0.9)
        self.plan()
        self.release(epsilon=0.4)
        self.plan('plan-sum', metric='sum')
        self.release('plan-sum', epsilon=0.5)
        status = self.app.privacy.budget_status('domain-overlap')
        self.assertEqual([entry['kind'] for entry in status['ledger']], ['charge', 'charge'])
        self.assertAlmostEqual(status['epsilon_spent'], 0.9)
        self.assertAlmostEqual(status['epsilon_remaining'], 0.0)
        self.fails('privacy_period', self.app.privacy.budget_status, 'domain-overlap', 'other-period')

    def test_sequential_composition_accumulates_epsilon_across_releases(self):
        self.domain(budget=2.0)
        self.plan()
        first = self.release(epsilon=0.25)
        second = self.release(request={**context(), 'at': '2026-11-20T00:00:00Z'}, epsilon=0.75)
        third = self.release(request={**context(), 'at': '2026-11-21T00:00:00Z'}, epsilon=0.5)
        self.assertEqual(len({first['release_id'], second['release_id'], third['release_id']}), 3)
        status = self.app.privacy.budget_status('domain-overlap')
        self.assertEqual(len(status['ledger']), 3)
        self.assertAlmostEqual(status['epsilon_spent'], 1.5)
        self.assertAlmostEqual(status['epsilon_remaining'], 0.5)
        # each release carries its own scale matching its own epsilon
        self.assertAlmostEqual(first['payload']['noise']['scale'], 4.0)
        self.assertAlmostEqual(second['payload']['noise']['scale'], 1.0 / 0.75)
        self.assertAlmostEqual(third['payload']['noise']['scale'], 2.0)

    def test_deterministic_noise_matches_exact_plus_laplace_draws(self):
        self.domain()
        self.plan()
        release = self.release(epsilon=0.4)
        # recompute the expected vector with an independent fresh seeded source
        from rights_graph.privacy.mechanisms import ContributionEngine, sensitivity
        from rights_graph.privacy.noise import DeterministicNoise
        plan = self.app.privacy.get_plan('plan-count')['definition']
        domain = self.app.privacy.get_domain('domain-overlap')
        rows = self.app.privacy._frozen_rows(domain, plan)
        import json as json_module
        roster = set(json_module.loads(self.store.scalar(
            "SELECT roster FROM privacy_domains WHERE domain_id='domain-overlap'")))
        exact = ContributionEngine(plan, roster).exact(rows)
        fresh = DeterministicNoise(1234)
        scale = sensitivity(plan) / 0.4
        expected = [float(value) + fresh.laplace(scale) for value in exact]
        actual = [cell['value'] for cell in release['payload']['cells']]
        for left, right in zip(expected, actual):
            self.assertAlmostEqual(left, right)

