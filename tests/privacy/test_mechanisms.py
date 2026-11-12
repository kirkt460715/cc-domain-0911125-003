import math
from tests.support import Case
from rights_graph.privacy.noise import DeterministicNoise, SystemNoise, laplace_inverse_cdf, NoiseError
from rights_graph.privacy.mechanisms import (
    normalize_plan, sensitivity, ContributionEngine, release_vector, bin_labels, assign_bin,
)


class NoiseTests(Case):
    def test_inverse_cdf_matches_laplace_quantiles(self):
        self.assertAlmostEqual(laplace_inverse_cdf(0.5, 2.0), 0.0)
        self.assertAlmostEqual(laplace_inverse_cdf(0.25, 2.0), 2.0 * math.log(0.5))
        self.assertAlmostEqual(laplace_inverse_cdf(0.75, 2.0), -2.0 * math.log(0.5))
        self.fails_noise(NoiseError, laplace_inverse_cdf, 0.0, 1.0)
        self.fails_noise(NoiseError, laplace_inverse_cdf, 0.5, 0.0)

    def fails_noise(self, kind, function, *args):
        with self.assertRaises(kind):
            function(*args)

    def test_deterministic_source_is_replayable(self):
        left = DeterministicNoise(7)
        right = DeterministicNoise(7)
        draws_left = [left.laplace(1.5) for _ in range(5)]
        draws_right = [right.laplace(1.5) for _ in range(5)]
        self.assertEqual(draws_left, draws_right)
        other = DeterministicNoise(8)
        self.assertNotEqual(draws_left, [other.laplace(1.5) for _ in range(5)])

    def test_system_noise_is_unseedable_and_finite(self):
        noise = SystemNoise()
        self.assertTrue(all(math.isfinite(noise.laplace(3.0)) for _ in range(20)))
        with self.assertRaises(TypeError):
            SystemNoise(1234)  # type: ignore[misc]

    def test_bad_seed_rejected(self):
        with self.assertRaises(NoiseError):
            DeterministicNoise(-1)
        with self.assertRaises(NoiseError):
            DeterministicNoise(1.5)  # type: ignore[arg-type]


class MechanismTests(Case):
    def _rows(self):
        return [
            {'__subject__': 'a', 'region': 'north', 'amount': '10'},
            {'__subject__': 'a', 'region': 'south', 'amount': '40'},
            {'__subject__': 'b', 'region': 'north', 'amount': '100'},
            {'__subject__': 'c', 'region': 'west', 'amount': '5'},
            {'__subject__': None, 'region': 'north', 'amount': '5'},
            {'__subject__': 'd', 'region': 'unknown-label', 'amount': '5'},
        ]

    def test_plan_validation(self):
        self.fails('invalid_fields', normalize_plan, 'p', {'domain_id': 'd', 'metric': 'count'})
        self.fails('privacy_metric', normalize_plan, 'p',
                   {'domain_id': 'd', 'metric': 'median',
                    'groups': {'column': 'region', 'labels': ['north']}, 'max_contributions': 1})
        self.fails('privacy_groups', normalize_plan, 'p',
                   {'domain_id': 'd', 'metric': 'count',
                    'groups': {'column': 'region', 'labels': ['north', 'north']}, 'max_contributions': 1})
        self.fails('privacy_bounds', normalize_plan, 'p',
                   {'domain_id': 'd', 'metric': 'sum',
                    'groups': {'column': 'region', 'labels': ['north']}, 'max_contributions': 1,
                    'value_column': 'amount', 'clamp': {'low': 5.0, 'high': 5.0}})
        self.fails('privacy_histogram', normalize_plan, 'p',
                   {'domain_id': 'd', 'metric': 'histogram',
                    'groups': {'column': 'region', 'labels': ['north']}, 'max_contributions': 1,
                    'value_column': 'amount', 'histogram': {'edges': [1.0, 1.0]}})
        self.fails('privacy_histogram', normalize_plan, 'p',
                   {'domain_id': 'd', 'metric': 'histogram',
                    'groups': {'column': 'region', 'labels': ['north']}, 'max_contributions': 1,
                    'value_column': 'amount',
                    'histogram': {'edges': [1.0, 2.0], 'include_overflow': False}})

    def test_count_sensitivity_and_contribution_cap(self):
        plan = normalize_plan('p', {'domain_id': 'd', 'metric': 'count',
                                    'groups': {'column': 'region', 'labels': ['north', 'south', 'west', 'empty']},
                                    'max_contributions': 1})
        self.assertEqual(sensitivity(plan), 1.0)
        exact = ContributionEngine(plan, {'a', 'b', 'c', 'd'}).exact(self._rows())
        # a keeps north (first label order), b north, c west; null and unknown-label rows excluded
        self.assertEqual(exact, [2, 0, 1, 0])
        plan_two = normalize_plan('p2', {'domain_id': 'd', 'metric': 'count',
                                         'groups': {'column': 'region', 'labels': ['north', 'south', 'west', 'empty']},
                                         'max_contributions': 2})
        self.assertEqual(sensitivity(plan_two), 2.0)
        self.assertEqual(ContributionEngine(plan_two, {'a', 'b', 'c', 'd'}).exact(self._rows()), [2, 1, 1, 0])

    def test_sum_clips_and_averages_per_subject_group(self):
        plan = normalize_plan('p', {'domain_id': 'd', 'metric': 'sum',
                                    'groups': {'column': 'region', 'labels': ['north', 'south', 'west', 'empty']},
                                    'max_contributions': 1, 'value_column': 'amount',
                                    'clamp': {'low': 0.0, 'high': 50.0},
                                    'raw_domain': {'low': 0.0, 'high': 100.0}})
        self.assertEqual(sensitivity(plan), 50.0)
        exact = ContributionEngine(plan, {'a', 'b', 'c', 'd'}).exact(self._rows())
        # a -> north average 10; b -> north clipped 50; c -> west 5
        self.assertEqual([float(value) for value in exact], [60.0, 0.0, 5.0, 0.0])

    def test_histogram_uses_overflow_bin_and_unit_sensitivity(self):
        plan = normalize_plan('p', {'domain_id': 'd', 'metric': 'histogram',
                                    'groups': {'column': 'region', 'labels': ['north', 'south', 'west', 'empty']},
                                    'max_contributions': 1, 'value_column': 'amount',
                                    'histogram': {'edges': [0.0, 10.0, 50.0]}})
        self.assertEqual(bin_labels(plan['histogram']),
                         ['(-inf,0.0)', '[0.0,10.0)', '[10.0,50.0)', 'overflow>=50.0'])
        self.assertEqual(assign_bin(plan['histogram'], 100.0), 3)
        self.assertEqual(assign_bin(plan['histogram'], -1.0), 0)
        self.assertEqual(sensitivity(plan), 1.0)
        exact = ContributionEngine(plan, {'a', 'b', 'c', 'd'}).exact(self._rows())
        north = exact[0]  # a votes bin1 (10), b votes overflow (100 clipped only for sums)
        self.assertAlmostEqual(sum(north), 2.0)
        self.assertAlmostEqual(north[3], 1.0)  # b's 100 lands in overflow
        empty = exact[3]
        self.assertEqual(empty, [0.0, 0.0, 0.0, 0.0])  # empty group still emitted

    def test_laplace_scale_equals_sensitivity_over_epsilon(self):
        plan = normalize_plan('p', {'domain_id': 'd', 'metric': 'count',
                                    'groups': {'column': 'region', 'labels': ['north', 'south']},
                                    'max_contributions': 2})
        noise = DeterministicNoise(99)
        noisy, scale = release_vector(plan, [3, 0], 0.5, noise)
        self.assertEqual(scale, 4.0)  # sensitivity 2 / epsilon 0.5
        self.assertEqual(len(noisy), 2)
        # rerun with a fresh identical source gives identical draws; no silent redraw
        again, _ = release_vector(plan, [3, 0], 0.5, DeterministicNoise(99))
        self.assertEqual(noisy, again)

    def test_neighboring_datasets_differ_by_at_most_sensitivity(self):
        plan = normalize_plan('p', {'domain_id': 'd', 'metric': 'sum',
                                    'groups': {'column': 'region', 'labels': ['north', 'south']},
                                    'max_contributions': 1, 'value_column': 'amount',
                                    'clamp': {'low': 0.0, 'high': 10.0}})
        roster = {'a', 'b'}
        base = [{'__subject__': 'a', 'region': 'north', 'amount': '10'},
                {'__subject__': 'b', 'region': 'south', 'amount': '10'}]
        with_subject = ContributionEngine(plan, roster).exact(base)
        without = ContributionEngine(plan, roster).exact(base[:1])
        l1 = sum(abs(float(x) - float(y)) for x, y in zip(with_subject, without))
        self.assertLessEqual(l1, sensitivity(plan))
