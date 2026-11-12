"""Pre-registered statistics, subject-level contribution bounding and the Laplace mechanism.

Adjacency declaration
---------------------
Two frozen inputs are adjacent when one can be obtained from the other by
adding or removing *one whole subject*: every row carrying that subject's
stable key, across every included data version, appears or disappears
together.  Rows are never independent units.

Contribution model
------------------
A subject may appear in many rows and several frozen batches.  Before any
noise is added, per subject:

* rows outside the public roster, with an unmatched public group label or a
  null subject key are excluded;
* the subject keeps at most ``max_contributions`` distinct groups, chosen by a
  deterministic public ordering (group label order), so the rule itself does
  not leak anything beyond the pre-registered plan;
* inside a retained group the subject contributes 1 to a count, one clipped
  average to a sum (the mean of its per-row clipped values), and one
  probability vector over bins to a histogram (each present row votes once
  over the public bins, including the overflow bin).

Sensitivities (L1, per subject add/remove)
------------------------------------------
* count vector over the public groups:            C = max_contributions
* sum vector over the public groups:               C * (high - low)
* histogram vector (group x bin, one vector):      C

The Laplace mechanism with L1 sensitivity ``s`` and budget ``epsilon`` adds
independent Laplace noise with scale ``s / epsilon`` to every cell of the
released vector, which gives pure epsilon-DP for the whole multi-group
release (sequential composition over releases, parallel within the vector).
"""
import math
from decimal import Decimal, InvalidOperation
from rights_graph.primitives import checksum, count, fields, label, name, reject

METRICS = ('count', 'sum', 'histogram')


def _finite_number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        reject('privacy_number', 'Expected a finite JSON number', field=field)
    if not math.isfinite(value):
        reject('privacy_number', 'Expected a finite JSON number', field=field)
    return float(value)


def _bounds(value):
    fields(value, {'low', 'high'})
    low = _finite_number(value['low'], 'low')
    high = _finite_number(value['high'], 'high')
    if not low < high:
        reject('privacy_bounds', 'Lower bound must be strictly below upper bound')
    return {'low': low, 'high': high}


def normalize_groups(value):
    fields(value, {'column', 'labels'})
    name(value['column'], 'group_column')
    labels = value['labels']
    if not isinstance(labels, list) or not 1 <= len(labels) <= 1000:
        reject('privacy_groups', 'Public groups need one to one thousand pre-registered labels')
    normalized = [label(item, 'group_label', maximum=200) for item in labels]
    if len(normalized) != len(set(normalized)):
        reject('privacy_groups', 'Public group labels must be unique')
    return {'column': value['column'], 'labels': normalized}


def normalize_histogram(value):
    fields(value, {'edges'}, {'include_overflow'})
    edges = value['edges']
    if not isinstance(edges, list) or not 1 <= len(edges) <= 200:
        reject('privacy_histogram', 'Histogram needs one to two hundred bin edges')
    normalized_edges = [_finite_number(edge, 'bin_edge') for edge in edges]
    if any(left >= right for left, right in zip(normalized_edges, normalized_edges[1:])):
        reject('privacy_histogram', 'Bin edges must be strictly increasing')
    include_overflow = value.get('include_overflow', True)
    if type(include_overflow) is not bool:
        reject('privacy_histogram', 'include_overflow must be boolean')
    if not include_overflow:
        reject('privacy_histogram', 'Out-of-range values require an explicit overflow bin')
    return {'edges': normalized_edges, 'include_overflow': True}


def bin_labels(histogram):
    edges = histogram['edges']
    labels = [f'(-inf,{edges[0]})']
    labels.extend(f'[{edges[index]},{edges[index + 1]})' for index in range(len(edges) - 1))
    labels.append(f'overflow>={edges[-1]}')
    return labels


def assign_bin(histogram, numeric_value):
    edges = histogram['edges']
    if numeric_value < edges[0]:
        return 0
    for index in range(len(edges) - 1):
        if edges[index] <= numeric_value < edges[index + 1]:
            return index + 1
    return len(edges)  # overflow bin (includes the upper boundary)


def normalize_plan(plan_id, value):
    """Validate a statistic plan.  No data is read at registration time."""
    fields(value, {'domain_id', 'metric', 'groups', 'max_contributions'},
           {'value_column', 'clamp', 'raw_domain', 'histogram', 'description'})
    name(plan_id, 'plan_id')
    name(value['domain_id'], 'domain_id')
    metric = value['metric']
    if metric not in METRICS:
        reject('privacy_metric', 'Unsupported statistic metric', metric=metric)
    cap = count(value['max_contributions'], 'max_contributions', 1, 1000)
    groups = normalize_groups(value['groups'])
    normalized = {
        'plan_id': plan_id,
        'domain_id': value['domain_id'],
        'metric': metric,
        'groups': groups,
        'max_contributions': cap,
        'description': label(value.get('description', 'Pre-registered private statistic'), 'description'),
    }
    if metric == 'sum':
        if 'value_column' not in value or 'clamp' not in value:
            reject('privacy_plan', 'Sum statistic requires value_column and clamp')
        name(value['value_column'], 'value_column')
        normalized['value_column'] = value['value_column']
        normalized['clamp'] = _bounds(value['clamp'])
        normalized['raw_domain'] = _bounds(value['raw_domain']) if 'raw_domain' in value else dict(normalized['clamp'])
        if not (normalized['raw_domain']['low'] <= normalized['clamp']['low']
                < normalized['clamp']['high'] <= normalized['raw_domain']['high']):
            reject('privacy_bounds', 'Clamping range must sit inside the declared raw value domain')
    if metric == 'histogram':
        if 'value_column' not in value or 'histogram' not in value:
            reject('privacy_plan', 'Histogram statistic requires value_column and histogram')
        name(value['value_column'], 'value_column')
        normalized['value_column'] = value['value_column']
        normalized['histogram'] = normalize_histogram(value['histogram'])
    return normalized


def plan_digest(plan):
    return checksum({key: plan[key] for key in plan if key != 'plan_id'})


def sensitivity(plan):
    """Declared L1 sensitivity of the whole released vector under subject add/remove."""
    cap = plan['max_contributions']
    metric = plan['metric']
    if metric == 'count':
        return float(cap)
    if metric == 'histogram':
        return float(cap)
    width = Decimal(str(plan['clamp']['high'])) - Decimal(str(plan['clamp']['low']))
    return float(Decimal(cap) * width)


def _subject_key(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _as_decimal(value, column_name):
    if isinstance(value, bool) or value is None:
        reject('privacy_value', 'Aggregation value must be numeric', column=column_name)
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        reject('privacy_value', 'Aggregation value must be numeric', column=column_name)
        raise AssertionError(exc)
    if not parsed.is_finite():
        reject('privacy_value', 'Aggregation value must be finite', column=column_name)
    return parsed


class ContributionEngine:
    """Computes the exact pre-registered aggregate from frozen rows.

    Exact values are returned only to the mechanism layer inside the release
    transaction; they are never persisted and never written to the audit log.
    """

    def __init__(self, plan, roster):
        self.plan = plan
        self.roster = roster
        self.labels = plan['groups']['labels']
        self.label_order = {label: index for index, label in enumerate(self.labels)}
        self.cap = plan['max_contributions']

    def _retain_groups(self, group_set):
        if len(group_set) <= self.cap:
            return group_set
        chosen = sorted(group_set, key=lambda label: self.label_order[label])[:self.cap]
        return set(chosen)

    def collect(self, rows):
        """Fold rows (each a payload dict) into per-subject contributions."""
        metric = self.plan['metric']
        group_column = self.plan['groups']['column']
        if metric == 'count':
            seen = {}
            for row in rows:
                key = _subject_key(row.get('__subject__'))
                if key is None or key not in self.roster:
                    continue
                label = row.get(group_column)
                if label not in self.label_order:
                    continue
                seen.setdefault(key, set()).add(label)
            return {key: self._retain_groups(groups) for key, groups in seen.items()}
        value_column = self.plan['value_column']
        if metric == 'sum':
            low = Decimal(str(self.plan['clamp']['low']))
            high = Decimal(str(self.plan['clamp']['high']))
            collected = {}
            for row in rows:
                key = _subject_key(row.get('__subject__'))
                if key is None or key not in self.roster:
                    continue
                label = row.get(group_column)
                if label not in self.label_order:
                    continue
                amount = _as_decimal(row.get(value_column), value_column)
                clamped = min(max(amount, low), high)
                collected.setdefault(key, {}).setdefault(label, []).append(clamped)
            result = {}
            for key, per_group in collected.items():
                retained = self._retain_groups(set(per_group))
                result[key] = {label: sum(values) / Decimal(len(values))
                               for label, values in per_group.items() if label in retained}
            return result
        histogram = self.plan['histogram']
        bin_count = len(histogram['edges']) + 1
        collected = {}
        for row in rows:
            key = _subject_key(row.get('__subject__'))
            if key is None or key not in self.roster:
                continue
            label = row.get(group_column)
            if label not in self.label_order:
                continue
            amount = float(_as_decimal(row.get(value_column), value_column))
            bin_index = assign_bin(histogram, amount)
            votes = collected.setdefault(key, {}).setdefault(label, [0] * bin_count)
            votes[bin_index] += 1
        result = {}
        for key, per_group in collected.items():
            retained = self._retain_groups(set(per_group))
            result[key] = {}
            for label in retained:
                votes = per_group[label]
                total = sum(votes)
                result[key][label] = [vote / total for vote in votes]
        return result

    def exact(self, rows):
        """Aggregate subject contributions into the exact (unnoised) vector."""
        contributions = self.collect(rows)
        metric = self.plan['metric']
        if metric == 'count':
            vector = {label: 0 for label in self.labels}
            for groups in contributions.values():
                for label in groups:
                    vector[label] += 1
            return [vector[label] for label in self.labels]
        if metric == 'sum':
            vector = {label: Decimal('0') for label in self.labels}
            for per_group in contributions.values():
                for label, amount in per_group.items():
                    vector[label] += amount
            return [vector[label] for label in self.labels]
        bin_count = len(self.plan['histogram']['edges']) + 1
        vector = {label: [0.0] * bin_count for label in self.labels}
        for per_group in contributions.values():
            for label, probabilities in per_group.items():
                for index, probability in enumerate(probabilities):
                    vector[label][index] += probability
        return [vector[label] for label in self.labels]


def _decimal_to_number(value):
    if isinstance(value, Decimal):
        return float(value)
    return float(value)


def _flatten(plan, exact_values):
    if plan['metric'] == 'histogram':
        return [value for row in exact_values for value in row]
    return [_decimal_to_number(value) for value in exact_values]


def release_vector(plan, exact_values, epsilon, noise):
    """Apply the Laplace mechanism to one pre-registered vector.

    The histogram is one L1-sensitive vector of group x bin cells, so every
    cell draws independent Laplace noise with the same scale.
    """
    flat = _flatten(plan, exact_values)
    scale = sensitivity(plan) / epsilon
    noises = noise.laplace_vector([scale] * len(flat))
    noisy_flat = [value + draw for value, draw in zip(flat, noises)]
    if plan['metric'] == 'histogram':
        width = len(plan['histogram']['edges']) + 1
        noisy = [noisy_flat[index:index + width] for index in range(0, len(noisy_flat), width)]
        return noisy, scale
    return noisy_flat, scale


def error_explanation(plan, epsilon, scale, roster_size):
    """Public error description: distribution, scales, and clipping bias bounds."""
    explanation = {
        'mechanism': 'laplace',
        'privacy_model': 'pure_epsilon_differential_privacy',
        'adjacency': 'add_or_remove_one_subject_all_rows_and_frozen_versions',
        'epsilon': float(epsilon),
        'noise_scale': float(scale),
        'noise_distribution': {
            'family': 'Laplace',
            'location': 0.0,
            'scale': float(scale),
            'mean_absolute_error': float(scale),
            'standard_deviation': float(math.sqrt(2) * scale),
        },
        'guarantees': [
            'Each cell receives independent Laplace noise with the declared scale.',
            'Noisy counts may be negative and noisy group sums are not promised to equal any other total.',
            'Empty public groups are still emitted and receive the same noise distribution.',
        ],
        'sensitivity': {'norm': 'L1', 'value': sensitivity(plan), 'basis': 'single_subject_add_or_remove'},
    }
    if plan['metric'] == 'count':
        explanation['clipping'] = {
            'kind': 'per_subject_group_contribution_cap',
            'max_contributions': plan['max_contributions'],
            'bias_bound_per_group': roster_size,
            'bias_note': 'A subject contributing to more groups than the cap loses whole-group contributions; '
                         'per-group exact count is biased downward by at most the public roster size.',
        }
    elif plan['metric'] == 'sum':
        clamp = plan['clamp']
        raw = plan['raw_domain']
        width = max(abs(Decimal(str(clamp['low'])) - Decimal(str(raw['low']))),
                    abs(Decimal(str(raw['high'])) - Decimal(str(clamp['high']))))
        explanation['clipping'] = {
            'kind': 'per_row_value_clamp_then_subject_group_average',
            'clamp_low': clamp['low'],
            'clamp_high': clamp['high'],
            'declared_raw_domain': raw,
            'per_subject_per_group_bias_bound': float(width),
            'aggregate_bias_bound_per_group': float(Decimal(roster_size) * width),
            'bias_note': 'Bias bounds assume raw values stay inside the declared raw domain; '
                         'clipping only pushes values toward the clamped range.',
        }
    else:
        explanation['clipping'] = {
            'kind': 'public_bins_with_overflow_bin',
            'bin_labels': bin_labels(plan['histogram']),
            'bias_bound': 0.0,
            'bias_note': 'Out-of-range values land in the explicit overflow bin, so binning introduces no clipping bias; '
                         'the subject group cap can only move whole probability mass between groups.',
        }
    return explanation


def cells(plan, noisy_vector):
    """Pair noisy values with their public, pre-registered cell coordinates."""
    labels = plan['groups']['labels']
    if plan['metric'] == 'histogram':
        bins = bin_labels(plan['histogram'])
        result = []
        for label, row in zip(labels, noisy_vector):
            for bin_label, value in zip(bins, row):
                result.append({'group': label, 'bin': bin_label, 'value': value})
        return result
    return [{'group': label, 'value': value} for label, value in zip(labels, noisy_vector)]
