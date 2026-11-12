"""Privacy desk: pre-registered aggregate delivery with explicit budget accounting.

Design rules enforced here:

* Budget is accumulated per *protected subject domain* and *budget period*.
  Changing the requester, taking a subset, or swapping to another frozen data
  version never creates fresh allowance.
* A release either reuses an identical prior release (same normalized request
  and identical frozen input digests) at zero cost, or atomically reserves
  budget, computes the statistic, draws noise once and persists the result.
  A failure rolls the whole transaction back, so no result can be retrieved
  while budget is refunded; noise is never redrawn to pick a nicer value.
* Authorization is evaluated before computing and again whenever a finished
  release is retrieved.  Spent budget does not imply an ongoing delivery
  right.
* The audit journal records plans, budget movements and lineage only.  Exact
  unnoised aggregates are never stored and never written to the journal.
"""
import json
from decimal import Decimal, ROUND_HALF_UP
from rights_graph.primitives import canonical, checksum, count, fields, label, name, reject, symbols
from rights_graph.catalog import assets
from rights_graph.catalog.records import DataCatalog
from rights_graph.policy import grants
from rights_graph.policy.algebra import context, evaluate
from rights_graph.journal import audit
from rights_graph.privacy import mechanisms
from rights_graph.privacy.noise import NoiseSource, SystemNoise

SCHEMA = '''
CREATE TABLE IF NOT EXISTS privacy_domains(
 domain_id TEXT PRIMARY KEY,period TEXT NOT NULL,subject_column TEXT NOT NULL,
 roster TEXT NOT NULL,roster_size INTEGER NOT NULL,epsilon_budget REAL NOT NULL,
 epsilon_spent REAL NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_sources(
 domain_id TEXT NOT NULL REFERENCES privacy_domains(domain_id),
 asset_id TEXT NOT NULL,asset_version INTEGER NOT NULL,batch_id TEXT NOT NULL,
 batch_digest TEXT NOT NULL,PRIMARY KEY(domain_id,batch_id));
CREATE TABLE IF NOT EXISTS privacy_plans(
 plan_id TEXT PRIMARY KEY,domain_id TEXT NOT NULL REFERENCES privacy_domains(domain_id),
 definition TEXT NOT NULL,digest TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_releases(
 release_id TEXT PRIMARY KEY,plan_id TEXT NOT NULL REFERENCES privacy_plans(plan_id),
 domain_id TEXT NOT NULL,period TEXT NOT NULL,epsilon REAL NOT NULL,
 request_context TEXT NOT NULL,fingerprint TEXT NOT NULL,payload TEXT NOT NULL,
 digest TEXT NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_ledger(
 ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id TEXT NOT NULL,period TEXT NOT NULL,
 release_id TEXT NOT NULL,epsilon REAL NOT NULL,kind TEXT NOT NULL,at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_postprocessings(
 post_id TEXT PRIMARY KEY,release_id TEXT NOT NULL REFERENCES privacy_releases(release_id),
 steps TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,created_at TEXT NOT NULL);
'''

POST_STEPS = {'round_nearest_integer', 'clip_nonnegative'}


class PrivacyDesk:
    def __init__(self, store, *, noise=None):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize privacy desk outside transaction')
        if noise is not None and not isinstance(noise, NoiseSource):
            reject('privacy_noise', 'Injected randomness must implement NoiseSource')
        self.noise = noise or SystemNoise()
        self.formal_noise = noise is None
        self.data = DataCatalog(store)
        store.db.executescript(SCHEMA)

    # ------------------------------------------------------------------ domains
    def register_domain(self, domain_id, period, subject_column, roster, epsilon_budget, sources):
        name(domain_id, 'domain_id')
        name(period, 'period')
        name(subject_column, 'subject_column')
        if not isinstance(roster, list) or not 1 <= len(roster) <= 1000000:
            reject('privacy_roster', 'Roster must be a bounded nonempty list of stable subject keys')
        normalized_roster = []
        seen = set()
        for entry in roster:
            key = _roster_key(entry)
            if key in seen:
                reject('privacy_roster', 'Roster contains duplicate subject keys')
            seen.add(key)
            normalized_roster.append(key)
        budget = _epsilon(epsilon_budget, 'epsilon_budget')
        if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
            reject('privacy_sources', 'Domain needs one to one hundred frozen sources')
        with self.store.atomic():
            if self.store.one('SELECT domain_id FROM privacy_domains WHERE domain_id=?', (domain_id,)):
                reject('privacy_domain_exists', 'Privacy domain already registered')
            frozen = []
            covered_assets = set()
            for source in sources:
                fields(source, {'asset_id', 'batch_id'}, {'version'})
                asset_id = name(source['asset_id'], 'asset_id')
                batch = self.data.get(name(source['batch_id'], 'batch_id'))
                version = source.get('version', batch['asset_version'])
                count(version, 'version', 1)
                asset = assets.get(self.store, asset_id, version)
                if asset['kind'] != 'source' or asset['state'] != 'active':
                    reject('privacy_source', 'Privacy domains freeze active source assets only')
                if batch['asset_id'] != asset_id or batch['asset_version'] != version:
                    reject('privacy_source', 'Frozen batch does not match declared asset version')
                if subject_column not in {column['name'] for column in asset['schema']}:
                    reject('privacy_source', 'Subject column is absent from frozen source', asset_id=asset_id)
                if batch['batch_id'] in {item['batch_id'] for item in frozen}:
                    reject('privacy_sources', 'A frozen batch may only be listed once per domain')
                self.data.verify(batch['batch_id'])
                frozen.append({'asset_id': asset_id, 'asset_version': version,
                               'batch_id': batch['batch_id'], 'batch_digest': batch['digest']})
                covered_assets.add(asset_id)
            definition = {
                'domain_id': domain_id, 'period': period, 'subject_column': subject_column,
                'roster': normalized_roster, 'epsilon_budget': budget, 'sources': sorted(frozen, key=lambda item: item['batch_id']),
            }
            digest = checksum(definition)
            self.store.execute(
                'INSERT INTO privacy_domains(domain_id,period,subject_column,roster,roster_size,epsilon_budget,epsilon_spent,definition,digest,created_at) '
                'VALUES(?,?,?,?,?,?,0,?,?,?)',
                (domain_id, period, subject_column, canonical(normalized_roster), len(normalized_roster),
                 budget, canonical(definition), digest, self.store.clock()))
            for item in definition['sources']:
                self.store.execute(
                    'INSERT INTO privacy_sources(domain_id,asset_id,asset_version,batch_id,batch_digest) VALUES(?,?,?,?,?)',
                    (domain_id, item['asset_id'], item['asset_version'], item['batch_id'], item['batch_digest']))
            audit.append(self.store, 'privacy.domain_registered',
                         {'domain_id': domain_id, 'period': period, 'roster_size': len(normalized_roster),
                          'epsilon_budget': budget, 'sources': len(frozen), 'digest': digest})
            return self.get_domain(domain_id)

    def get_domain(self, domain_id):
        name(domain_id, 'domain_id')
        row = self.store.one('SELECT * FROM privacy_domains WHERE domain_id=?', (domain_id,))
        if row is None:
            reject('unknown_privacy_domain', 'Privacy domain does not exist')
        definition = json.loads(row['definition'])
        if checksum(definition) != row['digest']:
            reject('privacy_domain_corrupt', 'Privacy domain definition differs from checksum')
        return {
            'domain_id': row['domain_id'], 'period': row['period'],
            'subject_column': row['subject_column'], 'roster_size': row['roster_size'],
            'epsilon_budget': row['epsilon_budget'], 'epsilon_spent': row['epsilon_spent'],
            'epsilon_remaining': row['epsilon_budget'] - row['epsilon_spent'],
            'sources': self.store.all('SELECT asset_id,asset_version,batch_id,batch_digest FROM privacy_sources WHERE domain_id=? ORDER BY batch_id', (domain_id,)),
            'definition': definition, 'digest': row['digest'], 'created_at': row['created_at'],
        }

    def budget_status(self, domain_id, period=None):
        domain = self.get_domain(domain_id)
        if period is not None and period != domain['period']:
            reject('privacy_period', 'Budget period does not match the registered domain')
        entries = self.store.all(
            'SELECT release_id,epsilon,kind,at FROM privacy_ledger WHERE domain_id=? AND period=? ORDER BY ledger_id',
            (domain_id, domain['period']))
        return {
            'domain_id': domain_id, 'period': domain['period'],
            'epsilon_budget': domain['epsilon_budget'], 'epsilon_spent': domain['epsilon_spent'],
            'epsilon_remaining': domain['epsilon_remaining'], 'ledger': entries,
            'scope_rule': 'budget is shared across requesters, subsets and frozen versions for this domain and period',
        }

    # -------------------------------------------------------------------- plans
    def register_plan(self, plan_id, definition):
        normalized = mechanisms.normalize_plan(plan_id, definition)
        with self.store.atomic():
            domain = self.get_domain(normalized['domain_id'])
            self._validate_plan_columns(domain, normalized)
            if self.store.one('SELECT plan_id FROM privacy_plans WHERE plan_id=?', (plan_id,)):
                reject('privacy_plan_exists', 'Privacy plan already registered')
            digest = mechanisms.plan_digest(normalized)
            self.store.execute('INSERT INTO privacy_plans(plan_id,domain_id,definition,digest,created_at) VALUES(?,?,?,?,?)',
                               (plan_id, normalized['domain_id'], canonical(normalized), digest, self.store.clock()))
            audit.append(self.store, 'privacy.plan_registered',
                         {'plan_id': plan_id, 'domain_id': normalized['domain_id'],
                          'metric': normalized['metric'], 'groups': len(normalized['groups']['labels']),
                          'max_contributions': normalized['max_contributions'], 'digest': digest})
            return self.get_plan(plan_id)

    def _validate_plan_columns(self, domain, plan):
        needed = [plan['groups']['column']]
        if 'value_column' in plan:
            needed.append(plan['value_column'])
        for source in domain['sources']:
            asset = assets.get(self.store, source['asset_id'], source['asset_version'])
            available = {column['name']: column for column in asset['schema']}
            missing = sorted(set(needed) - set(available))
            if missing:
                reject('privacy_plan_columns', 'Plan references absent source columns',
                       asset_id=source['asset_id'], columns=missing)
            if domain['subject_column'] in needed:
                reject('privacy_plan_columns', 'Subject column cannot be reused as a statistic column')

    def get_plan(self, plan_id):
        name(plan_id, 'plan_id')
        row = self.store.one('SELECT * FROM privacy_plans WHERE plan_id=?', (plan_id,))
        if row is None:
            reject('unknown_privacy_plan', 'Privacy plan does not exist')
        definition = json.loads(row['definition'])
        if mechanisms.plan_digest(definition) != row['digest']:
            reject('privacy_plan_corrupt', 'Privacy plan differs from checksum')
        return {'plan_id': row['plan_id'], 'domain_id': row['domain_id'],
                'definition': definition, 'digest': row['digest'], 'created_at': row['created_at']}

    def list_plans(self, domain_id=None):
        if domain_id is None:
            rows = self.store.all('SELECT plan_id FROM privacy_plans ORDER BY created_at,plan_id')
        else:
            self.get_domain(domain_id)
            rows = self.store.all('SELECT plan_id FROM privacy_plans WHERE domain_id=? ORDER BY created_at,plan_id', (domain_id,))
        return [self.get_plan(row['plan_id']) for row in rows]

    # ----------------------------------------------------------------- releases
    def _authorize(self, domain, request):
        decision_context = context(request)
        failures = []
        for source in domain['sources']:
            asset = assets.get(self.store, source['asset_id'], source['asset_version'])
            if asset['state'] != 'active':
                failures.append({'code': 'asset_retired', 'asset_id': source['asset_id']})
            active = grants.for_asset(self.store, source['asset_id'], active_only=False)
            if not any(grant['state'] == 'active' and evaluate(grant['policy'], decision_context)['allowed']
                       for grant in active):
                failures.append({'code': 'no_active_grant', 'asset_id': source['asset_id']})
        return decision_context, failures

    def _frozen_rows(self, domain, plan):
        group_column = plan['groups']['column']
        value_column = plan.get('value_column')
        rows = []
        expected_digests = {source['batch_id']: source['batch_digest'] for source in domain['sources']}
        for source in domain['sources']:
            batch = self.data.get(source['batch_id'])
            if batch['digest'] != expected_digests[source['batch_id']]:
                reject('privacy_frozen_input', 'Frozen input content changed since domain registration',
                       batch_id=source['batch_id'])
            self.data.verify(source['batch_id'])
            for row in self.data.rows(source['batch_id'], limit=100000):
                payload = row['payload']
                projected = {'__subject__': payload.get(domain['subject_column']),
                             group_column: payload.get(group_column)}
                if value_column is not None:
                    projected[value_column] = payload.get(value_column)
                rows.append(projected)
        return rows

    def release(self, plan_id, request_context, epsilon, *, requester):
        """Return a private release, reusing an identical one or charging budget once."""
        name(plan_id, 'plan_id')
        name(requester, 'requester')
        budget = _epsilon(epsilon, 'epsilon')
        with self.store.atomic():
            plan_row = self.get_plan(plan_id)
            plan = plan_row['definition']
            domain = self.get_domain(plan['domain_id'])
            authorized_context, failures = self._authorize(domain, request_context)
            if failures:
                reject('privacy_unauthorized', 'Authorization check failed before computing the statistic',
                       failures=failures)
            frozen_fingerprint = [
                {'batch_id': source['batch_id'], 'batch_digest': source['batch_digest'],
                 'asset_id': source['asset_id'], 'asset_version': source['asset_version']}
                for source in domain['sources']]
            fingerprint = checksum({
                'plan_digest': plan_row['digest'],
                'frozen_inputs': frozen_fingerprint,
                'context': authorized_context,
            })
            release_id = 'priv-release-' + fingerprint
            existing = self.store.one('SELECT release_id FROM privacy_releases WHERE release_id=?', (release_id,))
            if existing:
                audit.append(self.store, 'privacy.release_reused',
                             {'release_id': release_id, 'plan_id': plan_id, 'requester': requester,
                              'epsilon_charged': 0.0})
                return self.get_release(release_id)
            if domain['epsilon_spent'] + budget > domain['epsilon_budget'] + 1e-12:
                reject('privacy_budget_exhausted', 'Remaining privacy budget cannot cover this release',
                       domain_id=domain['domain_id'], period=domain['period'],
                       epsilon_requested=budget, epsilon_remaining=domain['epsilon_remaining'])
            rows = self._frozen_rows(domain, plan)
            roster = set(json.loads(self.store.one('SELECT roster FROM privacy_domains WHERE domain_id=?',
                                                    (domain['domain_id'],))['roster']))
            engine = mechanisms.ContributionEngine(plan, roster)
            exact = engine.exact(rows)  # exact values stay in this transaction's local memory
            noisy, scale = mechanisms.release_vector(plan, exact, budget, self.noise)
            explanation = mechanisms.error_explanation(plan, budget, scale, domain['roster_size'])
            payload = {
                'format': 'rights-private-aggregate', 'version': 1,
                'release_id': release_id, 'plan_id': plan_id, 'domain_id': domain['domain_id'],
                'period': domain['period'], 'metric': plan['metric'],
                'adjacency': explanation['adjacency'],
                'sensitivity': explanation['sensitivity'],
                'epsilon': budget, 'noise': explanation['noise_distribution'],
                'clipping': explanation['clipping'], 'guarantees': explanation['guarantees'],
                'cells': mechanisms.cells(plan, noisy),
                'group_labels': plan['groups']['labels'],
                'bin_labels': mechanisms.bin_labels(plan['histogram']) if plan['metric'] == 'histogram' else [],
                'lineage': {
                    'plan_digest': plan_row['digest'], 'frozen_inputs': frozen_fingerprint,
                    'subject_column': domain['subject_column'], 'roster_size': domain['roster_size'],
                    'max_contributions': plan['max_contributions'],
                },
                'randomness': 'system_csprng_laplace' if self.formal_noise else 'injected_test_randomness',
            }
            digest = checksum(payload)
            self.store.execute(
                'INSERT INTO privacy_releases(release_id,plan_id,domain_id,period,epsilon,request_context,fingerprint,payload,digest,state,created_at) '
                "VALUES(?,?,?,?,?,?,?,?,?,'released',?)",
                (release_id, plan_id, domain['domain_id'], domain['period'], budget,
                 canonical(authorized_context), fingerprint, canonical(payload), digest, self.store.clock()))
            self.store.execute(
                'INSERT INTO privacy_ledger(domain_id,period,release_id,epsilon,kind,at) VALUES(?,?,?,?,\'charge\',?)',
                (domain['domain_id'], domain['period'], release_id, budget, self.store.clock()))
            self.store.execute('UPDATE privacy_domains SET epsilon_spent=epsilon_spent+? WHERE domain_id=?',
                               (budget, domain['domain_id']))
            audit.append(self.store, 'privacy.release_published',
                         {'release_id': release_id, 'plan_id': plan_id, 'domain_id': domain['domain_id'],
                          'period': domain['period'], 'epsilon': budget, 'requester': requester,
                          'cell_count': len(payload['cells']), 'digest': digest})
            return self.get_release(release_id)

    def get_release(self, release_id):
        name(release_id, 'release_id')
        row = self.store.one('SELECT * FROM privacy_releases WHERE release_id=?', (release_id,))
        if row is None:
            reject('unknown_privacy_release', 'Private release does not exist')
        payload = json.loads(row['payload'])
        if checksum(payload) != row['digest']:
            reject('privacy_release_corrupt', 'Private release differs from checksum')
        domain = self.get_domain(row['domain_id'])
        # Re-check authorization at retrieval time: spent budget is not a delivery right.
        _, failures = self._authorize(domain, json.loads(row['request_context']))
        authorization = {'authorized': not failures, 'failures': failures,
                         'checked_at': self.store.clock()}
        return {'release_id': row['release_id'], 'plan_id': row['plan_id'],
                'domain_id': row['domain_id'], 'period': row['period'], 'epsilon': row['epsilon'],
                'state': row['state'], 'payload': payload, 'digest': row['digest'],
                'created_at': row['created_at'], 'authorization': authorization}

    def list_releases(self, domain_id=None):
        if domain_id is None:
            rows = self.store.all('SELECT release_id FROM privacy_releases ORDER BY created_at,release_id')
        else:
            self.get_domain(domain_id)
            rows = self.store.all('SELECT release_id FROM privacy_releases WHERE domain_id=? ORDER BY created_at,release_id', (domain_id,))
        return [self.get_release(row['release_id']) for row in rows]

    # ------------------------------------------------------------ postprocessing
    def postprocess(self, post_id, release_id, steps):
        name(post_id, 'post_id')
        if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
            reject('privacy_post_steps', 'Postprocessing needs a bounded nonempty step list')
        normalized_steps = symbols(steps, 'steps')
        unknown = sorted(set(normalized_steps) - POST_STEPS)
        if unknown:
            reject('privacy_post_step', 'Unsupported postprocessing step', steps=unknown)
        with self.store.atomic():
            if self.store.one('SELECT post_id FROM privacy_postprocessings WHERE post_id=?', (post_id,)):
                reject('privacy_post_exists', 'Postprocessing identifier already used')
            release = self.get_release(release_id)
            if not release['authorization']['authorized']:
                reject('privacy_unauthorized', 'Postprocessing requires a currently authorized release',
                       failures=release['authorization']['failures'])
            cells = json.loads(json.dumps(release['payload']['cells']))  # copy, never mutate the release
            for step in normalized_steps:
                for cell in cells:
                    if step == 'round_nearest_integer':
                        cell['value'] = float(_round_half_up(Decimal(str(cell['value']))))
                    elif step == 'clip_nonnegative':
                        cell['value'] = max(0.0, float(cell['value']))
            payload = {
                'format': 'rights-private-aggregate-postprocessed', 'version': 1,
                'post_id': post_id, 'release_id': release_id, 'steps': normalized_steps,
                'cells': cells, 'parent_digest': release['digest'],
                'note': 'Deterministic postprocessing of a differentially private release; no budget charged.',
            }
            digest = checksum(payload)
            self.store.execute('INSERT INTO privacy_postprocessings(post_id,release_id,steps,payload,digest,created_at) VALUES(?,?,?,?,?,?)',
                               (post_id, release_id, canonical(normalized_steps), canonical(payload), digest, self.store.clock()))
            audit.append(self.store, 'privacy.postprocessed',
                         {'post_id': post_id, 'release_id': release_id, 'steps': normalized_steps, 'digest': digest})
            return self.get_postprocessing(post_id)

    def get_postprocessing(self, post_id):
        name(post_id, 'post_id')
        row = self.store.one('SELECT * FROM privacy_postprocessings WHERE post_id=?', (post_id,))
        if row is None:
            reject('unknown_privacy_postprocessing', 'Postprocessed release does not exist')
        payload = json.loads(row['payload'])
        if checksum(payload) != row['digest']:
            reject('privacy_post_corrupt', 'Postprocessed release differs from checksum')
        return {'post_id': row['post_id'], 'release_id': row['release_id'],
                'steps': json.loads(row['steps']), 'payload': payload,
                'digest': row['digest'], 'created_at': row['created_at']}


def _epsilon(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        reject('privacy_epsilon', 'Epsilon must be a positive finite number', field=field)
    if not 0.0 < float(value) <= 100.0:
        reject('privacy_epsilon', 'Epsilon must lie inside (0, 100]', field=field)
    return float(value)


def _roster_key(value):
    if isinstance(value, bool) or value is None:
        reject('privacy_roster', 'Stable subject keys must be bounded strings or integers')
    if isinstance(value, int) and abs(value) <= 2**53 - 1:
        return str(value)
    if isinstance(value, str) and value.strip() and len(value) <= 200:
        return value.strip()
    reject('privacy_roster', 'Stable subject keys must be bounded strings or integers')


def _round_half_up(value):
    return int(value.quantize(Decimal('1'), rounding=ROUND_HALF_UP))
