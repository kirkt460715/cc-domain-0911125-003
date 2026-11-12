import json
from tests.support import Case, column, context, policy
from rights_graph.catalog import assets
from rights_graph.policy import grants
from rights_graph.privacy.noise import DeterministicNoise
from rights_graph.journal import audit

SUBJECT_COLUMNS = [
    column('subject_id', 'string', 'restricted'),
    column('region', 'string', 'internal'),
    column('amount', 'decimal', 'restricted'),
]

ALPHA_ROWS = [
    {'subject_id': 'S001', 'region': 'north', 'amount': '12.50'},
    {'subject_id': 'S001', 'region': 'north', 'amount': '7.50'},
    {'subject_id': 'S002', 'region': 'south', 'amount': '20.00'},
    {'subject_id': 'S003', 'region': 'north', 'amount': '5.00'},
    {'subject_id': 'S004', 'region': 'west', 'amount': '999.00'},
    {'subject_id': 'S009', 'region': 'north', 'amount': '8.00'},
]
BETA_ROWS = [
    {'subject_id': 'S001', 'region': 'south', 'amount': '4.00'},
    {'subject_id': 'S002', 'region': 'south', 'amount': '16.00'},
    {'subject_id': 'S003', 'region': 'north', 'amount': '6.00'},
    {'subject_id': 'S005', 'region': 'west', 'amount': '30.00'},
    {'subject_id': 'S006', 'region': 'north', 'amount': '10.00'},
]
ROSTER = [f'S00{i}' for i in range(1, 9)]
GROUPS = ['north', 'south', 'west', 'empty-isle']


class PrivacyCase(Case):
    def setUp(self):
        super().setUp()
        self.app.privacy.noise = DeterministicNoise(1234)
        self.app.privacy.formal_noise = False
        assets.create(self.store, 'detail_alpha', 'source', 'owner', SUBJECT_COLUMNS, 'Synthetic detail A')
        assets.create(self.store, 'detail_beta', 'source', 'owner', SUBJECT_COLUMNS, 'Synthetic detail B')
        grants.create(self.store, 'grant-alpha', 'detail_alpha', policy(['subject_id', 'region', 'amount']))
        grants.create(self.store, 'grant-beta', 'detail_beta', policy(['subject_id', 'region', 'amount']))
        self.app.preview.data.import_rows('batch-alpha', 'detail_alpha', 1, ALPHA_ROWS)
        self.app.preview.data.import_rows('batch-beta', 'detail_beta', 1, BETA_ROWS)

    def domain(self, domain_id='domain-overlap', budget=1.0, roster=None, sources=None):
        return self.app.privacy.register_domain(
            domain_id, 'period-2026-H2', 'subject_id', roster or ROSTER, budget,
            sources or [{'asset_id': 'detail_alpha', 'batch_id': 'batch-alpha'},
                        {'asset_id': 'detail_beta', 'batch_id': 'batch-beta'}])

    def plan(self, plan_id='plan-count', metric='count', **changes):
        definition = {
            'domain_id': 'domain-overlap', 'metric': metric,
            'groups': {'column': 'region', 'labels': GROUPS},
            'max_contributions': 1,
        }
        if metric == 'sum':
            definition.update({'value_column': 'amount',
                               'clamp': {'low': 0.0, 'high': 50.0},
                               'raw_domain': {'low': 0.0, 'high': 1000.0}})
        if metric == 'histogram':
            definition.update({'value_column': 'amount',
                               'histogram': {'edges': [0.0, 10.0, 20.0, 50.0]}})
        definition.update(changes)
        return self.app.privacy.register_plan(plan_id, definition)

    def release(self, plan_id='plan-count', epsilon=0.4, request=None, requester='analyst-a'):
        return self.app.privacy.release(plan_id, request or context(), epsilon, requester=requester)

    def audit_bodies(self):
        page = audit.page(self.store, 0, 1000)
        return [{'action': entry['action'], **entry['body']} for entry in page]
