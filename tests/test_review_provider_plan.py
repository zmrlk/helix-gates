"""A READY plan must retain the actual model selected from fallback chains."""
import copy
import unittest
from test_provider_plan import routing, inventory


class ReviewProviderPlan(unittest.TestCase):
    def test_apply_retains_selected_models_and_accepts_models_only_config(self):
        for providers in (None, {}):
            cfg = dict(models={'codex': ['codex-old', 'codex-new'],
                               'claude': ['claude-old', 'claude-new'],
                               'gemini': ['gemini-old', 'gemini-new']})
            if providers is not None: cfg['providers'] = providers
            before = copy.deepcopy(cfg)
            available = inventory(*[(p, chain[1]) for p, chain in cfg['models'].items()])
            plan = routing.plan(cfg, available)
            self.assertEqual(plan['status'], 'READY')
            applied = routing.apply_plan(cfg, plan)
            self.assertEqual(cfg, before)
            for role, item in plan['roles'].items():
                if role == 'reviewers':
                    self.assertEqual([r['model'] for r in applied['providers'][role]], [r['model'] for r in item])
                else:
                    self.assertEqual(applied['models'][item['provider']][0], item['model'])
            reapplied = routing.plan(applied, available, applied)
            self.assertEqual(reapplied['status'], 'READY')

    def test_explicit_unavailable_selection_is_preserved(self):
        cfg = dict(models={'claude': ['claude-old', 'claude-new']}, providers={'planner': 'claude'})
        plan = routing.plan(cfg, inventory(('claude', 'claude-new')), cfg)
        applied = routing.apply_plan(cfg, plan, cfg)
        self.assertEqual(applied['models'], cfg['models'])
        self.assertEqual(applied['providers']['planner'], 'claude')

    def test_auto_role_cannot_reorder_an_explicit_reviewers_default_model(self):
        cfg = dict(models={'claude': ['claude-old', 'claude-new']},
                   providers={'reviewers': [dict(provider='claude', name='owner-reviewer')]})
        explicit = dict(providers=copy.deepcopy(cfg['providers']))
        plan = routing.plan(cfg, inventory(('claude', 'claude-new')), explicit)
        applied = routing.apply_plan(cfg, plan, explicit)
        self.assertEqual(applied['models']['claude'], cfg['models']['claude'])
        self.assertEqual(applied['providers']['reviewers'], cfg['providers']['reviewers'])


if __name__ == '__main__': unittest.main()
