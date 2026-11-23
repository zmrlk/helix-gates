"""Regressions from the independent transport review; no services are started."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_runtime_transport as T


class ReviewTransport(unittest.TestCase):
    def plan(self):
        return T.transport_plan({'web/server.js': 'const ready = true;',
                                 'auth/server.js': 'cookies.set("__Secure-session", token, {});'},
                                [{'path': 'web'}, {'path': 'auth'}], {'integrations': []}, {})

    def receipt(self, plan, path='web', status='ready'):
        row = next(row for row in plan['parts'] if row['part'] == path)
        return dict(path=path, transport=dict(selected=row['selected'], gaps=row['gaps'], status=status))

    def test_omitted_https_part_never_records_whole_plan(self):
        plan = self.plan(); entries = [self.receipt(plan)]
        self.assertEqual(T.derive_transport_coverage(plan, entries), 'INCOMPLETE')
        report = dict(transport_plan=plan, parts=entries, transport_coverage='INCOMPLETE')
        self.assertEqual(T.project_transport(report)['status'], 'INCOMPLETE')
        self.assertEqual(T.project_transport(report)['parts'][0]['coverage'], 'RECORDED')

    def test_http_requires_ready_even_when_all_parts_are_present(self):
        plan = self.plan(); plan['parts'] = [r for r in plan['parts'] if r['part'] == 'web']
        for status in ('not_checked', 'starting', 'blocked'):
            with self.subTest(status=status):
                self.assertEqual(T.derive_transport_coverage(plan, [self.receipt(plan, status=status)]), 'INCOMPLETE')
        self.assertEqual(T.derive_transport_coverage(plan, [self.receipt(plan)]), 'RECORDED')

    def test_property_and_async_cookie_aliases_preserve_https_requirement(self):
        for expression in ('event.cookies', 'req.cookies', 'await cookies()', 'cookies()'):
            for alias in ('cookies', 'jar'):
                with self.subTest(expression=expression, alias=alias):
                    reqs, gaps, _ = T._source_signals('server.ts',
                        f'const {alias} = {expression}; {alias}.set("__Secure-session", token, opts);')
                    self.assertTrue(any(row['kind'] == 'secure_cookie' for row in reqs))
                    self.assertTrue(any(row['kind'] == 'cookie_options_unresolved' for row in gaps))

    def test_unknown_cookie_setters_remain_gaps(self):
        for source in ('const jar = factory(); jar.set("__Host-session", token, {});',
                       'const jar = factory(); jar.set("session", token, opts);'):
            with self.subTest(source=source):
                _, gaps, _ = T._source_signals('server.ts', source)
                self.assertTrue(any(row['kind'] == 'cookie_receiver_unresolved' for row in gaps))

    def test_local_method_and_overwritten_alias_do_not_become_cookie_proof(self):
        for source in ('const cookies = {set(name, value, opts) {}}; cookies.set("__Host-a", value, {});',
                       'let jar = event.cookies; jar = factory(); jar.set("__Host-a", value, {});'):
            with self.subTest(source=source):
                reqs, _, _ = T._source_signals('server.ts', source)
                self.assertEqual(reqs, [])


if __name__ == '__main__': unittest.main()
