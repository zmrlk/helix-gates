"""Independent debt parsing, privacy and local-only source identity checks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))

OBSERVED = '2026-01-12T00:00:00+00:00'
COMMENT = '# ponytail: single queue, split after one hundred jobs\n'


def source_coverage(sources):
    rows = [dict(file=name, status='read', category='code',
                 lines_total=text.count('\n') + int(bool(text) and not text.endswith('\n')),
                 lines_read=text.count('\n') + int(bool(text) and not text.endswith('\n')),
                 sha256=hashlib.sha256(text.encode()).hexdigest()) for name, text in sources.items()]
    return dict(schema_version=1, status='COMPLETE', inventory_method='git',
                files_total=len(rows), files_read=len(rows), files=rows,
                lines_total=sum(row['lines_total'] for row in rows),
                lines_read=sum(row['lines_read'] for row in rows), unknown_line_totals=0)


class PonytailDebtParserSecurity(unittest.TestCase):
    def report(self, sources, coverage=None):
        import helix_ponytail_debt as debt
        return debt.debt(sources, source_coverage(sources) if coverage is None else coverage,
                         observed_at=OBSERVED)

    def test_python_strings_docstrings_and_html_attributes_are_not_comments(self):
        sources = {
            'src/example.py': 'literal = "# ponytail: phantom, never"\n'
                'doc = """# ponytail: phantom, never"""\n' + COMMENT,
            'src/example.html': '<div title="<!-- ponytail: phantom, never -->">Text</div>\n'
                '<!-- ponytail: one page, split after ten sections -->\n',
        }
        rows = self.report(sources)['rows']
        self.assertEqual([(row['file'], row['line']) for row in rows],
                         [('src/example.html', 2), ('src/example.py', 3)])
        self.assertNotIn('phantom', json.dumps(rows))

    def test_javascript_strings_regex_and_template_text_never_create_fake_markers(self):
        specimens = [
            'const value = "// ponytail: phantom, never";',
            r'const matcher = /\/\/ ponytail: phantom, never/;',
            r'const matcher = /[/*] ponytail: phantom, never/;',
            'const template = `// ponytail: phantom, never`;',
            'const url = "https://example.invalid/ponytail:phantom";',
        ]
        for source in specimens:
            with self.subTest(source=source):
                report = self.report({'src/example.ts': source + '\n// ponytail: one queue, split later\n'})
                self.assertEqual(len(report['rows']), 1)
                self.assertEqual(report['rows'][0]['line'], 2)
                self.assertNotIn('phantom', json.dumps(report['rows']))

    def test_css_and_svelte_keep_real_comment_locations(self):
        sources = {
            'src/style.css': '.x::before { content: "/* ponytail: phantom, never */"; }\n'
                '/* ponytail: one style, split after theme expansion */\n',
            'src/view.svelte': '<script>\nconst value = "// ponytail: phantom, never";\n'
                '// ponytail: one component, split after second consumer\n</script>\n'
                '<div title="<!-- ponytail: phantom, never -->">Text</div>\n'
                '<!-- ponytail: one view, split after second layout -->\n',
        }
        rows = self.report(sources)['rows']
        self.assertEqual({(row['file'], row['line']) for row in rows},
                         {('src/style.css', 2), ('src/view.svelte', 3), ('src/view.svelte', 6)})
        self.assertNotIn('phantom', json.dumps(rows))

    def test_html_raw_text_markers_are_not_comments(self):
        for element in ('textarea', 'title'):
            with self.subTest(element=element):
                source = '<'+element+'><!-- ponytail: phantom, never --></'+element+'>\n'
                source += '<!-- ponytail: real boundary, revise later -->\n'
                report = self.report({'src/view.html': source})
                self.assertEqual([(row['line'], row['ceiling']) for row in report['rows']], [(2, 'real boundary')])
                self.assertEqual(report['status'], 'COMPLETE')

    def test_javascript_regex_without_semicolon_keeps_following_real_comment(self):
        source = 'const matcher = /value/\n// ponytail: real boundary, revise later\n'
        report = self.report({'src/example.ts': source})
        self.assertEqual([(row['line'], row['ceiling']) for row in report['rows']], [(2, 'real boundary')])
        self.assertEqual(report['status'], 'COMPLETE')

    def test_mismatched_read_coverage_cannot_claim_complete_source_identity(self):
        sources = {'src/example.py': COMMENT}; coverage = source_coverage(sources)
        coverage['files'][0]['sha256'] = 'f'*64
        report = self.report(sources, coverage)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIn('SOURCE_HASH_MISMATCH', [gap['code'] for gap in report['coverage']['gaps']])

    def test_projector_cannot_upgrade_a_preserved_source_gap_to_complete(self):
        import helix_ponytail_debt as debt
        sources = {'src/example.py': COMMENT}; coverage = source_coverage(sources)
        coverage['files'][0]['sha256'] = 'f'*64
        report = self.report(sources, coverage)
        report['status'] = report['coverage']['read_status'] = 'COMPLETE'
        with self.assertRaises(ValueError):debt.project_debt(report)

    def test_long_single_comment_privacy_scan_has_bounded_cost_without_truncation(self):
        code = """
import json
from test_ponytail_debt_security import source_coverage, OBSERVED
from helix_ponytail_debt import debt
sources={'src/long.py':'# ponytail: '+'a'*100000+', split later\\n'}
report=debt(sources,source_coverage(sources),observed_at=OBSERVED)
print(json.dumps([report['status'],len(report['rows']),len(report['rows'][0]['ceiling'])]))
"""
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, '-c', code], cwd=root,
            env={**os.environ, 'PYTHONPATH': str(root/'bin')+os.pathsep+str(root/'tests')},
            text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ['COMPLETE', 1, 100000])

    def test_unsupported_interpolation_or_broken_lexing_keeps_a_coverage_gap(self):
        for source in ('const x = `raw ${value /* ponytail: ambiguous, never */}`;',
                       'const x = `unterminated // ponytail: phantom, never',
                       'const x = <Box title="// ponytail: phantom, never" />;'):
            with self.subTest(source=source):
                report = self.report({'src/example.tsx': source})
                self.assertTrue(report['coverage']['gaps'])
                self.assertEqual(report['status'], 'INCOMPLETE')
                self.assertEqual(report['rows'], [])

    def test_full_large_source_and_multiple_markers_preserve_lines(self):
        source = ('value = 1\n' * 110000) + COMMENT + '# ponytail: second queue, split later\n'
        rows = self.report({'src/large.py': source})['rows']
        self.assertEqual([row['line'] for row in rows], [110001, 110002])
        self.assertEqual(len({row['comment_sha256'] for row in rows}), 2)
        self.assertTrue(all(row['source_sha256'] == hashlib.sha256(source.encode()).hexdigest() for row in rows))

    def test_public_rows_redact_credentials_and_personal_identifiers(self):
        canaries = ('sk_test_PRIVATE_CREDENTIAL_123456789', 'person.canary@example.invalid', '+48 501 234 567')
        sources = {'src/example.py': '\n'.join('# ponytail: '+value+', contact later' for value in canaries)+'\n'}
        report = self.report(sources)
        serialized = json.dumps(report)
        self.assertEqual(len(report['rows']), 3)
        for canary in canaries:self.assertNotIn(canary, serialized)
        for row in report['rows']:
            self.assertEqual(row['text_status'], 'redacted')
            self.assertIsNone(row['ceiling'])
            self.assertIsNone(row['upgrade_path'])

    def test_pure_parser_does_not_read_paths_run_processes_or_mutate_inputs(self):
        import helix_ponytail_debt as debt
        sources = {'src/example.py': COMMENT}; coverage = source_coverage(sources)
        before = copy.deepcopy((sources, coverage))
        with patch.object(Path, 'open', side_effect=AssertionError('pure parser cannot read files')), \
                patch('subprocess.run', side_effect=AssertionError('pure parser cannot execute')), \
                patch('socket.socket', side_effect=AssertionError('pure parser cannot network')):
            report = debt.debt(sources, coverage, observed_at=OBSERVED)
            projected = debt.project_debt(report)
        self.assertEqual((sources, coverage), before)
        self.assertEqual(len(projected['rows']), 1)


class PonytailDebtGitSecurity(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve(); self.repo = self.base / 'repo'; self.repo.mkdir()
        home = self.base / 'home'; home.mkdir()
        self.env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home),
            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM='1',
            GIT_AUTHOR_NAME='Synthetic', GIT_AUTHOR_EMAIL='author.canary@example.invalid',
            GIT_COMMITTER_NAME='Synthetic', GIT_COMMITTER_EMAIL='author.canary@example.invalid',
            GIT_AUTHOR_DATE='2026-01-02T00:00:00+00:00', GIT_COMMITTER_DATE='2026-01-02T00:00:00+00:00')
        for key in list(self.env):
            if key.startswith('GIT_CONFIG_KEY_') or key.startswith('GIT_CONFIG_VALUE_') or key in (
                'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
                del self.env[key]
        self.command('init', '-q')
        (self.repo / 'src').mkdir(); (self.repo / 'src/example.py').write_text(COMMENT + 'value = 1\n')
        self.command('add', '.'); self.command('commit', '-qm', 'synthetic source')
        self.head = self.command('rev-parse', 'HEAD')
        self.sources = {'src/example.py': (self.repo / 'src/example.py').read_text()}
        import helix_ponytail_debt as debt
        self.debt = debt.debt(self.sources, source_coverage(self.sources), observed_at=OBSERVED)
        self.ref = dict(head=self.head, dirty=False, status='recorded', dirty_reason='git_status_without_filters')
        self.marker = self.base / 'callback-ran'
        self.trap = self.base / 'git-callback.py'
        self.trap.write_text('from pathlib import Path\nimport sys\nPath('+repr(str(self.marker))+').write_text("called")\nsys.stdout.write(sys.stdin.read())\n')
        self.trap_command = shlex.join([sys.executable, str(self.trap)])

    def command(self, *args, repo=None):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', *args],
            cwd=repo or self.repo, env=self.env, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def ages(self, ref=None):
        import helix_ponytail_age as age
        with patch.dict(os.environ, self.env, clear=True):
            return age.collect_line_ages(self.repo, self.debt, self.sources,
                self.ref if ref is None else ref, observed_at=OBSERVED)

    def test_local_blame_records_time_without_author_pii_or_index_write(self):
        import helix_ponytail_debt as debt
        index = self.repo / '.git/index'
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        rows = self.ages()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'known')
        self.assertEqual(rows[0]['head'], self.head)
        self.assertEqual(rows[0]['changed_at'], '2026-01-02T00:00:00+00:00')
        projected = debt.with_line_ages(self.debt, rows, observed_at=OBSERVED)
        self.assertEqual(projected['rows'][0]['age_days'], 10)
        self.assertNotIn('author.canary', json.dumps(rows))
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before)

    def test_textconv_clean_filter_and_fsmonitor_are_never_executed(self):
        (self.repo / '.gitattributes').write_text('src/example.py diff=trap filter=trap\n')
        self.command('add', '.gitattributes'); self.command('commit', '-qm', 'synthetic attributes')
        self.head = self.command('rev-parse', 'HEAD'); self.ref['head'] = self.head
        for key in ('diff.trap.textconv', 'filter.trap.clean', 'filter.trap.smudge', 'core.fsmonitor'):
            self.command('config', key, self.trap_command)
        rows = self.ages()
        self.assertFalse(self.marker.exists())
        self.assertNotIn(str(self.trap), json.dumps(rows))
        self.assertTrue(all(row['status'] in ('known', 'unknown') for row in rows))

    def test_unrelated_dirty_state_preserves_exact_head_line_age_but_untracked_is_unknown(self):
        # Global dirty is not the age of this source line. Exact HEAD blob
        # equality is the required evidence, even with unrelated untracked data.
        (self.repo / 'unrelated.txt').write_text('untracked elsewhere')
        for dirty in (True, None):
            with self.subTest(dirty=dirty):
                rows = self.ages(dict(self.ref, dirty=dirty))
                self.assertTrue(rows)
                self.assertTrue(all(row['status'] == 'known' for row in rows))
                self.assertEqual(rows[0]['changed_at'], '2026-01-02T00:00:00+00:00')
        import helix_ponytail_debt as debt
        self.sources = {'src/untracked.py': COMMENT}; (self.repo / 'src/untracked.py').write_text(COMMENT)
        self.debt = debt.debt(self.sources, source_coverage(self.sources), observed_at=OBSERVED)
        rows = self.ages()
        self.assertEqual(rows[0]['status'], 'unknown')

    def test_promisor_and_shallow_never_trigger_blame_or_transport(self):
        import helix_ponytail_age as age
        original = age.read_git
        def no_objects(repo, *args, **kwargs):
            self.assertNotIn('blame', args)
            self.assertNotIn('cat-file', args)
            self.assertNotIn('fetch', args)
            return original(repo, *args, **kwargs)
        self.command('config', 'remote.origin.promisor', 'true')
        self.command('config', 'remote.origin.url', 'ext::'+self.trap_command)
        with patch.object(age, 'read_git', side_effect=no_objects):
            rows = self.ages()
        self.assertTrue(all(row['status'] == 'unknown' for row in rows))
        self.assertFalse(self.marker.exists())
        self.command('config', '--unset', 'remote.origin.promisor')
        (self.repo / '.git/shallow').write_text(self.head+'\n')
        with patch.object(age, 'read_git', side_effect=no_objects):
            rows = self.ages()
        self.assertTrue(all(row['status'] == 'unknown' for row in rows))

    def test_changed_source_and_future_timestamp_are_unknown(self):
        self.sources['src/example.py'] += '# local edit\n'
        rows = self.ages()
        self.assertTrue(all(row['status'] == 'unknown' for row in rows))
        self.sources['src/example.py'] = (self.repo / 'src/example.py').read_text()
        self.env.update(GIT_AUTHOR_DATE='2026-02-02T00:00:00+00:00', GIT_COMMITTER_DATE='2026-02-02T00:00:00+00:00')
        self.command('commit', '--amend', '--reset-author', '--no-edit', '-q')
        self.head = self.command('rev-parse', 'HEAD'); self.ref['head'] = self.head
        rows = self.ages()
        self.assertTrue(all(row['status'] == 'unknown' and row['changed_at'] is None for row in rows))

    def test_replacement_refs_do_not_change_the_recorded_line_date(self):
        tree = self.command('rev-parse', 'HEAD^{tree}')
        self.env.update(GIT_AUTHOR_DATE='2026-02-02T00:00:00+00:00', GIT_COMMITTER_DATE='2026-02-02T00:00:00+00:00')
        replacement = self.command('commit-tree', tree, '-m', 'replacement fixture')
        self.command('replace', self.head, replacement)
        rows = self.ages()
        self.assertEqual(rows[0]['status'], 'known')
        self.assertEqual(rows[0]['changed_at'], '2026-01-02T00:00:00+00:00')
        self.assertEqual(rows[0]['head'], self.head)

    def test_local_object_mode_disables_fetch_replacement_and_inherited_repo(self):
        import helix_git_readonly as readonly
        completed = subprocess.CompletedProcess([], 0, b'', b'')
        inherited = dict(GIT_DIR='/wrong/selection', GIT_WORK_TREE='/wrong/worktree',
                         GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='protocol.allow',
                         GIT_CONFIG_VALUE_0='always', PRIVATE_TOKEN='credential-canary')
        with patch.dict(os.environ, inherited), patch.object(readonly.subprocess, 'run', return_value=completed) as run:
            readonly.git(self.repo, 'cat-file', '--batch', text=False, input_data=b'local-object\n', local_objects_only=True)
        argv = run.call_args.args[0]; env = run.call_args.kwargs['env']
        for value in ('--no-replace-objects', '--literal-pathspecs', 'protocol.allow=never', 'core.fsmonitor=false'):
            self.assertIn(value, argv)
        for key in ('GIT_NO_LAZY_FETCH', 'GIT_NO_REPLACE_OBJECTS', 'GIT_CONFIG_NOSYSTEM'):
            self.assertEqual(env[key], '1')
        self.assertEqual(env['GIT_ALLOW_PROTOCOL'], '')
        self.assertEqual(env['GIT_GRAFT_FILE'], os.devnull)
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'PRIVATE_TOKEN'):
            self.assertNotIn(key, env)
        self.assertEqual(run.call_args.kwargs['input'], b'local-object\n')

    def summary(self, report=None):
        import helix_ponytail_age as age
        quality = dict(target=str(self.repo), provenance=dict(target_head=self.head, target_dirty=False),
                       ponytail_debt=self.debt if report is None else report)
        path = self.base / 'quality.json'; path.write_text(json.dumps(quality))
        state = self.base / 'state'
        age.write_debt_summary(self.repo, state, path)
        return path, state

    def test_current_summary_read_is_exact_and_does_not_scan_blame_or_write(self):
        import helix_ponytail_age as age
        import helix_source_coverage as coverage
        path, state = self.summary()
        cursor = age.debt_summary_path(self.repo, state)
        before = (path.read_bytes(), cursor.read_bytes(), path.stat().st_mtime_ns, cursor.stat().st_mtime_ns)
        with patch.object(age, 'read_git', side_effect=AssertionError('status must not call Git')), \
                patch.object(coverage, 'scan', side_effect=AssertionError('status must not scan')), \
                patch('subprocess.run', side_effect=AssertionError('status must not execute')):
            result = age.read_debt_summary(self.repo, state, self.ref)
        self.assertEqual(result['status'], 'CURRENT')
        self.assertEqual(result['execution'], dict(models=0, source_scans=0, git_blame=0, writes=0))
        self.assertEqual((path.read_bytes(), cursor.read_bytes(), path.stat().st_mtime_ns, cursor.stat().st_mtime_ns), before)

    def test_stale_dirty_tampered_and_foreign_summary_never_claim_current(self):
        import helix_ponytail_age as age
        path, state = self.summary()
        self.assertEqual(age.read_debt_summary(self.repo, state, dict(self.ref, head='f'*40))['status'], 'STALE')
        for dirty, expected in ((True, 'STALE'), (None, 'UNKNOWN')):
            self.assertEqual(age.read_debt_summary(self.repo, state, dict(self.ref, dirty=dirty))['status'], expected)
        path.write_text(path.read_text()+' ')
        self.assertEqual(age.read_debt_summary(self.repo, state, self.ref)['status'], 'UNKNOWN')
        path, state = self.summary()
        cursor = age.debt_summary_path(self.repo, state)
        data = json.loads(cursor.read_text()); data['target'] = str(self.base / 'foreign')
        cursor.write_text(json.dumps(data))
        result = age.read_debt_summary(self.repo, state, self.ref)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['counts'])

    def test_summary_symlink_and_missing_receipt_are_not_read_as_current(self):
        import helix_ponytail_age as age
        path, state = self.summary()
        copy_path = self.base / 'outside-canary.json'; copy_path.write_text(path.read_text())
        path.unlink(); path.symlink_to(copy_path)
        result = age.read_debt_summary(self.repo, state, self.ref)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['last_observation'])
        missing = age.read_debt_summary(self.repo, self.base / 'missing-state', self.ref)
        self.assertEqual(missing['status'], 'NOT_RUN')
        self.assertIsNone(missing['counts'])


if __name__ == '__main__':
    unittest.main()
