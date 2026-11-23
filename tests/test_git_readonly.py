"""Real local Git fixtures prove metadata reads cannot execute project hooks."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
import helix_git_readonly as readonly
import helix_environment as environment


class GitReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / 'project'
        self.repo.mkdir()
        self.command('init', '-q')
        self.command('config', 'user.name', 'Fixture')
        self.command('config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'app.txt').write_text('initial')
        (self.repo / '.gitattributes').write_text('app.txt filter=synthetic\n')
        self.command('add', '.')
        self.command('commit', '-qm', 'fixture')
        self.head = self.command('rev-parse', 'HEAD')
        self.marker = self.base / 'executed-marker'
        self.script = self.base / 'project-command.py'
        self.script.write_text('import sys\nfrom pathlib import Path\nPath(' + repr(str(self.marker)) + ').write_text("executed")\nsys.stdout.write(sys.stdin.read())\n')
        self.fake_command = shlex.join([sys.executable, str(self.script)])

    def command(self, *args, repo=None):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=repo or self.repo, text=True).strip()

    def provenance(self):
        with patch.object(environment, '_run', side_effect=AssertionError('provenance must not probe tools')):
            result = environment.provenance(self.repo)
        self.assertEqual(result['target_head'], self.head)
        self.assertEqual(result['target_ref']['head'], self.head)
        self.assertFalse(self.marker.exists())
        self.assertNotIn(str(self.script), json.dumps(result))
        return result

    def test_clean_dirty_and_index_identity_are_preserved(self):
        index = self.repo / '.git/index'
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        result = self.provenance()
        self.assertFalse(result['target_dirty'])
        self.assertEqual(result['target_ref']['status'], 'recorded')
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before)
        (self.repo / 'app.txt').write_text('changed')
        result = self.provenance()
        self.assertTrue(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_status_without_filters')
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before)

    def test_provenance_does_not_execute_local_clean_filter_on_same_length_change(self):
        self.command('config', 'filter.synthetic.clean', self.fake_command)
        (self.repo / 'app.txt').write_text('changed')
        result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['status'], 'partial')
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')
        self.assertIn('nieznane', result['target_ref']['reason'])

    def test_global_process_smudge_required_and_overlay_filters_are_not_executed(self):
        (self.repo / 'app.txt').write_text('changed')
        global_config = self.base / 'global.gitconfig'
        for field in ('clean', 'smudge', 'process', 'required'):
            with self.subTest(field=field):
                value = 'true' if field == 'required' else self.fake_command
                global_config.write_text('[filter "synthetic"]\n    ' + field + ' = ' + value + '\n')
                with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
                    result = self.provenance()
                self.assertIsNone(result['target_dirty'])
                self.assertEqual(result['target_ref']['status'], 'partial')
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'filter.synthetic.process',
                                     'GIT_CONFIG_VALUE_0': self.fake_command}):
            result = self.provenance()
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')

    def test_global_driver_unused_by_project_paths_is_inert_until_an_attribute_names_it(self):
        # CI runners configure git-lfs globally; git status runs a driver only for paths whose
        # `filter` attribute names it, so an unused global driver must not hide the dirty state.
        (self.repo / 'app.txt').write_text('changed')
        global_config = self.base / 'global.gitconfig'
        global_config.write_text('[filter "lfs"]\n    clean = ' + self.fake_command + '\n    process = ' + self.fake_command + '\n    required = true\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
            result = self.provenance()
            self.assertTrue(result['target_dirty'])
            self.assertEqual(result['target_ref']['dirty_reason'], 'git_status_without_filters')
            # An attribute source outside .gitattributes counts like the file itself.
            (self.repo / '.git/info').mkdir(exist_ok=True)
            (self.repo / '.git/info/attributes').write_text('app.txt filter=lfs\n')
            result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')

    def test_core_attributes_file_and_a_driver_named_like_a_placeholder(self):
        (self.repo / 'app.txt').write_text('changed')
        global_config = self.base / 'global.gitconfig'
        attributes = self.base / 'global-attributes'
        # The global file has the lowest precedence, so it names a path the project's .gitattributes leaves alone.
        attributes.write_text('.gitattributes filter=lfs\n')
        global_config.write_text('[filter "lfs"]\n    clean = ' + self.fake_command + '\n[core]\n    attributesFile = ' + str(attributes) + '\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
            result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')
        # check-attr prints `unspecified` for absent attributes; a driver of that name is still unused here.
        global_config.write_text('[filter "unspecified"]\n    clean = ' + self.fake_command + '\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
            result = self.provenance()
            self.assertTrue(result['target_dirty'])
            (self.repo / '.git/info').mkdir(exist_ok=True)
            (self.repo / '.git/info/attributes').write_text('app.txt filter=unspecified\n')
            result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')

    def test_attribute_assigned_after_the_check_still_runs_no_driver(self):
        # Same-length change: git must read the content, which is where a clean filter would run.
        (self.repo / 'app.txt').write_text('changed')
        global_config = self.base / 'global.gitconfig'
        global_config.write_text('[filter "lfs"]\n    clean = ' + self.fake_command + '\n    process = ' + self.fake_command + '\n    required = true\n')
        original = readonly.git
        calls = []
        def racing(repo, *args, **kwargs):
            calls.append(args)
            result = original(repo, *args, **kwargs)
            if 'check-attr' in args and Path(repo) == self.repo:
                (self.repo / '.git/info').mkdir(exist_ok=True)
                (self.repo / '.git/info/attributes').write_text('app.txt filter=lfs\n')
            return result
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}), patch.object(readonly, 'git', side_effect=racing):
            result = self.provenance()
        self.assertIn('filter.lfs.clean=', next(args for args in calls if 'status' in args))
        # Raw bytes are not what the filter would compare, so the result stays unknown.
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')
        self.assertFalse(self.marker.exists())

    def test_worktree_diffs_empty_known_drivers_even_after_a_late_attribute(self):
        import helix_packs, helix_advisory
        self.command('config', 'filter.synthetic.clean', self.fake_command)
        # Advisory diff: the project's own attribute names the local driver; it must not run.
        (self.repo / 'app.txt').write_text('changed')
        self.assertEqual(helix_advisory.changed_files(self.repo, 'HEAD'), ['app.txt'])
        self.assertFalse(self.marker.exists())
        # Integrity diff: read_ref sees an unused global driver, the attribute appears just before the diff.
        self.command('config', '--unset', 'filter.synthetic.clean')
        global_config = self.base / 'global.gitconfig'
        global_config.write_text('[filter "lfs"]\n    clean = ' + self.fake_command + '\n    required = true\n')
        original = readonly.git
        diffs = []
        def late(repo, *args, **kwargs):
            if 'diff' in args:
                diffs.append(args)
                (self.repo / '.git/info').mkdir(exist_ok=True)
                (self.repo / '.git/info/attributes').write_text('app.txt filter=lfs\n')
            return original(repo, *args, **kwargs)
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}), patch.object(readonly, 'git', side_effect=late):
            changed = helix_packs.git(self.repo, 'diff', '--name-only', '-z', 'HEAD', '--', required=True)
        self.assertIn('filter.lfs.clean=', diffs[0])
        self.assertIn('app.txt', changed)
        self.assertFalse(self.marker.exists())

    def test_path_with_crlf_in_its_name_keeps_its_attribute(self):
        # Text mode read CRLF in a name as LF, so check-attr matched another, shorter name.
        odd = self.repo / 'odd\r\nname.txt'
        odd.write_text('initial')
        # A driver name no global config defines: committing the fixture must not run a real filter (git-lfs on CI).
        (self.repo / '.gitattributes').write_text('app.txt filter=synthetic\nodd??name.txt filter=crlf-check\n')
        self.command('add', '.'); self.command('commit', '-qm', 'odd name')
        self.head = self.command('rev-parse', 'HEAD')
        odd.write_text('changed')
        global_config = self.base / 'global.gitconfig'
        global_config.write_text('[filter "crlf-check"]\n    clean = ' + self.fake_command + '\n    required = true\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}):
            result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filters_not_executed')

    def test_unreadable_attributes_never_fall_through_to_status(self):
        global_config = self.base / 'global.gitconfig'
        global_config.write_text('[filter "lfs"]\n    clean = ' + self.fake_command + '\n')
        original = readonly.git
        def failing(repo, *args, **kwargs):
            self.assertNotIn('status', args)
            if 'check-attr' in args: return subprocess.CompletedProcess(args, 128, '', 'fatal')
            return original(repo, *args, **kwargs)
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(global_config)}), patch.object(readonly, 'git', side_effect=failing):
            result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_filter_configuration_unknown')

    def test_fsmonitor_is_disabled_without_hiding_actual_dirty_state(self):
        self.command('config', 'core.fsmonitor', self.fake_command)
        (self.repo / 'app.txt').write_text('changed')
        result = self.provenance()
        self.assertTrue(result['target_dirty'])
        self.assertEqual(result['target_ref']['status'], 'recorded')

    def test_submodule_filter_is_not_executed_and_head_remains_known(self):
        origin = self.base / 'module-source'; origin.mkdir()
        self.command('init', '-q', repo=origin)
        self.command('config', 'user.name', 'Fixture', repo=origin)
        self.command('config', 'user.email', 'fixture@example.invalid', repo=origin)
        (origin / 'data.txt').write_text('initial')
        (origin / '.gitattributes').write_text('data.txt filter=nested\n')
        self.command('add', '.', repo=origin); self.command('commit', '-qm', 'fixture', repo=origin)
        self.command('-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(origin), 'module')
        self.command('commit', '-qam', 'module')
        self.head = self.command('rev-parse', 'HEAD')
        module = self.repo / 'module'
        self.command('config', 'filter.nested.clean', self.fake_command, repo=module)
        (module / 'data.txt').write_text('changed')
        result = self.provenance()
        self.assertIsNone(result['target_dirty'])
        self.assertEqual(result['target_ref']['status'], 'partial')
        self.assertEqual(result['target_ref']['dirty_reason'], 'git_submodules_not_inspected')

    def test_head_is_retained_on_failure_after_successful_revision_read(self):
        def git(repo, *args):
            if args == ('rev-parse', '--show-toplevel'):
                return subprocess.CompletedProcess([], 0, str(self.repo), '')
            if args == ('rev-parse', '--verify', 'HEAD^{commit}'):
                return subprocess.CompletedProcess([], 0, self.head, '')
            raise subprocess.TimeoutExpired('SECRET_COMMAND', 10)
        with patch.object(readonly, 'git', side_effect=git):
            result = readonly.read_ref(self.repo)
        self.assertEqual(result['head'], self.head)
        self.assertIsNone(result['dirty'])
        self.assertEqual(result['status'], 'partial')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_repository_environment_cannot_redirect_source_identity(self):
        other = self.base / 'other'; other.mkdir()
        self.command('init', '-q', repo=other)
        self.command('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'other', repo=other)
        with patch.dict(os.environ, {'GIT_DIR': str(other / '.git'), 'GIT_WORK_TREE': str(other),
                                     'GIT_INDEX_FILE': str(other / '.git/index')}):
            result = readonly.read_ref(self.repo)
        self.assertEqual(result['head'], self.head)
        self.assertFalse(result['dirty'])

    def test_git_environment_keeps_config_context_but_not_credentials(self):
        with patch.dict(os.environ, {'API_TOKEN': 'PRIVATE', 'GIT_CONFIG_GLOBAL': str(self.base / 'global'),
                                     'GIT_DIR': '/wrong/repo', 'GIT_INDEX_FILE': '/wrong/index'}), \
             patch.object(readonly.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')) as run:
            readonly.git(self.repo, 'rev-parse', 'HEAD')
        args, kwargs = run.call_args
        self.assertIn('core.fsmonitor=false', args[0])
        self.assertEqual(kwargs['env']['GIT_CONFIG_GLOBAL'], str(self.base / 'global'))
        self.assertEqual(kwargs['env']['GIT_OPTIONAL_LOCKS'], '0')
        for name in ('API_TOKEN', 'GIT_DIR', 'GIT_INDEX_FILE'): self.assertNotIn(name, kwargs['env'])

    def test_binary_inventory_call_preserves_requested_timeout(self):
        with patch.object(readonly.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'app.txt\0', b'')) as run:
            result = readonly.git(self.repo, 'ls-files', '-z', text=False, timeout=30)
        self.assertEqual(result.stdout, b'app.txt\0')
        self.assertFalse(run.call_args.kwargs['text'])
        self.assertEqual(run.call_args.kwargs['timeout'], 30)
        self.assertIn('core.fsmonitor=false', run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs['env']['GIT_OPTIONAL_LOCKS'], '0')

    def test_subdirectory_preserves_provenance_sha_but_strict_status_requires_root(self):
        plain = self.base / 'plain'; plain.mkdir()
        child = self.repo / 'child'; child.mkdir()
        for path in (plain, self.base / 'missing'):
            with self.subTest(path=path):
                result = readonly.read_ref(path)
                self.assertIsNone(result['head']); self.assertIsNone(result['dirty'])
                self.assertEqual(result['status'], 'unknown')
        result = readonly.read_ref(child)
        self.assertEqual(result['head'], self.head)
        self.assertEqual(result['status'], 'recorded')
        self.assertEqual(environment.provenance(child)['target_head'], self.head)
        self.assertIsNone(readonly.read_ref(child, require_root=True)['head'])
        import helix_security_status
        self.assertEqual(helix_security_status.report(child)['status'], 'ERROR')

    def test_partial_metadata_keeps_existing_normalization_and_manual_receipts(self):
        self.command('config', 'filter.synthetic.clean', self.fake_command)
        manual = dict(provider='grok', model='grok-synthetic', method='manual_handoff', status='declared',
                      request_id='request-1', reviewer='human', round=1, role='reviewer', family='xai')
        result = environment.provenance(self.repo, models=[manual], tools={'semgrep': {'version': '1.2.3', 'status': 'recorded', 'used': True}})
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['target_ref']['status'], 'partial')
        self.assertEqual(environment.normalize_models(result['models']), result['models'])
        self.assertEqual(environment.normalize_tools(result['tools']), result['tools'])
        self.assertEqual(result['models'][0]['method'], 'manual_handoff')
        self.assertFalse(result['models'][0]['call_invoked'])
        self.assertFalse(self.marker.exists())


if __name__ == '__main__': unittest.main()
