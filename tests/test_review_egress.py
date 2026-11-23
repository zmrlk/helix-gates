"""POSIX path glob regressions for source exclusion."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from helix_data_egress import _matches
from test_data_egress_security import prepared, approved


class ReviewEgress(unittest.TestCase):
    def test_nested_globstar_includes_zero_directory_segments(self):
        for name, pattern in [('apps/private/keys.txt', 'apps/**/private/**'),
                              ('packages/.env.local', 'packages/**/.env*'),
                              ('a/b/c.txt', 'a/**/b/**/c.txt'),
                              ('apps/x/y/private/keys.txt', 'apps/**/private/**'),
                              ('.env', '**/.env*'), ('private', '**/private/**')]:
            with self.subTest(name=name, pattern=pattern): self.assertTrue(_matches(name, pattern))

    def test_single_star_stays_in_its_path_segment(self):
        self.assertFalse(_matches('apps/a/b/private/key', 'apps/*/private/**'))
        self.assertTrue(_matches('apps/a/private/key', 'apps/*/private/**'))
        self.assertFalse(_matches('app/private/key', 'apps/**/private/**'))

    def test_custom_nested_exclusion_removes_payload_from_prepared_sources(self):
        sources = {'apps/internal/code.ts': 'EXCLUDED_PAYLOAD', 'apps/public.ts': 'export const x=1;'}
        outbound, meta = prepared(sources, policy=approved(exclude_paths=['apps/**/internal/**']))
        self.assertEqual(outbound, {'apps/public.ts': sources['apps/public.ts']})
        self.assertEqual(meta['counts']['excluded_files'], 1)

    def test_owner_patterns_written_for_fnmatch_still_exclude(self):
        # Regression for the strict-segment fix: *.csv and dir/* used to cross /.
        sources = {'a/b/x.csv': 'EXPORT_ROWS', 'exports/2026/q3.txt': 'EXPORT_TEXT',
                   'secret-dir/sub/f.ts': 'SECRET', 'src/ok.ts': 'export const ok=1;'}
        outbound, meta = prepared(sources, policy=approved(exclude_paths=['*.csv', 'exports/*', 'secret-dir']))
        self.assertEqual(outbound, {'src/ok.ts': sources['src/ok.ts']})
        self.assertEqual(meta['counts']['excluded_files'], 3)


if __name__ == '__main__': unittest.main()
