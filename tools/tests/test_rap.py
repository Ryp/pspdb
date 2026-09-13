from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from tools import rap


CONTENT_ID = 'JP0024-NPJH50321_00-0000A70000010100'
KEY = '0123456789abcdef0123456789abcdef'
OTHER_KEY = 'fedcba9876543210fedcba9876543210'


class RapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / 'licenses'
        self.path = self.directory / (CONTENT_ID + '.rap')

    def test_import_is_private_idempotent_and_readable_by_extractor(self):
        result = rap.import_raps(self.directory, [(CONTENT_ID, KEY), (CONTENT_ID, KEY.upper()),
                                                  (CONTENT_ID, 'NOT REQUIRED')])
        self.assertEqual(result['counts'], {'imported': 1})
        self.assertEqual(rap.read_rap(CONTENT_ID, self.directory), bytes.fromhex(KEY))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, KEY)])['counts'], {'present': 1})
        self.assertNotIn(KEY, json.dumps(result))
        self.assertEqual(list(self.directory.iterdir()), [self.path])

    def test_conflicting_snapshots_never_publish_or_replace_a_key(self):
        entries = [(CONTENT_ID, KEY), (CONTENT_ID, OTHER_KEY)]
        self.assertEqual(rap.import_raps(self.directory, entries)['counts'], {'conflict': 1})
        self.assertFalse(self.path.exists())
        rap.import_raps(self.directory, [(CONTENT_ID, KEY)])
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, OTHER_KEY)])['counts'], {'conflict': 1})
        self.assertEqual(self.path.read_bytes(), bytes.fromhex(KEY))

    def test_invalid_keys_and_identifiers_cannot_publish_or_leak(self):
        result = rap.import_raps(self.directory, [('../' + KEY, KEY), (CONTENT_ID, KEY[:-1]), (CONTENT_ID, KEY)])
        self.assertEqual(result['counts'], {'invalid': 2})
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertNotIn(KEY, json.dumps(result))
        with self.assertRaises(ValueError):
            rap.read_rap('../' + KEY, self.directory)

    def test_missing_keys_can_reuse_existing_files_but_not_invalid_files(self):
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, '')])['counts'], {'missing': 1})
        with self.assertRaises(ValueError) as caught:
            rap.read_rap(CONTENT_ID, self.directory)
        self.assertIn(CONTENT_ID, str(caught.exception))
        self.assertIn(str(self.directory), str(caught.exception))
        self.path.write_bytes(b'short')
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, KEY)])['counts'], {'invalid': 1})
        self.assertEqual(self.path.read_bytes(), b'short')
        with self.assertRaises(ValueError):
            rap.read_rap(CONTENT_ID, self.directory)
        self.path.write_bytes(bytes.fromhex(KEY))
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, 'MISSING')])['counts'], {'present': 1})

    def test_symlinks_and_special_files_are_not_read_or_replaced(self):
        self.directory.mkdir()
        outside = self.root / 'outside'
        outside.write_bytes(bytes.fromhex(KEY))
        self.path.symlink_to(outside)
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, KEY)])['counts'], {'invalid': 1})
        with self.assertRaises(ValueError):
            rap.read_rap(CONTENT_ID, self.directory)
        self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            rap.read_rap(CONTENT_ID, self.directory)
        self.assertEqual(rap.import_raps(self.directory, [(CONTENT_ID, KEY)])['counts'], {'invalid': 1})
        self.assertTrue(stat.S_ISFIFO(self.path.stat().st_mode))

    def test_concurrent_conflicting_imports_do_not_clobber(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda key: rap.import_raps(self.directory, [(CONTENT_ID, key)]), [KEY, OTHER_KEY]))
        self.assertCountEqual([next(iter(result['counts'])) for result in results], ['imported', 'conflict'])
        self.assertIn(rap.read_rap(CONTENT_ID, self.directory), [bytes.fromhex(KEY), bytes.fromhex(OTHER_KEY)])
        self.assertEqual(list(self.directory.iterdir()), [self.path])


if __name__ == '__main__':
    unittest.main()
