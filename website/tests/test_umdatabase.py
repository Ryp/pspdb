import json
from pathlib import Path
import tempfile
import unittest

from pspdb.umdatabase import load_matches
from pspdb.server import catalog_data


class UMDatabaseTests(unittest.TestCase):
    def test_disc_hash_matching_ignores_comments_and_file_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pages = root / 'pages'; pages.mkdir()
            sha1 = 'a' * 40
            page = (
                '<title>UMDatabase — A &amp; B</title>'
                '<!-- <p class="text-subkey">SHA-1:</p><p class="text-value">' + 'b' * 40 + '</p> -->'
                '<p class="text-subkey">SHA-1:</p><p class="text-value">' + sha1.upper() + '</p>'
                '<a title="SHA1: ' + 'c' * 40 + '">file.bin</a>'
            )
            for name in ('ABCDEF01', 'ABCDEF02'):
                (pages / (name + '.html')).write_text(page)
            (pages / 'ABCDEF03.html').write_text('<title>No dump hashes available</title>')
            matches = load_matches(pages)
            self.assertEqual(set(matches), {sha1})
            self.assertEqual([m['id'] for m in matches[sha1]], ['ABCDEF01', 'ABCDEF02'])
            self.assertEqual(matches[sha1][0]['name'], 'UMDatabase — A & B')
            catalog = root / 'catalog'; folder = catalog / 'iso'; folder.mkdir(parents=True)
            for char in ('a', 'b'):
                record = dict(kind='iso', schema_version=1, sha256=char * 64,
                              sha1=char * 40, metadata={})
                (folder / (char * 64 + '.json')).write_text(json.dumps(record))
            before = {p: p.read_bytes() for p in folder.iterdir()}
            records = catalog_data(catalog, umdatabase=matches)['records']['iso']
            self.assertEqual(records[0]['umdatabase'], matches[sha1])
            self.assertNotIn('umdatabase', records[1])
            self.assertTrue(all('umdatabase' not in r for r in catalog_data(catalog)['records']['iso']))
            self.assertEqual(before, {p: p.read_bytes() for p in folder.iterdir()})

    def test_rejects_invalid_source_and_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                load_matches(root / 'missing')
            page = root / 'unsafe.html'
            page.write_text('')
            with self.assertRaises(ValueError):
                load_matches(root)
            page.unlink()
            (root / 'ABCDEF01.html').write_text(
                '<p class="text-subkey">SHA-1:</p><p class="text-value">invalid</p>')
            with self.assertRaises(ValueError):
                load_matches(root)
