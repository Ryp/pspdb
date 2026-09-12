import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from pspdb.redump import load_matches
from pspdb.server import catalog_data


class RedumpTests(unittest.TestCase):
    def test_dat_zip_exact_matches_and_multiple_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sha1 = 'a' * 40
            xml = ('<datafile>' + ''.join(
                f'<game id="{id}" name="Game {id}"><rom name="game.iso" size="42" sha1="{sha1.upper()}"/></game>'
                for id in (123, 456, 123)) + '</datafile>')
            dat = root / 'games.dat'; dat.write_text(xml)
            archive = root / 'games.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr('games.dat', xml)
                output.writestr('readme.txt', 'unused')
            self.assertEqual(load_matches(dat), load_matches(archive))
            index = load_matches(archive)
            folder = root / 'iso'; folder.mkdir(parents=True)
            for char, extra in [('a', {'sha1': sha1, 'size_bytes': 42}),
                                ('b', {'sha1': sha1, 'size_bytes': 43}),
                                ('c', {'sha1': 'b' * 40, 'size_bytes': 42}),
                                ('d', {'size_bytes': 42})]:
                record = dict(kind='iso', schema_version=1, sha256=char * 64, metadata={}, **extra)
                (folder / (char * 64 + '.json')).write_text(json.dumps(record))
            before = {p: p.read_bytes() for p in folder.iterdir()}
            records = catalog_data(root, index)['records']['iso']
            self.assertEqual([m['id'] for m in records[0]['redump']], [123, 456])
            self.assertEqual(records[0]['redump'][0], {'id': 123, 'name': 'Game 123'})
            self.assertTrue(all('redump' not in record for record in records[1:]))
            self.assertTrue(all('redump' not in record for record in catalog_data(root)['records']['iso']))
            self.assertEqual(before, {p: p.read_bytes() for p in folder.iterdir()})

    def test_rejects_bad_dat(self):
        with tempfile.TemporaryDirectory() as tmp:
            dat = Path(tmp) / 'games.dat'
            for xml in ['<broken', '<other/>', '<datafile><game id="javascript:1"/></datafile>',
                        '<datafile><game id="1"><rom name="a.iso" size="1" sha1="oops"/></game></datafile>']:
                dat.write_text(xml)
                with self.assertRaises(ValueError):
                    load_matches(dat)
