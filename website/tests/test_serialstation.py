import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pspdb.serialstation import load_matches
from pspdb.server import _CatalogCache, catalog_data
from pspdb.wire import decode_catalog

PRESENT = 'UP0555-NPUF30007_00-BOMBERMAN940EH01'
ABSENT = 'JP0101-NPJH50721_00-GAMEUPDATE000101'
PKG_ID = 'c540df25-fb8d-4312-9586-cc2e18b154ee'
OTHER_PKG_ID = '03962268-7c32-4e56-bd7f-e9b480c6435f'
SHA1 = '0000' + 'abcdef012345' * 3
NAME = "BOMBERMAN '94 (PS3/PSP)"
DISC_ID = '9fc05e93-ba96-4cac-919c-864a9143704b'
OTHER_DISC_ID = 'e82154c6-772e-4719-a2a6-690a9d936937'
DISC_NAME = 'Verified PSP disc'


def entry(**overrides):
    data = dict(id=PKG_ID, name=NAME, sha1=SHA1, size_bytes=4, content_id=PRESENT)
    data.update(overrides)
    return data


def snapshot(path, entries, missing=(), **overrides):
    data = {'schema_version': 2, 'retrieved': '2026-09-21T00:00:00+00:00',
            'entries': entries, 'missing': list(missing)}
    data.update(overrides)
    path.write_text(json.dumps(data), encoding='utf-8')
    return path


class SerialStationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = self.root / 'catalog'
        folder = self.catalog / 'pkg'
        folder.mkdir(parents=True)
        for char, sha1, size, content_id in (
                ('a', SHA1, 4, PRESENT),
                ('b', 'e' * 40, 4, PRESENT),
                ('c', SHA1, 5, PRESENT),
                ('d', SHA1, 4, ABSENT),
                ('e', None, 4, PRESENT),
                ('f', SHA1[4:], 4, PRESENT)):
            record = dict(kind='pkg', schema_version=1, sha256=char * 64, size_bytes=size,
                          metadata={'content_id': content_id, 'content_type': 7, 'boot_file': 'EBOOT.PBP'})
            if sha1 is not None:
                record['sha1'] = sha1
            (folder / (char * 64 + '.json')).write_text(json.dumps(record))

    def test_only_exact_package_identities_annotate_packages(self):
        source = snapshot(self.root / 'snapshot.json', {'a' * 64: entry()},
                          missing=['b' * 64, 'c' * 64, 'd' * 64, 'e' * 64])
        matches = load_matches(source)
        self.assertEqual(matches, {
            'packages': {(SHA1, 4, PRESENT): {'id': PKG_ID, 'name': NAME}},
            'discs': {},
        })
        records = catalog_data(self.catalog, serialstation=matches)['records']['pkg']
        annotated = {record['sha256']: record.get('serialstation') for record in records}
        self.assertEqual(annotated, {
            'a' * 64: {'id': PKG_ID, 'name': NAME},
            'b' * 64: None, 'c' * 64: None, 'd' * 64: None, 'e' * 64: None,
            'f' * 64: {'id': PKG_ID, 'name': NAME},
        })
        self.assertTrue(all('serialstation' not in record
                            for record in catalog_data(self.catalog)['records']['pkg']))

    def add_iso(self, char='1', sha1=SHA1, size=4):
        folder = self.catalog / 'iso'
        folder.mkdir(exist_ok=True)
        record = dict(kind='iso', schema_version=1, sha256=char * 64,
                      sha1=sha1, size_bytes=size, metadata={})
        (folder / (char * 64 + '.json')).write_text(json.dumps(record))

    def test_disc_editions_follow_only_exact_redump_matches(self):
        self.add_iso()
        self.add_iso('2', sha1='e' * 40)
        self.add_iso('3', size=5)
        self.add_iso('4', sha1='d' * 40)
        editions = [
            {'id': DISC_ID, 'name': DISC_NAME},
            {'id': OTHER_DISC_ID, 'name': 'Another edition'},
        ]
        source = snapshot(self.root / 'discs.json', {}, discs={'33401': editions})
        matches = load_matches(source)
        self.assertEqual(matches, {'packages': {}, 'discs': {33401: editions}})
        provenance = [
            {'id': 33401, 'name': 'Redump verified name'},
            {'id': 99999, 'name': 'Unmapped Redump edition'},
        ]
        redump = {(SHA1, 4): provenance, ('d' * 40, 4): [provenance[1]]}
        records = catalog_data(self.catalog, redump=redump, serialstation=matches)['records']['iso']
        records = {record['sha256']: record for record in records}
        self.assertEqual(records['1' * 64]['serialstation_discs'], [
            dict(edition, redump_id=33401) for edition in editions
        ])
        self.assertEqual(records['1' * 64]['redump'], provenance)
        self.assertEqual(records['4' * 64]['redump'], [provenance[1]])
        for char in ('2', '3', '4'):
            self.assertNotIn('serialstation_discs', records[char * 64])
        for char in ('2', '3'):
            self.assertNotIn('redump', records[char * 64])
        without_redump = catalog_data(self.catalog, serialstation=matches)['records']['iso']
        self.assertTrue(all('serialstation_discs' not in record for record in without_redump))

    def test_disk_cache_tracks_package_and_disc_changes(self):
        self.add_iso()
        redump = {(SHA1, 4): [{'id': 33401, 'name': DISC_NAME}]}
        source = self.root / 'cache-source.json'
        with patch.dict('os.environ', {'PSPDB_WEB_CACHE_DIR': str(self.root / 'cache')}):
            for pkg_id, disc_id in (
                    (PKG_ID, DISC_ID), (OTHER_PKG_ID, DISC_ID), (OTHER_PKG_ID, OTHER_DISC_ID)):
                matches = load_matches(snapshot(source, {'a' * 64: entry(id=pkg_id)},
                                                discs={'33401': [{'id': disc_id, 'name': DISC_NAME}]}))
                payload = _CatalogCache(self.catalog, None, redump, None, serialstation=matches).get()
                records = decode_catalog(json.loads(payload['body']))['records']
                packages = {record['sha256']: record for record in records['pkg']}
                self.assertEqual(packages['a' * 64]['serialstation']['id'], pkg_id)
                self.assertEqual(records['iso'][0]['serialstation_discs'], [
                    {'id': disc_id, 'name': DISC_NAME, 'redump_id': 33401},
                ])

    def test_rejects_invalid_disc_mapping(self):
        edition = {'id': DISC_ID, 'name': DISC_NAME}
        invalid = (None, [], {'33401': None}, {'33401': []}, {'33401': edition},
                   {'33401': [None]}, {'33401': [edition, edition]})
        for discs in invalid:
            with self.subTest(discs=discs):
                with self.assertRaises(ValueError):
                    load_matches(snapshot(self.root / 'invalid-discs.json', {}, discs=discs))

    def test_rejects_noncanonical_redump_ids(self):
        for identifier in ('0', '-1', '+1', '033401', '33401.0', ' 33401', '٣٣٤٠١'):
            with self.subTest(identifier=identifier):
                discs = {identifier: [{'id': DISC_ID, 'name': DISC_NAME}]}
                with self.assertRaisesRegex(ValueError, 'Redump ID'):
                    load_matches(snapshot(self.root / 'invalid-id.json', {}, discs=discs))

    def test_rejects_invalid_disc_identity_fields(self):
        invalid = (
            ('id', None), ('id', 'not-a-uuid'), ('id', DISC_ID.upper()),
            ('id', DISC_ID.replace('-', '')), ('name', None), ('name', '  '),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                edition = {'id': DISC_ID, 'name': DISC_NAME, field: value}
                with self.assertRaises(ValueError):
                    load_matches(snapshot(self.root / 'invalid-edition.json', {},
                                          discs={'33401': [edition]}))

    def test_rejects_content_id_only_schema(self):
        source = snapshot(self.root / 'schema.json', {PRESENT: {'name': NAME}}, schema_version=1)
        with self.assertRaisesRegex(ValueError, 'schema'):
            load_matches(source)

    def test_rejects_invalid_package_identity_fields(self):
        invalid = (
            ('sha1', SHA1[4:]),
            ('sha1', SHA1.upper()),
            ('sha1', 'g' * 40),
            ('sha1', None),
            ('size_bytes', 0),
            ('size_bytes', -1),
            ('size_bytes', True),
            ('size_bytes', 4.0),
            ('content_id', 'NOT-A-CONTENT-ID'),
            ('content_id', None),
            ('id', 'not-a-uuid'),
            ('id', PKG_ID.upper()),
            ('id', PKG_ID.replace('-', '')),
            ('id', None),
            ('name', '  '),
            ('name', None),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                source = snapshot(self.root / 'invalid.json', {'a' * 64: entry(**{field: value})})
                with self.assertRaises(ValueError):
                    load_matches(source)

    def test_rejects_invalid_sha256_keys(self):
        for sha256 in ('a' * 63, 'A' * 64, 'g' * 64, PRESENT):
            with self.subTest(sha256=sha256):
                source = snapshot(self.root / 'sha256.json', {sha256: entry()})
                with self.assertRaisesRegex(ValueError, 'SHA256'):
                    load_matches(source)

    def test_rejects_conflicting_package_identities(self):
        for conflicting in (entry(id=OTHER_PKG_ID), entry(name='Another package')):
            with self.subTest(conflicting=conflicting):
                source = snapshot(self.root / 'conflict.json', {
                    'a' * 64: entry(), 'b' * 64: conflicting,
                })
                with self.assertRaisesRegex(ValueError, 'Conflicting'):
                    load_matches(source)

    def test_identical_package_identities_are_unambiguous(self):
        source = snapshot(self.root / 'duplicate.json', {
            'a' * 64: entry(), 'b' * 64: entry(),
        })
        self.assertEqual(load_matches(source), {
            'packages': {(SHA1, 4, PRESENT): {'id': PKG_ID, 'name': NAME}},
            'discs': {},
        })

    def test_rejects_unusable_snapshots(self):
        for entries in (None, [], {'a' * 64: None}):
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    load_matches(snapshot(self.root / 'entries.json', entries))
        broken = self.root / 'broken.json'
        broken.write_text('{')
        with self.assertRaises(ValueError):
            load_matches(broken)


if __name__ == '__main__':
    unittest.main()
