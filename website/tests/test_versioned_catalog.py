import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pspdb.server import catalog_data, load_extractor_registry
from pspdb.export import export_site


class VersionedCatalogTests(unittest.TestCase):
    @patch('pspdb.server.load_extractor_registry', return_value=({'iso': '11'}, {}))
    def test_selects_latest_complete_pair_numerically_and_exports_it(self, registry):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'catalog'; root.mkdir()
            digest = 'a' * 64
            def write(version):
                folder = root / 'iso' / f'v{version}'; folder.mkdir(parents=True)
                record = dict(kind='iso', schema_version=1, sha256=digest, size_bytes=42,
                              metadata={'title': f'Extractor {version}'})
                tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=42,
                            extractor={'name': 'pspdb-ingest', 'version': str(version), 'options': []}, entries=[])
                (folder / (digest + '-ingest.json')).write_text(json.dumps(record))
                (folder / (digest + '-tree.json')).write_text(json.dumps(tree))
                return folder
            write(2); latest = write(10)
            before = {path: path.read_bytes() for path in root.rglob('*.json')}
            data = catalog_data(root)
            self.assertEqual(len(data['records']['iso']), 1)
            self.assertEqual(data['records']['iso'][0]['metadata']['title'], 'Extractor 10')
            self.assertEqual(data['trees']['iso'][digest]['extractor']['version'], '10')
            self.assertEqual(data['trees']['iso'][digest]['stale_extraction'],
                             {'kind': 'iso', 'version': '10', 'latest_version': '11'})
            export_site(root, Path(tmp) / 'export')
            exported = json.loads((Path(tmp) / 'export/catalog.json').read_text())
            self.assertEqual(exported['trees'], data['trees'])
            self.assertEqual(before, {path: path.read_bytes() for path in root.rglob('*.json')})
            (latest / (digest + '-tree.json')).unlink()
            self.assertEqual(catalog_data(root)['trees']['iso'][digest]['extractor']['version'], '2')
            # A tree alone does not publish a newer metadata result.
            newer = write(11)
            (newer / (digest + '-ingest.json')).unlink()
            self.assertEqual(catalog_data(root)['trees']['iso'][digest]['extractor']['version'], '2')

    @patch('pspdb.server.load_extractor_registry', return_value=({'pkg': '1'}, {}))
    def test_pkg_metadata_and_inventory_survive_static_export(self, registry):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'catalog'; folder = root/'pkg/v1'; folder.mkdir(parents=True)
            digest = 'f'*64
            record = dict(kind='pkg', schema_version=1, sha256=digest, size_bytes=123,
                          metadata={'content_id':'UP9000-NPUG00001_00-FIXTURE000000000', 'title':'Demo'})
            tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=123,
                        extractor={'name':'pspdb-ingest', 'version':'1', 'options':[]}, entries=[])
            (folder/(digest+'-ingest.json')).write_text(json.dumps(record))
            (folder/(digest+'-tree.json')).write_text(json.dumps(tree))
            export_site(root, Path(tmp)/'export')
            data = json.loads((Path(tmp)/'export/catalog.json').read_text())
            self.assertEqual(data['records']['pkg'], [record])
            self.assertEqual(data['trees']['pkg'][digest], tree)
            self.assertFalse(data['downloads_enabled'])

    def test_rejects_tree_version_and_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); folder = root / 'iso/v1'; folder.mkdir(parents=True)
            digest = 'a'*64
            (folder / (digest + '-ingest.json')).write_text(json.dumps(dict(kind='iso', schema_version=1, sha256=digest, size_bytes=42)))
            tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=42,
                        extractor={'name': 'pspdb-ingest', 'version': '2', 'options': []}, entries=[])
            path = folder / (digest + '-tree.json'); path.write_text(json.dumps(tree))
            with self.assertRaisesRegex(ValueError, 'versioned tree'):
                catalog_data(root)
            tree['extractor']['version'] = '1'; tree['size_bytes'] = 43
            path.write_text(json.dumps(tree))
            with self.assertRaisesRegex(ValueError, 'versioned tree'):
                catalog_data(root)


class RoleCatalogTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.digest = 'a' * 64

    def write_pair(self, kind, digest, entries, size=42, version=1):
        folder = self.root / kind / f'v{version}'
        folder.mkdir(parents=True, exist_ok=True)
        record = dict(kind=kind, schema_version=1, sha256=digest, size_bytes=size)
        tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=size,
                    extractor={'name': 'pspdb-ingest', 'version': str(version)}, entries=entries)
        (folder / f'{digest}-ingest.json').write_text(json.dumps(record))
        path = folder / f'{digest}-tree.json'
        path.write_text(json.dumps(tree))
        return path

    def test_legacy_tree_retains_unique_historical_owner_beside_new_role(self):
        source = self.root / 'iso'; source.mkdir()
        record = dict(kind='iso', schema_version=1, sha256=self.digest, size_bytes=42)
        (source / f'{self.digest}.json').write_text(json.dumps(record))
        legacy = self.root / 'trees'; legacy.mkdir()
        tree = dict(kind='tree', schema_version=1, sha256=self.digest, size_bytes=42,
                    extractor={'name': 'iso'}, entries=[dict(type='directory', path='root-only')])
        (legacy / f'{self.digest}.json').write_text(json.dumps(tree))
        self.write_pair('iso9660', self.digest, [dict(type='directory', path='nested-only')])
        data = catalog_data(self.root)
        self.assertEqual(data['trees']['iso'][self.digest]['entries'][0]['path'], 'root-only')
        self.assertEqual(data['trees']['iso9660'][self.digest]['entries'][0]['path'], 'nested-only')
        record['kind'] = 'iso9660'
        (self.root / 'iso9660' / f'{self.digest}.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'Ambiguous legacy'):
            catalog_data(self.root)

    def test_conflicting_source_sizes_are_rejected_across_roles(self):
        self.write_pair('iso', self.digest, [])
        self.write_pair('iso9660', self.digest, [], size=43)
        with self.assertRaisesRegex(ValueError, 'Conflicting source sizes'):
            catalog_data(self.root)

    def test_ambiguous_derived_reference_rejects_catalog_but_inline_wins(self):
        parent, leaf = 'b' * 64, 'c' * 64
        self.write_pair('prx', self.digest, [])
        self.write_pair('gzip', self.digest, [])
        # Multiple observations can coexist until a bare byte reference needs a choice.
        data = catalog_data(self.root)
        self.assertEqual(set(data['trees']), {'prx', 'gzip'})
        entry = dict(type='file', path='DATA.PSP', sha256=self.digest, size_bytes=42)
        path = self.write_pair('iso', parent, [entry], size=100)
        with self.assertRaisesRegex(ValueError, 'Ambiguous non-root'):
            catalog_data(self.root)
        entry['extraction'] = dict(sha256=self.digest, size_bytes=42, name_rule='source_stem',
                                  entries=[dict(type='file', path='payload.gz', sha256=leaf, size_bytes=7)])
        tree = json.loads(path.read_text())
        tree['entries'] = [entry]
        path.write_text(json.dumps(tree))
        from pspdb.server import download_index
        self.assertIn('DATA.gz', download_index(catalog_data(self.root))[leaf][1])

    def test_stale_observations_remain_scoped_to_kind_and_inline_occurrence(self):
        leaf = dict(type='directory', path='still-browsable')
        inline = dict(sha256=self.digest, size_bytes=42,
                      extractor={'name': 'pspdb-pops', 'version': '1'}, entries=[leaf])
        entries = [dict(type='file', path='DATA.PSP', sha256=self.digest, size_bytes=42,
                        extraction=inline)]
        self.write_pair('iso', self.digest, entries, version=4)
        self.write_pair('pbp', self.digest, [leaf], version=12)
        self.write_pair('gzip', self.digest, [], version=3)
        versions = {'iso': '4', 'pbp': '13', 'gzip': '2', 'pops': '2'}
        with patch('pspdb.server.load_extractor_registry', return_value=(versions, load_extractor_registry()[1])):
            data = catalog_data(self.root)
        root = data['trees']['iso'][self.digest]
        self.assertNotIn('stale_extraction', root)
        self.assertEqual(data['trees']['pbp'][self.digest]['stale_extraction'],
                         {'kind': 'pbp', 'version': '12', 'latest_version': '13'})
        self.assertNotIn('stale_extraction', data['trees']['gzip'][self.digest])
        contextual = root['entries'][0]['extraction']
        self.assertEqual(contextual['stale_extraction'],
                         {'kind': 'pops', 'version': '1', 'latest_version': '2'})
        self.assertEqual(contextual['entries'], [leaf])

    def test_unknown_revisions_and_contextual_names_do_not_claim_stale(self):
        entries = []
        for index, extractor in enumerate((
                {'name': 'pops', 'version': '2'},
                {'name': 'pops', 'version': '10'},
                {'name': 'pops', 'version': '11'},
                {'name': 'pops'},
                {'name': 'pops', 'version': '1.0'},
                {'name': 'pops', 'version': 1},
                {'name': 'unknown', 'version': '1'})):
            entries.append(dict(type='file', path=f'{index}.bin', sha256=self.digest, size_bytes=42,
                                extraction=dict(sha256=self.digest, size_bytes=42,
                                                extractor=extractor, entries=[])))
        self.write_pair('iso', self.digest, entries)
        with patch('pspdb.server.load_extractor_registry',
                   return_value=({'pops': '10'}, load_extractor_registry()[1])):
            data = catalog_data(self.root)
        root = data['trees']['iso'][self.digest]
        self.assertNotIn('stale_extraction', root)
        self.assertEqual(root['entries'][0]['extraction']['stale_extraction'],
                         {'kind': 'pops', 'version': '2', 'latest_version': '10'})
        for entry in root['entries'][1:]:
            self.assertNotIn('stale_extraction', entry['extraction'])
