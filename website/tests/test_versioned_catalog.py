import json
from pathlib import Path
import tempfile
import unittest

from pspdb.server import catalog_data
from pspdb.export import export_site


class VersionedCatalogTests(unittest.TestCase):
    def test_selects_latest_complete_pair_numerically_and_exports_it(self):
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
            data = catalog_data(root)
            self.assertEqual(len(data['records']['iso']), 1)
            self.assertEqual(data['records']['iso'][0]['metadata']['title'], 'Extractor 10')
            self.assertEqual(data['trees'][digest]['extractor']['version'], '10')
            export_site(root, Path(tmp) / 'export')
            exported = json.loads((Path(tmp) / 'export/catalog.json').read_text())
            self.assertEqual(exported['trees'], data['trees'])
            (latest / (digest + '-tree.json')).unlink()
            self.assertEqual(catalog_data(root)['trees'][digest]['extractor']['version'], '2')
            # A tree alone does not publish a newer metadata result.
            newer = write(11)
            (newer / (digest + '-ingest.json')).unlink()
            self.assertEqual(catalog_data(root)['trees'][digest]['extractor']['version'], '2')

    def test_pkg_metadata_and_inventory_survive_static_export(self):
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
            self.assertEqual(data['trees'][digest], tree)
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
