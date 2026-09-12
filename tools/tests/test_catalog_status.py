import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import extract_external
from tools.catalog_status import catalog_status


class CatalogStatusTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.revisions = {'iso': '2', 'gzip': '3', 'pbp': '1'}
        self.patch = patch.object(extract_external, 'VERSIONS', self.revisions)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.current = {kind: extract_external.tool_provenance(kind) for kind in self.revisions}

    def write(self, kind, version, digest, children=(), provenance=None):
        path = self.root / kind / ('v' + version) / (digest + '-tree.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        record = dict(kind=kind, schema_version=1, sha256=digest, size_bytes=42)
        path.with_name(digest + '-ingest.json').write_text(json.dumps(record))
        tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=42,
                    extractor=provenance or dict(self.current[kind], version=version),
                    entries=[dict(path=str(i), type='file', sha256=child, size_bytes=42)
                             for i, child in enumerate(children)])
        path.write_text(json.dumps(tree))
        return path

    def test_nested_revision_invalidates_roots_without_invalidating_current_parent(self):
        a, b, c = 'a'*64, 'b'*64, 'c'*64
        self.write('iso', '2', a, [b])
        self.write('pbp', '1', b, [c])
        old = self.write('gzip', '2', c)
        before = old.read_bytes()
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['affected_isos'], [a])
        self.assertEqual([x['sha256'] for x in report['stale']], [c])
        self.assertEqual(set(report['fresh_trees']), {a, b})
        self.write('gzip', '3', c)
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['stale'], [])
        self.assertEqual(report['fresh_isos'], {a: True})
        self.assertEqual(old.read_bytes(), before)

    def test_cycles_propagate_staleness_and_terminate(self):
        a, b, c = 'a'*64, 'b'*64, 'c'*64
        self.write('iso', '2', a, [b])
        self.write('pbp', '1', b, [c])
        self.write('gzip', '2', c, [b])
        self.assertEqual(catalog_status(self.root, self.current)['affected_isos'], [a])

    def test_tool_change_and_unavailable_tool_are_not_fresh(self):
        digest = 'b'*64
        self.write('gzip', '3', digest, provenance=dict(self.current['gzip'], sha256='a'*64))
        self.assertEqual(catalog_status(self.root, self.current)['stale'][0]['reason'], 'extractor changed')
        report = catalog_status(self.root, {}, {'gzip': 'tool missing'})
        self.assertEqual(report['fresh_trees'], {})
        self.assertEqual(report['stale'][0]['unavailable'], 'tool missing')

    def test_numeric_versions_and_identity_validation(self):
        digest = 'a'*64
        self.revisions['iso'] = '10'; self.current['iso']['version'] = '10'
        self.write('iso', '2', digest)
        path = self.write('iso', '10', digest)
        self.assertEqual(catalog_status(self.root, self.current)['stale'], [])
        record = json.loads(path.read_text()); record['extractor']['version'] = '2'
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'Invalid versioned extraction'):
            catalog_status(self.root, self.current)

    def test_missing_half_of_pair_requires_regeneration(self):
        digest = 'a'*64
        path = self.write('iso', '2', digest)
        path.unlink()
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['stale'][0]['reason'], 'missing tree')
        self.assertEqual(report['affected_isos'], [digest])
        path = self.write('iso', '2', digest)
        path.with_name(digest + '-ingest.json').unlink()
        self.assertEqual(catalog_status(self.root, self.current)['stale'][0]['reason'], 'missing metadata')
