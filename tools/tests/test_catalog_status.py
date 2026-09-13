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

    def test_pkg_root_tracks_nested_staleness(self):
        self.revisions['pkg'] = '1'
        self.current['pkg'] = extract_external.tool_provenance('pkg')
        root, child = 'd'*64, 'e'*64
        self.write('pkg', '1', root, [child])
        self.write('gzip', '2', child)
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['affected_pkgs'], [root])
        self.assertEqual(report['fresh_pkgs'], {})
        self.write('gzip', '3', child)
        self.assertEqual(catalog_status(self.root, self.current)['fresh_pkgs'], {root: True})

    def test_contextual_decoder_and_descendant_invalidate_parent(self):
        a, b, c = 'a'*64, 'b'*64, 'c'*64
        path = self.write('pbp', '1', a, [b])
        decoder = dict(name='pops', version='1', sha256='d'*64, options=[])
        self.current['pops'] = decoder
        tree = json.loads(path.read_text())
        tree['entries'][0]['extraction'] = dict(sha256=b, size_bytes=42,
            extractor=decoder, name_rule='source_stem', entries=[dict(path='payload.gz', type='file', sha256=c, size_bytes=42)])
        path.write_text(json.dumps(tree))
        self.write('gzip', '2', c)
        report = catalog_status(self.root, self.current)
        self.assertIn(a, report['fresh_trees'])
        self.current['pops'] = dict(decoder, sha256='e'*64)
        report = catalog_status(self.root, self.current)
        self.assertEqual(next(x for x in report['stale'] if x['sha256']==a)['reason'], 'contextual extractor changed')

    def document_entries(self, companion='c'*64, child='d'*64):
        decoder = self.current.setdefault('document',
            dict(name='PSP-DOCUMENT.DAT', version='2', sha256='f'*64, options=[]))
        dependency = dict(path='DOCINFO.EDAT', sha256=companion, size_bytes=304)
        return [dict(dependency, type='file'),
                dict(path='DOCUMENT.DAT', type='file', sha256='b'*64, size_bytes=42,
                     extraction=dict(sha256='b'*64, size_bytes=42, name_rule='identity',
                         extractor=decoder, dependencies=[dependency],
                         entries=[dict(path='page.png', type='file', sha256=child, size_bytes=42)]))]

    def test_document_provenance_and_descendants_are_occurrence_scoped(self):
        first, second = '1'*64, '2'*64
        for root, companion, child in [(first, 'c'*64, 'd'*64), (second, 'e'*64, 'a'*64)]:
            path = self.write('iso', '2', root)
            tree = json.loads(path.read_text())
            tree['entries'] = self.document_entries(companion, child)
            path.write_text(json.dumps(tree))
        self.revisions['document'] = '2'
        self.write('document', '1', 'b'*64)
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['fresh_isos'], {first: True, second: True})
        self.write('gzip', '2', 'd'*64)
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['affected_isos'], [first])
        self.assertEqual(report['fresh_isos'], {second: True})
        self.current['document'] = dict(self.current['document'], sha256='9'*64)
        report = catalog_status(self.root, self.current)
        self.assertEqual(report['affected_isos'], [first, second])
        self.assertEqual({item['sha256'] for item in report['stale']
                          if item['reason'] == 'contextual extractor changed'}, {first, second})

    def test_document_does_not_fall_through_to_pops_provenance(self):
        root = '1'*64
        path = self.write('iso', '2', root)
        tree = json.loads(path.read_text())
        tree['entries'] = self.document_entries()
        path.write_text(json.dumps(tree))
        self.current['pops'] = self.current.pop('document')
        self.assertEqual(catalog_status(self.root, self.current)['affected_isos'], [root])

    def test_nested_dependencies_cannot_bind_other_occurrences_or_outer_inventory(self):
        root = '1'*64
        path = self.write('iso', '2', root)
        tree = json.loads(path.read_text())
        decoder = dict(name='pspdb-pops', version='1', sha256='9'*64, options=[])
        self.current['pops'] = decoder
        first, second = self.document_entries(), self.document_entries('e'*64)
        tree['entries'] = [dict(path='DOCINFO.EDAT', type='file', sha256='a'*64, size_bytes=304)]
        for name, digest, entries in [('first', '3'*64, first), ('second', '4'*64, second)]:
            tree['entries'].append(dict(path=name, type='file', sha256=digest, size_bytes=42,
                extraction=dict(sha256=digest, size_bytes=42, name_rule='identity',
                    extractor=decoder, entries=entries)))
        path.write_text(json.dumps(tree))
        self.assertEqual(catalog_status(self.root, self.current)['fresh_isos'], {root: True})
        second[1]['extraction']['dependencies'][0]['sha256'] = first[0]['sha256']
        path.write_text(json.dumps(tree))
        with self.assertRaisesRegex(ValueError, 'dependency identity mismatch'):
            catalog_status(self.root, self.current)
        second[1]['extraction']['dependencies'][0]['sha256'] = 'a'*64
        second.pop(0)
        path.write_text(json.dumps(tree))
        with self.assertRaisesRegex(ValueError, 'Missing contextual dependency'):
            catalog_status(self.root, self.current)

    def test_freshness_rejects_malformed_dependency_claims_even_in_stale_trees(self):
        root = '1'*64
        path = self.write('iso', '1', root)
        tree = json.loads(path.read_text())
        mutations = {
            'self': lambda entries, deps: deps[0].update(path='DOCUMENT.DAT', sha256='b'*64, size_bytes=42),
            'missing': lambda entries, deps: deps[0].update(path='MISSING.EDAT'),
            'directory': lambda entries, deps: entries.__setitem__(0, dict(path='DOCINFO.EDAT', type='directory')),
            'changed bytes': lambda entries, deps: entries[0].update(sha256='e'*64),
            'changed size': lambda entries, deps: entries[0].update(size_bytes=305),
            'duplicate binding': lambda entries, deps: deps.append(dict(deps[0], sha256='e'*64)),
            'ambiguous sibling': lambda entries, deps: entries.append(dict(entries[0])),
            'unsafe path': lambda entries, deps: deps[0].update(path='../DOCINFO.EDAT'),
            'invalid hash': lambda entries, deps: deps[0].update(sha256='INVALID'),
            'invalid size': lambda entries, deps: deps[0].update(size_bytes=True),
            'extra field': lambda entries, deps: deps[0].update(extra='not identity'),
            'empty': lambda entries, deps: deps.clear(),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                tree['entries'] = entries = self.document_entries()
                mutate(entries, entries[1]['extraction']['dependencies'])
                path.write_text(json.dumps(tree))
                with self.assertRaises(ValueError):
                    catalog_status(self.root, self.current)

    def test_historical_pbp_inline_extractions_need_no_dependencies(self):
        root, source = '1'*64, 'b'*64
        path = self.write('pbp', '1', root, [source])
        tree = json.loads(path.read_text())
        for name, kind in [('pops', 'pops'), ('pspdb-pops', 'pops'), ('PSXtract-2', 'psx')]:
            with self.subTest(name=name):
                decoder = dict(name=name, version='1', sha256='c'*64, options=[])
                self.current[kind] = decoder
                tree['entries'][0]['extraction'] = dict(sha256=source, size_bytes=42,
                    extractor=decoder, name_rule='source_stem',
                    entries=[dict(path='payload.bin', type='file', sha256='d'*64, size_bytes=42)])
                path.write_text(json.dumps(tree))
                self.assertIn(root, catalog_status(self.root, self.current)['fresh_trees'])
                self.current[kind] = dict(decoder, sha256='e'*64)
                self.assertNotIn(root, catalog_status(self.root, self.current)['fresh_trees'])

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
