import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.validate_catalog import read_json, validate_catalog, validate_changes


class CatalogValidationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'catalog'
        self.folder = self.root / 'iso/v1'; self.folder.mkdir(parents=True)
        self.digest = 'a' * 64
        self.record = dict(kind='iso', schema_version=1, sha256=self.digest, size_bytes=42)
        self.tree = dict(kind='tree', schema_version=1, sha256=self.digest, size_bytes=42,
                         extractor={'name': 'pspdb-ingest', 'version': '1', 'options': []}, entries=[])
        self.ingest_path = self.folder / (self.digest + '-ingest.json')
        self.tree_path = self.folder / (self.digest + '-tree.json')
        self.save()

    def save(self):
        self.ingest_path.write_text(json.dumps(self.record))
        self.tree_path.write_text(json.dumps(self.tree))

    def test_valid_pair_needs_no_external_tools(self):
        with patch.dict(os.environ, {'PATH': ''}):
            self.assertEqual(validate_catalog(self.root), {'pairs': 1, 'isos': 1})

    def test_native_prx_accepts_native_provenance_but_external_requires_hash(self):
        folder = self.root / 'prx/v4'
        folder.mkdir(parents=True)
        self.ingest_path.unlink()
        self.tree_path.unlink()
        self.ingest_path = folder / (self.digest + '-ingest.json')
        self.tree_path = folder / (self.digest + '-tree.json')
        self.record['kind'] = 'prx'
        self.tree['extractor']['version'] = '4'
        self.save()
        self.assertEqual(validate_catalog(self.root), {'pairs': 1, 'isos': 0})
        self.tree['extractor']['name'] = 'pspdecrypt'
        self.save()
        with self.assertRaisesRegex(ValueError, 'external executable hash'):
            validate_catalog(self.root)
        self.tree['extractor']['sha256'] = 'b' * 64
        self.save()
        self.assertEqual(validate_catalog(self.root), {'pairs': 1, 'isos': 0})

    def test_contextual_tree_checks_attachment_and_nested_entries(self):
        entry = dict(path='DATA.PSP', type='file', sha256='b'*64, size_bytes=14)
        entry['extraction'] = dict(sha256='b'*64, size_bytes=14, name_rule='source_stem',
            extractor=dict(name='pops', version='1', options=[]),
            entries=[dict(path='payload.gz', type='file', sha256='c'*64, size_bytes=7)])
        self.tree['entries'] = [entry]; self.save()
        self.assertEqual(validate_catalog(self.root)['pairs'], 1)
        entry['extraction']['sha256'] = 'd'*64; self.save()
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            validate_catalog(self.root)
        entry['extraction']['sha256'] = 'b'*64
        entry['extraction']['entries'][0]['size_bytes'] = 0; self.save()
        with self.assertRaisesRegex(ValueError, 'empty-file'):
            validate_catalog(self.root)

    def paired_entries(self, companion='c'*64):
        document = dict(path='DOCUMENT.DAT', type='file', sha256='b'*64, size_bytes=14)
        dependency = dict(path='DOCINFO.EDAT', sha256=companion, size_bytes=304)
        document['extraction'] = dict(sha256='b'*64, size_bytes=14, name_rule='identity',
            extractor=dict(name='PSP-DOCUMENT.DAT', version='2', options=[]),
            dependencies=[dependency],
            entries=[dict(path='001.png', type='file', sha256='d'*64, size_bytes=7)])
        return [dict(dependency, type='file'), document]

    def test_dependencies_bind_same_document_separately_in_nested_occurrences(self):
        first, second = self.paired_entries(), self.paired_entries('e'*64)
        self.tree['entries'] = [dict(path='DOCINFO.EDAT', type='file', sha256='f'*64, size_bytes=304)]
        for path, digest, entries in [('first.pbp', '1'*64, first), ('second.pbp', '2'*64, second)]:
            self.tree['entries'].append(dict(path=path, type='file', sha256=digest, size_bytes=100,
                extraction=dict(sha256=digest, size_bytes=100, name_rule='identity',
                    extractor=dict(name='pops', version='1', options=[]), entries=entries)))
        self.save()
        self.assertEqual(validate_catalog(self.root)['pairs'], 1)
        second[1]['extraction']['dependencies'][0]['sha256'] = first[0]['sha256']
        self.save()
        with self.assertRaisesRegex(ValueError, 'dependency identity mismatch'):
            validate_catalog(self.root)
        second[1]['extraction']['dependencies'][0]['sha256'] = 'f'*64
        second.pop(0)
        self.save()
        with self.assertRaisesRegex(ValueError, 'Missing contextual dependency'):
            validate_catalog(self.root)

    def test_dependencies_reject_false_or_ambiguous_bindings(self):
        mutations = {
            'self': lambda entries, deps: deps[0].update(path='DOCUMENT.DAT', sha256='b'*64, size_bytes=14),
            'missing': lambda entries, deps: deps[0].update(path='MISSING.EDAT'),
            'directory': lambda entries, deps: entries.__setitem__(0, dict(path='DOCINFO.EDAT', type='directory')),
            'hash': lambda entries, deps: deps[0].update(sha256='e'*64),
            'size': lambda entries, deps: deps[0].update(size_bytes=303),
            'duplicate': lambda entries, deps: deps.append(dict(deps[0], sha256='e'*64)),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.tree['entries'] = entries = self.paired_entries()
                mutate(entries, entries[1]['extraction']['dependencies'])
                self.save()
                with self.assertRaises(ValueError):
                    validate_catalog(self.root)

    def test_dependency_schema_rejects_empty_unsafe_and_incomplete_identities(self):
        dependency = dict(path='DOCINFO.EDAT', sha256='c'*64, size_bytes=304)
        invalid = [[], [dependency, dependency], [dict(dependency, sha256='INVALID')],
                   [dict(dependency, size_bytes=-1)], [dict(dependency, extra='not identity')],
                   [dict(path='DOCINFO.EDAT', sha256='c'*64)]]
        invalid.extend([dict(dependency, path=path)] for path in
                       ('../DOCINFO.EDAT', '/DOCINFO.EDAT', 'a//b', 'a/./b', 'a\\b', 'a:', 'a/', 'a\nb'))
        for dependencies in invalid:
            with self.subTest(dependencies=dependencies):
                self.tree['entries'] = self.paired_entries()
                self.tree['entries'][1]['extraction']['dependencies'] = dependencies
                self.save()
                with self.assertRaises(ValueError):
                    validate_catalog(self.root)

    def test_dependency_bytes_participate_in_global_size_consistency(self):
        self.tree['entries'] = self.paired_entries()
        self.tree['entries'].append(dict(path='other', type='file', sha256='c'*64, size_bytes=305))
        self.save()
        with self.assertRaisesRegex(ValueError, 'Conflicting byte sizes'):
            validate_catalog(self.root)

    def test_missing_partner_and_wrong_identity_are_rejected(self):
        self.tree_path.unlink()
        with self.assertRaisesRegex(ValueError, 'partner'):
            validate_catalog(self.root)
        self.tree['sha256'] = 'b' * 64; self.save()
        with self.assertRaisesRegex(ValueError, 'identity'):
            validate_catalog(self.root)

    def test_schema_rejects_payload_and_invalid_paths(self):
        self.record['payload'] = 'not catalog data'; self.save()
        with self.assertRaises(ValueError): validate_catalog(self.root)
        del self.record['payload']
        self.tree['entries'] = [dict(path='../file', type='file', sha256='b'*64, size_bytes=2)]
        self.save()
        with self.assertRaises(ValueError): validate_catalog(self.root)

    def test_tree_structure_and_hash_sizes(self):
        self.tree['entries'] = [dict(path='folder/file', type='file', sha256='b'*64, size_bytes=2)]
        self.save()
        with self.assertRaisesRegex(ValueError, 'parent directory'): validate_catalog(self.root)
        self.tree['entries'] = [dict(path='file', type='file', sha256=self.digest, size_bytes=2)]
        self.save()
        with self.assertRaisesRegex(ValueError, 'Conflicting byte sizes'): validate_catalog(self.root)
        self.tree['entries'] *= 2; self.save()
        with self.assertRaisesRegex(ValueError, 'unique and sorted'): validate_catalog(self.root)

    def test_revision_and_empty_hash_are_checked(self):
        self.tree['extractor']['version'] = '2'; self.save()
        with self.assertRaisesRegex(ValueError, 'revision'): validate_catalog(self.root)
        self.tree['extractor']['version'] = '1'
        self.tree['entries'] = [dict(path='empty', type='file', sha256='b'*64, size_bytes=0)]
        self.save()
        with self.assertRaisesRegex(ValueError, 'empty-file'): validate_catalog(self.root)

    def test_unexpected_files_and_symlinks_are_rejected(self):
        extra = self.root / 'source.iso'; extra.write_bytes(b'not metadata')
        with self.assertRaisesRegex(ValueError, 'Unexpected catalog path'): validate_catalog(self.root)
        extra.unlink(); extra.symlink_to(self.ingest_path)
        with self.assertRaisesRegex(ValueError, 'symlinks'): validate_catalog(self.root)

    def test_duplicate_json_keys_are_rejected(self):
        self.ingest_path.write_text('{"kind":"iso","kind":"prx"}')
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'): read_json(self.ingest_path)

    def test_git_comparison_allows_additions_but_not_edits_or_removals(self):
        repo = self.root.parent
        def git(*args):
            return subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
        git('init', '-q'); git('add', 'catalog')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'Baseline')
        base = git('rev-parse', 'HEAD')
        added = self.folder / ('b'*64 + '-ingest.json'); added.write_text('{}')
        git('add', 'catalog'); validate_changes(repo, base)
        self.ingest_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'immutable'): validate_changes(repo, base)
        self.save(); self.tree_path.unlink()
        with self.assertRaisesRegex(ValueError, 'immutable'): validate_changes(repo, base)
