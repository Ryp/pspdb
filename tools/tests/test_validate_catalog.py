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
