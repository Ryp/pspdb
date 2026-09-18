import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from pspdb.wire import decode_catalog, encode_catalog

WEB = Path(__file__).resolve().parents[1] / 'pspdb' / 'web'

# One source of truth for the cross-language wire contract: the Python encoder
# produces this payload and the browser decoder must rebuild SNAPSHOT from it.
SNAPSHOT = {
    'records': {'iso': [{'sha256': 'a' * 64, 'size_bytes': 42, 'metadata': {'title': '日本語'}}]},
    'downloads_enabled': False,
    'trees': {
        'iso': {
            'a' * 64: {
                'kind': 'tree', 'schema_version': 1, 'sha256': 'a' * 64, 'size_bytes': 42,
                'extractor': {'name': 'iso', 'version': '3'}, 'extraction_kind': 'iso',
                'entries': [
                    {'path': 'PSP_GAME', 'type': 'directory'},
                    {'path': 'PSP_GAME/EBOOT.BIN', 'type': 'file', 'size_bytes': 7, 'sha256': 'b' * 64},
                    {'path': 'DATA.PSP', 'type': 'file', 'size_bytes': 9, 'sha256': 'c' * 64,
                     'redump': [{'id': 5, 'name': 'Example'}],
                     'extraction': {
                         'kind': 'tree', 'schema_version': 1, 'sha256': 'c' * 64, 'size_bytes': 9,
                         'extractor': {'name': 'gzip'}, 'extraction_kind': 'gzip',
                         'name_rule': 'strip_suffix',
                         'stale_extraction': {'kind': 'gzip', 'version': '1', 'latest_version': '2'},
                         'entries': [{'path': 'module.prx', 'type': 'file', 'size_bytes': 4, 'sha256': 'd' * 64}],
                     }},
                ],
            },
            'e' * 64: {
                'kind': 'tree', 'schema_version': 1, 'sha256': 'e' * 64, 'size_bytes': 12,
                'extractor': {'name': 'iso', 'version': '3'}, 'extraction_kind': 'iso',
                'error': 'Unreadable image', 'entries': [],
            },
        },
    },
}

ENCODED = {
    'records': SNAPSHOT['records'],
    'downloads_enabled': False,
    'wire_schema': 3,
    'hashes': ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64],
    'profiles': [
        {'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'iso', 'version': '3'},
         'extraction_kind': 'iso'},
        {'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'gzip'},
         'extraction_kind': 'gzip', 'name_rule': 'strip_suffix',
         'stale_extraction': {'kind': 'gzip', 'version': '1', 'latest_version': '2'}},
        {'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'iso', 'version': '3'},
         'extraction_kind': 'iso', 'error': 'Unreadable image'},
    ],
    'trees': {
        'iso': {
            'a' * 64: [42, 0, 0, {
                'PSP_GAME': {'EBOOT.BIN': [7, 1]},
                'DATA.PSP': [9, 2, {
                    'redump': [{'id': 5, 'name': 'Example'}],
                    'extraction': [9, 1, 2, {'module.prx': [4, 3]}],
                }],
            }],
            'e' * 64: [12, 2, 4, {}],
        },
    },
}


class WireFormatTests(unittest.TestCase):
    def test_encoding_pools_repetition_and_round_trips_exactly(self):
        self.assertEqual(encode_catalog(SNAPSHOT), ENCODED)
        self.assertEqual(decode_catalog(encode_catalog(SNAPSHOT)), SNAPSHOT)

    def test_repeated_hashes_and_tree_metadata_are_sent_once(self):
        repeated = {'records': {}, 'trees': {'iso': {}}}
        for index in range(50):
            digest = f'{index:064x}'
            repeated['trees']['iso'][digest] = {
                'kind': 'tree', 'schema_version': 1, 'sha256': digest, 'size_bytes': 42,
                'extractor': {'name': 'iso', 'version': '3'}, 'extraction_kind': 'iso',
                'entries': [{'path': 'shared', 'type': 'directory'}]
                + [{'path': f'shared/{name}.bin', 'type': 'file',
                    'size_bytes': 7, 'sha256': 'f' * 64} for name in range(20)],
            }
        encoded = encode_catalog(repeated)
        self.assertEqual(encoded['profiles'], [
            {'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'iso', 'version': '3'},
             'extraction_kind': 'iso'}])
        # The shared payload hash and each source hash appear once, not 1000 times.
        self.assertEqual(len(encoded['hashes']), 51)
        self.assertEqual(decode_catalog(encoded), repeated)
        compact = len(json.dumps(encoded, separators=(',', ':')))
        self.assertLess(compact, len(json.dumps(repeated, separators=(',', ':'))) // 2)

    def test_nesting_names_each_directory_once_and_restores_implied_parents(self):
        listed = {'records': {}, 'trees': {'iso': {'a' * 64: {
            'sha256': 'a' * 64, 'size_bytes': 3, 'extractor': {'name': 'iso'},
            'entries': [{'path': 'PSP_GAME/SYSDIR/EBOOT.BIN', 'type': 'file',
                         'size_bytes': 3, 'sha256': 'b' * 64}]}}}}
        encoded = encode_catalog(listed)
        self.assertEqual(encoded['trees']['iso']['a' * 64][3],
                         {'PSP_GAME': {'SYSDIR': {'EBOOT.BIN': [3, 1]}}})
        # Parents a path only implies are rebuilt as ordinary directory entries.
        self.assertEqual([entry['path'] for entry in
                          decode_catalog(encoded)['trees']['iso']['a' * 64]['entries']],
                         ['PSP_GAME', 'PSP_GAME/SYSDIR', 'PSP_GAME/SYSDIR/EBOOT.BIN'])

    def test_one_name_cannot_describe_two_children_of_a_directory(self):
        def inventory(entries):
            return {'records': {}, 'trees': {'iso': {'a' * 64: {
                'sha256': 'a' * 64, 'size_bytes': 3, 'extractor': {'name': 'iso'},
                'entries': entries}}}}
        duplicate = [{'path': 'DATA.BIN', 'type': 'file', 'size_bytes': 1, 'sha256': 'b' * 64},
                     {'path': 'DATA.BIN', 'type': 'file', 'size_bytes': 2, 'sha256': 'c' * 64}]
        crossed = [{'path': 'DATA.BIN', 'type': 'file', 'size_bytes': 1, 'sha256': 'b' * 64},
                   {'path': 'DATA.BIN/inner', 'type': 'file', 'size_bytes': 1, 'sha256': 'c' * 64}]
        shadowed = [{'path': 'DATA.BIN', 'type': 'file', 'size_bytes': 1, 'sha256': 'b' * 64},
                    {'path': 'DATA.BIN', 'type': 'directory'}]
        for entries in (duplicate, crossed, shadowed):
            with self.assertRaises(ValueError):
                encode_catalog(inventory(entries))
        # A directory named before its children is not a conflict.
        repeated = [{'path': 'DIR', 'type': 'directory'},
                    {'path': 'DIR', 'type': 'directory'},
                    {'path': 'DIR/file', 'type': 'file', 'size_bytes': 1, 'sha256': 'b' * 64}]
        self.assertEqual([entry['path'] for entry in
                          decode_catalog(encode_catalog(inventory(repeated)))
                          ['trees']['iso']['a' * 64]['entries']], ['DIR', 'DIR/file'])

    def test_foreign_or_missing_schema_is_rejected(self):
        for payload in ({}, {'wire_schema': 1, 'hashes': [], 'profiles': [], 'trees': {}},
                        SNAPSHOT):
            with self.assertRaisesRegex(ValueError, 'wire schema'):
                decode_catalog(payload)

    @unittest.skipUnless(shutil.which('node'), 'node is required for the browser decoder')
    def test_browser_decoder_rebuilds_the_same_snapshot(self):
        harness = '''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const el = {addEventListener(){}, setAttribute(){}, removeAttribute(){}};
const context = vm.createContext({
  document: {documentElement:{dataset:{catalog:'api/catalog'}}, getElementById:()=>el, addEventListener(){}},
  window: {addEventListener(){}},
  ResizeObserver: class {observe(){}},
  getComputedStyle: ()=>({getPropertyValue:()=>'21px'}),
  fetch: ()=>new Promise(()=>{}),
  Worker: class {postMessage(){} terminate(){}}, setTimeout, URLSearchParams, URL,
  location: {href:'http://localhost/', search:'', hash:''},
  history: {replaceState(){}},
});
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
context.encoded = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const decoded = JSON.parse(vm.runInContext('JSON.stringify(decodeCatalog(encoded))', context));
assert.deepEqual(decoded, JSON.parse(fs.readFileSync(process.argv[4], 'utf8')));
assert.throws(() => vm.runInContext('decodeCatalog({wire_schema: 1})', context), /wire schema/);
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'harness.mjs').write_text(harness, encoding='utf-8')
            (root / 'encoded.json').write_text(json.dumps(ENCODED), encoding='utf-8')
            (root / 'expected.json').write_text(json.dumps(SNAPSHOT), encoding='utf-8')
            result = subprocess.run(
                ['node', str(root / 'harness.mjs'), str(WEB / 'app.js'),
                 str(root / 'encoded.json'), str(root / 'expected.json')],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
