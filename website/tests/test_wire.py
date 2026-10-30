import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from pspdb import wire
from wirehelp import canonical
from pspdb.wire import (HASH_CHUNK_BYTES, HASH_CHUNK_SLOTS, decode_container, encode_container,
                        hash_chunk, hash_chunk_count, unpack)

FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'catalog-small.json'

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


def roundtrip(data):
    encoded = encode_container(data)
    return decode_container(encoded.container, encoded.hashes)


def paths(tree):
    return [entry['path'] for entry in tree['entries']]


def inventory(entries, key='a' * 64):
    return {'records': {}, 'trees': {'iso': {key: {
        'sha256': key, 'size_bytes': 3, 'extractor': {'name': 'iso'}, 'entries': entries}}}}


def file_entry(path, size, digest, **extra):
    return {'path': path, 'type': 'file', 'size_bytes': size, 'sha256': digest, **extra}


def digest_of(index):
    return hashlib.sha256(str(index).encode()).hexdigest()


def sections_of(container):
    return {name: bytes(body) for name, body in unpack(container).items()}


class ContainerFormatTests(unittest.TestCase):
    def test_snapshot_and_shared_fixture_round_trip_exactly(self):
        self.assertEqual(roundtrip(SNAPSHOT), SNAPSHOT)  # already in viewer order
        fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
        self.assertEqual(canonical(roundtrip(fixture)), canonical(fixture))

    def test_container_framing_alignment_and_sections(self):
        container = encode_container(SNAPSHOT).container
        self.assertEqual(container[:6], b'PSPDBW')
        self.assertEqual(struct.unpack_from('<H', container, 6)[0], 4)
        count = struct.unpack_from('<I', container, 8)[0]
        self.assertEqual(count, len(wire.SECTIONS))
        position, table = 12, []
        for _ in range(count):
            length = container[position]
            name = container[position + 1:position + 1 + length].decode('ascii')
            table.append((name, struct.unpack_from('<I', container, position + 1 + length)[0]))
            position += 5 + length
        self.assertEqual([name for name, _ in table], list(wire.SECTIONS))
        for name, length in table:
            position += -position % 8
            self.assertEqual(position % 8, 0, name)
            self.assertEqual(bytes(unpack(container)[name]), container[position:position + length])
            position += length
        self.assertLessEqual(len(container) - position, 7)  # only alignment padding may trail

    def test_meta_holds_everything_that_is_not_tree_structure(self):
        encoded = encode_container(SNAPSHOT)
        meta = json.loads(unpack(encoded.container)['meta'].tobytes())
        self.assertEqual(meta['kinds'], [['iso', 2]])
        self.assertEqual(meta['downloads_enabled'], False)
        self.assertEqual(meta['hash_count'], 5)
        self.assertEqual(meta['hash_chunk_size'], HASH_CHUNK_SLOTS)
        self.assertEqual(meta['generation'], encoded.generation)
        self.assertEqual(meta['extras'], [{'redump': [{'id': 5, 'name': 'Example'}], 'extraction': None}])
        self.assertEqual([profile.get('extraction_kind') for profile in meta['profiles']], ['iso', 'gzip', 'iso'])
        self.assertEqual(meta['profiles'][1]['name_rule'], 'strip_suffix')
        self.assertEqual(meta['profiles'][2]['error'], 'Unreadable image')
        self.assertEqual(meta['records']['iso'][0]['sha256'], 'a' * 64)
        self.assertNotIn('trees', meta)
        # The error-only tree is a header with an empty directory (children count + 1 = 1).
        self.assertEqual(wire._varints(sections_of(encoded.container)['tkids'])[-1], 1)

    def test_hash_slots_follow_first_use_and_prefixes_are_digest_prefixes(self):
        encoded = encode_container(SNAPSHOT)
        prefixes = sections_of(encoded.container)['prefixes']
        # key a, tree hash a (back reference), b, c (file), c tree hash (back ref), d, key e
        order = ['a', 'b', 'c', 'd', 'e']
        self.assertEqual(encoded.hashes, b''.join(bytes.fromhex(c * 64) for c in order))
        self.assertEqual(prefixes, b''.join(bytes.fromhex(c * 16) for c in order))
        self.assertEqual(encoded.generation, hashlib.sha256(encoded.hashes).hexdigest()[:16])

    def test_each_hash_name_and_tree_profile_is_stored_once(self):
        repeated = {'records': {}, 'trees': {'iso': {}}}
        for index in range(50):
            digest = digest_of(index)
            repeated['trees']['iso'][digest] = {
                'kind': 'tree', 'schema_version': 1, 'sha256': digest, 'size_bytes': 42,
                'extractor': {'name': 'iso', 'version': '3'}, 'extraction_kind': 'iso',
                'entries': [{'path': 'shared', 'type': 'directory'}]
                + [file_entry(f'shared/{name}.bin', 7, 'f' * 64) for name in range(20)],
            }
        encoded = encode_container(repeated)
        meta = json.loads(unpack(encoded.container)['meta'].tobytes())
        self.assertEqual(len(meta['profiles']), 1)
        self.assertEqual(meta['hash_count'], 51)  # 50 sources + the shared payload hash
        self.assertEqual(canonical(roundtrip(repeated)), canonical(repeated))
        self.assertLess(len(encoded.container), len(json.dumps(repeated, separators=(',', ':'))) // 10)

    def test_sizes_are_stored_once_per_hash_and_conflicts_fail(self):
        repeated = inventory([file_entry(f'{name}.bin', 123456789, 'b' * 64) for name in 'abcdef'])
        encoded = encode_container(repeated)
        self.assertEqual(len(sections_of(encoded.container)['size']), 4)  # one 4-byte varint
        self.assertEqual(canonical(roundtrip(repeated)), canonical(repeated))
        with self.assertRaisesRegex(ValueError, 'two sizes'):
            encode_container(inventory([file_entry('a.bin', 1, 'b' * 64), file_entry('b.bin', 2, 'b' * 64)]))

    def test_identical_subtrees_become_references_and_stay_lossless(self):
        def assets(prefix):
            return [{'path': prefix, 'type': 'directory'}, {'path': prefix + '/sub', 'type': 'directory'},
                    file_entry(prefix + '/sub/one.bin', 11, '1' * 64), file_entry(prefix + '/two.bin', 12, '2' * 64)]
        data = {'records': {}, 'trees': {'iso': {
            'a' * 64: {'sha256': 'a' * 64, 'size_bytes': 1, 'extractor': {'name': 'iso'},
                       'entries': assets('DATA') + assets('COPY') + [{'path': 'LONE', 'type': 'directory'},
                                                                      file_entry('LONE/x', 3, '3' * 64)]},
            'b' * 64: {'sha256': 'b' * 64, 'size_bytes': 1, 'extractor': {'name': 'iso'},
                       'entries': assets('DATA')}}}}
        self.assertEqual(canonical(roundtrip(data)), canonical(data))
        sections = sections_of(encode_container(data).container)
        # COPY (under tree a) and the whole DATA subtree of tree b refer back; LONE has one entry only.
        self.assertGreaterEqual(len(wire._varints(sections['refs'])), 2)
        small = inventory([{'path': 'A', 'type': 'directory'}, file_entry('A/x', 1, '1' * 64),
                           {'path': 'B', 'type': 'directory'}, file_entry('B/x', 1, '1' * 64)])
        self.assertEqual(canonical(roundtrip(small)), canonical(small))
        # One-entry directories are not worth a reference; they are written out.
        self.assertEqual(sections_of(encode_container(small).container)['refs'], b'')

    def test_nested_extractions_empty_errors_hashless_files_and_types_survive(self):
        data = inventory([
            {'path': 'nohash.txt', 'type': 'file'},
            {'path': 'sizeless.bin', 'type': 'file', 'sha256': 'b' * 64},
            file_entry('empty.gz', 2, 'c' * 64, extraction={
                'kind': 'tree', 'schema_version': 1, 'sha256': 'c' * 64, 'size_bytes': 2,
                'extractor': {'name': 'gzip'}, 'error': 'Corrupt stream', 'entries': []}),
            file_entry('outer.pbp', 10, 'd' * 64, extraction={
                'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'pbp'},
                'entries': [file_entry('inner/deep.bin', 1, 'e' * 64, extraction={
                    'kind': 'tree', 'schema_version': 1, 'sha256': 'e' * 64, 'size_bytes': 1,
                    'extractor': {'name': 'x'}, 'entries': [file_entry('leaf', 1, 'f' * 64)]})]}),
            {'path': 'link', 'type': 'symlink', 'size_bytes': 0},
        ])
        data['trees']['iso']['a' * 64]['entries'][3]['extraction']['entries'].insert(
            0, {'path': 'inner', 'type': 'directory'})
        self.assertEqual(canonical(roundtrip(data)), canonical(data))

    def test_children_are_ordered_as_the_viewer_shows_them(self):
        listed = inventory([
            file_entry('b.bin', 1, '1' * 64), file_entry('B.bin', 2, '2' * 64), {'path': 'zdir', 'type': 'directory'},
            file_entry('zdir/file', 3, '3' * 64, extraction={
                'kind': 'tree', 'schema_version': 1, 'extractor': {'name': 'x'},
                'entries': [file_entry('y', 4, '4' * 64), file_entry('X', 5, '5' * 64),
                            {'path': 'sub', 'type': 'directory'}]}),
            {'path': 'adir', 'type': 'directory'}, file_entry('a.bin', 6, '6' * 64),
            {'path': '\U0001f600dir', 'type': 'directory'}, {'path': '\uffffdir', 'type': 'directory'},
        ])
        tree = roundtrip(listed)['trees']['iso']['a' * 64]
        # UTF-16 code unit order: the surrogate pair of U+1F600 sorts before U+FFFF.
        self.assertEqual(paths(tree), ['adir', 'zdir', 'zdir/file', '\U0001f600dir', '\uffffdir',
                                       'B.bin', 'a.bin', 'b.bin'])
        nested = next(entry for entry in tree['entries'] if entry['path'] == 'zdir/file')['extraction']
        self.assertEqual(paths(nested), ['sub', 'X', 'y'])
        self.assertEqual(canonical(roundtrip(listed)), canonical(listed))

    def test_trees_keep_their_dictionary_key_independent_of_their_own_hash(self):
        data = inventory([file_entry('a', 1, '1' * 64)], key='9' * 64)
        data['trees']['iso']['9' * 64]['sha256'] = '8' * 64
        data['trees']['pkg'] = {}
        self.assertEqual(canonical(roundtrip(data)), canonical(data))

    def test_records_get_their_digest_slot_even_without_a_tree(self):
        data = inventory([file_entry('a', 1, '1' * 64)])
        data['records'] = {'iso': [{'sha256': 'a' * 64, 'sha1': '3' * 40, 'size_bytes': 1},
                                   {'sha256': '7' * 64, 'size_bytes': 5}, {'kind': 'iso'}],
                           'pkg': [{'sha256': '1' * 64, 'size_bytes': 1}]}
        encoded = encode_container(data)
        meta = json.loads(unpack(encoded.container)['meta'].tobytes())
        slots = [[record.get('slot') for record in records] for records in meta['records'].values()]
        self.assertEqual(slots, [[0, 2, None], [1]])
        for records in meta['records'].values():
            for record in records:
                if 'slot' in record:
                    self.assertEqual(encoded.hashes[record['slot'] * 32:][:32].hex(), record['sha256'])
        self.assertEqual(canonical(roundtrip(data)), canonical(data))  # the slot is wire-only
        data['records']['iso'][0]['slot'] = 3
        with self.assertRaisesRegex(ValueError, 'slot'):
            encode_container(data)

    def test_empty_catalog_and_unicode_names(self):
        self.assertEqual(roundtrip({'records': {}, 'trees': {}}), {'records': {}, 'trees': {}})
        data = inventory([{'path': '日本語', 'type': 'directory'}, file_entry('日本語/ファイル.bin', 1, '1' * 64),
                          file_entry('😀 spaced name.bin', 2, '2' * 64)])
        self.assertEqual(canonical(roundtrip(data)), canonical(data))

    def test_encoding_is_deterministic_and_generation_tracks_only_the_digests(self):
        first = encode_container(SNAPSHOT)
        self.assertEqual(first, encode_container(json.loads(json.dumps(SNAPSHOT))))
        renamed = json.loads(json.dumps(SNAPSHOT))
        renamed['trees']['iso']['a' * 64]['entries'][1]['path'] = 'PSP_GAME/OTHER.BIN'
        self.assertNotEqual(encode_container(renamed).container, first.container)
        self.assertEqual(encode_container(renamed).generation, first.generation)
        renamed['trees']['iso']['a' * 64]['entries'][1]['sha256'] = '9' * 64
        self.assertNotEqual(encode_container(renamed).generation, first.generation)

    def test_nesting_names_each_directory_once_and_restores_implied_parents(self):
        listed = inventory([file_entry('PSP_GAME/SYSDIR/EBOOT.BIN', 3, 'b' * 64)])
        names = sections_of(encode_container(listed).container)['names_blob']
        self.assertEqual(sorted(names.decode()), sorted('PSP_GAMESYSDIREBOOT.BIN'))
        # Parents a path only implies are rebuilt as ordinary directory entries.
        self.assertEqual([entry['path'] for entry in roundtrip(listed)['trees']['iso']['a' * 64]['entries']],
                         ['PSP_GAME', 'PSP_GAME/SYSDIR', 'PSP_GAME/SYSDIR/EBOOT.BIN'])

    def test_one_name_cannot_describe_two_children_of_a_directory(self):
        duplicate = [file_entry('DATA.BIN', 1, 'b' * 64), file_entry('DATA.BIN', 2, 'c' * 64)]
        crossed = [file_entry('DATA.BIN', 1, 'b' * 64), file_entry('DATA.BIN/inner', 1, 'c' * 64)]
        shadowed = [file_entry('DATA.BIN', 1, 'b' * 64), {'path': 'DATA.BIN', 'type': 'directory'}]
        for entries in (duplicate, crossed, shadowed):
            with self.assertRaises(ValueError):
                encode_container(inventory(entries))
        # A directory named before its children is not a conflict.
        repeated = [{'path': 'DIR', 'type': 'directory'}, {'path': 'DIR', 'type': 'directory'},
                    file_entry('DIR/file', 1, 'b' * 64)]
        self.assertEqual([entry['path'] for entry in roundtrip(inventory(repeated))['trees']['iso']['a' * 64]['entries']],
                         ['DIR', 'DIR/file'])

    def test_reserved_wire_keys_cannot_be_catalog_keys(self):
        with self.assertRaisesRegex(ValueError, 'reserved'):
            encode_container({'records': {}, 'trees': {}, 'generation': 'x'})


class PrefixAndChunkTests(unittest.TestCase):
    def test_distinct_digests_sharing_an_eight_byte_prefix_fail_loudly(self):
        first = '0123456789abcdef' + '0' * 48
        second = '0123456789abcdef' + '1' * 48
        with self.assertRaisesRegex(ValueError, 'prefix collision'):
            encode_container(inventory([file_entry('a', 1, first), file_entry('b', 1, second)]))
        with self.assertRaisesRegex(ValueError, 'prefix collision'):  # a record digest counts too
            data = inventory([file_entry('a', 1, first)])
            data['records'] = {'iso': [{'sha256': second}]}
            encode_container(data)
        # The same digest repeated is not a collision; one differing prefix nibble is not either.
        same = inventory([file_entry('a', 1, first), file_entry('b', 1, first)])
        self.assertEqual(canonical(roundtrip(same)), canonical(same))
        near = '0123456789abcdee' + '0' * 48
        both = inventory([file_entry('a', 1, first), file_entry('b', 1, near)])
        self.assertEqual(canonical(roundtrip(both)), canonical(both))

    def test_malformed_digests_are_rejected(self):
        for digest in ('A' * 64, 'a' * 63, 'a' * 65, 'g' * 64, '', 5):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, 'Invalid SHA-256'):
                encode_container(inventory([file_entry('a', 1, digest)]))
        for size in (-1, 1.5, '3', True):
            with self.subTest(size=size), self.assertRaises(ValueError):
                encode_container(inventory([file_entry('a', size, 'b' * 64)]))

    def test_chunk_addressing_at_slot_boundaries_and_short_last_chunk(self):
        total = 2 * HASH_CHUNK_SLOTS + 5
        digests = [digest_of(index) for index in range(total)]
        data = {'records': {}, 'trees': {'iso': {}}}
        for index, digest in enumerate(digests):
            data['trees']['iso'][digest] = {'sha256': digest, 'size_bytes': index, 'extractor': {'name': 'iso'},
                                            'entries': []}
        encoded = encode_container(data)
        meta = json.loads(unpack(encoded.container)['meta'].tobytes())
        self.assertEqual(meta['hash_count'], total)
        self.assertEqual(hash_chunk_count(encoded.hashes), 3)
        chunks = [hash_chunk(encoded.hashes, index) for index in range(3)]
        self.assertEqual([len(chunk) for chunk in chunks], [HASH_CHUNK_BYTES, HASH_CHUNK_BYTES, 5 * 32])
        self.assertIsNone(hash_chunk(encoded.hashes, 3))
        self.assertIsNone(hash_chunk(encoded.hashes, -1))
        prefixes = sections_of(encoded.container)['prefixes']
        for slot in (0, 4095, 4096, 4097, 8191, 8192, total - 1):
            chunk, offset = divmod(slot, HASH_CHUNK_SLOTS)
            digest = chunks[chunk][offset * 32:offset * 32 + 32]
            self.assertEqual(digest.hex(), digests[slot], slot)
            self.assertEqual(prefixes[slot * 8:slot * 8 + 8], digest[:8])
        self.assertEqual(canonical(decode_container(encoded.container, b''.join(chunks))), canonical(data))

    def test_exact_multiple_of_chunk_size_has_no_empty_chunk(self):
        hashes = bytes(HASH_CHUNK_BYTES * 2)
        self.assertEqual(hash_chunk_count(hashes), 2)
        self.assertIsNone(hash_chunk(hashes, 2))
        self.assertEqual(hash_chunk_count(b''), 0)
        self.assertIsNone(hash_chunk(b'', 0))


class DecoderGuardTests(unittest.TestCase):
    def setUp(self):
        self.encoded = encode_container(SNAPSHOT)

    def test_foreign_or_truncated_containers_are_rejected(self):
        container = bytearray(self.encoded.container)
        for broken in (b'', bytes(container[:-40]), b'PSPDBX' + bytes(container[6:]),
                       bytes(container[:6]) + struct.pack('<H', 3) + bytes(container[8:])):
            with self.subTest(size=len(broken)), self.assertRaisesRegex(ValueError, 'container'):
                decode_container(broken, self.encoded.hashes)

    def test_hashes_must_belong_to_the_container(self):
        with self.assertRaisesRegex(ValueError, 'Hash table'):
            decode_container(self.encoded.container, self.encoded.hashes[:-32])
        damaged = bytearray(self.encoded.hashes)
        damaged[40] ^= 1
        with self.assertRaisesRegex(ValueError, 'Hash table'):
            decode_container(self.encoded.container, bytes(damaged))
        other = encode_container(inventory([file_entry('x', 1, 'f' * 64)]))
        with self.assertRaisesRegex(ValueError, 'Hash table'):
            decode_container(self.encoded.container, other.hashes)


class CommandLineTests(unittest.TestCase):
    def test_module_encodes_a_json_catalog_into_container_and_chunks(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-m', 'pspdb.wire', str(FIXTURE), temporary],
                                    capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(temporary)
            container = (root / 'catalog.bin').read_bytes()
            chunks = sorted((root / 'hashes').iterdir())
            self.assertEqual([chunk.name for chunk in chunks], ['0.bin'])
            self.assertEqual(result.stdout.strip(), json.loads(unpack(container)['meta'].tobytes())['generation'])
            self.assertEqual(canonical(decode_container(container, chunks[0].read_bytes())),
                             canonical(json.loads(FIXTURE.read_text(encoding='utf-8'))))


if __name__ == '__main__':
    unittest.main()
