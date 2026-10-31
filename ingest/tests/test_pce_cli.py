"""PC Engine Archives: synthetic PSN packages (invented keys, ROMs and pages)."""
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import subprocess

if __package__:
    from .test_ingest_cli import BINARY, REPO, iso_files_bytes, tree_path
    from .test_pkg_cli import pkg_bytes, sfo
else:
    from test_ingest_cli import BINARY, REPO, iso_files_bytes, tree_path
    from test_pkg_cli import pkg_bytes, sfo

# A PSP-KEY.EDAT generated for this test (invented content ID and key, built with
# libkirk's own PGD primitives and checked by PPSSPP's pgd_open): its payload is KEY.
PSP_KEY_EDAT = bytes.fromhex(
    '005053504544415402000000900000015550303030302d4e50554630303030305f30302d504345544553543030303030' \
    '3030303000000000000000000000000040454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6db' \
    'e0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cb' \
    '00504744010000000100000000000000303336393c3f4245484b4e5154575a5d00000000000000000000000000000000' \
    '2fa4e10a8d17d9042ddd74c6f201a8819d39f077d606951ea91a60127000ef285cd728797cf554c4d16fa5b5a87c2d3b' \
    'e40e3f4bce69a567e3737f6afe47b983642728c989a95c184f918080d85cddd01c0cc3ec8373b0bd0cac82db5628a142' \
    '5ef55c2489b5aa9def543b936fdb7b76b6bde2d62f2c604553bf3ed5fe06ee2a202122232425262728292a2b2c2d2e2f')
KEY = bytes.fromhex('c0decafe5043452d746573742d6b6579')
PUBLIC_TABLE = bytes(int(value, 16) for value in re.findall(
    r'0x([0-9a-f]{2})', re.search(r'pub const public_table: \[512\]u8 = \.\{(.*?)\};',
                                  (REPO / 'ingest/src/pce.zig').read_text(), re.S).group(1)))
assert len(PUBLIC_TABLE) == 512 and hashlib.sha256(PUBLIC_TABLE).hexdigest().startswith('b2d7084c')

EDAT_KEY = bytes.fromhex('be959ca8308defa2e5e180c63712a9ae')
SDAT_KEY = bytes.fromhex('0d655ef8e674a98ab8505cfa7d012933')
BLOCK = 16384


def xor_layer(data, key=KEY):
    return bytes(byte ^ key[i & 15] ^ PUBLIC_TABLE[i & 511] for i, byte in enumerate(data))


def container(files):
    cursor = 0x80 + 0x50 * len(files)
    table, body = bytearray(), bytearray()
    for name, data in files:
        table += name.encode().ljust(0x40, b'\0') + struct.pack('<II', cursor + len(body), len(data)) + bytes(8)
        body += data + bytes(-len(data) % 16)
    header = bytearray(0x80)
    header[:4] = b'\x12\x34\x56\x78'
    struct.pack_into('<I', header, 0x28, len(files))
    return bytes(header + table + body) + bytes(16)


def track(image):
    chunks = [zlib.compress(image[i:i + 0x40000]) for i in range(0, len(image), 0x40000)]
    chunks = [chunk + b'\xaa' * (-len(chunk) % 4) for chunk in chunks]  # the writer pads streams to 4 bytes
    offset, table = 4 + 8 * len(chunks), bytearray(struct.pack('<I', len(chunks)))
    for chunk in chunks:
        table += struct.pack('<II', offset, len(chunk))
        offset += len(chunk)
    return bytes(table) + b''.join(chunks)


def cbc_decrypt(key, data):
    return AES.new(key, AES.MODE_CBC, iv=bytes(16)).decrypt(data)


def cmac(key, data):
    return CMAC.new(key, msg=data, ciphermod=AES).digest()


def sdat(plain):
    """NPD v2 SDAT, flags 0x0100000D, with uncompressed blocks in the compressed layout."""
    blocks = [plain[i:i + BLOCK] for i in range(0, len(plain), BLOCK)]
    dev, iv = bytes(range(0x62, 0x72)), bytes(range(0x41, 0x51))
    key = bytes(a ^ b for a, b in zip(dev, SDAT_KEY))
    header_key = cbc_decrypt(EDAT_KEY, key)
    data_offset = 0x100 + 0x20 * len(blocks)
    metadata, data = bytearray(), bytearray()
    first = [0xC, 0xD, 0xE, 0xF, 4, 5, 6, 7, 0xC, 0xD, 0xE, 0xF, 4, 5, 6, 7]
    second = [8, 9, 0xA, 0xB, 8, 9, 0xA, 0xB, 0, 1, 2, 3, 0, 1, 2, 3]
    for index, block in enumerate(blocks):
        derived = AES.new(key, AES.MODE_ECB).encrypt(dev[:12] + struct.pack('>I', index))
        block_key = cbc_decrypt(EDAT_KEY, derived)
        cipher = AES.new(block_key, AES.MODE_CBC, iv=iv).encrypt(block + bytes(-len(block) % 16))
        fields = struct.pack('>IIII', (data_offset + len(data)) >> 4, 0, len(block), 0)
        entry = bytearray(cmac(block_key, cipher) + bytes(16))
        for i in range(16):
            entry[16 + i] = fields[i] ^ entry[first[i]] ^ entry[second[i]]
        metadata += entry
        data += cipher
    header = bytearray(0x100)
    header[0:4] = b'NPD\0'
    struct.pack_into('>III', header, 4, 2, 0, 0)
    header[0x40:0x50] = iv
    header[0x60:0x70] = dev
    struct.pack_into('>IIQ', header, 0x80, 0x0100000D, BLOCK, len(plain))
    header[0x90:0xa0] = cmac(header_key, bytes(metadata))
    header[0xa0:0xb0] = cmac(header_key, bytes(header[:0xa0]))
    return bytes(header) + bytes(metadata) + bytes(data)


IMAGE = (bytes(2080) + b'PC Engine CD-ROM SYSTEM' + bytes(range(256)) * 32)[:2048 * 4]
TOC = b'readwait,0.20\r\nplaywait,0.00\r\ntrack01,code ,GAME_01.bin,000150,000004\r\ntrack02,audio,GAME_02.at3,000200,000100\r\n'


def game_files(toc=TOC, image=IMAGE):
    return [('GAME.PCE', bytes(range(256)) * 32), ('GAME.hcd', toc), ('GAME_01.bin', track(image)),
            ('GAME_02.at3', b'RIFF....WAVE'), ('psp_001.png', b'\x89PNG page')]


# A second data track that does carry an ISO9660 volume descriptor.
FILESYSTEM = iso_files_bytes({'HELLO.TXT': b'hello from the second data track'})
assert len(FILESYSTEM) % 2048 == 0


MANUAL = [('ps3_001.png', b'\x89PNG manual 1'), ('ps3_002.png', b'\x89PNG manual 2')]


def package(game=None, manual_sdat=None, key=PSP_KEY_EDAT, game_key=KEY):
    game = container(game_files()) if game is None else game
    manual_sdat = sdat(xor_layer(container(MANUAL))) if manual_sdat is None else manual_sdat
    files = [('PARAM.SFO', sfo({'TITLE': 'PC Engine fixture', 'CATEGORY': 'HG'}), False),
             ('USRDIR', None, False), ('USRDIR/CONTENT', None, False), ('USRDIR/DOC', None, False)]
    if key is not None:
        files.append(('USRDIR/CONTENT/PSP-KEY.EDAT', key, True))
    files += [('USRDIR/CONTENT/CONTENT.DAT', xor_layer(game, game_key), True), ('USRDIR/DOC/CONTENT1.sdat', manual_sdat, False)]
    return pkg_bytes(7, files_override=files)[0]


class PceCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['zig', 'build', '-Doptimize=ReleaseSafe'], cwd=REPO / 'ingest', check=True)

    def run_ingest(self, root, *args):
        return subprocess.run([str(BINARY), str(root), '--no-progress', '--threads', '2', *map(str, args)],
                              capture_output=True, text=True, timeout=60)

    def ingest(self, source):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        inputs = base / 'inputs'
        inputs.mkdir()
        (inputs / 'pce.pkg').write_bytes(source)
        run = self.run_ingest(inputs, '--catalog', base / 'catalog', '--store', base / 'store')
        self.assertEqual(run.returncode, 0, run.stderr)
        tree = json.loads(tree_path(base / 'catalog', hashlib.sha256(source).hexdigest()).read_text())
        return base, {entry['path']: entry for entry in tree['entries']}, run

    def test_game_and_manual_are_published_with_bound_key_and_honest_trust(self):
        base, entries, _ = self.ingest(package())
        key_file = entries['USRDIR/CONTENT/PSP-KEY.EDAT']
        dependency = [{'path': 'USRDIR/CONTENT/PSP-KEY.EDAT', 'sha256': key_file['sha256'], 'size_bytes': len(PSP_KEY_EDAT)}]
        provenance = {'name': 'pspdb-pce', 'version': '1', 'options': [
            'in-memory', 'xor-table:b2d7084c', 'content-dat:structure-checked', 'content1-sdat:mac-verified']}
        game = entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']
        self.assertNotIn('error', game)
        self.assertEqual(game['extractor'], provenance)
        self.assertEqual(game['dependencies'], dependency)
        self.assertEqual(game['name_rule'], 'identity')
        files = {e['path']: e for e in game['entries']}
        self.assertEqual(sorted(files), sorted(name for name, _ in game_files()))
        for name, data in game_files():
            self.assertEqual(files[name]['sha256'], hashlib.sha256(data).hexdigest())
            digest = files[name]['sha256']
            self.assertEqual((base / 'store/sha256' / digest[:2] / digest[2:4] / digest).read_bytes(), data)
        manual = entries['USRDIR/DOC/CONTENT1.sdat']['extraction']
        self.assertEqual(manual['extractor'], provenance)
        self.assertEqual(manual['dependencies'], dependency)
        self.assertEqual([e['path'] for e in manual['entries']], sorted(name for name, _ in MANUAL))
        # The data track is a derived plain ISO, bound to its TOC, never an ISO9660 candidate.
        extraction = files['GAME_01.bin']['extraction']
        self.assertEqual(extraction['name_rule'], 'source_stem')
        self.assertEqual(extraction['extractor']['name'], 'pspdb-pcecd')
        self.assertEqual([(e['path'], e['sha256']) for e in extraction['entries']],
                         [('disc.iso', hashlib.sha256(IMAGE).hexdigest())])
        self.assertEqual(extraction['dependencies'],
                         [{'path': 'GAME.hcd', 'sha256': files['GAME.hcd']['sha256'], 'size_bytes': len(TOC)}])
        self.assertFalse((base / 'catalog/iso9660').exists())
        # The SDAT is consumed contextually, so no standalone EDAT result duplicates it.
        self.assertFalse((base / 'catalog/edat').exists())
        # The key file itself is a standalone PSPEDAT extraction.
        tree = json.loads((base / f"catalog/pspedat/v1/{key_file['sha256']}-tree.json").read_text())
        self.assertEqual(tree['name_rule'], 'source_stem')
        self.assertEqual([e['path'] for e in tree['entries']], ['payload.dat'])
        self.assertEqual(tree['entries'][0]['sha256'], hashlib.sha256(KEY).hexdigest())

    def test_only_a_track_with_an_iso9660_descriptor_is_inventoried_as_a_file_system(self):
        toc = TOC + b'track03,code ,GAME_03.bin,000300,%06d\r\n' % (len(FILESYSTEM) // 2048)
        files = game_files(toc) + [('GAME_03.bin', track(FILESYSTEM))]
        base, entries, _ = self.ingest(package(game=container(files)))
        game = {e['path']: e for e in entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']['entries']}
        for name, image in (('GAME_01.bin', IMAGE), ('GAME_03.bin', FILESYSTEM)):
            extraction = game[name]['extraction']
            self.assertNotIn('error', extraction)
            self.assertEqual(extraction['entries'][0]['sha256'], hashlib.sha256(image).hexdigest())
        trees = list((base / 'catalog/iso9660').rglob('*-tree.json'))
        self.assertEqual([path.name.split('-')[0] for path in trees], [hashlib.sha256(FILESYSTEM).hexdigest()])
        self.assertFalse(json.loads(trees[0].read_text()).get('error'))

    def test_without_the_key_file_containers_stay_opaque_and_sdat_is_plain_edat(self):
        base, entries, _ = self.ingest(package(key=None))
        self.assertNotIn('extraction', entries['USRDIR/CONTENT/CONTENT.DAT'])
        self.assertNotIn('extraction', entries['USRDIR/DOC/CONTENT1.sdat'])
        digest = entries['USRDIR/DOC/CONTENT1.sdat']['sha256']
        edat = json.loads((base / f'catalog/edat/v7/{digest}-tree.json').read_text())
        self.assertNotIn('error', edat)
        self.assertEqual([e['path'] for e in edat['entries']], ['payload.dat'])

    def test_tampered_sdat_publishes_nothing(self):
        damaged = bytearray(sdat(xor_layer(container(MANUAL))))
        damaged[0x100 + 3] ^= 1  # first block's MAC
        _, entries, run = self.ingest(package(manual_sdat=bytes(damaged)))
        manual = entries['USRDIR/DOC/CONTENT1.sdat']['extraction']
        self.assertEqual(manual['error'], 'EdatAuthenticationFailed')
        self.assertEqual(manual['entries'], [])
        self.assertIn('Extraction error: EdatAuthenticationFailed', run.stderr)
        self.assertNotIn('error', entries['USRDIR/CONTENT/CONTENT.DAT']['extraction'])

    def test_invalid_containers_and_tables_are_rejected_before_publication(self):
        plain = bytearray(container(game_files()))
        cases = [
            ('magic', lambda b: b.__setitem__(0, 0), 'InvalidPceContainer'),
            ('count', lambda b: struct.pack_into('<I', b, 0x28, 4097), 'TooManyPceEntries'),
            ('trailer', lambda b: b.__setitem__(0x80 + 0x4f, 1), 'InvalidPceTrailer'),
            ('range', lambda b: struct.pack_into('<I', b, 0x80 + 0x44, len(b)), 'InvalidPceEntry'),
            ('overlap', lambda b: b.__setitem__(slice(0x80 + 0x50 + 0x40, 0x80 + 0x50 + 0x44), b[0x80 + 0x40:0x80 + 0x44]),
             'OverlappingPceEntries'),
            ('name', lambda b: b.__setitem__(slice(0x80, 0x84), b'a/b\0'), 'InvalidPceName'),
        ]
        for label, damage, error in cases:
            with self.subTest(label):
                damaged = bytearray(plain)
                damage(damaged)
                _, entries, _ = self.ingest(package(game=bytes(damaged)))
                extraction = entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']
                self.assertEqual(extraction['error'], error)
                self.assertEqual(extraction['entries'], [])

    def test_bad_key_file_or_wrong_key_publishes_nothing(self):
        wrong = bytearray(PSP_KEY_EDAT)
        wrong[0x90 + 0xa0] ^= 1
        _, entries, _ = self.ingest(package(key=bytes(wrong)))
        self.assertEqual(entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']['error'], 'PgdAuthenticationFailed')
        # A key other than the file's own decodes to noise and fails the container magic.
        _, entries, _ = self.ingest(package(game_key=bytes(16)))
        self.assertEqual(entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']['error'], 'InvalidPceContainer')

    def test_cd_track_must_match_its_toc(self):
        for label, toc, image in [('length', TOC.replace(b'000004', b'000005'), IMAGE),
                                  ('ipl', TOC, IMAGE.replace(b'PC Engine', b'PX Engine'))]:
            with self.subTest(label):
                _, entries, _ = self.ingest(package(game=container(game_files(toc, image))))
                game = entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']
                files = {e['path']: e for e in game['entries']}
                self.assertEqual(files['GAME_01.bin']['extraction']['error'], 'InvalidPceTrack')
                self.assertEqual(files['GAME_01.bin']['extraction']['entries'], [])
                self.assertIn('GAME.PCE', files)
        with self.subTest('TOC names a missing file'):
            toc = TOC + b'track03,audio,MISSING.at3,000300,000100\r\n'
            _, entries, _ = self.ingest(package(game=container(game_files(toc))))
            extraction = entries['USRDIR/CONTENT/CONTENT.DAT']['extraction']
            self.assertEqual((extraction['error'], extraction['entries']), ('InvalidPceToc', []))


if __name__ == '__main__':
    unittest.main()
