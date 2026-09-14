import hashlib
import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


# Fixed-key, 99-slot layouts from PSP-DOCUMENT.DAT at
# 8c95b37949c9a9ca183b7fd69c85d2e2dad7216d (decrypt_document_ps1.py/psp.py).
_DES_PARAMETERS = {
    'ps1': (bytes.fromhex('39f7efa16cce5f4c'), bytes.fromhex('a819c4f5e154e30b')),
    'psp': (bytes.fromhex('da3923ef9c61b930'), bytes.fromhex('2dee8950969112d9')),
}
_HMAC_KEYS = (
    bytes.fromhex('4d1b6b1269ddd22faae1f54207e798b5'),
    bytes.fromhex('ef690ec0e0bfa41f08455bd038eb8762'),
)


def _png(color):
    from PIL import Image

    output = BytesIO()
    Image.new('RGB', (2, 2), color).save(output, format='PNG')
    return output.getvalue()


def _encrypt(data, variant, document_key=None):
    from Crypto.Cipher import DES

    key, iv = _DES_PARAMETERS[variant]
    if document_key is not None:
        key = bytes(a ^ b for a, b in zip(document_key, bytes.fromhex('f932ff26474a8dc0')))
    return DES.new(key, DES.MODE_CBC, iv).encrypt(data)


def _protect(data, variant):
    if variant == 'ps1':
        # Optional BB-MAC is absent; SHA1 still protects every encrypted frame.
        return data + bytes(0x10) + hashlib.sha1(data).digest()[:0x10]
    return data + bytes(0x10) + b''.join(
        hmac.new(key, data, hashlib.sha1).digest()[:0x10] for key in _HMAC_KEYS
    )


def _document(variant, pages, document_key=None, encrypted_ranges=()):
    header = bytearray(0x60)
    header[:0x0c] = b'DOC \0\0\1\0\0\0\1\0'
    code = b'../../escape'
    header[0x0c:0x0c + len(code)] = code
    # The zero size flag at 0x1c selects all 99 metadata slots.
    frames = []
    for png in pages:
        payload = png + bytes(-len(png) % 8)
        for start, size in reversed(encrypted_ranges):
            payload = (payload[:start] + _encrypt(payload[start:start + size], variant, document_key)
                       + payload[start + size:])
        descriptors = b''.join(struct.pack('<II', *item) for item in encrypted_ranges)
        protection_size = 0x20 if variant == 'ps1' else 0x30
        frame_header = bytearray(0x20)
        struct.pack_into('<I', frame_header, 0, 0x20 + len(descriptors) + len(payload) + protection_size)
        struct.pack_into('<I', frame_header, 8, len(encrypted_ranges))
        frames.append(_protect(_encrypt(frame_header, variant, document_key)
                               + _encrypt(descriptors, variant, document_key) + payload, variant))

    offset = 0x3298 if variant == 'ps1' else 0x32b8
    offsets = []
    for frame in frames:
        offsets.append(offset)
        offset += len(frame)

    metadata = bytearray(0x31e8)
    struct.pack_into('<II', metadata, 0, 0xffffffff, len(pages))
    struct.pack_into('<I', metadata, 0x3188, len(pages))
    for index, frame in enumerate(frames):
        entry = 8 + index * 0x80
        ps3_index = len(pages) - index - 1 if variant == 'ps1' else index
        struct.pack_into('<I', metadata, entry, offsets[index])
        struct.pack_into('<I', metadata, entry + 0x0c, len(frame))
        struct.pack_into('<I', metadata, entry + 0x10, offsets[ps3_index])
        struct.pack_into('<I', metadata, entry + 0x1c, len(frames[ps3_index]))

    return (
        b'\0PGD\1\0\0\0\1\0\0\0\0\0\0\0'
        + _protect(_encrypt(header, variant, document_key), variant)
        + _protect(_encrypt(metadata, variant, document_key), variant)
        + b''.join(frames)
    )


def _docinfo(executable, document_key, descriptor=(8, 0x400, 0x90)):
    # Use the crypto shipped inside the configured pinned zipapp, not a new
    # implementation. All keys and signatures here are deterministic test data.
    sys.path.insert(0, shutil.which(executable) or executable)
    try:
        from pspdoclib import bbox
        from pspdoclib.ecdsa_psp import PSPECDSA, PSP_KEYS
    finally:
        sys.path.pop(0)

    install_id = bytes(range(16))
    descriptor_key = bytes(range(16, 32))
    data_key = bytes(range(32, 48))
    inner = bytearray(0xb0)
    inner[:0x10] = b'\0PGD\1\0\0\0\1\0\0\0\0\0\0\0'
    inner[0x10:0x20] = descriptor_key
    description = bytearray(0x30)
    description[:0x10] = data_key
    struct.pack_into('<IIII', description, 0x10, 0, *descriptor)
    bbox.bbox_decrypt(description, 0, install_id, descriptor_key, 1)
    inner[0x30:0x60] = description
    ciphertext = bytearray(document_key + bytes(8))
    bbox.bbox_decrypt(ciphertext, 0, install_id, data_key, 1)
    inner[0x90:0xa0] = ciphertext
    inner[0xa0:0xb0] = bbox.bbox_mac_gen(ciphertext, install_id, 1)
    inner[0x60:0x70] = bbox.bbox_mac_gen(inner[0xa0:0xb0], install_id, 1)
    inner[0x70:0x80] = bbox.bbox_mac_gen(inner[:0x70], install_id, 1)
    inner[0x80:0x90] = bbox.bbox_mac_gen(inner[:0x80], bbox._DNAS_KEY1, 1)

    outer = bytearray(0x80)
    outer[:0x10] = b'\0PSPEDAT\x02\0\0\0\x80\0\0\0'
    signature = PSPECDSA().sign(
        hashlib.sha1(outer[:0x58]).digest(), PSP_KEYS['EDATA_PRIVKEY'], k=1)
    outer[0x58:0x80] = b''.join(signature)
    return bytes(outer + inner)


class DocumentIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = os.environ.get('PSPDB_DOCUMENT')
        if not executable:
            raise unittest.SkipTest('PSPDB_DOCUMENT is not configured; external DOCUMENT helper required')
        # Preserve PATH lookup while making configured relative paths independent
        # of each subprocess's isolated working directory.
        cls.executable = str(Path(executable).resolve()) if os.sep in executable else executable
        cls.pages = (_png((240, 20, 40)), _png((10, 180, 230)))

    def _extract(self, root, document, companion=None, explicit=True):
        work = root / 'work' / 'run'
        work.mkdir(parents=True)
        source = work / 'DOCUMENT.DAT'
        source.write_bytes(document)
        docinfo = work / 'DOCINFO.EDAT'
        if companion is not None:
            docinfo.write_bytes(companion)
        output = work / 'output'
        output.mkdir()
        scratch = root / 'scratch'
        scratch.mkdir()
        command = [self.executable, str(source), '--output', str(output)]
        if companion is not None and explicit:
            command.extend(('--docinfo', str(docinfo)))
        result = subprocess.run(
            command,
            cwd=work,
            env={**os.environ, 'TMPDIR': str(scratch)},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(source.read_bytes(), document, 'helper changed the source DOCUMENT')
        if companion is not None:
            self.assertEqual(docinfo.read_bytes(), companion, 'helper changed the source DOCINFO')
        return result, source, output

    def test_exact_pages_and_platform_ordinals_ignore_unsafe_document_code(self):
        for variant in ('ps1', 'psp'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, source, output = self._extract(root, _document(variant, self.pages))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('docinfo', json.loads(result.stdout))
                expected = {
                    'psp/001.png': self.pages[0],
                    'psp/002.png': self.pages[1],
                    'ps3/001.png': self.pages[1] if variant == 'ps1' else self.pages[0],
                    'ps3/002.png': self.pages[0] if variant == 'ps1' else self.pages[1],
                }
                self.assertEqual(
                    {path.relative_to(output).as_posix() for path in output.rglob('*')},
                    {'psp', 'ps3', *expected},
                )
                for name, png in expected.items():
                    self.assertEqual((output / name).read_bytes(), png, name)
                for path in output.rglob('*'):
                    self.assertFalse(path.is_symlink(), str(path))
                # The unsafe title must not create files outside caller output,
                # including inside the helper's temporary working area.
                self.assertEqual(
                    {path.relative_to(root) for path in root.rglob('*') if path.is_file()},
                    {source.relative_to(root)}
                    | {(output / name).relative_to(root) for name in expected},
                )

    def test_overlapping_encrypted_ranges_preserve_declared_order(self):
        for variant in ('ps1', 'psp'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                document = _document(variant, self.pages, encrypted_ranges=((16, 24), (0, 32), (48, 16)))
                result, _, output = self._extract(Path(directory), document)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((output / 'psp/001.png').read_bytes(), self.pages[0])
                self.assertEqual((output / 'psp/002.png').read_bytes(), self.pages[1])

    def test_bad_second_page_fails_without_publishing_first_page(self):
        for variant in ('ps1', 'psp'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                document = bytearray(_document(variant, self.pages))
                # Only page two's protection hash changes; page one remains valid.
                document[-1] ^= 1
                root = Path(directory)
                result, source, output = self._extract(root, bytes(document))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(list(output.iterdir()), [], 'partial pages escaped a failed extraction')
                self.assertEqual(
                    {path.relative_to(root) for path in root.rglob('*') if path.is_file()},
                    {source.relative_to(root)},
                )

    def test_authenticated_frame_cannot_hide_trailing_png_data(self):
        with tempfile.TemporaryDirectory() as directory:
            pages = (self.pages[0], self.pages[1] + b'unframedIEND\xaeB`\x82')
            result, _, output = self._extract(Path(directory), _document('psp', pages))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(output.iterdir()), [])

    def test_explicit_companion_pages_identity_and_source_frames(self):
        key = bytes(range(8))
        document = _document('psp', self.pages, key)
        companion = _docinfo(self.executable, key)
        with tempfile.TemporaryDirectory() as directory:
            result, _, output = self._extract(Path(directory), document, companion)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual({page['path'] for page in manifest['pages']}, {
                'psp/001.png', 'psp/002.png', 'ps3/001.png', 'ps3/002.png'})
            self.assertEqual(manifest['docinfo'], {
                'sha256': hashlib.sha256(companion).hexdigest(), 'size_bytes': len(companion)})
            for page in manifest['pages']:
                ordinal = int(Path(page['path']).stem)
                self.assertEqual((output / page['path']).read_bytes(), self.pages[ordinal - 1])
                frame = page['source_frame']
                original = document[frame['offset']:frame['offset'] + frame['size_bytes']]
                self.assertEqual(hashlib.sha256(original).hexdigest(), frame['sha256'])

    def test_companion_corruption_fails_atomically_without_default_fallback(self):
        # A companion recovering the fixed DES key makes a fallback bug observable:
        # rejecting EDAT must not silently retry the otherwise valid fixed-key DOC.
        key = bytes(a ^ b for a, b in zip(
            _DES_PARAMETERS['psp'][0], bytes.fromhex('f932ff26474a8dc0')))
        document = _document('psp', self.pages)
        companion = _docinfo(self.executable, key)
        for name, offset in (
                ('outer-signature', 0x58), ('header-mac', 0x100),
                ('key-des-parity-bit', 0x110), ('ciphertext-padding', 0x118),
                ('block-mac-table', 0x120)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                damaged = bytearray(companion)
                damaged[offset] ^= 1
                result, _, output = self._extract(Path(directory), document, bytes(damaged))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(list(output.iterdir()), [])

    def test_authenticated_unsupported_companion_extents_fail(self):
        key = bytes(range(8))
        document = _document('psp', self.pages, key)
        for descriptor in ((9, 0x400, 0x90), (8, 0x400, 0xfffffff0)):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as directory:
                companion = _docinfo(self.executable, key, descriptor)
                result, _, output = self._extract(Path(directory), document, companion)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(list(output.iterdir()), [])

    def test_adjacent_companion_is_never_inferred(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _, output = self._extract(
                Path(directory), _document('psp', self.pages, bytes(range(8))),
                _docinfo(self.executable, bytes(range(8))), explicit=False)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(output.iterdir()), [])

    def test_paired_late_page_corruption_does_not_publish_earlier_pages(self):
        key = bytes(range(8))
        document = bytearray(_document('psp', self.pages, key))
        document[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            result, _, output = self._extract(
                Path(directory), bytes(document), _docinfo(self.executable, key))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(output.iterdir()), [])

    def test_authenticated_wrong_companion_cannot_decode_document(self):
        key = bytes(range(8))
        wrong_key = bytes([key[0] ^ 2]) + key[1:]
        with tempfile.TemporaryDirectory() as directory:
            result, _, output = self._extract(
                Path(directory), _document('psp', self.pages, key),
                _docinfo(self.executable, wrong_key))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(output.iterdir()), [])
