import hashlib
import hmac
from io import BytesIO
import os
from pathlib import Path
import struct
import subprocess
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


def _encrypt(data, variant):
    from Crypto.Cipher import DES

    key, iv = _DES_PARAMETERS[variant]
    return DES.new(key, DES.MODE_CBC, iv).encrypt(data)


def _protect(data, variant):
    if variant == 'ps1':
        # Optional BB-MAC is absent; SHA1 still protects every encrypted frame.
        return data + bytes(0x10) + hashlib.sha1(data).digest()[:0x10]
    return data + bytes(0x10) + b''.join(
        hmac.new(key, data, hashlib.sha1).digest()[:0x10] for key in _HMAC_KEYS
    )


def _document(variant, pages):
    header = bytearray(0x60)
    header[:0x0c] = b'DOC \0\0\1\0\0\0\1\0'
    code = b'../../escape'
    header[0x0c:0x0c + len(code)] = code
    # The zero size flag at 0x1c selects all 99 metadata slots.
    frames = []
    for png in pages:
        payload = png + bytes(-len(png) % 8)
        protection_size = 0x20 if variant == 'ps1' else 0x30
        frame_header = bytearray(0x20)
        struct.pack_into('<I', frame_header, 0, 0x20 + len(payload) + protection_size)
        # Zero encrypted-range descriptors: the PNG itself is plaintext.
        frames.append(_protect(_encrypt(frame_header, variant) + payload, variant))

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
        + _protect(_encrypt(header, variant), variant)
        + _protect(_encrypt(metadata, variant), variant)
        + b''.join(frames)
    )


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

    def _extract(self, root, document):
        work = root / 'work' / 'run'
        work.mkdir(parents=True)
        source = work / 'DOCUMENT.DAT'
        source.write_bytes(document)
        output = work / 'output'
        output.mkdir()
        scratch = root / 'scratch'
        scratch.mkdir()
        result = subprocess.run(
            [self.executable, str(source), '--output', str(output)],
            cwd=work,
            env={**os.environ, 'TMPDIR': str(scratch)},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(source.read_bytes(), document, 'helper changed the source DOCUMENT')
        return result, source, output

    def test_exact_pages_and_platform_ordinals_ignore_unsafe_document_code(self):
        for variant in ('ps1', 'psp'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, source, output = self._extract(root, _document(variant, self.pages))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = {
                    'psp/001.png': self.pages[0],
                    'psp/002.png': self.pages[1],
                    'ps3/001.png': self.pages[1] if variant == 'ps1' else self.pages[0],
                    'ps3/002.png': self.pages[0] if variant == 'ps1' else self.pages[1],
                }
                self.assertEqual(
                    {path.relative_to(output).as_posix() for path in output.rglob('*')},
                    {'psp', 'ps3', 'structure.json', *expected},
                )
                for name, png in expected.items():
                    self.assertEqual((output / name).read_bytes(), png, name)
                for path in output.rglob('*'):
                    self.assertFalse(path.is_symlink(), str(path))
                # The unsafe title must not create files outside caller output,
                # including inside the helper's temporary working area.
                self.assertEqual(
                    {path.relative_to(root) for path in root.rglob('*') if path.is_file()},
                    {source.relative_to(root), (output / 'structure.json').relative_to(root)}
                    | {(output / name).relative_to(root) for name in expected},
                )

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
