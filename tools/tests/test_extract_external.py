import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

class ProvenanceTests(unittest.TestCase):
    def test_document_rejects_helpers_that_publish_bookkeeping_files(self):
        from tools import extract_external as adapter
        legacy = json.dumps({'name': 'PSP-DOCUMENT.DAT', 'options': ['platform-ordinals']})
        with patch.object(adapter.subprocess, 'check_output', return_value=legacy):
            with self.assertRaises(ValueError):
                adapter.tool_provenance('document', Path(sys.executable))


class PsxExtractionTests(unittest.TestCase):
    def test_partial_disc_is_rejected_when_native_audio_conversion_fails(self):
        from tools import extract_external as adapter
        for status, diagnostic in ((1, ''), (0, 'ERROR: audio conversion failed')):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / 'parent.pbp'
                source.write_bytes(b'\0PBP' + bytes(36))
                output = root / 'output'
                output.mkdir()
                helper = root / 'psxtract'
                helper.write_text(
                    '#!' + sys.executable + '\n'
                    'from pathlib import Path\n'
                    'disc = bytearray(20 * 2352)\n'
                    "disc[16 * 2352 + 24:16 * 2352 + 31] = b'\\x01CD001\\x01'\n"
                    "Path('partial.bin').write_bytes(disc)\n"
                    "Path('TEMP').mkdir()\n"
                    "Path('TEMP/ISO_HEADER.BIN').write_bytes(b'partial header')\n"
                    "print('Disc successfully converted')\n"
                    f'print({diagnostic!r})\n'
                    f'raise SystemExit({status})\n')
                helper.chmod(0o755)
                with self.assertRaises(ValueError):
                    adapter.extract_psx(source, output, helper)
                self.assertEqual(list(output.iterdir()), [])

    def test_multidisc_admission_validates_every_disc_before_publishing(self):
        from tools import extract_external as adapter
        for invalid_second in (False, True):
            with self.subTest(invalid_second=invalid_second), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / 'parent.pbp'
                source.write_bytes(b'\0PBP' + bytes(36))
                output = root / 'output'
                output.mkdir()
                helper = root / 'psxtract'
                helper.write_text(
                    '#!' + sys.executable + '\n'
                    'from pathlib import Path\n'
                    'disc = bytearray(20 * 2352)\n'
                    "disc[16 * 2352 + 24:16 * 2352 + 31] = b'\\x01CD001\\x01'\n"
                    "Path('first.bin').write_bytes(disc)\n"
                    + ("disc[16 * 2352 + 24] = 0\n" if invalid_second else '')
                    + "Path('second.bin').write_bytes(disc)\n"
                    "Path('TEMP').mkdir()\n"
                    "Path('TEMP/ISO_HEADER_1.BIN').write_bytes(b'first header')\n"
                    "Path('TEMP/ISO_HEADER_2.BIN').write_bytes(b'second header')\n")
                helper.chmod(0o755)
                if invalid_second:
                    with self.assertRaises(ValueError):
                        adapter.extract_psx(source, output, helper)
                    self.assertEqual(list(output.iterdir()), [])
                else:
                    adapter.extract_psx(source, output, helper)
                    self.assertEqual({path.name for path in output.iterdir()}, {
                        'disc-1.bin', 'disc-2.bin', 'ISO_HEADER_1.BIN', 'ISO_HEADER_2.BIN',
                    })
