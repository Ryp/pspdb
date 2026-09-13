import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.extract_external import extract_psar as extract, extract_rco


class ExtractionTests(unittest.TestCase):
    def test_zero_exit_with_error_leaves_cleanup_to_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'; source.write_bytes(b'PSAR test')
            output = root / 'output'; output.mkdir()
            def run(args, **kwargs):
                (output / 'partial').write_bytes(b'partial')
                return subprocess.CompletedProcess(args, 0, 'error decompressing\nDone!\n', '')
            with patch('tools.extract_external.subprocess.run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'did not complete cleanly'):
                    extract(source, output, Path(sys.executable))
            self.assertTrue((output / 'partial').exists())

    def test_source_verified_before_running_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'; source.write_bytes(b'not PSAR')
            with patch('tools.extract_external.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'not a firmware PSAR'):
                    extract(source, Path(directory) / 'output', Path(sys.executable))
                run.assert_not_called()

    def test_rco_rejects_success_with_resource_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.write_bytes(b'\0PRF')
            config = root / 'config'; config.mkdir(); (config / 'test.ini').write_text('test')
            output = root / 'output'; output.mkdir()
            result = subprocess.CompletedProcess([], 0, 'Warning: RLZ unsupported', '')
            with patch('tools.extract_external.subprocess.run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'did not complete cleanly'):
                    extract_rco(source, output, Path(sys.executable), config)


class ProvenanceTests(unittest.TestCase):
    def test_revision_and_configuration_changes_are_visible(self):
        from tools import extract_external as adapter
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / 'tool'; tool.write_bytes(b'executable one')
            data = root / 'data'; data.mkdir()
            config = data / 'rco.ini'; config.write_text('old config')
            original = adapter.tool_provenance('rco', tool, data)
            config.write_text('new config')
            changed = adapter.tool_provenance('rco', tool, data)
            self.assertNotEqual(original['options'], changed['options'])
            self.assertEqual(original['sha256'], changed['sha256'])
            tool.write_bytes(b'executable two')
            self.assertNotEqual(changed['sha256'], adapter.tool_provenance('rco', tool, data)['sha256'])
            with patch.object(adapter, 'VERSIONS', dict(adapter.versions(), rco='2')):
                self.assertEqual(adapter.tool_provenance('rco', tool, data)['version'], '2')

    def test_document_rejects_helpers_that_publish_bookkeeping_files(self):
        from tools import extract_external as adapter
        legacy = json.dumps({'name': 'PSP-DOCUMENT.DAT', 'options': ['platform-ordinals']})
        with patch.object(adapter.subprocess, 'check_output', return_value=legacy):
            with self.assertRaises(ValueError):
                adapter.tool_provenance('document', Path(sys.executable))

class NpumdimgTests(unittest.TestCase):
    def test_signature_failure_and_iso_validation(self):
        from tools.extract_external import extract_npumdimg
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source'; output = root/'output'; output.mkdir()
            source.write_bytes(b'PSAR')
            with patch('tools.extract_external.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'not NPUMDIMG'):
                    extract_npumdimg(source, output, Path(sys.executable))
                run.assert_not_called()
            source.write_bytes(b'NPUMDIMG' + bytes(248))
            for code, data in [(1, bytes(34816)), (0, b'bad iso')]:
                def run(args, **kwargs):
                    Path(args[2]).write_bytes(data)
                    return subprocess.CompletedProcess(args, code, '', '')
                with patch('tools.extract_external.subprocess.run', side_effect=run):
                    with self.assertRaises(ValueError):
                        extract_npumdimg(source, output, Path(sys.executable))
            iso = bytearray(34816); iso[32768:32775] = b'\x01CD001\x01'
            def run(args, **kwargs):
                Path(args[2]).write_bytes(iso)
                return subprocess.CompletedProcess(args, 0, '', '')
            with patch('tools.extract_external.subprocess.run', side_effect=run):
                provenance = extract_npumdimg(source, output, Path(sys.executable))
            self.assertEqual(provenance['name'], 'pkg2zip-npumdimg')
            self.assertEqual(provenance['sha256'], hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest())
            self.assertEqual((output/'disc.iso').read_bytes(), iso)


class EdatTests(unittest.TestCase):
    def setUp(self):
        from tools import extract_external as adapter
        from tools import rap
        self.adapter = adapter
        self.rap_store = rap
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = patch.dict(os.environ, {
            'HOME': str(self.root / 'home'),
            'XDG_DATA_HOME': str(self.root / 'data'),
            'PSPDB_RAP_DIR': '',
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.identifier = 'UP0001-TEST00001_00-' + 'A' * 16
        self.license = bytes(range(16))
        self.payload = b'authenticated payload'
        self.source = self.root / 'source.edat'
        header = bytearray(0x100)
        header[:4] = b'NPD\0'
        header[0x10:0x40] = self.identifier.encode().ljust(48, b'\0')
        header[0x88:0x90] = len(self.payload).to_bytes(8, 'big')
        self.source.write_bytes(header)
        self.output = self.root / 'output'
        self.output.mkdir()
        self.tool = Path(sys.executable)
        provenance = patch.object(adapter.subprocess, 'check_output', return_value=json.dumps({
            'name': 'make-npdata',
            'options': [adapter.EDAT_UPSTREAM, 'authenticated-edat:1'],
        }))
        provenance.start()
        self.addCleanup(provenance.stop)

    def import_license(self):
        self.rap_store.import_raps(self.rap_store.license_directory(),
                                   [(self.identifier, self.license.hex())])

    def test_missing_license_prevents_decryption(self):
        with patch.object(self.adapter.subprocess, 'run') as decrypt:
            with self.assertRaises(ValueError) as failure:
                self.adapter.extract_edat(self.source, self.output, self.tool)
            decrypt.assert_not_called()
        self.assertIn(self.identifier, str(failure.exception))
        self.assertIn(str(self.rap_store.license_directory()), str(failure.exception))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_invalid_license_prevents_decryption(self):
        self.import_license()
        license_path = self.rap_store.license_directory() / (self.identifier + '.rap')
        license_path.write_bytes(self.license + b'invalid')
        with patch.object(self.adapter.subprocess, 'run') as decrypt:
            with self.assertRaises(ValueError) as failure:
                self.adapter.extract_edat(self.source, self.output, self.tool)
            decrypt.assert_not_called()
        self.assertIn(self.identifier, str(failure.exception))
        self.assertIn(str(license_path.parent), str(failure.exception))
        self.assertNotIn(self.license.hex(), str(failure.exception))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_invalid_content_id_padding_prevents_decryption(self):
        self.import_license()
        header = bytearray(self.source.read_bytes())
        header[0x3f] = ord('A')
        self.source.write_bytes(header)
        with patch.object(self.adapter.subprocess, 'run') as decrypt:
            with self.assertRaisesRegex(ValueError, 'content ID'):
                self.adapter.extract_edat(self.source, self.output, self.tool)
            decrypt.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_authentication_failure_never_publishes_plaintext(self):
        self.import_license()
        for code, message in ((1, ''), (0, 'authentication failed')):
            with self.subTest(code=code, message=message):
                def decrypt(args, **kwargs):
                    Path(args[2]).write_bytes(self.payload)
                    return subprocess.CompletedProcess(args, code, message, self.license.hex())
                with patch.object(self.adapter.subprocess, 'run', side_effect=decrypt):
                    with self.assertRaisesRegex(ValueError, 'authentication or decryption failed') as failure:
                        self.adapter.extract_edat(self.source, self.output, self.tool)
                self.assertNotIn(self.license.hex(), str(failure.exception))
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(list(self.root.glob('.pspdb-edat-*')), [])
