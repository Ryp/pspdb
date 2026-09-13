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


