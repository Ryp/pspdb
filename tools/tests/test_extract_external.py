import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.extract_external import extract_psar as extract, extract_prx, extract_rco


class ExtractionTests(unittest.TestCase):
    def test_extracts_into_caller_directory_and_reports_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'; source.write_bytes(b'PSAR test input')
            output = root / 'output'; output.mkdir()
            tool = Path(sys.executable).resolve()
            def run(args, **kwargs):
                self.assertEqual(args, [str(tool), '-O', str(output), str(source)])
                (output / 'module.prx').write_bytes(b'decoded')
                return subprocess.CompletedProcess(args, 0, 'Done!\n', '')
            with patch('tools.extract_external.subprocess.run', side_effect=run):
                record = extract(source, output, tool)
            self.assertEqual((output / 'module.prx').read_bytes(), b'decoded')
            self.assertEqual(record, {'name': 'pspdecrypt', 'version': '1',
                'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
                'options': ['-O', '<output>', '<source>']})

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

    def test_prx_requires_success_and_declared_output_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'
            header = bytearray(0x150); header[:4] = b'~PSP'; header[0xb0:0xb4] = (4).to_bytes(4, 'little'); source.write_bytes(header)
            output = root / 'output'; output.mkdir()
            def run(args, **kwargs):
                Path(args[2]).write_bytes(b'\x7fELF')
                return subprocess.CompletedProcess(args, 0, 'Decryption failed', '')
            with patch('tools.extract_external.subprocess.run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'PRX decryption failed'):
                    extract_prx(source, output, Path(sys.executable))
            def wrong_size(args, **kwargs):
                Path(args[2]).write_bytes(b'bad')
                return subprocess.CompletedProcess(args, 0, 'Decryption successful', '')
            with patch('tools.extract_external.subprocess.run', side_effect=wrong_size):
                with self.assertRaisesRegex(ValueError, 'Unexpected decrypted PSP size'):
                    extract_prx(source, output, Path(sys.executable))

    def test_rco_rejects_success_with_resource_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.write_bytes(b'\0PRF')
            config = root / 'config'; config.mkdir(); (config / 'test.ini').write_text('test')
            output = root / 'output'; output.mkdir()
            result = subprocess.CompletedProcess([], 0, 'Warning: RLZ unsupported', '')
            with patch('tools.extract_external.subprocess.run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'did not complete cleanly'):
                    extract_rco(source, output, Path(sys.executable), config)

    def test_prx_output_suffix_comes_from_wrapper_and_elf_type(self):
        from tools.extract_external import prx_payload_name
        header = bytearray(0x150)
        header[6:8] = (0x201).to_bytes(2, 'little')
        self.assertEqual(prx_payload_name(b'KL4E', header), 'module.prx.kl4e')
        header[6:8] = (0x203).to_bytes(2, 'little')
        self.assertEqual(prx_payload_name(b'KL4E', header), 'module.elf.kl4e')
        header[6:8] = bytes(2)
        self.assertEqual(prx_payload_name(b'KL3E', header), 'module.bin.kl3e')
        self.assertEqual(prx_payload_name(b'\x7fELF' + bytes(12) + b'\xa0\xff', header), 'module.prx')

    def test_kl_decoder_rejects_tool_failure_and_missing_output(self):
        from tools.extract_external import extract_kle
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'input'; source.write_bytes(b'KL4E')
            output = root / 'output'; output.mkdir()
            for result in [subprocess.CompletedProcess([], 1, '', 'bad stream'),
                           subprocess.CompletedProcess([], 0, 'Decompression successful', '')]:
                with patch('tools.extract_external.subprocess.run', return_value=result):
                    with self.assertRaisesRegex(ValueError, 'KL decompression failed'):
                        extract_kle(source, output, Path(sys.executable))


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
