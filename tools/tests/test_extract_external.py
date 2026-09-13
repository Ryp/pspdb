import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.extract_external import extract_psar as extract, extract_prx, extract_rco


class ExtractionTests(unittest.TestCase):
    def test_gzip_names_decoded_psp_module_by_elf_format(self):
        import gzip
        from tools.extract_external import extract_gzip, decoded_payload_name
        # PSP-specific e_type remains in the bytes even with a generic ELF suffix.
        elf = b'\x7fELF\x01\x01' + bytes(10) + b'\xa0\xff' + bytes(34)
        self.assertEqual(decoded_payload_name(elf), 'module.elf')
        self.assertEqual(decoded_payload_name(b'\x1f\x8b\x08'), 'payload.gz')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'opaque-source'; output = root/'out'; output.mkdir()
            source.write_bytes(gzip.compress(elf, mtime=0))
            extract_gzip(source, output)
            self.assertEqual([p.name for p in output.iterdir()], ['module.elf'])
            self.assertEqual((output/'module.elf').read_bytes(), elf)

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
        self.assertEqual(prx_payload_name(b'\x7fELF' + bytes(12) + b'\xa0\xff', header), 'module.elf')

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


class PsmfTests(unittest.TestCase):
    def setUp(self):
        from tools import extract_external as adapter
        self.adapter = adapter
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.output = self.root / 'output'
        self.output.mkdir()
        self.tool = self.root / 'pspdb-psmf'
        self.tool.write_bytes(b'helper identity')
        header = bytearray(4096)
        header[:16] = b'PSMF0014' + (4096).to_bytes(4, 'big') + bytes(4)
        header[128:130] = (2).to_bytes(2, 'big')
        header[130:132] = b'\xe1\x00'
        header[146:148] = b'\xbd\x02'
        self.outputs = {'video-e1.h264': b'\x00\x00\x00\x01\x65video-first-video-last',
                        'audio-bd-02.framed-at3': b'\x0f\xd0\x00\x01audio-framing'}
        packets = []
        body = bytearray()

        def packet(sid, rest, key=None, skip=None):
            start = len(header) + len(body)
            raw = b'\x00\x00\x01' + bytes([sid]) + rest
            body.extend(raw)
            packets.append(dict(start=start, end=start + len(raw), packet_id=sid, stream=key,
                                payload_start=start + skip if skip is not None else None,
                                payload_end=start + len(raw) if skip is not None else None))

        def pes(sid, payload, key, optional=b'', private=b''):
            rest = b'\x80\x00' + bytes([len(optional)]) + optional + private + payload
            packet(sid, len(rest).to_bytes(2, 'big') + rest, key, 9 + len(optional) + len(private))

        packet(0xba, b'\x44' + bytes(8) + b'\x02\xff\xff')
        packet(0xbb, b'\x00\x02\x12\x34')
        pes(0xe1, b'\x00\x00\x00\x01\x65video-first', 'e1:00', optional=b'\xff\xff')
        pes(0xbd, self.outputs['audio-bd-02.framed-at3'], 'bd:02', private=b'\x02\x00\x00\x00')
        packet(0xbe, b'\x00\x03\xff\xff\xff')
        pes(0xe1, b'-video-last', 'e1:00')
        packet(0xb9, b'')
        header[12:16] = len(body).to_bytes(4, 'big')
        self.source.write_bytes(header + body)
        self.manifest = dict(source_sha256=hashlib.sha256(header + body).hexdigest(),
                             source_size_bytes=len(header) + len(body), data_start=len(header),
                             data_end=len(header) + len(body), consumed_end=len(header) + len(body),
                             declared_streams=['bd:02', 'e1:00'], packets=packets,
                             outputs=[dict(path=name, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                                      for name, data in self.outputs.items()])
        self.helper_action = None
        run = patch.object(adapter, 'run_psmf', side_effect=self.run_helper)
        run.start()
        self.addCleanup(run.stop)

    def run_helper(self, command, timeout):
        if command[-1] == '--provenance':
            return json.dumps(dict(name='pmftools', options=[self.adapter.PSMF_UPSTREAM, 'manifest-budget-env:1'])).encode()
        destination = Path(command[-1])
        destination.mkdir()
        for name, data in self.outputs.items():
            (destination / name).write_bytes(data)
        (destination / 'manifest.json').write_text(json.dumps(self.manifest))
        if self.helper_action:
            self.helper_action(destination)
        return b''

    def extract(self):
        return self.adapter.extract_psmf(self.source, self.output, self.tool)

    def assert_rejected_cleanly(self):
        before = {path.name for path in self.root.iterdir()}
        with self.assertRaises((ValueError, OSError)):
            self.extract()
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual({path.name for path in self.root.iterdir()}, before)

    def test_preserves_interleaved_raw_spans_and_range_manifest(self):
        self.extract()
        self.assertEqual({path.name for path in self.output.iterdir()}, set(self.outputs) | {'structure.json'})
        for name, expected in self.outputs.items():
            self.assertEqual((self.output / name).read_bytes(), expected)

    def test_rejects_wrong_source_and_output_hashes_before_publication(self):
        self.manifest['source_sha256'] = '0' * 64
        self.assert_rejected_cleanly()
        self.manifest['source_sha256'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['outputs'][0]['sha256'] = '0' * 64
        self.assert_rejected_cleanly()

    def test_output_hash_cannot_authorize_bytes_absent_from_source_spans(self):
        name = 'video-e1.h264'
        self.outputs[name] = b'x' * len(self.outputs[name])
        self.manifest['outputs'][0]['sha256'] = hashlib.sha256(self.outputs[name]).hexdigest()
        self.assert_rejected_cleanly()

    def test_rejects_payload_range_lie_and_omitted_structural_packet(self):
        self.manifest['packets'][2]['payload_start'] += 1
        self.assert_rejected_cleanly()
        self.manifest['packets'][2]['payload_start'] -= 1
        del self.manifest['packets'][1]
        self.assert_rejected_cleanly()

    def test_private_channel_must_be_declared_in_source_header(self):
        raw = bytearray(self.source.read_bytes())
        raw[self.manifest['packets'][3]['payload_start'] - 4] = 3
        self.source.write_bytes(raw)
        self.manifest['source_sha256'] = hashlib.sha256(raw).hexdigest()
        self.assert_rejected_cleanly()

    def test_rejects_path_escape_and_output_omission(self):
        self.manifest['outputs'][0]['path'] = '../video-e1.h264'
        self.assert_rejected_cleanly()
        self.manifest['outputs'][0]['path'] = 'video-e1.h264'
        self.manifest['outputs'].pop()
        self.assert_rejected_cleanly()

    def test_rejects_unexpected_file_and_symlink(self):
        self.helper_action = lambda directory: (directory / 'unexpected').write_bytes(b'not inventoried')
        self.assert_rejected_cleanly()

        def symlink(directory):
            path = directory / 'video-e1.h264'
            path.unlink()
            path.symlink_to(self.source)

        self.helper_action = symlink
        self.assert_rejected_cleanly()

    def test_rejects_duplicate_metadata_keys_and_noninteger_ranges(self):
        def duplicate(directory):
            path = directory / 'manifest.json'
            path.write_text(path.read_text().replace('"data_start": 4096', '"data_start": 0, "data_start": 4096'))

        self.helper_action = duplicate
        self.assert_rejected_cleanly()
        self.helper_action = None
        self.manifest['packets'][0]['end'] = float(self.manifest['packets'][0]['end'])
        self.assert_rejected_cleanly()

    def test_helper_failure_cleans_partial_private_work(self):
        def failure(directory):
            (directory / 'partial').write_bytes(b'partial')
            raise ValueError('PSMF helper exceeded 120 seconds')

        self.helper_action = failure
        self.assert_rejected_cleanly()

    def test_provenance_cannot_override_registry_revision(self):
        with patch.object(self.adapter, 'run_psmf', return_value=json.dumps(dict(
                name='pmftools', version='999', options=[self.adapter.PSMF_UPSTREAM])).encode()):
            self.assert_rejected_cleanly()


class MpegpsTests(unittest.TestCase):
    def setUp(self):
        from tools import extract_external as adapter
        self.adapter = adapter
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.output = self.root / 'output'
        self.output.mkdir()
        self.tool = self.root / 'pspdb-mpegps'
        self.tool.write_bytes(b'standalone helper identity')
        self.outputs = {'pes-e1.bin': b'video-first-video-last',
                        'private-bd.bin': b'\x80\x00\x12\x34opaque-first\x02\xff\x00\x01opaque-last'}
        packets, body = [], bytearray()

        def packet(sid, rest, payload_skip=None):
            start = len(body)
            body.extend(b'\x00\x00\x01' + bytes([sid]) + rest)
            packets.append(dict(start=start, end=len(body), packet_id=sid,
                                stream=f'{sid:02x}' if payload_skip is not None else None,
                                payload_start=start + payload_skip if payload_skip is not None else None,
                                payload_end=len(body) if payload_skip is not None else None))

        def pes(sid, payload, flags=0, optional=b''):
            rest = b'\x80' + bytes([flags, len(optional)]) + optional + payload
            packet(sid, len(rest).to_bytes(2, 'big') + rest, 9 + len(optional))

        packet(0xba, bytes.fromhex('440004000401000003fa') + b'\xff\xff')
        packet(0xbb, b'\x00\x02\x12\x34')
        pes(0xe1, b'video-first', flags=0xc1,
            optional=bytes.fromhex('310001000111000100011e4000ff'))
        pes(0xbd, b'\x80\x00\x12\x34opaque-first', optional=b'\xff')
        packet(0xbe, b'\x00\x03\xff\xff\xff')
        pes(0xe1, b'-video-last', flags=0x80, optional=bytes.fromhex('2100010001'))
        pes(0xbd, b'\x02\xff\x00\x01opaque-last')
        packet(0xbf, b'\x00\x02\x56\x78')
        packet(0xb9, b'')
        self.source.write_bytes(body)
        self.manifest = dict(source_sha256=hashlib.sha256(body).hexdigest(), source_size_bytes=len(body),
                             data_start=0, data_end=len(body), consumed_end=len(body),
                             observed_streams=['bd', 'e1'], packets=packets, outputs=[])
        self.update_output_metadata()
        self.helper_action = None
        run = patch.object(adapter, 'run_mpegps', side_effect=self.run_helper)
        run.start()
        self.addCleanup(run.stop)
        revisions = patch.object(adapter, 'VERSIONS', dict(adapter.versions(), mpegps='1'))
        revisions.start()
        self.addCleanup(revisions.stop)

    def update_output_metadata(self):
        self.manifest['outputs'] = [
            dict(path=name, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            for name, data in self.outputs.items()]

    def run_helper(self, command, timeout):
        if command[-1] == '--provenance':
            return json.dumps(dict(name='pmftools-mpegps', options=[
                self.adapter.MPEGPS_UPSTREAM, 'raw-mpeg2:1', 'opaque-private-pes:1',
                'manifest:1', 'manifest-budget-env:1'])).encode()
        directory = Path(command[-1])
        directory.mkdir()
        for name, data in self.outputs.items():
            (directory / name).write_bytes(data)
        (directory / 'manifest.json').write_text(json.dumps(self.manifest))
        if self.helper_action:
            self.helper_action(directory)
        return b''

    def assert_rejected_cleanly(self):
        before = {path.name for path in self.root.iterdir()}
        with self.assertRaises((ValueError, OSError)):
            self.adapter.extract_mpegps(self.source, self.output, self.tool)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual({path.name for path in self.root.iterdir()}, before)

    def test_preserves_interleaved_opaque_private_prefixes_and_raw_video(self):
        self.adapter.extract_mpegps(self.source, self.output, self.tool)
        self.assertEqual({path.name for path in self.output.iterdir()}, set(self.outputs) | {'structure.json'})
        for name, data in self.outputs.items():
            self.assertEqual((self.output / name).read_bytes(), data)

    def test_rejects_forged_spans_and_missing_structural_packet(self):
        private = self.manifest['packets'][3]
        private['payload_start'] += 4
        self.assert_rejected_cleanly()
        private['payload_start'] -= 4
        self.manifest['packets'][2]['end'] += 1
        self.assert_rejected_cleanly()
        self.manifest['packets'][2]['end'] -= 1
        del self.manifest['packets'][1]
        self.assert_rejected_cleanly()

    def test_output_hash_cannot_authorize_stripped_prefix_forged_bytes_or_suffix(self):
        original = self.outputs['private-bd.bin']
        for forged in (original[4:], b'x' * len(original), original + b'extra'):
            with self.subTest(output=forged):
                self.outputs['private-bd.bin'] = forged
                self.update_output_metadata()
                self.assert_rejected_cleanly()

    def test_rejects_uninventoried_files_and_symlinked_outputs_or_manifest(self):
        self.helper_action = lambda directory: (directory / 'extra.bin').write_bytes(b'extra')
        self.assert_rejected_cleanly()
        for name in ('private-bd.bin', 'manifest.json'):
            with self.subTest(path=name):
                def symlink(directory):
                    target = directory / name
                    target.unlink()
                    target.symlink_to(self.source)
                self.helper_action = symlink
                self.assert_rejected_cleanly()

    def test_rejects_duplicate_unknown_fields_and_noninteger_ranges(self):
        def duplicate(directory):
            path = directory / 'manifest.json'
            path.write_text(path.read_text().replace('"data_start": 0', '"data_start": 0, "data_start": 0'))
        self.helper_action = duplicate
        self.assert_rejected_cleanly()
        self.helper_action = None
        self.manifest['packets'][0]['extra'] = 0
        self.assert_rejected_cleanly()
        del self.manifest['packets'][0]['extra']
        for value in (False, 0.0):
            with self.subTest(value=value):
                self.manifest['packets'][0]['start'] = value
                self.assert_rejected_cleanly()

    def test_rejects_malformed_source_headers_even_with_matching_source_hash(self):
        original = self.source.read_bytes()
        pes = self.manifest['packets'][2]['start']
        corruptions = {
            'MPEG1 pack': (4, b'\x21'),
            'pack marker': (9, b'\x00'),
            'pack reserved bits': (13, b'\xf2'),
            'pack stuffing': (14, b'\x00'),
            'PES marker': (pes + 6, b'\x40'),
            'scrambled PES': (pes + 6, b'\xb0'),
            'reserved timestamps': (pes + 7, b'\x40'),
            'unsupported optional field': (pes + 7, b'\xc2'),
            'optional header overrun': (pes + 8, b'\xff'),
            'PTS marker': (pes + 9, b'\x30'),
            'DTS prefix': (pes + 14, b'\x21'),
            'extension reserved bits': (pes + 19, b'\x10'),
            'P-STD prefix': (pes + 20, b'\x80'),
            'PES stuffing': (pes + 22, b'\x00'),
            'zero packet length': (pes + 4, b'\x00\x00'),
        }
        for name, (offset, replacement) in corruptions.items():
            with self.subTest(header=name):
                raw = original[:offset] + replacement + original[offset + len(replacement):]
                self.source.write_bytes(raw)
                self.manifest['source_sha256'] = hashlib.sha256(raw).hexdigest()
                self.assert_rejected_cleanly()

    def test_rejects_wrong_identity_inventory_and_unaccounted_source_suffix(self):
        self.manifest['source_sha256'] = '0' * 64
        self.assert_rejected_cleanly()
        self.manifest['source_sha256'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['observed_streams'].append('ef')
        self.assert_rejected_cleanly()
        self.manifest['observed_streams'].pop()
        raw = self.source.read_bytes() + b'suffix'
        self.source.write_bytes(raw)
        self.manifest.update(source_sha256=hashlib.sha256(raw).hexdigest(), source_size_bytes=len(raw),
                             data_end=len(raw), consumed_end=len(raw))
        self.assert_rejected_cleanly()

    def test_rejects_nonregular_source_oversized_files_and_helper_failure(self):
        original = self.root / 'original'
        self.source.rename(original)
        self.source.symlink_to(original)
        self.assert_rejected_cleanly()
        self.source.unlink()
        original.rename(self.source)
        with patch.object(self.adapter, 'MPEGPS_SOURCE_LIMIT', self.source.stat().st_size - 1):
            self.assert_rejected_cleanly()
        with patch.object(self.adapter, 'MPEGPS_MANIFEST_LIMIT', 16):
            self.assert_rejected_cleanly()
        original.write_bytes(self.source.read_bytes())

        def replace_source(directory):
            self.source.unlink()
            self.source.symlink_to(original)
        self.helper_action = replace_source
        self.assert_rejected_cleanly()
        self.source.unlink()
        original.rename(self.source)

        def oversized(directory):
            with (directory / 'private-bd.bin').open('ab') as stream:
                stream.truncate(self.adapter.MPEGPS_SOURCE_LIMIT + 1)
        self.helper_action = oversized
        self.assert_rejected_cleanly()

        def failure(directory):
            (directory / 'partial').write_bytes(b'partial')
            raise ValueError('helper failure')
        self.helper_action = failure
        self.assert_rejected_cleanly()
