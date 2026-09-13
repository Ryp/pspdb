"""Retail PKG fixtures encrypted independently with OpenSSL, without game data."""
import hashlib
import io
import os
import sys
import pycdlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zipfile

from test_ingest_cli import BINARY, REPO, result_path, tree_path, snapshot

PSP_KEY = '07f2c68290b50d2c33818d709b60e62b'
PS3_KEY = '2e7b71d7c9c9a14ea3221f188828b8f8'


def sfo(fields):
    keys, values, entries = bytearray(), bytearray(), bytearray()
    for name, value in fields.items():
        text = value.encode() + b'\0'
        entries.extend(struct.pack('<HHIII', len(keys), 0x204, len(text), len(text), len(values)))
        keys.extend(name.encode() + b'\0'); values.extend(text)
    return struct.pack('<4sIIII', b'\0PSF', 0x101, 20 + len(entries), 20 + len(entries) + len(keys), len(fields)) + entries + keys + values


def pkg_bytes(content_type=7, extra=(), broken_pbp=False, pbp_override=None, files_override=None):
    inner = sfo({'TITLE': 'Fixture game', 'DISC_ID': 'NPUG00001', 'DISC_VERSION': '1.00', 'PSP_SYSTEM_VER': '3.80'})
    offsets = [40] + [40 + len(inner)] * 7
    pbp = b'\0PBP' + struct.pack('<I8I', 0x10000, *offsets) + inner + b'payload'
    if pbp_override is not None:
        pbp = pbp_override
    if broken_pbp:
        pbp = bytearray(pbp); struct.pack_into('<I', pbp, 36, len(pbp) + 1); pbp = bytes(pbp)
    files = [('PARAM.SFO', sfo({'TITLE': 'Outer fixture'}), False), ('USRDIR', None, False),
             ('USRDIR/CONTENT', None, False), ('USRDIR/CONTENT/EBOOT.PBP', pbp, True),
             ('USRDIR/ISO.BIN.EDAT', b'opaque bytes', False), ('empty', b'', True), *extra]
    if files_override is not None:
        files = files_override
    plain = bytearray(32 * len(files)); pieces = []
    def append(data):
        plain.extend(b'\0' * (-len(plain) % 16)); pos = len(plain); plain.extend(data); return pos
    for i, (name, data, portable) in enumerate(files):
        name_bytes = name.encode(); no = append(name_bytes); off = append(data or b'')
        raw = struct.pack('>IIQQ', no, len(name_bytes), off, len(data or b'')) + bytes([0x90 if portable else 0x80, 0, 0, 4 if data is None else 3]) + b'\0' * 4
        plain[i*32:i*32+32] = raw
        pieces.extend([(no, len(name_bytes), portable), (off, len(data or b''), portable)])
    def encrypt(key):
        return subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-K', key, '-iv', '00'*16], input=plain, capture_output=True, check=True).stdout
    portable, other = encrypt(PSP_KEY), encrypt(PS3_KEY)
    encrypted = bytearray(portable)
    for off, size, use_psp in pieces:
        encrypted[off:off+size] = (portable if use_psp else other)[off:off+size]
    header = bytearray(256)
    struct.pack_into('>4sHHIIIIQQQ', header, 0, b'\x7fPKG', 0x8000, 2, 192, 1, 12, len(files), 256+len(encrypted), 256, len(encrypted))
    cid = b'UP9000-NPUG00001_00-FIXTURE000000000'; header[48:48+len(cid)] = cid
    struct.pack_into('>III', header, 192, 2, 4, content_type)
    return bytes(header) + encrypted, files


class PkgCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['zig', 'build', '-Doptimize=ReleaseSafe'], cwd=REPO/'ingest', check=True)

    def run_ingest(self, root, *args):
        return subprocess.run([str(BINARY), str(root), '--no-progress', '--threads', '2', *map(str,args)], capture_output=True, text=True, timeout=30)

    def test_psp_and_ps1_roots_zip_nested_store_and_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); inputs = base/'inputs'; inputs.mkdir(); catalog = base/'catalog'; store = base/'store'
            psp, files = pkg_bytes()
            # Inner metadata must win even when the outer SFO is inventoried last.
            ps1, _ = pkg_bytes(6, files_override=list(reversed(files)))
            (inputs/'demo.PKG').write_bytes(psp)
            with zipfile.ZipFile(inputs/'archive.zip', 'w', zipfile.ZIP_DEFLATED) as z: z.writestr('game.pkg', ps1)
            before = snapshot(inputs)
            run = self.run_ingest(inputs, '--catalog', catalog, '--store', store)
            self.assertEqual(run.returncode, 0, run.stderr)
            for source in (psp, ps1):
                digest = hashlib.sha256(source).hexdigest()
                record = json.loads(result_path(catalog, 'pkg', digest).read_text())
                self.assertEqual(record['metadata']['title'], 'Fixture game')
                self.assertEqual(record['metadata']['required_firmware'], '3.80')
                tree = json.loads(tree_path(catalog, digest).read_text())
                self.assertEqual([e['path'] for e in tree['entries']], sorted(name for name, _, _ in files))
                for entry in tree['entries']:
                    if entry['type'] == 'directory': continue
                    original = next(data for name, data, _ in files if name == entry['path'])
                    self.assertEqual(entry['sha256'], hashlib.sha256(original).hexdigest())
                    h = entry['sha256']; self.assertEqual((store/'sha256'/h[:2]/h[2:4]/h).read_bytes(), original)
                self.assertEqual(record['sha1'], hashlib.sha1(source).hexdigest())
            pbp = next(data for name, data, _ in files if name.endswith('.PBP'))
            self.assertTrue(result_path(catalog, 'pbp', hashlib.sha256(pbp).hexdigest()).exists())
            before_catalog = snapshot(catalog)
            run = self.run_ingest(inputs, '--catalog', catalog, '--store', store, '--skip-existing')
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr.count('source already in catalog'), 2)
            self.assertEqual(snapshot(catalog), before_catalog)
            self.assertEqual(snapshot(inputs), before)

    def test_theme_preserves_payload_and_optional_metadata(self):
        payload = b'\0PSPEDAT' + bytes(range(128))
        for metadata in (None, sfo({'TITLE': 'Observed theme'})):
            with self.subTest(has_sfo=metadata is not None), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp); inputs = base/'inputs'; inputs.mkdir()
                catalog, store = base/'catalog', base/'store'
                files = [('Original Theme.PTF', payload, True)]
                if metadata is not None:
                    files.append(('PARAM.SFO', metadata, False))
                source, _ = pkg_bytes(9, files_override=files)
                (inputs/'theme.pkg').write_bytes(source)
                before = snapshot(inputs)
                run = self.run_ingest(inputs, '--catalog', catalog, '--store', store)
                self.assertEqual(run.returncode, 0, run.stderr)
                digest = hashlib.sha256(source).hexdigest()
                record = json.loads(result_path(catalog, 'pkg', digest).read_text())
                self.assertEqual(record['metadata']['content_type'], 9)
                self.assertEqual(record['metadata']['content_id'], 'UP9000-NPUG00001_00-FIXTURE000000000')
                self.assertEqual(record['metadata'].get('title'), 'Observed theme' if metadata is not None else None)
                self.assertIsNone(record['metadata'].get('disc_id'))
                self.assertIsNone(record['metadata'].get('required_firmware'))
                tree = json.loads(tree_path(catalog, digest).read_text())
                self.assertEqual(tree['entries'], [
                    dict(path=name, type='file', size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    for name, data, _ in sorted(files)
                ])
                for _, data, _ in files:
                    h = hashlib.sha256(data).hexdigest()
                    self.assertEqual((store/'sha256'/h[:2]/h[2:4]/h).read_bytes(), data)
                self.assertEqual(snapshot(inputs), before)

    def test_theme_support_keeps_platform_and_metadata_boundaries(self):
        cases = [
            ('ps3_theme', 1, 9, None, 'UnsupportedPkg'),
            ('vita_app', 2, 0x15, None, 'UnsupportedPkg'),
            ('psm', 2, 0x18, None, 'UnsupportedPkg'),
            ('missing_game_sfo', 2, 7, None, 'MissingPkgMetadata'),
            ('empty_theme_sfo', 2, 9, b'', 'InvalidSfo'),
            ('corrupt_theme_sfo', 2, 9, b'\0PSF' + bytes(8), 'InvalidSfo'),
        ]
        for name, platform, content_type, metadata, error in cases:
            with self.subTest(mode=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp); inputs = base/'inputs'; inputs.mkdir(); catalog = base/'catalog'
                files = [('theme.PTF', b'opaque theme payload', True)]
                if metadata is not None:
                    files.append(('PARAM.SFO', metadata, False))
                source, _ = pkg_bytes(content_type, files_override=files)
                source = bytearray(source); struct.pack_into('>H', source, 6, platform)
                (inputs/'bad.pkg').write_bytes(source)
                run = self.run_ingest(inputs, '--catalog', catalog, '--store', base/'store')
                self.assertNotEqual(run.returncode, 0, run.stderr)
                self.assertIn(error, run.stderr)
                self.assertFalse(list((catalog/'pkg').rglob('*-ingest.json')))

    def test_pops_uses_parent_pbp_and_attaches_only_to_executable(self):
        import gzip
        from unittest.mock import patch
        inner = sfo({'TITLE': 'POPS fixture'})
        executable = b'~PSP' + bytes(400)
        sections = [inner, b'', b'', b'', b'', b'', executable, b'PSISOIMG0000' + bytes(64)]
        offsets, cursor = [], 40
        for section in sections:
            offsets.append(cursor); cursor += len(section)
        pbp = b'\0PBP' + struct.pack('<I8I', 0x10000, *offsets) + b''.join(sections)
        package, _ = pkg_bytes(content_type=6, pbp_override=pbp)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); inputs = base/'inputs'; inputs.mkdir()
            (inputs/'pops.pkg').write_bytes(package)
            catalog, store = base/'catalog', base/'store'
            helper = base/'helper'
            compressed = gzip.compress(b'original verified plaintext', mtime=0)
            helper.write_text('#!/usr/bin/env python3\nimport pathlib,sys\n'
                + 'source=pathlib.Path(sys.argv[1]).read_bytes()\n'
                + 'assert source == ' + repr(pbp) + '\n'
                + 'pathlib.Path(sys.argv[2]).write_bytes(' + repr(compressed) + ')\n')
            helper.chmod(0o755)
            wine = base/'wine'
            disc = bytearray(20 * 2352)
            disc[16*2352+24:16*2352+31] = b'\x01CD001\x01'
            wine.write_text('#!' + sys.executable + '\nimport pathlib,sys\n'
                + 'assert pathlib.Path(sys.argv[2]).read_bytes() == ' + repr(pbp) + '\n'
                + 'pathlib.Path("fixture.bin").write_bytes(' + repr(bytes(disc)) + ')\n'
                + 'print("Disc successfully converted using prebaked CUE file!")\n')
            wine.chmod(0o755)
            with patch.dict(os.environ, {'PSPDB_POPS': str(helper), 'PSPDB_PSXTRACT2': str(helper), 'PSPDB_WINE': str(wine)}):
                run = self.run_ingest(inputs, '--catalog', catalog, '--store', store)
                self.assertEqual(run.returncode, 0, run.stderr)
                digest = hashlib.sha256(pbp).hexdigest()
                tree = json.loads(tree_path(catalog, digest).read_text())
                entries = {e['path']: e for e in tree['entries']}
                child = entries['DATA.PSP']['extraction']
                self.assertEqual(child['sha256'], hashlib.sha256(executable).hexdigest())
                self.assertEqual(child['entries'][0]['sha256'], hashlib.sha256(compressed).hexdigest())
                disc_tree = entries['DATA.BIN']['extraction']
                self.assertEqual(disc_tree['sha256'], hashlib.sha256(sections[-1]).hexdigest())
                self.assertEqual(disc_tree['extractor']['name'], 'PSXtract-2')
                self.assertEqual(disc_tree['name_rule'], 'identity')
                self.assertEqual(disc_tree['entries'][0]['path'], 'disc.bin')
                self.assertEqual(disc_tree['entries'][0]['sha256'], hashlib.sha256(disc).hexdigest())
                self.assertFalse((catalog/'prx').exists())
                # Recreate only the root, forcing reuseTask through inline children.
                for path in (catalog/'pkg').rglob('*.json'): path.unlink()
                run = self.run_ingest(inputs, '--catalog', catalog, '--store', store, '--skip-existing')
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertNotIn('pops '+digest+':', run.stderr)
                self.assertEqual(tree, json.loads(tree_path(catalog, digest).read_text()))
                wine.write_text(wine.read_text() + 'sys.exit(1)\n')
                failed = base/'failed'
                run = self.run_ingest(inputs, '--catalog', failed, '--store', store)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(list((failed/'pkg').rglob('*-ingest.json')))

    def test_invalid_packages_do_not_publish_roots(self):
        for mode in ('truncated', 'unsupported', 'traversal', 'duplicate', 'missing_parent', 'nested_failure', 'offset'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp); inputs=base/'inputs'; inputs.mkdir(); catalog=base/'catalog'
                extra = {'traversal':[('../escape', b'x', True)], 'duplicate':[('empty', b'x', True)], 'missing_parent':[('missing/child', b'x', True)]}.get(mode, [])
                data, _ = pkg_bytes(0x15 if mode == 'unsupported' else 7, extra, mode == 'nested_failure')
                if mode == 'truncated': data=data[:-1]
                if mode == 'offset':
                    data=bytearray(data); struct.pack_into('>Q',data,32,2**64-1); data=bytes(data)
                (inputs/'bad.pkg').write_bytes(data)
                run=self.run_ingest(inputs,'--catalog',catalog,'--store',base/'store')
                self.assertNotEqual(run.returncode,0,run.stderr)
                self.assertFalse(list((catalog/'pkg').rglob('*-ingest.json')))

    def test_npumdimg_to_iso_traversal_and_failure_blocks_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); inputs = base/'inputs'; inputs.mkdir()
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            payload = b'fixture ISO file'
            iso.add_fp(io.BytesIO(payload), len(payload), iso_path='/HELLO.TXT;1')
            image = io.BytesIO(); iso.write_fp(image); iso.close()
            (base/'fixture.iso').write_bytes(image.getvalue())
            source, _ = pkg_bytes(extra=[('DATA.PSAR', b'NPUMDIMG'+bytes(248), True)])
            (inputs/'test.pkg').write_bytes(source)
            tool = base/'decoder'
            tool.write_text('#!' + sys.executable + '\nimport shutil, sys\nshutil.copyfile(' + repr(str(base/'fixture.iso')) + ',sys.argv[2])\n')
            tool.chmod(0o755)
            env = dict(os.environ, PKG2ZIP_NPUMDIMG=str(tool))
            args = [str(BINARY),str(inputs),'--no-progress','--threads','2','--store',str(base/'store'),'--catalog',str(base/'catalog')]
            run = subprocess.run(args,env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            digest = hashlib.sha256(image.getvalue()).hexdigest()
            self.assertTrue(result_path(base/'catalog','iso9660',digest).exists())
            tree = json.loads(tree_path(base/'catalog',digest).read_text())
            self.assertEqual(tree['entries'],[dict(path='HELLO.TXT',type='file',size_bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest())])
            self.assertFalse((base/'catalog'/'iso').exists())
            # A failing decoder cannot publish a fresh package root, even if it wrote output.
            tool.write_text(tool.read_text()+'sys.exit(1)\n')
            args[-1] = str(base/'failed-catalog')
            run = subprocess.run(args,env=env,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(run.returncode,0)
            self.assertFalse(list((base/'failed-catalog'/'pkg').rglob('*-ingest.json')))
