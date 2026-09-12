"""Build the current ingester and test it against generated ISO/ZIP fixtures."""

from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


import pycdlib


GAME_UMD = b"UMDT-99872|8D53CBDF6A4FC495|0001|G" + b"\0" * 13 + b"|"


def iso_bytes(umd=GAME_UMD, nested=False):
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    if nested:
        iso.add_directory("/PSP_GAME")
    if umd is not None:
        location = "/PSP_GAME/UMD_DATA.BIN;1" if nested else "/UMD_DATA.BIN;1"
        iso.add_fp(BytesIO(umd), len(umd), iso_path=location)
    output = BytesIO()
    iso.write_fp(output)
    iso.close()
    return output.getvalue()


REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "ingest/zig-out/bin/pspdb-ingest"
SUMMARY = re.compile(
    r"Summary: (\d+) directories scanned, (\d+) files ignored, "
    r"(\d+) symlinks skipped, (\d+) input candidates, (\d+) accepted, "
    r"(\d+) errors, (\d+) ISO input bytes\."
)


def setUpModule():
    subprocess.run(
        ['zig', 'build', '-Doptimize=ReleaseSafe'],
        cwd=REPO / 'ingest',
        check=True,
    )


def snapshot(root):
    """Include content and modification metadata, but not read access times."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            content = (
                os.readlink(path) if path.is_symlink()
                else path.read_bytes() if path.is_file()
                else None
            )
            result[str(path.relative_to(root))] = (
                info.st_mode, info.st_size, info.st_mtime_ns, content
            )
    return result


class IngestCliTests(unittest.TestCase):
    def run_cli(self, root, *args):
        completed = subprocess.run(
            [str(BINARY), str(root), *args],
            cwd=root.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return completed.returncode, completed.stdout + completed.stderr

    def assert_summary(self, output, expected):
        matches = SUMMARY.findall(output)
        self.assertEqual(len(matches), 1, output)
        self.assertEqual(tuple(map(int, matches[0])), expected, output)
        self.assertNotIn("\x1b[", output)

    def records(self, output):
        return [json.loads(line) for line in output.splitlines() if line.startswith("{")]

    def assert_processed_once(self, output, files):
        actual = [(row["source"], row["iso_bytes"]) for row in self.records(output)
                  if "!" not in row["source"]]
        self.assertCountEqual(actual, [(str(p), p.stat().st_size) for p in files])

    def assert_zip_results(self, output, expected_members, counts):
        actual = [(row["source"], row["iso_bytes"]) for row in self.records(output)
                  if "!" in row["source"]]
        self.assertCountEqual(actual, expected_members)
        self.assertIn(
            f"ZIPs: {counts[0]} scanned, {counts[1]} ISO members, "
            f"{counts[2]} other members ignored.", output
        )

    def test_psp_descriptor_compatibility_in_iso_and_zip(self):
        data = bytearray(iso_bytes())
        data[16 * 2048 + 881] = 2
        # PSP identifiers omit the ISO file-version suffix.
        name = data.index(b"UMD_DATA.BIN;1")
        data[name - 1] -= 2
        data[name + 12:name + 14] = b"\0\0"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "psp.iso").write_bytes(data)
            with zipfile.ZipFile(root / "psp.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("psp.iso", data)
            before = snapshot(root)
            code, output = self.run_cli(root, "--threads", "4", "--no-progress")
            self.assertEqual(code, 0, output)
            self.assertEqual(len(self.records(output)), 2, output)
            for record in self.records(output):
                self.assertEqual(record["identifier"], "UMDT-99872")
                self.assertEqual(record["umd_data_bytes"], len(GAME_UMD))
                self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(record["sha1"], hashlib.sha1(data).hexdigest())
            self.assertEqual(snapshot(root), before)

    def test_zip_stored_deflate_and_zip64_members_without_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            expected = []
            archive_path = root / "mixed.ZIP"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, data, compression in (
                    ("wrapper/disc.iso", iso_bytes(), zipfile.ZIP_STORED),
                    ("other/deep/second.ISO", iso_bytes(), zipfile.ZIP_DEFLATED),
                ):
                    archive.writestr(name, data, compress_type=compression)
                    expected.append((f"{archive_path}!{name}", len(data)))
                archive.writestr("notes.txt", "ignored")
                archive.writestr("nested.zip", b"not recursively inspected")
                archive.writestr("folder/", b"")
            zip64_path = root / "large-format.zip"
            # Force ZIP64 central-directory records as well as a local header.
            with patch.object(zipfile, "ZIP64_LIMIT", 0):
                with zipfile.ZipFile(zip64_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    with archive.open("zip64.iso", "w", force_zip64=True) as member:
                        member.write(iso_bytes())
            expected.append((f"{zip64_path}!zip64.iso", len(iso_bytes())))
            self.assertIn(b"PK\x06\x06", zip64_path.read_bytes())
            before = snapshot(Path(tmp))
            code, output = self.run_cli(root, "--threads", "4", "--no-progress")
            self.assertEqual(code, 0, output)
            self.assert_zip_results(output, expected, (2, 3, 3))
            self.assert_summary(output, (1, 0, 0, 2, 3, 0, sum(size for _, size in expected)))
            self.assertEqual(snapshot(Path(tmp)), before)

    def test_zip_crc_failure_continues_with_next_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            archive_path = root / "corrupt.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("bad.iso", iso_bytes())
                archive.writestr("good.iso", iso_bytes())
            data = bytearray(archive_path.read_bytes())
            name_len, extra_len = struct.unpack_from("<HH", data, 26)
            data[30 + name_len + extra_len] ^= 1
            archive_path.write_bytes(data)
            before = snapshot(Path(tmp))
            code, output = self.run_cli(root, "--threads", "1", "--no-progress")
            self.assertEqual(code, 1, output)
            self.assertIn(f"Rejected {archive_path}!bad.iso: ZipCrcMismatch", output)
            self.assert_zip_results(output, [(f"{archive_path}!good.iso", len(iso_bytes()))], (1, 2, 0))
            self.assert_summary(output, (1, 0, 0, 1, 1, 1, len(iso_bytes())))
            self.assertEqual(snapshot(Path(tmp)), before)

    def test_zip_malformed_unsupported_and_empty_inputs_continue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            bad = root / "malformed.zip"
            bad.write_bytes(b"not a ZIP archive")
            archive_path = root / "members.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("unsupported.iso", iso_bytes(), compress_type=zipfile.ZIP_BZIP2)
                archive.writestr("empty.iso", b"")
                archive.writestr("good.iso", iso_bytes(), compress_type=zipfile.ZIP_DEFLATED)
            raw = root / "raw.iso"
            raw.write_bytes(iso_bytes())
            before = snapshot(Path(tmp))
            code, output = self.run_cli(root, "--threads", "4", "--no-progress")
            self.assertEqual(code, 1, output)
            self.assertIn(f"Rejected {bad}:", output)
            self.assertIn(f"Rejected {archive_path}!unsupported.iso: UnsupportedCompressionMethod", output)
            self.assertIn(f"Rejected {archive_path}!empty.iso: EmptyFile", output)
            self.assert_zip_results(output, [(f"{archive_path}!good.iso", len(iso_bytes()))], (1, 3, 0))
            self.assert_processed_once(output, [raw])
            self.assert_summary(output, (1, 0, 0, 3, 2, 3, 2 * len(iso_bytes())))
            self.assertEqual(snapshot(Path(tmp)), before)

    def test_discovery_mapping_and_rejection_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            nested = root / "nested folder" / "deeper"
            nested.mkdir(parents=True)
            files = [root / "first.iso", nested / "second.ISO", nested / "third.iSo"]
            for path in files:
                path.write_bytes(iso_bytes())
            (root / "empty.iso").touch()
            with zipfile.ZipFile(root / "archive.zip", "w") as archive:
                archive.writestr("notes.txt", "not an ISO")
            (root / "incomplete.iso.part").write_bytes(b"partial")
            (nested / "notes.txt").write_text("ignored")
            (root / "alias.iso").symlink_to(files[0])
            (root / "loop").symlink_to(root, target_is_directory=True)
            before = snapshot(Path(tmp))
            for threads in (1, 4):
                with self.subTest(threads=threads):
                    code, output = self.run_cli(
                        root, "--threads", str(threads), "--no-progress"
                    )
                    self.assertEqual(code, 1, output)
                    self.assert_processed_once(output, files)
                    self.assert_summary(output, (3, 2, 2, 5, 3, 1, sum(p.stat().st_size for p in files)))
                    self.assertIn(f"Rejected {root / 'empty.iso'}: EmptyFile", output)
                    self.assertEqual(snapshot(Path(tmp)), before)

    def test_many_sibling_directories_finish_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            files = []
            for index in range(16):
                directory = root / f"directory-{index}"
                directory.mkdir()
                for suffix in ("iso", "ISO"):
                    path = directory / f"image.{suffix}"
                    path.write_bytes(iso_bytes())
                    files.append(path)
            before = snapshot(Path(tmp))
            for attempt in range(3):
                with self.subTest(attempt=attempt):
                    code, output = self.run_cli(root, "--threads", "4", "--no-progress")
                    self.assertEqual(code, 0, output)
                    self.assert_processed_once(output, files)
                    self.assert_summary(output, (17, 0, 0, 32, 32, 0, sum(p.stat().st_size for p in files)))
                    self.assertEqual(snapshot(Path(tmp)), before)

    def test_hashing_storage_reuse_and_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            store = Path(tmp) / "store"
            catalog = Path(tmp) / "catalog"
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            iso.add_directory('/PSP_GAME')
            iso.add_directory('/EMPTY')
            contents = {"UMD_DATA.BIN": GAME_UMD, "PSP_GAME/DATA.BIN": b'abc' * 700000,
                        "PSP_GAME/ZERO.BIN": b'', "PSP_GAME/COPY.BIN": b'abc' * 700000}
            for name, data in contents.items():
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            iso.add_hard_link(iso_old_path='/PSP_GAME/DATA.BIN;1', iso_new_path='/PSP_GAME/ALIAS.BIN;1')
            contents['PSP_GAME/ALIAS.BIN'] = contents['PSP_GAME/DATA.BIN']
            output = BytesIO(); iso.write_fp(output); iso.close()
            image = output.getvalue()
            (root / 'raw.iso').write_bytes(image)
            with zipfile.ZipFile(root / 'copy.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('game.iso', image)
            before = snapshot(root)
            objects = {hashlib.sha256(data).hexdigest(): data for data in contents.values()}
            for attempt in range(2):
                if attempt:
                    # Reuse must succeed even when temporary writes are impossible.
                    (store / '.incoming').rmdir()
                    (store / '.incoming').write_text('no temporary files allowed')
                code, output = self.run_cli(root, '--catalog', str(catalog), '--store', str(store), '--threads', '4', '--no-progress')
                self.assertEqual(code, 0, output)
                records = self.records(output)
                self.assertEqual(len(records), 2)
                self.assertEqual(sum(r['stored_objects'] for r in records), len(objects) if attempt == 0 else 0)
                for record in records:
                    self.assertEqual(record['sha256'], hashlib.sha256(image).hexdigest())
                    self.assertNotIn('entries', record)
                    saved = json.loads((catalog / 'trees' / (record['sha256'] + '.json')).read_text())
                    self.assertEqual(record['entry_count'], len(saved['entries']))
                    entries = {entry['path']: entry for entry in saved['entries']}
                    self.assertEqual(entries['EMPTY'], {'path': 'EMPTY', 'type': 'directory'})
                    for name, data in contents.items():
                        self.assertEqual(entries[name], dict(path=name, type='file', size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
                for digest, data in objects.items():
                    self.assertEqual((store / 'sha256' / digest[:2] / digest[2:4] / digest).read_bytes(), data)
                if attempt:
                    self.assertEqual((store / '.incoming').read_text(), 'no temporary files allowed')
                    (store / '.incoming').unlink()
                    (store / '.incoming').mkdir()
                self.assertEqual(list((store / '.incoming').iterdir()), [])
                self.assertEqual(snapshot(root), before)
            # The synchronous payload callback must produce the same inventory
            # without a store, including empty files and shared ISO extents.
            no_store_catalog = Path(tmp) / 'without-store'
            code, output = self.run_cli(root, '--catalog', str(no_store_catalog), '--no-progress')
            self.assertEqual(code, 0, output)
            self.assertEqual(
                {p.relative_to(catalog): json.loads(p.read_text()) for p in catalog.rglob('*.json')},
                {p.relative_to(no_store_catalog): json.loads(p.read_text()) for p in no_store_catalog.rglob('*.json')})
            digest = hashlib.sha256(GAME_UMD).hexdigest()
            path = store / 'sha256' / digest[:2] / digest[2:4] / digest
            path.write_bytes(b'x' * len(GAME_UMD))
            code, output = self.run_cli(root, '--store', str(store), '--threads', '4', '--no-progress')
            self.assertEqual(code, 1, output)
            self.assertIn('CorruptObject', output)
            self.assertEqual(path.read_bytes(), b'x' * len(GAME_UMD))
            self.assertEqual(list((store / '.incoming').iterdir()), [])

    def test_metadata_is_read_before_inventory_and_resolves_shared_extents(self):
        def sfo(title):
            key = b'TITLE\0'
            value = title.encode() + b'\0'
            return (struct.pack('<4sIIII', b'\0PSF', 0x101, 36, 36 + len(key), 1)
                    + struct.pack('<HHIII', 0, 0x204, len(value), len(value), 0) + key + value)

        cases = [
            ('shared-game', sfo('Shared game'), None, True, 'Shared game'),
            ('shared-umd', sfo('Game title'), None, False, 'Game title'),
            ('video-with-game-media-code', None, sfo('Video title'), False, 'Video title'),
            ('mixed', sfo('Game title'), sfo('Video title'), False, 'Game title'),
            ('game-with-updater', sfo('Game title'), None, False, 'Game title'),
            ('invalid-video', sfo('Game title'), b'not an SFO', False, None),
            ('updater-only', None, None, False, 'Bundled updater'),
        ]
        for name, game, video, shared, title in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'inputs'; root.mkdir()
                catalog = Path(tmp) / 'catalog'; store = Path(tmp) / 'store'
                iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
                if name == 'shared-umd':
                    iso.add_fp(BytesIO(GAME_UMD), len(GAME_UMD), iso_path='/AAA_UMD.BIN;1')
                    iso.add_hard_link(iso_old_path='/AAA_UMD.BIN;1', iso_new_path='/UMD_DATA.BIN;1')
                else:
                    iso.add_fp(BytesIO(GAME_UMD), len(GAME_UMD), iso_path='/UMD_DATA.BIN;1')
                for folder, data in [('PSP_GAME', game), ('UMD_VIDEO', video)]:
                    if data is None: continue
                    iso.add_directory('/' + folder)
                    path = '/' + folder + '/PARAM.SFO;1'
                    if shared:
                        iso.add_fp(BytesIO(data), len(data), iso_path='/AAA_SFO.BIN;1')
                        iso.add_hard_link(iso_old_path='/AAA_SFO.BIN;1', iso_new_path=path)
                    else:
                        iso.add_fp(BytesIO(data), len(data), iso_path=path)
                if name in ('updater-only', 'game-with-updater'):
                    folders = ['/PSP_GAME/SYSDIR', '/PSP_GAME/SYSDIR/UPDATE']
                    if game is None: folders.insert(0, '/PSP_GAME')
                    for folder in folders:
                        iso.add_directory(folder)
                    updater = sfo('Bundled updater')
                    iso.add_fp(BytesIO(updater), len(updater), iso_path='/PSP_GAME/SYSDIR/UPDATE/PARAM.SFO;1')
                output = BytesIO(); iso.write_fp(output); iso.close()
                image = output.getvalue()
                # Exercise both raw ISO and ZIP callers, including no catalog output.
                for zipped in (False, True):
                    for old in root.iterdir(): old.unlink()
                    if zipped:
                        with zipfile.ZipFile(root / 'sample.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
                            archive.writestr('sample.iso', image)
                    else:
                        (root / 'sample.iso').write_bytes(image)
                    args = ('--store', str(store), '--threads', '1', '--no-progress')
                    code, output = self.run_cli(root, *args, '--catalog', str(catalog))
                    if name == 'invalid-video':
                        self.assertEqual(code, 1, output)
                        self.assertIn('InvalidSfo', output)
                        self.assertFalse(list(catalog.rglob('*.json')))
                        self.assertFalse(list(store.rglob('*')))
                        code, output = self.run_cli(root, *args)
                        self.assertEqual(code, 1, output)
                        self.assertIn('InvalidSfo', output)
                        continue
                    self.assertEqual(code, 0, output)
                    record = json.loads(next((catalog / 'iso').glob('*.json')).read_text())
                    self.assertEqual(record['metadata'].get('title'), title)
                    self.assertEqual(record['metadata']['umd_uid'], '8D53CBDF6A4FC495')
                    self.assertEqual(record['sha256'], hashlib.sha256(image).hexdigest())
                    self.assertEqual(record['sha1'], hashlib.sha1(image).hexdigest())
                    for folder, data in [('PSP_GAME', game), ('UMD_VIDEO', video)]:
                        if data is None: continue
                        tree = json.loads((catalog / 'trees' / (record['sha256'] + '.json')).read_text())
                        entry = next(e for e in tree['entries'] if e['path'] == folder + '/PARAM.SFO')
                        digest = hashlib.sha256(data).hexdigest()
                        self.assertEqual(entry['sha256'], digest)
                        self.assertEqual((store / 'sha256' / digest[:2] / digest[2:4] / digest).read_bytes(), data)

    def test_catalog_uses_iso_identity_and_keeps_identical_inventories(self):
        from jsonschema import Draft202012Validator
        from pspdb.server import catalog_data, download_index
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'inputs'; root.mkdir()
            catalog = Path(tmp) / 'catalog'
            store = Path(tmp) / 'store'
            fields = {'DISC_ID': 'UMDT99872', 'DISC_VERSION': '1.00', 'TITLE': 'Sample game'}
            keys = bytearray(); values = bytearray(); table = bytearray()
            for key, value in fields.items():
                data = value.encode() + b'\0'
                table.extend(struct.pack('<HHIII', len(keys), 0x204, len(data), len(data), len(values)))
                keys.extend(key.encode() + b'\0'); values.extend(data)
            key_offset = 20 + len(table)
            sfo = struct.pack('<4sIIII', b'\0PSF', 0x101, key_offset, key_offset + len(keys), len(fields)) + table + keys + values
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            iso.add_directory('/PSP_GAME')
            iso.add_fp(BytesIO(sfo), len(sfo), iso_path='/PSP_GAME/PARAM.SFO;1')
            iso.add_fp(BytesIO(GAME_UMD), len(GAME_UMD), iso_path='/UMD_DATA.BIN;1')
            output = BytesIO(); iso.write_fp(output); iso.close()
            image = output.getvalue()
            padded = image + b'\0' * 2048
            (root / 'one.iso').write_bytes(image)
            (root / 'two.iso').write_bytes(padded)
            with zipfile.ZipFile(root / 'same.zip', 'w') as archive:
                archive.writestr('copy.iso', image)
            args = ('--catalog', str(catalog), '--store', str(store), '--threads', '4', '--no-progress')
            code, output = self.run_cli(root, *args)
            self.assertEqual(code, 0, output)
            files = sorted((catalog / 'iso').glob('*.json'))
            self.assertEqual({p.stem for p in files}, {hashlib.sha256(image).hexdigest(), hashlib.sha256(padded).hexdigest()})
            records = [json.loads(p.read_text()) for p in files]
            trees = [json.loads((catalog / 'trees' / p.name).read_text()) for p in files]
            self.assertEqual(trees[0]['entries'], trees[1]['entries'])
            self.assertNotEqual(trees[0]['sha256'], trees[1]['sha256'])
            tree_validator = Draft202012Validator(json.loads((REPO / 'schemas/tree.schema.json').read_text()))
            for tree in trees: tree_validator.validate(tree)
            validator = Draft202012Validator(json.loads((REPO / 'schemas/record.schema.json').read_text()))
            for record in records:
                validator.validate(record)
                self.assertNotIn('snapshot_sha256', record)
                self.assertEqual(record['metadata']['disc_version'], '1.00')
                self.assertEqual(record['metadata']['title'], 'Sample game')
                self.assertEqual(record['metadata']['umd_uid'], '8D53CBDF6A4FC495')
            served = catalog_data(catalog)
            self.assertEqual(len(served['records']['iso']), 2)
            self.assertNotIn('snapshots', served)
            self.assertIn(hashlib.sha256(GAME_UMD).hexdigest(), download_index(served))
            for record in records:
                original = image if record['sha256'] == hashlib.sha256(image).hexdigest() else padded
                self.assertEqual(record['sha1'], hashlib.sha1(original).hexdigest())
            # An incorrect existing SHA-1 must not be overwritten.
            damaged = dict(records[0], sha1='0' * 40)
            files[0].write_text(json.dumps(damaged))
            before = snapshot(catalog)
            code, output = self.run_cli(root, *args)
            self.assertEqual(code, 1, output)
            self.assertIn('CatalogConflict', output)
            self.assertEqual(snapshot(catalog), before)
            # Formatting and key order do not affect repeat-import identity.
            files[0].write_text(json.dumps(records[0], sort_keys=True))
            before = snapshot(catalog)
            code, output = self.run_cli(root, *args)
            self.assertEqual(code, 0, output)
            self.assertEqual(snapshot(catalog), before)
            # Opt-in skip avoids all store access after the ISO hash lookup.
            import shutil
            shutil.rmtree(store / 'sha256')
            before = snapshot(catalog)
            code, output = self.run_cli(root, *args, '--skip-existing')
            self.assertEqual(code, 0, output)
            self.assertIn('Already cataloged: 3 ISO images skipped.', output)
            self.assertEqual(self.records(output), [])
            self.assertFalse((store / 'sha256').exists())
            self.assertEqual(snapshot(catalog), before)
            # Missing inventories are rebuilt even with --skip-existing enabled.
            missing_tree = catalog / 'trees' / files[0].name
            expected_tree = json.loads(missing_tree.read_text())
            missing_tree.unlink()
            code, output = self.run_cli(root, *args, '--skip-existing')
            self.assertEqual(code, 0, output)
            self.assertEqual(json.loads(missing_tree.read_text()), expected_tree)
            # Default still processes known images and restores missing objects.
            code, output = self.run_cli(root, *args)
            self.assertEqual(code, 0, output)
            self.assertEqual(len(self.records(output)), 3)
            self.assertTrue((store / 'sha256').is_dir())
            record = records[0]; record['size_bytes'] += 1
            files[0].write_text(json.dumps(record))
            before = snapshot(catalog)
            code, output = self.run_cli(root, *args)
            self.assertEqual(code, 1, output)
            self.assertIn('CatalogConflict', output)
            self.assertEqual(snapshot(catalog), before)

    def test_psar_header_dispatches_python_adapter_for_iso_and_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'inputs'; root.mkdir()
            store = Path(tmp) / 'store'; catalog = Path(tmp) / 'catalog'
            payload = b'PSAR' + bytes(64)
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('UNUSUAL.DAT', payload),
                               ('FAKE.PSAR', b'not an archive')]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            output = BytesIO(); iso.write_fp(output); iso.close()
            image = output.getvalue()
            (root / 'sample.iso').write_bytes(image)
            with zipfile.ZipFile(root / 'sample.zip', 'w') as archive:
                archive.writestr('sample.iso', image)
            tool = Path(tmp) / 'pspdecrypt'
            tool.write_text('#!/bin/sh\necho "$2" >> "$PSPDB_TEST_OUTPUTS"\nmkdir -p "$2/F0"\nprintf decoded > "$2/F0/module.prx"\necho Done!\n')
            tool.chmod(0o755)
            args = ('--catalog', str(catalog), '--store', str(store), '--threads', '2', '--no-progress')
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_TEST_OUTPUTS': str(Path(tmp) / 'outputs')}):
                code, output = self.run_cli(root, *args)
            self.assertEqual(code, 0, output)
            h = hashlib.sha256(payload).hexdigest()
            self.assertEqual([p.stem for p in (catalog / 'psar').glob('*.json')], [h])
            tree = json.loads((catalog / 'trees' / (h + '.json')).read_text())
            entry = next(e for e in tree['entries'] if e['type'] == 'file')
            self.assertEqual(entry['path'], 'F0/module.prx')
            self.assertEqual(entry['sha256'], hashlib.sha256(b'decoded').hexdigest())
            blob = store / 'sha256' / entry['sha256'][:2] / entry['sha256'][2:4] / entry['sha256']
            self.assertEqual(blob.read_bytes(), b'decoded')
            self.assertEqual(output.count('psar '), 2)
            self.assertTrue(all(not Path(p).exists() for p in (Path(tmp) / 'outputs').read_text().splitlines()))
            # A child failure must be visible, even if pspdecrypt exits zero.
            tool.write_text('#!/bin/sh\necho "$2" >> "$PSPDB_TEST_OUTPUTS"\necho "error decoding"\necho Done!\n')
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_TEST_OUTPUTS': str(Path(tmp) / 'outputs')}):
                code, output = self.run_cli(root, *args)
            self.assertEqual(code, 1, output)
            self.assertIn('ExtractionFailed', output)
            self.assertIn('error decoding', output)
            self.assertTrue(all(not Path(p).exists() for p in (Path(tmp) / 'outputs').read_text().splitlines()))
            self.assertEqual(json.loads((catalog / 'trees' / (h + '.json')).read_text()), tree)

    def test_nested_psar_trees_are_walked_and_cycles_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'inputs'; root.mkdir()
            store = Path(tmp) / 'store'; catalog = Path(tmp) / 'catalog'
            parent = b'PSARparent'; child = b'PSARchild'
            parent_hash = hashlib.sha256(parent).hexdigest()
            child_hash = hashlib.sha256(child).hexdigest()
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('UPDATE.DAT', parent)]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            output = BytesIO(); iso.write_fp(output); iso.close()
            (root / 'sample.iso').write_bytes(output.getvalue())
            # With one worker, the parent temporary directory must already be gone
            # before the child runs; the child owns its in-memory input.
            # Both extractions emit the same nested PSAR: its own output therefore
            # contains a cycle. Zig must extract it once and still visit the PRX.
            tool = Path(tmp) / 'pspdecrypt'
            tool.write_text('#!/bin/sh\nif [ -f "$PSPDB_TEST_OUTPUTS" ]; then while IFS= read -r parent; do [ ! -d "$parent" ] || exit 1; done < "$PSPDB_TEST_OUTPUTS"; fi\necho "$2" >> "$PSPDB_TEST_OUTPUTS"\nmkdir -p "$2/F0"\nprintf PSARchild > "$2/F0/child.dat"\nprintf decoded > "$2/F0/module.prx"\necho Done!\n')
            tool.chmod(0o755)
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_TEST_OUTPUTS': str(Path(tmp) / 'outputs')}):
                code, output = self.run_cli(root, '--catalog', str(catalog), '--store', str(store),
                    '--threads', '1', '--no-progress')
            self.assertEqual(code, 0, output)
            self.assertEqual(output.count('psar '), 2)
            self.assertTrue(all(not Path(p).exists() for p in (Path(tmp) / 'outputs').read_text().splitlines()))
            self.assertEqual({p.stem for p in (catalog / 'psar').glob('*.json')}, {parent_hash, child_hash})
            for h in (parent_hash, child_hash):
                tree = json.loads((catalog / 'trees' / (h + '.json')).read_text())
                self.assertEqual(next(e['sha256'] for e in tree['entries'] if e['path'] == 'F0/child.dat'), child_hash)
            iso_record = json.loads(next((catalog / 'iso').glob('*.json')).read_text())
            iso_tree = json.loads((catalog / 'trees' / (iso_record['sha256'] + '.json')).read_text())
            self.assertEqual({e['path'] for e in iso_tree['entries']}, {'UMD_DATA.BIN', 'UPDATE.DAT'})
            # A failure while Zig walks a child must also clean both temp trees.
            (Path(tmp) / 'outputs').unlink()
            tool.write_text(tool.read_text().replace('echo Done!', 'if [ "$(wc -l < "$PSPDB_TEST_OUTPUTS")" -eq 2 ]; then ln -s module.prx "$2/F0/link"; fi\necho Done!'))
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_TEST_OUTPUTS': str(Path(tmp) / 'outputs')}):
                code, output = self.run_cli(root, '--catalog', str(catalog / 'failed'), '--store', str(store),
                    '--threads', '1', '--no-progress')
            self.assertEqual(code, 1, output)
            self.assertIn('UnsupportedExtractedEntry', output)
            self.assertFalse((catalog / 'failed' / 'iso').exists())
            self.assertEqual(self.records(output), [])
            self.assertTrue(all(not Path(p).exists() for p in (Path(tmp) / 'outputs').read_text().splitlines()))


    def test_nested_jobs_overlap_within_and_across_isos_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root / 'inputs'; inputs.mkdir()
            catalog = root / 'catalog'; markers = root / 'started'; markers.mkdir()
            hashes = set()
            for index in range(2):
                iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
                files = [('UMD_DATA.BIN', GAME_UMD)]
                for child in range(2):
                    payload = f'PSAR{index}/{child}'.encode()
                    hashes.add(hashlib.sha256(payload).hexdigest())
                    files.append((f'CHILD{child}.BIN', payload))
                for name, payload in files:
                    iso.add_fp(BytesIO(payload), len(payload), iso_path='/' + name + ';1')
                image = BytesIO(); iso.write_fp(image); iso.close()
                if index == 0:
                    (inputs / 'one.iso').write_bytes(image.getvalue())
                else:
                    with zipfile.ZipFile(inputs / 'two.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                        archive.writestr('two.iso', image.getvalue())
            # Four extractors rendezvous. Serial recursive processing deadlocks
            # here; premature ISO publication is rejected before joining.
            tool = root / 'pspdecrypt'
            tool.write_text('''#!/bin/sh
set -eu
[ ! -d "$PSPDB_TEST_CATALOG/iso" ] || exit 1
touch "$PSPDB_TEST_STARTED/$(basename "$3")"
n=0
while [ "$(ls "$PSPDB_TEST_STARTED" | wc -l)" -lt 4 ]; do
    n=$((n + 1)); [ "$n" -lt 500 ] || exit 1
    sleep 0.01
done
echo "$2" >> "$PSPDB_TEST_OUTPUTS"
printf decoded > "$2/module.prx"
echo Done!
''')
            tool.chmod(0o755)
            with patch.dict(os.environ, {
                'PSPDECRYPT': str(tool), 'PSPDB_TEST_STARTED': str(markers),
                'PSPDB_TEST_CATALOG': str(catalog), 'PSPDB_TEST_OUTPUTS': str(root / 'outputs'),
            }):
                code, output = self.run_cli(inputs, '--catalog', str(catalog),
                    '--store', str(root / 'store'), '--threads', '4', '--no-progress')
            self.assertEqual(code, 0, output)
            self.assertEqual({p.name for p in markers.iterdir()}, hashes)
            self.assertEqual(len(list((catalog / 'iso').glob('*.json'))), 2)
            self.assertEqual({p.stem for p in (catalog / 'psar').glob('*.json')}, hashes)
            self.assertEqual(len(self.records(output)), 2)
            self.assertTrue(all(not Path(p).exists() for p in (root / 'outputs').read_text().splitlines()))

    def test_rco_is_automatically_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root / 'inputs'; inputs.mkdir()
            payload = b'\0PRF' + bytes(160)
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('RESOURCE.BIN', payload)]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            iso.write(str(inputs / 'test.iso')); iso.close()
            tool = root / 'rcomage'
            tool.write_text('#!/bin/sh\nprintf \'<RcoFile/>\' > "$3"\nprintf image > resources/icon.gim\n')
            tool.chmod(0o755)
            config = root / 'config'; config.mkdir(); (config / 'test.ini').write_text('config')
            with patch.dict(os.environ, {'RCOMAGE': str(tool), 'RCOMAGE_DATA': str(config)}):
                code, output = self.run_cli(inputs, '--catalog', str(root / 'catalog'), '--store', str(root / 'store'), '--no-progress')
            self.assertEqual(code, 0, output)
            h = hashlib.sha256(payload).hexdigest()
            self.assertTrue((root / 'catalog/rco' / (h + '.json')).exists())
            tree = json.loads((root / 'catalog/trees' / (h + '.json')).read_text())
            self.assertEqual({e['path'] for e in tree['entries']}, {'resources', 'resources/icon.gim', 'structure.xml'})
            self.assertEqual(tree['extractor']['name'], 'rcomage')

    def test_pbp_sce_prx_and_gzip_recurse(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root / 'inputs'; inputs.mkdir()
            elf = b'\x7fELF' + bytes(12) + struct.pack('<H', 0xffa0) + b'decoded module'
            compressed = gzip.compress(elf, mtime=0)
            prx = bytearray(0x150); prx[:4] = b'~PSP'; struct.pack_into('<H', prx, 6, 1)
            struct.pack_into('<I', prx, 0xb0, len(compressed))
            sce = b'~SCE' + struct.pack('<I', 64) + bytes(56) + prx
            pbp = b'\0PBP' + struct.pack('<I', 0x10000) + struct.pack('<8I', *([40] * 7 + [40 + len(sce)])) + sce
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('SHARE.BIN', pbp)]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            iso.write(str(inputs / 'test.iso')); iso.close()
            decoded = root / 'decrypted'; decoded.write_bytes(compressed)
            tool = root / 'pspdecrypt'; tool.write_text('#!/bin/sh\ncp "$PSPDB_DECODED" "$2"\necho "Decryption successful"\n'); tool.chmod(0o755)
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_DECODED': str(decoded)}):
                code, output = self.run_cli(inputs, '--catalog', str(root / 'catalog'), '--store', str(root / 'store'), '--no-progress')
            self.assertEqual(code, 0, output)
            for kind, source, name, child in [('pbp', pbp, 'DATA.PSP', sce), ('sce', sce, 'payload.psp', prx), ('prx', prx, 'module.prx.gz', compressed), ('gzip', compressed, 'module.prx', elf)]:
                h = hashlib.sha256(source).hexdigest()
                self.assertTrue((root / 'catalog' / kind / (h + '.json')).exists())
                tree = json.loads((root / 'catalog/trees' / (h + '.json')).read_text())
                self.assertEqual(tree['entries'], [{'path': name, 'type': 'file', 'size_bytes': len(child), 'sha256': hashlib.sha256(child).hexdigest()}])
                self.assertEqual(tree.get('name_rule'), {'prx': 'source_stem', 'sce': 'source_stem', 'gzip': 'strip_suffix'}.get(kind))
            # Reject malformed section tables before invoking a child extractor.
            broken = bytearray(pbp); struct.pack_into('<I', broken, 12, 39)
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('SHARE.BIN', broken)]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            iso.write(str(inputs / 'test.iso')); iso.close()
            code, output = self.run_cli(inputs, '--catalog', str(root / 'catalog'), '--store', str(root / 'store'), '--no-progress')
            self.assertEqual(code, 1, output)
            self.assertIn('InvalidPbp', output)

    def test_elf_embedded_wrapper_recurses_to_kl3e(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = root / 'inputs'; inputs.mkdir()
            decoded = b'KL3E' + bytes(60)
            wrapper = bytearray(0x150 + len(decoded)); wrapper[:4] = b'~PSP'
            struct.pack_into('<I', wrapper, 0x2c, len(wrapper))
            struct.pack_into('<I', wrapper, 0xb0, len(decoded))
            elf = bytearray(128); elf[:6] = b'\x7fELF\x01\x01'
            struct.pack_into('<HH', elf, 16, 0xffa0, 8)
            elf += wrapper
            iso = pycdlib.PyCdlib(); iso.new(interchange_level=3)
            for name, data in [('UMD_DATA.BIN', GAME_UMD), ('MODULE.BIN', elf)]:
                iso.add_fp(BytesIO(data), len(data), iso_path='/' + name + ';1')
            iso.write(str(inputs / 'test.iso')); iso.close()
            payload = root / 'decrypted'; payload.write_bytes(decoded)
            kle = root / 'kle'; kle.write_text('#!/bin/sh\nprintf reboot > "$2"\necho "Decompression successful"\n'); kle.chmod(0o755)
            tool = root / 'pspdecrypt'
            tool.write_text('#!/bin/sh\ncp "$PSPDB_DECODED" "$2"\necho "Decryption successful"\n')
            tool.chmod(0o755)
            with patch.dict(os.environ, {'PSPDECRYPT': str(tool), 'PSPDB_DECODED': str(payload), 'PSPDECRYPT_KLE': str(kle)}):
                code, output = self.run_cli(inputs, '--catalog', str(root / 'catalog'), '--store', str(root / 'store'), '--no-progress')
            self.assertEqual(code, 0, output)
            for kind, source, name, child in [('elf', elf, 'embedded-80.psp', wrapper), ('prx', wrapper, 'module.bin.kl3e', decoded), ('kl3e', decoded, 'payload.bin', b'reboot')]:
                h = hashlib.sha256(source).hexdigest()
                self.assertTrue((root / 'catalog' / kind / (h + '.json')).exists())
                tree = json.loads((root / 'catalog/trees' / (h + '.json')).read_text())
                self.assertEqual(tree['entries'], [{'path': name, 'type': 'file', 'size_bytes': len(child), 'sha256': hashlib.sha256(child).hexdigest()}])
                child_hash = hashlib.sha256(child).hexdigest()
                self.assertEqual((root / 'store/sha256' / child_hash[:2] / child_hash[2:4] / child_hash).read_bytes(), child)

    def test_empty_folder_and_missing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            code, output = self.run_cli(root, "--threads", "1", "--no-progress")
            self.assertEqual(code, 0, output)
            self.assert_summary(output, (1, 0, 0, 0, 0, 0, 0))
            missing = Path(tmp) / "missing"
            code, output = self.run_cli(missing, "--threads", "4", "--no-progress")
            self.assertEqual(code, 1, output)
            self.assertIn(f"Rejected {missing}: FileNotFound", output)
            self.assert_summary(output, (0, 0, 0, 0, 0, 1, 0))
            self.assertFalse(missing.exists())

    def test_positive_thread_cap_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, output = self.run_cli(root, "--threads", "1", "--no-progress")
            self.assertEqual(code, 0, output)
            self.assert_summary(output, (1, 0, 0, 0, 0, 0, 0))
            for args, reason in (
                (("--threads", "0", "--no-progress"), "InvalidThreadCount"),
            ):
                with self.subTest(args=args):
                    code, output = self.run_cli(root, *args)
                    self.assertEqual(code, 2, output)
                    self.assertIn(reason, output)
                    self.assertNotIn("mock_processed:", output)
                    self.assertEqual(list(root.iterdir()), [])

    def test_umd_fields_preserve_variable_identifiers_and_unknown_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            examples = [
                ("game.iso", GAME_UMD, {
                    "identifier": "UMDT-99872", "uid": "8D53CBDF6A4FC495",
                    "type_code": "0001", "media_code": "G",
                    "media": "game/update", "extra": "",
                }),
                ("video.iso", b"UMD Authoring Demo  |AB9B89|0002|V\0\0|", {
                    "identifier": "UMD Authoring Demo  ", "uid": "AB9B89",
                    "type_code": "0002", "media_code": "V",
                    "media": "video", "extra": "",
                }),
                ("unknown.iso", b'label "quoted"|id|9999|X|extra|\0', {
                    "identifier": 'label "quoted"', "uid": "id",
                    "type_code": "9999", "media_code": "X",
                    "media": "unknown", "extra": "extra|\0",
                }),
            ]
            expected = []
            for name, umd, fields in examples:
                path = root / name
                data = iso_bytes(umd)
                path.write_bytes(data)
                expected.append(dict(fields, source=str(path), umd_data_bytes=len(umd), iso_bytes=len(data)))
            before = snapshot(Path(tmp))
            code, output = self.run_cli(root, "--threads", "4", "--no-progress")
            self.assertEqual(code, 0, output)
            self.assertCountEqual([{key: row[key] for key in expected[0]} for row in self.records(output)], expected)
            self.assert_summary(output, (1, 0, 0, 3, 3, 0, sum(row["iso_bytes"] for row in expected)))
            self.assertEqual(snapshot(Path(tmp)), before)

    def test_root_umd_is_required_and_malformed_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "inputs"
            root.mkdir()
            invalid = [
                ("missing.iso", iso_bytes(None), "MissingUmdData"),
                ("nested.iso", iso_bytes(nested=True), "MissingUmdData"),
                ("malformed.iso", iso_bytes(b"not a UMD record"), "MalformedUmdData"),
                ("blank-field.iso", iso_bytes(b"label|id|0001||"), "MalformedUmdData"),
                ("not-iso.iso", b"not an ISO", "InvalidIso"),
            ]
            for name, data, _ in invalid:
                (root / name).write_bytes(data)
            valid = root / "valid.iso"
            valid.write_bytes(iso_bytes())
            before = snapshot(Path(tmp))
            code, output = self.run_cli(root, "--threads", "4", "--no-progress")
            self.assertEqual(code, 1, output)
            self.assert_processed_once(output, [valid])
            for name, _, reason in invalid:
                self.assertIn(f"Rejected {root / name}: {reason}", output)
            self.assert_summary(output, (1, 0, 0, 6, 1, 5, valid.stat().st_size))
            self.assertEqual(snapshot(Path(tmp)), before)


if __name__ == "__main__":
    unittest.main()
