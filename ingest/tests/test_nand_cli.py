"""Exercise the installed ingester with synthetic raw NAND markers, never backups."""

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zipfile

from ingest.tests.test_ingest_cli import BINARY, SUMMARY, result_path


RAW_SIZE = 2048 * 32 * 528
FUSE_TEXT = b"0123456789abcdef"


def metadata_ecc(metadata):
    """Independent parity-group definition of PSP spare bytes 4..11 ECC."""
    code = 0
    for byte_index, byte in enumerate(metadata):
        for bit_index in range(8):
            if not byte & (1 << bit_index):
                continue
            position = 8 * byte_index + bit_index
            for parity_bit in range(6):
                code ^= 1 << (parity_bit + (6 if position & (1 << parity_bit) else 0))
    return code


def sparse_nand(path, *, marker=False):
    # The sole identifying marker is valid, but its zero IPL table cannot
    # reconstruct a payload. Recognition must not require reconstructability.
    with path.open("xb") as output:
        output.truncate(RAW_SIZE)
        if marker:
            spare = bytearray(b"\xff" * 16)
            struct.pack_into("<I", spare, 8, 0x6DC64A38)
            struct.pack_into("<H", spare, 12, 0xF000 | metadata_ecc(spare[4:12]))
            output.seek(4 * 32 * 528 + 512)
            output.write(spare)


def fingerprint(path):
    info = path.stat()
    with path.open("rb") as source:
        sha256 = hashlib.file_digest(source, "sha256").hexdigest()
    with path.open("rb") as source:
        sha1 = hashlib.file_digest(source, "sha1").hexdigest()
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns, sha256, sha1


class NandCliTests(unittest.TestCase):
    def run_ingest(self, inputs, catalog, keys, *args):
        completed = subprocess.run(
            [str(BINARY), str(inputs), "--catalog", str(catalog), "--no-progress", "--threads", "2", *map(str, args)],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PSPDB_NAND_FUSE_DIR": str(keys)},
        )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        return output

    def read_tree(self, catalog, digest):
        record_path = result_path(catalog, "nand", digest)
        return json.loads(record_path.with_name(digest + "-tree.json").read_text())

    def test_marker_probe_explicit_failure_and_ignored_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store, keys = (base / name for name in ("inputs", "catalog", "store", "keys"))
            inputs.mkdir()
            keys.mkdir(mode=0o700)
            recognized = inputs / "marker.BiN"
            markerless = inputs / "ordinary.bin"
            malformed = inputs / "damaged.NaNd"
            sparse_nand(recognized, marker=True)
            sparse_nand(markerless)
            malformed.write_bytes(b"not supported raw NAND geometry")
            (inputs / "short.bin").write_bytes(b"not a NAND")
            (inputs / "linked.bin").symlink_to(recognized.name)
            os.mkfifo(inputs / "pipe.bin")
            with zipfile.ZipFile(inputs / "excluded.zip", "w") as archive:
                archive.writestr("dump.nand", b"explicit NAND is not ZIP intake")
                archive.writestr("dump.bin", b"NAND probes are not ZIP intake")
            before = {path: fingerprint(path) for path in (recognized, markerless, malformed)}

            output = self.run_ingest(inputs, catalog, keys, "--store", store)
            matches = SUMMARY.findall(output)
            self.assertEqual(len(matches), 1, output)
            self.assertEqual(tuple(map(int, matches[0])), (1, 3, 1, 3, 2, 0, RAW_SIZE + malformed.stat().st_size), output)
            self.assertRegex(output, r"Already cataloged: 0 sources skipped\.")
            self.assertRegex(output, r"ZIPs: 1 scanned, 0 ISO/PKG members, 2 other members ignored\.")
            rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            self.assertEqual({row["source"] for row in rows}, {str(recognized), str(malformed)})
            self.assertTrue(all(row["kind"] == "nand" for row in rows))
            summary = next(row for row in rows if row["source"] == str(recognized))
            self.assertEqual(summary["nand_bytes"], RAW_SIZE)
            self.assertEqual(summary["blocks"], 2048)
            self.assertEqual(summary["sha256"], before[recognized][3])
            self.assertEqual(summary["sha1"], before[recognized][4])
            self.assertEqual((summary["stored_objects"], summary["reused_objects"]), (0, 0))

            for path in (recognized, malformed):
                digest = before[path][3]
                record = json.loads(result_path(catalog, "nand", digest).read_text())
                self.assertEqual(record["kind"], "nand")
                self.assertEqual(record["schema_version"], 1)
                self.assertEqual(record["sha256"], digest)
                self.assertEqual(record["sha1"], before[path][4])
                self.assertEqual(record["size_bytes"], before[path][0])
                tree = self.read_tree(catalog, digest)
                self.assertEqual(tree["extractor"], {"name": "pspdb-nand", "version": "1", "options": []})
                self.assertEqual(tree["sha256"], digest)
                self.assertEqual(tree["size_bytes"], before[path][0])
                self.assertEqual(tree["error"], "InvalidIpl" if path == recognized else "UnsupportedNandSize")
                if path == recognized:
                    self.assertEqual(record["metadata"], {"page_bytes": 512, "spare_bytes": 16, "pages_per_block": 32, "blocks": 2048})
                else:
                    self.assertNotIn("metadata", record)
                    self.assertEqual(tree["entries"], [])
                self.assertFalse((store / "sha256" / digest[:2] / digest[2:4] / digest).exists())
            self.assertEqual(len(list(catalog.rglob("*-ingest.json"))), 2)
            self.assertFalse((catalog / "iso").exists())
            self.assertFalse((catalog / "pkg").exists())
            self.assertEqual({path: fingerprint(path) for path in before}, before)

    def test_invalid_fuse_files_are_durable_private_errors_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, keys = base / "inputs", base / "private-key-directory"
            inputs.mkdir()
            keys.mkdir(mode=0o700)
            source = inputs / "fixture.nand"
            sparse_nand(source, marker=True)
            before = fingerprint(source)
            digest = before[3]
            key = keys / (digest + ".fuse")
            target = base / "synthetic-key-target"
            target.write_bytes(FUSE_TEXT)
            cases = {
                "malformed": lambda: key.write_bytes(FUSE_TEXT + b" "),
                "oversize": lambda: key.write_bytes(FUSE_TEXT + b"\r\nextra"),
                "symlink": lambda: key.symlink_to(target),
                "directory": lambda: key.mkdir(),
                "fifo": lambda: os.mkfifo(key),
            }
            for label, prepare in cases.items():
                with self.subTest(kind=label):
                    prepare()
                    try:
                        catalog = base / ("catalog-" + label)
                        output = self.run_ingest(inputs, catalog, keys)
                        tree = self.read_tree(catalog, digest)
                        self.assertEqual(tree["error"], "InvalidNandFuseId")
                        serialized = "\n".join(path.read_text() for path in catalog.rglob("*.json"))
                        for secret in (FUSE_TEXT.decode(), str(keys), str(target)):
                            self.assertNotIn(secret, output)
                            self.assertNotIn(secret, serialized)
                    finally:
                        if key.is_dir() and not key.is_symlink():
                            key.rmdir()
                        else:
                            key.unlink()
            self.assertEqual(fingerprint(source), before)


if __name__ == "__main__":
    unittest.main()
