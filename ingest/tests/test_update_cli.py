"""Synthetic updater roots exercise native sections and the real recursive queue."""

import gzip
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zipfile
import zlib

import pycdlib

from ingest.tests.test_ingest_cli import BINARY, GAME_UMD, SUMMARY, result_path, snapshot
from ingest.tests.test_pkg_cli import sfo


SECTION_NAMES = ("PARAM.SFO", "ICON0.PNG", "ICON1.PMF", "PIC0.PNG", "PIC1.PNG", "SND0.AT3", "DATA.PSP", "DATA.BIN")
METADATA = {"UPDATER_VER": "6.61", "TITLE": "Synthetic updater · test", "DISC_ID": "MSTKUPDATE"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pbp(sections):
    offsets = []
    position = 40
    for name in SECTION_NAMES:
        offsets.append(position)
        position += len(sections.get(name, b""))
    return b"\0PBP" + struct.pack("<I8I", 0x10000, *offsets) + b"".join(sections.get(name, b"") for name in SECTION_NAMES)


def psar(files):
    # Decrypted version-1 PSAR, matching the existing native decoder fixture.
    archive = bytearray(0x121)
    archive[:5] = b"PSAR\x01"
    archive[0x20:0x29] = b"333,6.61\0"
    struct.pack_into("<I", archive, 0xA0, 1)
    for name, contents in files:
        compressed = zlib.compress(contents)
        header = bytearray(0x110)
        header[4:4 + len(name)] = name.encode()
        struct.pack_into("<II", header, 0x104, len(compressed), len(contents))
        archive.extend(header)
        archive.extend(compressed)
    return bytes(archive)


def update_sfo(bootable):
    param = bytearray(sfo({**METADATA, "BOOTABLE": "xxx"}))
    struct.pack_into("<H", param, 20 + len(METADATA) * 16 + 2, 0x404)
    struct.pack_into("<I", param, len(param) - 4, bootable)
    return bytes(param)


def fixture():
    plain = b"decoded synthetic updater payload"
    compressed = gzip.compress(plain, mtime=0)
    wrapper = b"~SCE" + struct.pack("<I", 8) + compressed
    # UPDATE-only fields remain unrelated to generic PBP metadata validation:
    # mistyped UPDATER_VER and BOOTABLE must stay acceptable inside the PSAR.
    inner_sfo = bytearray(sfo({"TITLE": "Nested generic PBP", "UPDATER_VER": "ignored", "BOOTABLE": "not an integer"}))
    struct.pack_into("<H", inner_sfo, 20 + 16 + 2, 0x404)
    inner = pbp({"PARAM.SFO": bytes(inner_sfo), "DATA.PSP": wrapper})
    archive = psar([("flash0:/nested.pbp", inner), ("flash0:/exact.bin", b"exact PSAR tail payload")])
    sections = {"PARAM.SFO": sfo(METADATA), "DATA.PSP": wrapper, "DATA.BIN": archive}
    return sections, inner, compressed, plain


def catalog_tree(catalog, kind, data):
    path = result_path(catalog, kind, digest(data))
    return path.with_name(digest(data) + "-tree.json")


def object_path(store, data):
    value = digest(data)
    return store / "sha256" / value[:2] / value[2:4] / value


class UpdateCliTests(unittest.TestCase):
    def run_ingest(self, inputs, *args, code=0, threads=1):
        completed = subprocess.run(
            [str(BINARY), str(inputs), "--no-progress", "--threads", str(threads), *map(str, args)],
            capture_output=True, text=True, timeout=30,
        )
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, code, output)
        rows = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        return output, rows

    def assert_inventory(self, catalog, kind, source, files):
        tree = json.loads(catalog_tree(catalog, kind, source).read_text())
        self.assertNotIn("error", tree)
        actual = {entry["path"]: (entry["size_bytes"], entry["sha256"])
                  for entry in tree["entries"] if entry["type"] == "file"}
        self.assertEqual(actual, {name: (len(data), digest(data)) for name, data in files.items()})
        return tree

    def test_shared_decoded_bytes_are_independent_of_occurrence_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store = (base / name for name in ("inputs", "catalog", "store"))
            inputs.mkdir()
            plain = b"shared firmware component"
            compressed = gzip.compress(plain, mtime=0)
            first = pbp({"PARAM.SFO": sfo(METADATA), "DATA.BIN": psar([("flash0:/alpha.elf.gz", compressed)])})
            second = pbp({"PARAM.SFO": sfo(METADATA), "DATA.BIN": psar([("flash0:/beta.bin.gz", compressed)])})
            (inputs / "first.pbp").write_bytes(first)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store)
            before = {path: value for path, value in snapshot(catalog).items() if path.endswith(".json")}
            (inputs / "second.pbp").write_bytes(second)
            _, rows = self.run_ingest(inputs, "--catalog", catalog, "--store", store, threads=4)
            self.assertEqual({row["sha256"] for row in rows}, {digest(first), digest(second)})
            after = snapshot(catalog)
            self.assertEqual({path: after[path] for path in before}, before)
            self.assertEqual(object_path(store, plain).read_bytes(), plain)
            old = snapshot(catalog)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store, "--skip-existing")
            self.assertEqual(snapshot(catalog), old)

    def test_compound_gzip_stays_opaque_while_standalone_children_decode(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store = (base / name for name in ("inputs", "catalog", "store"))
            inputs.mkdir()
            prefix = b"compound prefix must not be published"
            compound = gzip.compress(prefix, mtime=0) + bytes(32) + b"PACK\x07compound suffix"
            plain = b"standalone child without gzip extension"
            first, second = b"first concatenated member", b"second concatenated member"
            compressed = gzip.compress(plain, mtime=0)
            concatenated = gzip.compress(first, mtime=0) + gzip.compress(second, mtime=0)
            padded = gzip.compress(second, mtime=0) + bytes(16) + gzip.compress(first, mtime=0) + bytes(32)
            files = {
                "F0/data.bin": compound,
                "F0/same-content.gz": compound,
                "F0/module.bin": compressed,
                "F0/concatenated.bin": concatenated,
                "F0/padded.bin": padded,
            }
            archive = psar([("flash0:/" + name.removeprefix("F0/"), data) for name, data in files.items()])
            source = pbp({"PARAM.SFO": sfo(METADATA), "DATA.BIN": archive})
            source_path = inputs / "updater.pbp"
            source_path.write_bytes(source)
            output, _ = self.run_ingest(inputs, "--catalog", catalog, "--store", store, threads=4)
            self.assertNotIn("Extraction error:", output)
            parent = self.assert_inventory(catalog, "psar", archive, files)
            for entry in parent["entries"]:
                if entry.get("sha256") == digest(compound):
                    self.assertNotIn("extraction", entry)
            self.assertFalse(catalog_tree(catalog, "gzip", compound).exists())
            self.assertFalse(object_path(store, prefix).exists())
            for data in files.values():
                self.assertEqual(object_path(store, data).read_bytes(), data)
            for data, decoded in ((compressed, plain), (concatenated, first + second), (padded, second + first)):
                self.assert_inventory(catalog, "gzip", data, {"payload.bin": decoded})
                self.assertEqual(object_path(store, decoded).read_bytes(), decoded)
            self.assertEqual(source_path.read_bytes(), source)

    def test_corrupt_gzip_members_publish_failures_without_decoded_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store = (base / name for name in ("inputs", "catalog", "store"))
            inputs.mkdir()
            plain = b"validated prefix of a corrupt stream"
            member = gzip.compress(plain, mtime=0)
            crc = bytearray(member)
            crc[-8] ^= 1
            size = bytearray(member)
            size[-4] ^= 1
            method = bytearray(member)
            method[2] = 0
            files = {
                "F0/first-crc.bin": bytes(crc) + b"\0PACK",
                "F0/next-crc.bin": member + bytes(crc),
                "F0/next-size.bin": member + bytes(size),
                "F0/next-method.bin": member + bytes(method),
                "F0/next-trailer.bin": member + member[:-1],
                "F0/next-header.bin": member + b"\0\x1f\x8b",
                "F0/next-name.bin": member + b"\x1f\x8b\x08\x08" + bytes(6) + b"unterminated",
            }
            archive = psar([("flash0:/" + name.removeprefix("F0/"), data) for name, data in files.items()])
            source = pbp({"PARAM.SFO": sfo(METADATA), "DATA.BIN": archive})
            (inputs / "updater.pbp").write_bytes(source)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store)
            self.assert_inventory(catalog, "psar", archive, files)
            for name, data in files.items():
                with self.subTest(name=name):
                    failure = json.loads(catalog_tree(catalog, "gzip", data).read_text())
                    self.assertTrue(failure["error"])
                    self.assertNotEqual(failure["error"], "NotStandaloneGzip")
                    self.assertEqual(failure["entries"], [])
                    self.assertEqual(object_path(store, data).read_bytes(), data)
            for decoded in (plain, plain + plain):
                self.assertFalse(object_path(store, decoded).exists())

    def test_exact_sections_variants_metadata_and_deferred_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store = (base / name for name in ("inputs", "catalog", "store"))
            inputs.mkdir()
            sections, inner, compressed, plain = fixture()
            variants = []
            for name, icon in (("claimed-1.00.PbP", b"variant one"), ("claimed-2.00.pbp", b"variant two")):
                files = {**sections, "ICON0.PNG": icon}
                source = pbp(files)
                (inputs / name).write_bytes(source)
                variants.append((source, files))
            before = snapshot(inputs)
            ctimes = {path.name: path.stat().st_ctime_ns for path in inputs.iterdir()}

            # One worker guarantees all recursive jobs run after process_file
            # releases its source view. No-store operation rules out CAS rereads.
            _, rows = self.run_ingest(inputs, "--catalog", catalog)
            self.assertEqual({row["sha256"] for row in rows}, {digest(source) for source, _ in variants})
            for source, files in variants:
                record = json.loads(result_path(catalog, "update", digest(source)).read_text())
                self.assertEqual(record["metadata"], {
                    "updater_version": METADATA["UPDATER_VER"], "title": METADATA["TITLE"], "disc_id": METADATA["DISC_ID"],
                    "updater_target": None,
                })
                self.assertEqual((record["kind"], record["sha256"], record["sha1"], record["size_bytes"]),
                                 ("update", digest(source), hashlib.sha1(source).hexdigest(), len(source)))
                self.assert_inventory(catalog, "update", source, files)
                self.assertFalse(result_path(catalog, "pbp", digest(source)).exists())
            self.assert_inventory(catalog, "psar", sections["DATA.BIN"], {"F0/nested.pbp": inner, "F0/exact.bin": b"exact PSAR tail payload"})
            self.assert_inventory(catalog, "gzip", compressed, {"payload.bin": plain})
            self.assertNotIn("error", json.loads(catalog_tree(catalog, "pbp", inner).read_text()))

            # Adding a store later regenerates the same immutable inventories.
            old = snapshot(catalog)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store, threads=4)
            self.assertEqual(snapshot(catalog), old)
            for source, files in variants:
                self.assertFalse(object_path(store, source).exists())
                for data in files.values():
                    self.assertEqual(object_path(store, data).read_bytes(), data)
            self.assertEqual(object_path(store, plain).read_bytes(), plain)
            self.assertEqual(snapshot(inputs), before)
            self.assertEqual({path.name: path.stat().st_ctime_ns for path in inputs.iterdir()}, ctimes)

    def test_declared_target_uses_typed_content_not_names_or_payload_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog = base / "inputs", base / "catalog"
            inputs.mkdir()
            expected = {}
            # Every candidate uses the same non-Go-style PSAR v1 payload.
            archive = psar([])
            for name, param, target in (
                ("claimed-psp-go.pbp", update_sfo(1), "psp"),
                ("claimed-psp.pbp", update_sfo(2), "psp-go"),
                ("missing.pbp", sfo(METADATA), None),
                ("unsupported.pbp", update_sfo(0x80000002), None),
            ):
                source = pbp({"PARAM.SFO": param, "DATA.BIN": archive})
                (inputs / name).write_bytes(source)
                expected[digest(source)] = target
            before = snapshot(inputs)
            _, rows = self.run_ingest(inputs, "--catalog", catalog)
            self.assertEqual({row["sha256"]: row["updater_target"] for row in rows}, expected)
            for source_hash, target in expected.items():
                record_path = result_path(catalog, "update", source_hash)
                record = json.loads(record_path.read_text())
                self.assertEqual(record["metadata"]["updater_target"], target)
            self.assertEqual(snapshot(inputs), before)

    def test_probe_rejects_malformed_bootable_including_duplicate_unknown_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog = base / "inputs", base / "catalog"
            inputs.mkdir()
            archive = psar([])
            source = pbp({"PARAM.SFO": update_sfo(2), "DATA.BIN": archive})
            (inputs / "accepted.pbp").write_bytes(source)
            entry = 20 + len(METADATA) * 16
            bad_sfos = []
            for fmt in (0x204, 0x0004, 0xffff):
                param = bytearray(update_sfo(2))
                struct.pack_into("<H", param, entry + 2, fmt)
                bad_sfos.append(param)
            for length in (0, 3, 5):
                param = bytearray(update_sfo(2))
                param.append(0)
                struct.pack_into("<II", param, entry + 4, length, 5)
                bad_sfos.append(param)
            # An unsupported first value must still count as a seen BOOTABLE.
            duplicate = bytearray(update_sfo(0))
            duplicate[36:52] = duplicate[entry:entry + 16]
            bad_sfos.append(duplicate)
            for index, param in enumerate(bad_sfos):
                (inputs / f"malformed-{index}.pbp").write_bytes(pbp({"PARAM.SFO": param, "DATA.BIN": archive}))
            _, rows = self.run_ingest(inputs, "--catalog", catalog)
            self.assertEqual([row["sha256"] for row in rows], [digest(source)])
            self.assertEqual({path.name for path in (catalog / "update").rglob("*-ingest.json")},
                             {digest(source) + "-ingest.json"})

    def test_probe_ignores_non_updaters_malformed_and_compressed_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog = base / "inputs", base / "catalog"
            inputs.mkdir()
            sections, _, _, _ = fixture()
            recognized = pbp(sections)
            (inputs / "accepted.PBP").write_bytes(recognized)
            wrong_type = bytearray(sfo(METADATA))
            struct.pack_into("<H", wrong_type, 22, 0x404)
            duplicate = bytearray(sfo(METADATA))
            struct.pack_into("<H", duplicate, 36, 0)  # TITLE now duplicates UPDATER_VER.
            unterminated = bytearray(sfo({"UPDATER_VER": "6.61"}))
            unterminated[-1] = ord("x")
            bad_sfos = [sfo({"TITLE": "Ordinary PBP"}), sfo({"UPDATER_VER": ""}), bytes(wrong_type), bytes(duplicate), bytes(unterminated), b""]
            for index, param in enumerate(bad_sfos):
                (inputs / f"ignored-{index}.pbp").write_bytes(pbp({**sections, "PARAM.SFO": param}))
            malformed = bytearray(recognized)
            struct.pack_into("<I", malformed, 36, len(malformed) + 1)
            (inputs / "bad-offset.pbp").write_bytes(malformed)
            (inputs / "not-final.pbp").write_bytes(pbp({**sections, "DATA.PSP": sections["DATA.BIN"], "DATA.BIN": b"not PSAR"}))
            (inputs / "empty.pbp").write_bytes(b"")
            (inputs / "symlink.pbp").symlink_to("accepted.PBP")
            os.mkfifo(inputs / "pipe.pbp")
            with zipfile.ZipFile(inputs / "archive.zip", "w") as archive:
                archive.writestr("updater.pbp", recognized)
            before = snapshot(inputs)
            output, rows = self.run_ingest(inputs, "--catalog", catalog)
            self.assertEqual([row["sha256"] for row in rows], [digest(recognized)])
            counters = tuple(map(int, SUMMARY.search(output).groups()))
            self.assertEqual(counters, (1, 10, 1, 2, 1, 0, len(recognized)))
            self.assertEqual({path.name for path in (catalog / "update").rglob("*-ingest.json")}, {digest(recognized) + "-ingest.json"})
            self.assertEqual(snapshot(inputs), before)

    def test_native_inventory_without_catalog_and_fatal_store_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, store, catalog = (base / name for name in ("inputs", "store", "catalog"))
            inputs.mkdir()
            sections, _, _, plain = fixture()
            source = pbp(sections)
            (inputs / "updater.pbp").write_bytes(source)
            _, rows = self.run_ingest(inputs, "--store", store)
            self.assertEqual(rows[0]["entry_count"], len(sections))
            self.assertEqual(rows[0]["updater_version"], METADATA["UPDATER_VER"])
            for data in sections.values():
                self.assertEqual(object_path(store, data).read_bytes(), data)
            self.assertFalse(object_path(store, source).exists())
            self.assertFalse(object_path(store, plain).exists())
            # Objects are published only after their bytes are durable, so the
            # digest in the path is trusted and same-size bytes are never reread
            # to be rehashed. A size that disagrees with the record still stops
            # the run instead of publishing a record over damaged storage.
            damaged = object_path(store, sections["PARAM.SFO"])
            damaged.write_bytes(b"x" * len(sections["PARAM.SFO"]))
            self.run_ingest(inputs, "--store", store)
            damaged.write_bytes(b"x" * (len(sections["PARAM.SFO"]) - 1))
            self.run_ingest(inputs, "--catalog", catalog, "--store", store, code=1)
            self.assertFalse(result_path(catalog, "update", digest(source)).exists())
            self.assertEqual(damaged.read_bytes(), b"x" * (len(sections["PARAM.SFO"]) - 1))

    def test_fresh_skip_and_failed_descendant_retry_preserve_root_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog = base / "inputs", base / "catalog"
            inputs.mkdir()
            sections, _, _, _ = fixture()
            source = pbp(sections)
            (inputs / "updater.pbp").write_bytes(source)
            self.run_ingest(inputs, "--catalog", catalog)
            old = snapshot(catalog)
            _, rows = self.run_ingest(inputs, "--catalog", catalog, "--skip-existing")
            self.assertEqual(rows, [])
            self.assertEqual(snapshot(catalog), old)

            # A real failed PSAR is still a recognized updater. Its metadata is
            # immutable and a retry cannot mistake the successful root tree for
            # a complete reachable extraction graph.
            bad_psar = b"PSAR" + bytes(64)
            damaged = pbp({**sections, "DATA.BIN": bad_psar})
            (inputs / "damaged.pbp").write_bytes(damaged)
            self.run_ingest(inputs, "--catalog", catalog)
            record = result_path(catalog, "update", digest(damaged))
            saved = record.read_bytes()
            failure = json.loads(catalog_tree(catalog, "psar", bad_psar).read_text())
            self.assertEqual(failure["error"], "InvalidPsar")
            self.assertEqual(failure["entries"], [])
            _, rows = self.run_ingest(inputs, "--catalog", catalog, "--skip-existing")
            self.assertEqual([row["sha256"] for row in rows], [digest(damaged)])
            self.assertEqual(record.read_bytes(), saved)

            # A previously failed derived result is replaceable after a decoder
            # recovers, without rewriting its updater observation.
            child_path = catalog_tree(catalog, "psar", sections["DATA.BIN"])
            complete = json.loads(child_path.read_text())
            child_path.write_text(json.dumps({**complete, "error": "InvalidPsar", "entries": []}))
            _, rows = self.run_ingest(inputs, "--catalog", catalog, "--skip-existing")
            self.assertEqual({row["sha256"] for row in rows}, {digest(source), digest(damaged)})
            self.assertEqual(json.loads(child_path.read_text()), complete)
            self.assertEqual(result_path(catalog, "update", digest(source)).read_bytes(), old[str(result_path(catalog, "update", digest(source)).relative_to(catalog))][3])

    def test_update_root_and_generic_pbp_cache_roles_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs, catalog, store = (base / name for name in ("inputs", "catalog", "store"))
            inputs.mkdir()
            sections, _, _, _ = fixture()
            source = pbp(sections)
            (inputs / "updater.pbp").write_bytes(source)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store)
            self.assertFalse(object_path(store, source).exists())

            iso = pycdlib.PyCdlib()
            iso.new(interchange_level=3)
            for name, data in (("UMD_DATA.BIN", GAME_UMD), ("EBOOT.PBP", source)):
                iso.add_fp(BytesIO(data), len(data), iso_path="/" + name + ";1")
            image = BytesIO()
            iso.write_fp(image)
            iso.close()
            carrier = image.getvalue()
            (inputs / "carrier.iso").write_bytes(carrier)
            self.run_ingest(inputs, "--catalog", catalog, "--store", store, "--skip-existing")
            generic_path = catalog_tree(catalog, "pbp", source)
            self.assert_inventory(catalog, "pbp", source, sections)
            self.assertTrue(result_path(catalog, "update", digest(source)).exists())
            # Only the independent ISO occurrence legitimately inserts raw bytes.
            self.assertEqual(object_path(store, source).read_bytes(), source)
            old = snapshot(catalog)
            _, rows = self.run_ingest(inputs, "--catalog", catalog, "--store", store, "--skip-existing")
            self.assertEqual(rows, [])
            self.assertEqual(snapshot(catalog), old)

            # Root freshness cannot authorize reuse of stale generic PBP output.
            generic = json.loads(generic_path.read_text())
            generic["extractor"]["options"] = ["obsolete extraction recipe"]
            generic_path.write_text(json.dumps(generic))
            carrier_record = result_path(catalog, "iso", digest(carrier))
            carrier_record.unlink()
            catalog_tree(catalog, "iso", carrier).unlink()
            self.run_ingest(inputs, "--catalog", catalog, "--store", store, "--skip-existing", code=1)
            self.assertFalse(carrier_record.exists())
            self.assertEqual(json.loads(generic_path.read_text()), generic)


if __name__ == "__main__":
    unittest.main()
