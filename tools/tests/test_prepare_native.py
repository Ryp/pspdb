import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'prepare_native.py'


class PreparationTests(unittest.TestCase):
    def test_source_stays_immutable_without_explicit_in_place_permission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source', root / 'output'
            source.mkdir()
            original = b'before\r\n'
            (source / 'source.c').write_bytes(original)
            patch = root / 'change.patch'
            patch.write_text('--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-before\n+after\n')
            command = [sys.executable, str(SCRIPT), '--normalize', 'source.c']

            rejected = subprocess.run(command + [str(source), str(source), str(patch)],
                                      capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((source / 'source.c').read_bytes(), original)

            copied = subprocess.run(command + [str(source), str(output), str(patch)],
                                    capture_output=True, text=True)
            self.assertEqual(copied.returncode, 0, copied.stderr)
            self.assertEqual((source / 'source.c').read_bytes(), original)
            self.assertEqual((output / 'source.c').read_bytes(), b'after\n')

            isolated = subprocess.run(command + ['--in-place', str(source), str(source), str(patch)],
                                      capture_output=True, text=True)
            self.assertEqual(isolated.returncode, 0, isolated.stderr)
            self.assertEqual((source / 'source.c').read_bytes(), b'after\n')

    def test_exact_policy_rejects_offsets_and_reversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            patch = root / 'change.patch'
            patch.write_text('--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-before\n+after\n')
            for name, original in (('offset', b'prefix\nbefore\n'), ('reversed', b'after\n')):
                with self.subTest(name=name):
                    (source / 'source.c').write_bytes(original)
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), '--exact', str(source),
                         str(root / name), str(patch)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual((source / 'source.c').read_bytes(), original)

            (source / 'source.c').write_bytes(b'prefix\nbefore\n')
            composed = root / 'composed'
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), str(composed), str(patch)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((composed / 'source.c').read_bytes(), b'prefix\nafter\n')
