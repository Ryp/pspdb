import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

class ProvenanceTests(unittest.TestCase):
    def test_document_replacement_keeps_metadata_hash_and_execution_together(self):
        from tools import extract_external as adapter
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'DOCUMENT.DAT'
            source.write_bytes(b'document')
            output = root / 'output'
            output.mkdir()
            helper = root / 'document'
            replacement = root / 'replacement'
            for path, marker in ((helper, b'A'), (replacement, b'B')):
                path.write_text(
                    '#!' + sys.executable + '\n'
                    'import json, sys\n'
                    'from pathlib import Path\n'
                    "if '--provenance' in sys.argv:\n"
                    "    print(json.dumps({'name': 'PSP-DOCUMENT.DAT', "
                    "'options': ['page-files-only:1']}))\n"
                    'else:\n'
                    f"    (Path(sys.argv[sys.argv.index('--output') + 1]) / 'page.png').write_bytes({marker!r})\n")
                path.chmod(0o755)
            expected_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
            run = adapter.subprocess.run

            def replace_after_metadata(*args, **kwargs):
                result = run(*args, **kwargs)
                if '--provenance' in args[0]:
                    replacement.replace(helper)
                return result

            with patch.object(adapter.subprocess, 'run', side_effect=replace_after_metadata):
                provenance = adapter.extract_document(source, output, helper)
            self.assertEqual(provenance['sha256'], expected_hash)
            self.assertEqual((output / 'page.png').read_bytes(), b'A')

    def test_document_rejects_helpers_that_publish_bookkeeping_files(self):
        from tools import extract_external as adapter
        legacy = json.dumps({'name': 'PSP-DOCUMENT.DAT', 'options': ['platform-ordinals']})
        with patch.object(adapter.subprocess, 'check_output', return_value=legacy):
            with self.assertRaises(ValueError):
                adapter.tool_provenance('document', Path(sys.executable))


class PsxProvenanceTests(unittest.TestCase):
    def test_native_psx_provenance_has_no_executable_or_hash(self):
        from tools import extract_external as adapter
        expected = {'name': 'pspdb-psx', 'version': adapter.versions()['psx'], 'options': ['in-memory']}
        self.assertEqual(adapter.tool_provenance('psx'), expected)
        current, unavailable = adapter.current_provenance()
        self.assertEqual(current['psx'], expected)
        self.assertNotIn('psx', unavailable)
