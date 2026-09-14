import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

class ProvenanceTests(unittest.TestCase):
    def test_document_rejects_helpers_that_publish_bookkeeping_files(self):
        from tools import extract_external as adapter
        legacy = json.dumps({'name': 'PSP-DOCUMENT.DAT', 'options': ['platform-ordinals']})
        with patch.object(adapter.subprocess, 'check_output', return_value=legacy):
            with self.assertRaises(ValueError):
                adapter.tool_provenance('document', Path(sys.executable))

