import unittest


class DocumentProvenanceTests(unittest.TestCase):
    def test_native_document_provenance_has_no_executable_or_hash(self):
        from tools import extract_external as adapter
        expected = {'name': 'pspdb-document', 'version': adapter.versions()['document'], 'options': ['in-memory']}
        self.assertEqual(adapter.tool_provenance('document'), expected)
        current, unavailable = adapter.current_provenance()
        self.assertEqual(current['document'], expected)
        self.assertNotIn('document', unavailable)


class PsxProvenanceTests(unittest.TestCase):
    def test_native_psx_provenance_has_no_executable_or_hash(self):
        from tools import extract_external as adapter
        expected = {'name': 'pspdb-psx', 'version': adapter.versions()['psx'], 'options': ['in-memory']}
        self.assertEqual(adapter.tool_provenance('psx'), expected)
        current, unavailable = adapter.current_provenance()
        self.assertEqual(current['psx'], expected)
        self.assertNotIn('psx', unavailable)
