from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import gzip
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import build_opener, ProxyHandler

from pspdb.cli import main
from pspdb.export import export_site
from pspdb.server import catalog_data
from pspdb.wire import decode_catalog


class ExportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = self.root / 'catalog'
        self.output = self.root / 'public' / 'pspdb'
        for kind, record in {
            'iso': dict(kind='iso', schema_version=1, sha256='a' * 64,
                        sha1='b' * 40, size_bytes=42, metadata={'title': '日本語'}),
            'pkg': dict(kind='pkg', schema_version=1, sha256='e' * 64, size_bytes=99,
                        metadata={'content_type': 9, 'content_id': 'HP0000-THEME'}),
            'trees': dict(kind='tree', schema_version=1, sha256='a' * 64,
                          size_bytes=42, extractor={'name': 'iso'}, entries=[]),
        }.items():
            folder = self.catalog / kind
            folder.mkdir(parents=True)
            (folder / (record['sha256'] + '.json')).write_text(json.dumps(record))

    def test_export_is_metadata_only_and_preserves_matches(self):
        dat = self.root / 'redump.dat'
        dat.write_text('<datafile><game id="58161" name="Disc"><rom name="disc.iso" '
                       'size="42" sha1="' + 'b' * 40 + '"/></game></datafile>')
        pages = self.root / 'umdatabase'; pages.mkdir()
        (pages / '1FD42ACC.html').write_text('<title>Disc</title><p class="text-subkey">SHA-1:</p>'
                                          '<p class="text-value">' + 'b' * 40 + '</p>')
        before = {p: p.read_bytes() for p in self.catalog.rglob('*.json')}
        export_site(self.catalog, self.output, dat, pages)
        data = decode_catalog(json.loads(gzip.decompress((self.output / 'catalog.json.gz').read_bytes())))
        self.assertFalse(data['downloads_enabled'])
        iso = data['records']['iso'][0]
        self.assertEqual(iso['metadata']['title'], '日本語')
        self.assertEqual(iso['redump'], [{'id': 58161, 'name': 'Disc'}])
        self.assertEqual(iso['umdatabase'], [{'id': '1FD42ACC', 'name': 'Disc'}])
        self.assertEqual(data['records']['pkg'][0]['psn_kind'], 'theme')
        self.assertEqual(data['coverage']['umd']['total'], 1)
        self.assertIsNone(data['coverage']['psn'])
        self.assertEqual(data['trees'], catalog_data(self.catalog)['trees'])
        self.assertEqual(before, {p: p.read_bytes() for p in self.catalog.rglob('*.json')})

    def test_static_host_supports_repository_subpath(self):
        export_site(self.catalog, self.output)
        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=self.root / 'public'))
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), worker.join()))
        client = build_opener(ProxyHandler({}))
        base = f'http://127.0.0.1:{server.server_port}/pspdb/'
        with client.open(base) as response:
            html = response.read().decode()
        self.assertIn('data-catalog="catalog.json.gz"', html)
        self.assertIn('href="style.css"', html)
        self.assertIn('src="app.js"', html)
        for asset in ('app.js', 'search-worker.js', 'style.css', 'catalog.json.gz'):
            with client.open(base + asset) as response:
                self.assertEqual(response.status, 200)
                if asset.endswith('.gz'):
                    data = decode_catalog(json.loads(gzip.decompress(response.read())))
                    self.assertEqual(data['records']['iso'][0]['metadata']['title'], '日本語')
                    self.assertFalse(data['downloads_enabled'])

    def test_export_cli_and_destination_guards(self):
        with patch('sys.argv', ['pspdb-web', 'export', '--catalog', str(self.catalog), '--output', str(self.output)]):
            self.assertEqual(main(), 0)
        before = (self.output / 'catalog.json.gz').read_bytes()
        with self.assertRaisesRegex(ValueError, 'empty'):
            export_site(self.catalog, self.output)
        self.assertEqual((self.output / 'catalog.json.gz').read_bytes(), before)
        for output in (self.catalog, self.catalog / 'export', self.root):
            with self.assertRaisesRegex(ValueError, 'separate'):
                export_site(self.catalog, output)
