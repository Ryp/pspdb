import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import build_opener, ProxyHandler
from unittest.mock import patch

from pspdb.server import handler_for, download_index
from pspdb.cli import main


class ContextualIndexTests(unittest.TestCase):
    def test_scoped_output_is_downloadable_without_global_source_tree(self):
        source, payload = 'a'*64, 'b'*64
        tree = dict(sha256=source, size_bytes=14, name_rule='source_stem',
            entries=[dict(path='payload.gz', type='file', sha256=payload, size_bytes=7)])
        parent = dict(sha256='c'*64, size_bytes=100, entries=[
            dict(path='DATA.PSP', type='file', sha256=source, size_bytes=14, extraction=tree)])
        data = dict(records={}, trees={'c'*64:parent})
        self.assertIn('DATA.gz', download_index(data)[payload][1])
        tree['sha256'] = 'd'*64
        self.assertNotIn(payload, download_index(data))


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = self.root / 'catalog'
        self.store = self.root / 'store'
        self.store.mkdir()
        self.content = b'\x00actual file bytes\xff'
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.empty = hashlib.sha256(b'').hexdigest()
        self.missing = hashlib.sha256(b'missing').hexdigest()
        self.name = '日本語 "file".prx'
        entries = [
            {'type': 'file', 'path': 'PSP_GAME/' + self.name, 'size_bytes': len(self.content), 'sha256': self.digest},
            {'type': 'file', 'path': 'PSP_GAME/alias.prx', 'size_bytes': len(self.content), 'sha256': self.digest},
            {'type': 'file', 'path': 'PSP_GAME/empty.bin', 'size_bytes': 0, 'sha256': self.empty},
            {'type': 'file', 'path': 'PSP_GAME/missing.bin', 'size_bytes': 7, 'sha256': self.missing},
        ]
        target = self.catalog / 'iso'
        target.mkdir(parents=True)
        (target / ('a' * 64 + '.json')).write_text(json.dumps(dict(kind='iso', schema_version=1, sha256='a' * 64, sha1='b' * 40, size_bytes=42, metadata={})))
        trees = self.catalog / 'trees'; trees.mkdir()
        (trees / ('a' * 64 + '.json')).write_text(json.dumps(dict(kind='tree', schema_version=1,
            sha256='a' * 64, size_bytes=42, extractor={'name':'iso'}, entries=entries)))
        for digest, content in [(self.digest, self.content), (self.empty, b'')]:
            path = self.blob(digest); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
        self.client = build_opener(ProxyHandler({}))

    def blob(self, digest):
        return self.store / 'sha256' / digest[:2] / digest[2:4] / digest

    def start(self, store):
        handler = handler_for(self.catalog, store)
        handler.log_message = lambda *args: None
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def stop():
            server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(stop)
        self.base = f'http://127.0.0.1:{server.server_port}'

    def get(self, path):
        return self.client.open(self.base + path, timeout=5)

    def status(self, path, expected):
        with self.assertRaises(HTTPError) as result: self.get(path)
        self.assertEqual(result.exception.code, expected)
        result.exception.close()

    def test_optional_store_and_read_only_catalog(self):
        before = {p: p.read_bytes() for p in self.catalog.rglob('*.json')}
        self.start(None)
        with self.get('/api/catalog') as response: data = json.load(response)
        self.assertFalse(data['downloads_enabled'])
        self.status('/api/availability?hash=' + self.digest, 404)
        self.status('/download/' + self.digest + '/alias.prx', 404)
        self.assertEqual(before, {p: p.read_bytes() for p in self.catalog.rglob('*.json')})

    def test_extraction_files_are_indexed_and_downloadable(self):
        folder = self.catalog / 'trees'
        folder.mkdir(exist_ok=True)
        record = dict(kind='tree', schema_version=1, sha256=self.digest,
                      size_bytes=len(self.content), extractor={'name': 'pspdecrypt'},
                      entries=[dict(type='file', path='F0/decoded.prx',
                                    size_bytes=len(self.content), sha256=self.digest)])
        (folder / f'{self.digest}.json').write_text(json.dumps(record))
        self.start(self.store)
        with self.get('/api/catalog') as response:
            self.assertEqual(json.load(response)['trees'][self.digest], record)
        with self.get('/download/' + self.digest + '/decoded.prx') as response:
            self.assertEqual(response.read(), self.content)

    def test_extraction_record_identity_is_checked(self):
        folder = self.catalog / 'trees'
        folder.mkdir(exist_ok=True)
        (folder / f'{self.digest}.json').write_text(json.dumps(
            dict(kind='tree', schema_version=1, sha256='b' * 64)))
        self.start(None)
        self.status('/api/catalog', 500)

    def test_extractor_source_is_downloadable(self):
        folder = self.catalog / 'psar'; folder.mkdir()
        (folder / f'{self.digest}.json').write_text(json.dumps(dict(
            kind='psar', schema_version=1, sha256=self.digest, size_bytes=len(self.content))))
        self.start(self.store)
        with self.get('/download/' + self.digest + '/' + self.digest + '.psar') as response:
            self.assertEqual(response.read(), self.content)

    def test_availability_and_download_preserves_names(self):
        self.start(self.store)
        with self.get('/api/catalog') as response: self.assertTrue(json.load(response)['downloads_enabled'])
        query = urlencode([('hash', h) for h in [self.digest, self.empty, self.missing, 'b' * 64]])
        with self.get('/api/availability?' + query) as response: availability = json.load(response)
        self.assertEqual(availability, {self.digest: True, self.empty: True, self.missing: False, 'b' * 64: False})
        for name in [self.name, 'alias.prx']:
            with self.get('/download/' + self.digest + '/' + quote(name, safe='')) as response:
                self.assertEqual(response.read(), self.content)
                self.assertIn("filename*=UTF-8''" + quote(name, safe=''), response.headers['Content-Disposition'])
                self.assertEqual(response.headers['Content-Type'], 'application/octet-stream')
        with self.get('/download/' + self.empty + '/empty.bin') as response:
            self.assertEqual(response.read(), b'')
            self.assertEqual(response.headers['Content-Length'], '0')
        self.blob(self.digest).unlink()
        self.status('/download/' + self.digest + '/alias.prx', 404)

    def test_rejects_unknown_names_hashes_paths_and_bad_sizes(self):
        self.start(self.store)
        for suffix in ['other.prx', '..%2Falias.prx', '%0D%0AX-Test%3Ayes']:
            self.status('/download/' + self.digest + '/' + suffix, 404)
        self.status('/download/' + 'b' * 64 + '/alias.prx', 404)
        self.status('/download/../../etc/passwd', 404)
        self.status('/api/availability?' + urlencode([('hash', self.digest)] * 129), 400)
        self.blob(self.digest).write_bytes(b'wrong size')
        self.status('/download/' + self.digest + '/alias.prx', 404)

    def test_rejects_file_and_directory_symlinks(self):
        self.start(self.store)
        target = self.root / 'outside'; target.write_bytes(self.content)
        blob = self.blob(self.digest); blob.unlink(); blob.symlink_to(target)
        self.status('/download/' + self.digest + '/alias.prx', 404)
        blob.unlink()
        folder = blob.parent
        moved = self.root / 'elsewhere'; folder.rename(moved)
        (moved / self.digest).write_bytes(self.content)
        folder.symlink_to(moved, target_is_directory=True)
        self.status('/download/' + self.digest + '/alias.prx', 404)

    def test_cli_serve_does_not_initialize_or_write_store(self):
        with patch('sys.argv', ['pspdb-web', '--store', str(self.store)]), \
             patch('pspdb.server.serve') as serve:
            self.assertEqual(main(), 0)
            serve.assert_called_once_with('catalog', 8000, host='127.0.0.1', store=str(self.store), redump=None, umdatabase=None)


if __name__ == '__main__':
    unittest.main()


class ExtractedNamesTests(unittest.TestCase):
    def test_decoded_format_names_match_download_links(self):
        from pspdb.server import download_index
        compressed, decoded, parent = [c * 64 for c in 'abc']
        data = {'records': {}, 'trees': {
            parent: {'size_bytes': 100, 'entries': [dict(path=n, type='file', size_bytes=7, sha256=compressed)
                for n in ['DATA.gz', 'MODULE.prx.gz', 'EXISTING.elf.gz']]},
            compressed: {'size_bytes': 7, 'name_rule': 'decoded_suffix', 'entries': [
                dict(path='module.elf', type='file', size_bytes=20, sha256=decoded)]},
        }}
        names = download_index(data)[decoded][1]
        self.assertTrue({'DATA.elf', 'MODULE.elf', 'EXISTING.elf'} <= names)
        self.assertFalse({'DATA', 'MODULE.prx', 'EXISTING.elf.elf'} & names)

    def test_shared_tree_download_names_follow_each_parent(self):
        from pspdb.server import download_index
        source, compressed, decoded, iso = [c * 64 for c in 'abcd']
        data = {'records': {}, 'trees': {
            iso: {'size_bytes': 2048, 'entries': [
                {'path': name, 'type': 'file', 'size_bytes': 48, 'sha256': source}
                for name in ['OPNSSMP.BIN', 'ALIAS.BIN']]},
            source: {'size_bytes': 48, 'name_rule': 'source_stem', 'entries': [
                {'path': 'module.prx.gz', 'type': 'file', 'size_bytes': 32, 'sha256': compressed}]},
            compressed: {'size_bytes': 32, 'name_rule': 'strip_suffix', 'entries': [
                {'path': 'module.prx', 'type': 'file', 'size_bytes': 64, 'sha256': decoded}]},
        }}
        index = download_index(data)
        self.assertTrue({'OPNSSMP.prx.gz', 'ALIAS.prx.gz'} <= index[compressed][1])
        self.assertTrue({'OPNSSMP.prx', 'ALIAS.prx'} <= index[decoded][1])
        data['trees'][decoded] = {'size_bytes': 64, 'name_rule': 'source_stem', 'entries': [
            {'path': 'module.prx.gz', 'type': 'file', 'size_bytes': 48, 'sha256': source}]}
        self.assertLess(len(download_index(data)[source][1]), 20)
