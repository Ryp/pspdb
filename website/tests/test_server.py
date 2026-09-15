import hashlib
from http.server import ThreadingHTTPServer
import json
import gzip
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import build_opener, ProxyHandler, Request
from unittest.mock import patch

from pspdb.server import _CatalogCache, catalog_data, handler_for, download_index
from pspdb.cli import main
from pspdb.export import export_site


class ContextualIndexTests(unittest.TestCase):
    def test_scoped_output_is_downloadable_without_global_source_tree(self):
        source, payload = 'a'*64, 'b'*64
        tree = dict(sha256=source, size_bytes=14, name_rule='source_stem',
            entries=[dict(path='payload.gz', type='file', sha256=payload, size_bytes=7)])
        parent = dict(sha256='c'*64, size_bytes=100, entries=[
            dict(path='DATA.PSP', type='file', sha256=source, size_bytes=14, extraction=tree)])
        data = dict(records={}, trees={'pbp': {'c'*64:parent}})
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

    def test_catalog_validators_and_compression(self):
        self.start(None)
        with self.get('/api/catalog') as response:
            original = response.read()
            identity_etag = response.headers['ETag']
            self.assertEqual(response.headers['Cache-Control'], 'private, no-cache')
        request = Request(self.base + '/api/catalog', headers={'Accept-Encoding': 'gzip'})
        with self.client.open(request) as response:
            self.assertEqual(response.headers['Content-Encoding'], 'gzip')
            self.assertEqual(response.headers['Vary'], 'Accept-Encoding')
            self.assertEqual(gzip.decompress(response.read()), original)
            gzip_etag = response.headers['ETag']
            self.assertNotEqual(gzip_etag, identity_etag)
        request = Request(self.base + '/api/catalog', headers={
            'Accept-Encoding': 'gzip', 'If-None-Match': '"unrelated", W/' + gzip_etag})
        with self.assertRaises(HTTPError) as result:
            self.client.open(request)
        with result.exception as response:
            self.assertEqual(response.code, 304)
            self.assertEqual(response.headers['ETag'], gzip_etag)
            self.assertEqual(response.headers['Vary'], 'Accept-Encoding')
            self.assertEqual(response.read(), b'')
        request = Request(self.base + '/api/catalog', headers={'If-None-Match': gzip_etag})
        with self.client.open(request) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), original)
        request = Request(self.base + '/api/catalog', headers={'Accept-Encoding': 'gzip;q=0, *;q=1'})
        with self.client.open(request) as response:
            self.assertIsNone(response.headers['Content-Encoding'])
            self.assertEqual(response.read(), original)
        with self.get('/search-worker.js') as response:
            self.assertEqual(response.headers.get_content_type(), 'text/javascript')

    @patch('pspdb.server.monotonic', return_value=0)
    def test_cached_catalog_refreshes_with_new_validator(self, clock):
        self.start(None)
        with self.get('/api/catalog') as response:
            original, etag = response.read(), response.headers['ETag']
        path = self.catalog / 'iso' / ('a' * 64 + '.json')
        record = json.loads(path.read_text())
        record['metadata']['title'] = 'Changed title'
        path.write_text(json.dumps(record))
        with self.get('/api/catalog') as response:
            self.assertEqual(response.read(), original)
        clock.return_value = 31
        request = Request(self.base + '/api/catalog', headers={'If-None-Match': etag})
        with self.client.open(request) as response:
            self.assertEqual(response.status, 200)
            self.assertNotEqual(response.headers['ETag'], etag)
            self.assertEqual(json.load(response)['records']['iso'][0]['metadata']['title'], 'Changed title')
        path.unlink()
        clock.return_value = 62
        with self.get('/api/catalog') as response:
            self.assertNotIn('iso', json.load(response)['records'])

    @patch('pspdb.server.monotonic', return_value=0)
    def test_refresh_keeps_warm_readers_live_and_blocks_expired_readers(self, clock):
        cache = _CatalogCache(self.catalog, None, None, None)
        original = cache.get()['body']
        path = self.catalog / 'iso' / ('a' * 64 + '.json')
        record = json.loads(path.read_text())
        record['metadata']['title'] = 'First refresh'
        path.write_text(json.dumps(record))
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        result = []

        def delayed_read(*args):
            data = catalog_data(*args)
            entered.set()
            if not release.wait(5):
                raise TimeoutError('Refresh was not released')
            return data

        def expired_read():
            try:
                result.append(cache.get()['body'])
            finally:
                finished.set()

        with patch('pspdb.server.catalog_data', side_effect=delayed_read):
            clock.return_value = 5
            reader = None
            try:
                self.assertEqual(cache.get()['body'], original)
                self.assertTrue(entered.wait(5))
                record['metadata']['title'] = 'Next refresh'
                path.write_text(json.dumps(record))
                self.assertEqual(cache.get()['body'], original)
                clock.return_value = 31
                reader = threading.Thread(target=expired_read)
                reader.start()
                self.assertFalse(finished.wait(0.05))
            finally:
                release.set()
                if reader is not None:
                    reader.join(5)
        self.assertTrue(finished.is_set())
        self.assertEqual(json.loads(result[0])['records']['iso'][0]['metadata']['title'], 'First refresh')
        clock.return_value = 62
        self.assertEqual(json.loads(cache.get()['body'])['records']['iso'][0]['metadata']['title'], 'Next refresh')

    @patch('pspdb.server.monotonic', return_value=0)
    def test_refresh_errors_are_visible_and_recovery_is_bounded(self, clock):
        self.start(self.store)
        with self.get('/api/catalog') as response:
            original = response.read()
        path = self.catalog / 'iso' / ('a' * 64 + '.json')
        record = path.read_text()
        path.write_text('{')
        clock.return_value = 31
        with self.assertLogs('pspdb.server', level='ERROR'):
            self.status('/api/catalog', 500)
        self.status('/api/availability?hash=' + self.digest, 500)
        self.status('/download/' + self.digest + '/alias.prx', 500)
        path.write_text(record)
        clock.return_value = 32
        self.status('/api/catalog', 500)
        clock.return_value = 36
        with self.get('/api/catalog') as response:
            self.assertEqual(response.read(), original)

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
            self.assertEqual(json.load(response)['trees']['tree'][self.digest], record)
        with self.get('/download/' + self.digest + '/decoded.prx') as response:
            self.assertEqual(response.read(), self.content)

    @patch('pspdb.server.monotonic', return_value=0)
    def test_same_bytes_keep_root_and_nested_inventories_and_download_names(self, clock):
        def write_pair(kind, digest, version, size, entries):
            folder = self.catalog / kind / f'v{version}'
            folder.mkdir(parents=True, exist_ok=True)
            record = dict(kind=kind, schema_version=1, sha256=digest, size_bytes=size, metadata={})
            tree = dict(kind='tree', schema_version=1, sha256=digest, size_bytes=size,
                        extractor={'name': 'pspdb-ingest', 'version': str(version)}, entries=entries)
            (folder / f'{digest}-ingest.json').write_text(json.dumps(record))
            tree_path = folder / f'{digest}-tree.json'
            tree_path.write_text(json.dumps(tree))
            return tree_path

        def file(name, digest=self.empty, size=0):
            return dict(type='file', path=name, sha256=digest, size_bytes=size)

        write_pair('iso', self.digest, 2, len(self.content), [file('old-root.prx')])
        write_pair('iso', self.digest, 10, len(self.content), [file('root-only.prx')])
        write_pair('iso', self.digest, 11, len(self.content), [file('incomplete-root.prx')]).unlink()
        write_pair('iso9660', self.digest, 1, len(self.content), [file('nested-only.prx')])
        write_pair('iso9660', self.digest, 2, len(self.content), [file('incomplete-nested.prx')]).unlink()
        parent = 'c' * 64
        write_pair('pkg', parent, 1, 100, [file('recovered.iso', self.digest, len(self.content))])
        before = {p: p.read_bytes() for p in self.catalog.rglob('*.json')}
        self.start(self.store)
        with self.get('/api/catalog') as response:
            data = json.load(response)
        output = self.root / 'export'
        export_site(self.catalog, output)
        exported = json.loads((output / 'catalog.json').read_text())
        for snapshot in (data, exported):
            self.assertEqual([entry['path'] for entry in snapshot['trees']['iso'][self.digest]['entries']], ['root-only.prx'])
            self.assertEqual([entry['path'] for entry in snapshot['trees']['iso9660'][self.digest]['entries']], ['nested-only.prx'])
            self.assertEqual(snapshot['trees']['pkg'][parent]['entries'][0]['sha256'], self.digest)
        for name in ('root-only.prx', 'nested-only.prx'):
            with self.get(f'/download/{self.empty}/{name}') as response:
                self.assertEqual(response.read(), b'')
                self.assertIn("filename*=UTF-8''" + name, response.headers['Content-Disposition'])
        with self.get(f'/download/{self.digest}/recovered.iso') as response:
            self.assertEqual(response.read(), self.content)
        self.status(f'/download/{self.empty}/old-root.prx', 404)
        self.status(f'/download/{self.empty}/incomplete-nested.prx', 404)
        self.assertEqual(before, {p: p.read_bytes() for p in self.catalog.rglob('*.json')})
        pending = write_pair('iso', self.digest, 12, len(self.content), [file('published-root.prx')])
        completed_tree = pending.read_bytes()
        pending.unlink()
        clock.return_value = 31
        with self.get('/api/catalog') as response:
            data = json.load(response)
        self.assertEqual(data['trees']['iso'][self.digest]['extractor']['version'], '10')
        self.status(f'/download/{self.empty}/published-root.prx', 404)
        pending.write_bytes(completed_tree)
        clock.return_value = 62
        with self.get('/api/catalog') as response:
            data = json.load(response)
        self.assertEqual(data['trees']['iso'][self.digest]['extractor']['version'], '12')
        self.assertEqual(data['trees']['iso9660'][self.digest]['extractor']['version'], '1')
        with self.get(f'/download/{self.empty}/published-root.prx') as response:
            self.assertEqual(response.read(), b'')
        self.status(f'/download/{self.empty}/root-only.prx', 404)

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
        with self.get('/api/availability?hash=' + self.digest) as response:
            self.assertEqual(json.load(response), {self.digest: False})
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
            'iso': {parent: {'size_bytes': 100, 'entries': [dict(path=n, type='file', size_bytes=7, sha256=compressed)
                for n in ['DATA.gz', 'MODULE.prx.gz', 'EXISTING.elf.gz']]}},
            'gzip': {compressed: {'size_bytes': 7, 'name_rule': 'decoded_suffix', 'entries': [
                dict(path='module.elf', type='file', size_bytes=20, sha256=decoded)]}},
        }}
        names = download_index(data)[decoded][1]
        self.assertTrue({'DATA.elf', 'MODULE.elf', 'EXISTING.elf'} <= names)
        self.assertFalse({'DATA', 'MODULE.prx', 'EXISTING.elf.elf'} & names)

    def test_shared_tree_download_names_follow_each_parent(self):
        from pspdb.server import download_index
        source, compressed, decoded, iso = [c * 64 for c in 'abcd']
        data = {'records': {}, 'trees': {
            'iso': {iso: {'size_bytes': 2048, 'entries': [
                {'path': name, 'type': 'file', 'size_bytes': 48, 'sha256': source}
                for name in ['OPNSSMP.BIN', 'ALIAS.BIN']]}},
            'prx': {source: {'size_bytes': 48, 'name_rule': 'source_stem', 'entries': [
                {'path': 'module.prx.gz', 'type': 'file', 'size_bytes': 32, 'sha256': compressed}]}},
            'gzip': {compressed: {'size_bytes': 32, 'name_rule': 'strip_suffix', 'entries': [
                {'path': 'module.prx', 'type': 'file', 'size_bytes': 64, 'sha256': decoded}]}},
        }}
        index = download_index(data)
        self.assertTrue({'OPNSSMP.prx.gz', 'ALIAS.prx.gz'} <= index[compressed][1])
        self.assertTrue({'OPNSSMP.prx', 'ALIAS.prx'} <= index[decoded][1])
        data['trees']['prx'][decoded] = {'size_bytes': 64, 'name_rule': 'source_stem', 'entries': [
            {'path': 'module.prx.gz', 'type': 'file', 'size_bytes': 48, 'sha256': source}]}
        self.assertLess(len(download_index(data)[source][1]), 20)
