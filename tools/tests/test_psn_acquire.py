import csv
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import psn_acquire as acquire

URL = 'http://zeus.dl.playstation.net/cdn/UP0001/TEST00001_00/package.pkg'


def pkg_bytes(payload=b'x' * 384):
    header = bytearray(128)
    header[:4] = b'\x7fPKG'
    header[7] = 2
    header[24:32] = (128 + len(payload)).to_bytes(8, 'big')
    header[48:58] = b'ACTUAL-ID\0'
    return bytes(header) + payload


class Response:
    def __init__(self, status, headers, blocks):
        self.status, self.headers, self.blocks = status, headers, iter(blocks)

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, size):
        block = next(self.blocks, b'')
        if isinstance(block, Exception):
            raise block
        return block


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / 'work'
        for name in ('partial', 'completed'):
            (self.work / name).mkdir(parents=True)
        self.catalog = self.root / 'catalog'
        self.catalog.mkdir()

    def snapshot(self, filename, rows):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = ['Title ID', 'Name', 'Content ID', 'PKG direct link', 'File Size', 'SHA256', 'RAP', 'Download .RAP file']
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t')
            writer.writeheader()
            for row in rows:
                writer.writerow(dict({'Title ID': 'SAME-TITLE', 'Name': 'Same name',
                    'Content ID': 'REFERENCE-ID', 'PKG direct link': URL,
                    'RAP': 'LICENSE-SECRET', 'Download .RAP file': 'PRIVATE-LICENSE-LINK'}, **row))
        return path

    def candidate(self, data, known=True):
        return {'id': 'a' * 64, 'expected_size': len(data),
                'expected_sha256': hashlib.sha256(data).hexdigest() if known else None, 'urls': [URL]}

    def transfer(self, package, state, responses):
        def respond(url, headers, timeout):
            return Mock(), next(responses)(headers)
        with patch.object(acquire, 'request', side_effect=respond):
            acquire.download(package, self.work, state, lambda: None, 1, 0, 0)

    def catalog_pair(self, digest, size, revision=1, complete=True):
        folder = self.catalog / 'pkg' / f'v{revision}'
        folder.mkdir(parents=True, exist_ok=True)
        record = {'schema_version': 1, 'kind': 'pkg', 'sha256': digest, 'size_bytes': size,
                  'metadata': {'content_id': 'ACTUAL-ID'}}
        (folder / f'{digest}-ingest.json').write_text(json.dumps(record))
        if complete:
            tree = dict(record, kind='tree', extractor={'version': str(revision)}, entries=[])
            (folder / f'{digest}-tree.json').write_text(json.dumps(tree))

    def test_snapshot_attribution_conflicts_unknowns_and_private_columns(self):
        a, b = 'a' * 64, 'b' * 64
        rows = [{'File Size': '512', 'SHA256': a}, {'File Size': '513', 'SHA256': b},
                {'File Size': '', 'SHA256': ''}, {'PKG direct link': 'MISSING'}]
        first = self.snapshot('PSP_GAMES.tsv', rows)
        duplicate = self.root / 'PSP_DEMOS.tsv'
        duplicate.write_bytes(first.read_bytes())
        distinct = self.snapshot('PSX_GAMES.tsv', [{'File Size': '512', 'SHA256': a}])
        data = acquire.inventory([first, duplicate, distinct])
        acquire.reconcile(data, {'packages': {}}, self.work, {})
        self.assertEqual(data['summary']['unique_snapshot_rows'], 5)
        self.assertEqual(data['summary']['source_rows_including_copies'], 9)
        self.assertEqual(data['summary']['package_candidates'], 4)
        snapshot = next(s for s in data['snapshots'] if s['rows'] == 4)
        self.assertEqual({o['category'] for o in snapshot['origins']}, {'PSP_GAMES', 'PSP_DEMOS'})
        self.assertEqual({o['status'] for o in snapshot['origins']}, {None})
        exact = next(p for p in data['packages'] if p['expected_sha256'] == a)
        self.assertEqual(len(exact['references']), 2)
        self.assertEqual({c['field'] for c in data['conflicts']}, {'url', 'content_id'})
        self.assertEqual(data['summary']['row_states']['missing_url'], 1)
        self.assertTrue(any(p['expected_size'] is None and p['expected_sha256'] is None for p in data['packages']))
        serialized = json.dumps(data)
        self.assertNotIn('LICENSE-SECRET', serialized)
        self.assertNotIn('PRIVATE-LICENSE-LINK', serialized)

    def test_catalog_requires_exact_hash_size_and_complete_pkg_pair(self):
        data_bytes = pkg_bytes()
        digest = hashlib.sha256(data_bytes).hexdigest()
        path = self.snapshot('PSP_GAMES.tsv', [
            {'File Size': str(len(data_bytes)), 'SHA256': digest},
            {'File Size': str(len(data_bytes) + 1), 'SHA256': digest},
            {'File Size': str(len(data_bytes)), 'SHA256': ''},
            {'File Size': '', 'SHA256': digest}])
        self.catalog_pair(digest, len(data_bytes))
        self.catalog_pair(digest, len(data_bytes), revision=2, complete=False)
        identities = acquire.catalog_identities(self.catalog)
        data = acquire.inventory([path])
        acquire.reconcile(data, {'packages': {}}, self.work, identities)
        self.assertEqual(data['summary']['row_states'], {'already_ingested': 1, 'pending': 3})
        matched = next(p for p in data['packages'] if p['catalog'])
        self.assertEqual(matched['catalog']['revision'], 1)
        self.assertEqual(matched['catalog_match_basis'], 'reference_sha256_size')
        self.assertTrue(next(r for r in data['rows'] if r['package'] == matched['id'])['content_id_conflict'])
        self.assertIsNone(matched['observed'])

    def test_url_policy_and_dns_block_private_targets_without_leaking_credentials(self):
        for url in ['http://127.0.0.1/cdn/a.pkg', URL.replace('zeus.', 'zeus.evil.'),
                    URL.replace('http://', 'http://user:SECRET@'), URL + '?token=SECRET',
                    URL.replace('/cdn/', '/cdn/../'), URL.replace('http:', 'file:'),
                    'http://b0.ww.np.dl.playstation.net/cdn/a.pkg',
                    'http://zeus.dl.playstation.net/tppkg/np/a.pkg']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                acquire.safe_url(url)
        with self.assertRaisesRegex(ValueError, 'unsupported_host'):
            acquire.safe_url('http://ares.dl.playstation.net/cdn/a.pkg')
        update_url = 'http://b0.ww.np.dl.playstation.net/tppkg/np/NPUG80251/update.pkg'
        path = self.snapshot('PSP_UPDATES.tsv', [{'PKG direct link': update_url}])
        update = acquire.inventory([path])['packages'][0]
        self.assertEqual(update['urls'], [update_url])
        self.assertEqual(update['issues'], [])
        path = self.snapshot('PSP_GAMES.tsv', [{'PKG direct link': URL + '?token=SECRET'}])
        self.assertNotIn('SECRET', json.dumps(acquire.inventory([path])))
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]
        with patch.object(socket, 'getaddrinfo', return_value=answers), patch.object(socket, 'socket') as connect:
            with self.assertRaises(acquire.AcquisitionError):
                acquire.public_connection(('b0.ww.np.dl.playstation.net', 80))
            connect.assert_not_called()

    def test_interrupted_download_resumes_only_validated_prefix(self):
        data = pkg_bytes()
        package = self.candidate(data, known=False)
        state = {}
        first = lambda _: Response(200, {'Content-Length': str(len(data)), 'ETag': '"stable"'}, [data[:128], OSError()])
        self.transfer(package, state, iter([first]))
        self.assertEqual(state['status'], 'network_failure')
        self.assertEqual(list((self.work / 'completed').iterdir()), [])
        def resume(headers):
            start = int(headers['Range'].removeprefix('bytes=').removesuffix('-'))
            return Response(206, {'Content-Range': f'bytes {start}-{len(data)-1}/{len(data)}',
                'Content-Length': str(len(data) - start), 'ETag': '"stable"'}, [data[start:]])
        self.transfer(package, state, iter([resume]))
        self.assertEqual((self.work / 'completed' / state['file']).read_bytes(), data)
        self.assertFalse(state['observed']['hash_confirmed'])
        self.assertEqual(state['status'], 'verified')

    def test_modified_prefix_is_restarted_even_without_reference_hash(self):
        data = pkg_bytes()
        package = self.candidate(data, known=False)
        state = {}
        self.transfer(package, state, iter([lambda _: Response(200,
            {'Content-Length': str(len(data)), 'ETag': '"stable"'}, [data[:256], OSError()])]))
        part = self.work / 'partial' / (package['id'] + '.part')
        corrupt = bytearray(part.read_bytes())
        corrupt[-1] ^= 1
        part.write_bytes(corrupt)
        def server(headers):
            if 'Range' in headers:
                return Response(206, {'Content-Length': '256', 'Content-Range': 'bytes 256-511/512',
                    'ETag': '"stable"'}, [data[256:]])
            return Response(200, {'Content-Length': str(len(data))}, [data])
        self.transfer(package, state, iter([server]))
        self.assertEqual((self.work / 'completed' / state['file']).read_bytes(), data)

    def test_range_ignored_for_changed_remote_bytes_restarts_instead_of_appending(self):
        data = pkg_bytes()
        package = self.candidate(data, known=False)
        state = {}
        self.transfer(package, state, iter([lambda _: Response(200,
            {'Content-Length': str(len(data)), 'ETag': '"old"'}, [data[:256], OSError()])]))
        changed = pkg_bytes(b'y' * 384)
        self.transfer(package, state, iter([lambda _: Response(200,
            {'Content-Length': str(len(changed)), 'ETag': '"new"'}, [changed])]))
        self.assertEqual((self.work / 'completed' / state['file']).read_bytes(), changed)
        self.assertFalse(state['observed']['hash_confirmed'])

    def test_bad_hash_and_unknown_length_truncation_never_publish(self):
        data = pkg_bytes()
        package = self.candidate(data)
        changed = data[:-1] + b'y'
        state = {}
        self.transfer(package, state, iter([lambda _: Response(200, {}, [changed])]))
        self.assertEqual(state['status'], 'integrity_mismatch')
        self.assertEqual(state['mismatch_observed']['sha256'], hashlib.sha256(changed).hexdigest())
        self.assertFalse(state['mismatch_observed']['hash_confirmed'])
        unknown = dict(package, expected_sha256=None, expected_size=None)
        self.transfer(unknown, state, iter([lambda _: Response(200, {}, [data[:256]])]))
        self.assertEqual(state['status'], 'integrity_mismatch')
        self.assertEqual(list((self.work / 'completed').iterdir()), [])

    def test_redirects_do_not_publish_or_follow(self):
        state = {}
        self.transfer(self.candidate(pkg_bytes()), state, iter([lambda _: Response(302,
            {'Location': 'http://127.0.0.1/SECRET'}, [])]))
        self.assertEqual(state['status'], 'redirect_blocked')
        self.assertNotIn('SECRET', json.dumps(state))
        self.assertEqual(list((self.work / 'completed').iterdir()), [])

    def test_corrupt_completed_file_is_quarantined_not_offered_to_ingester(self):
        payload = pkg_bytes()
        path = self.snapshot('PSP_THEMES.tsv', [{'File Size': str(len(payload)), 'SHA256': ''}])
        data = acquire.inventory([path])
        package = data['packages'][0]
        filename = f'{hashlib.sha256(payload).hexdigest()}-{len(payload)}.pkg'
        (self.work / 'completed' / filename).write_bytes(payload[:-1] + b'y')
        state = {'packages': {package['id']: {'status': 'verified', 'file': filename}}}
        acquire.reconcile(data, state, self.work, {})
        self.assertEqual(package['status'], 'local_corrupt')
        self.assertIsNone(package['observed'])
        self.assertIsNone(package['file'])
        self.assertEqual(list((self.work / 'completed').iterdir()), [])

    def test_cli_download_bound_and_repeat_reuses_verified_files(self):
        payload = pkg_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        path = self.snapshot('PSP_THEMES.tsv', [{'File Size': str(len(payload)), 'SHA256': digest},
            {'File Size': str(len(payload) + 1), 'SHA256': 'b' * 64}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog)]
        with patch('sys.argv', argv), patch.object(acquire, 'request') as request, patch('sys.stdout', new=io.StringIO()):
            acquire.main()
            request.assert_not_called()
        with patch('sys.argv', argv + ['--limit', '1']), patch('sys.stdout', new=io.StringIO()), patch.object(acquire, 'request',
                return_value=(Mock(), Response(200, {'Content-Length': str(len(payload))}, [payload]))):
            acquire.main()
        report = json.loads((self.work / 'report.json').read_text())
        self.assertEqual(report['summary']['package_states'], {'pending': 1, 'verified': 1})
        candidate = next(p['id'] for p in report['packages'] if p['status'] == 'verified')
        with patch('sys.argv', argv + ['--limit', '1', '--package', candidate]), patch('sys.stdout', new=io.StringIO()), patch.object(acquire, 'request') as request:
            acquire.main()
            request.assert_not_called()
        self.assertEqual(json.loads((self.work / 'report.json').read_text())['attempted_this_run'], 0)


if __name__ == '__main__':
    unittest.main()
