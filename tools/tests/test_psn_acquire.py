import csv
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import psn_acquire as acquire

URL = 'http://zeus.dl.playstation.net/cdn/UP0001/TEST00001_00/package.pkg'
CONTENT_ID = 'UP0001-TEST00001_00-ABCDEFGHIJKLMNOP'


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
        if isinstance(block, BaseException):
            raise block
        return block


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / 'work'
        self.rap_dir = self.root / 'licenses'
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

    def test_fetched_snapshot_cache_can_be_replayed_offline_without_exposing_raps(self):
        key = bytes(range(16))
        body = self.snapshot('PSP_GAMES.tsv', [{'Content ID': CONTENT_ID, 'RAP': key.hex()}]).read_bytes()
        argv = ['psn-acquire', '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--no-progress']
        with patch('sys.argv', argv), patch('sys.stdout', new=io.StringIO()), \
                patch.object(acquire.http.client, 'HTTPSConnection') as connect, \
                patch.object(acquire, 'request') as packages:
            connect.return_value.getresponse.side_effect = [
                Response(200, {'Content-Length': str(len(body))}, [body]) for _ in acquire.SNAPSHOT_CATEGORIES]
            acquire.main()
            packages.assert_not_called()
        first = json.loads((self.work / 'report.json').read_text())
        self.assertEqual((self.rap_dir / f'{CONTENT_ID}.rap').read_bytes(), key)
        cache = self.work / 'snapshots'
        self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in cache.iterdir()))
        with patch('sys.argv', argv + [str(cache)]), patch('sys.stdout', new=io.StringIO()), \
                patch.object(acquire.http.client, 'HTTPSConnection') as connect:
            acquire.main()
            connect.assert_not_called()
        replay = json.loads((self.work / 'report.json').read_text())
        self.assertEqual(first['rows'], replay['rows'])
        self.assertEqual(first['summary'], replay['summary'])
        self.assertNotIn(key.hex(), json.dumps(first))
        self.assertNotIn('PRIVATE-LICENSE-LINK', json.dumps(first))

    def test_failed_snapshot_batch_preserves_cache_and_does_not_leak_response(self):
        body = self.snapshot('PSP_GAMES.tsv', []).read_bytes()
        cache = self.work / 'snapshots'
        cache.mkdir()
        previous = cache / 'PSP_GAMES.tsv'
        previous.write_bytes(body)
        responses = [
            Response(302, {'Location': 'http://127.0.0.1/private'}, []),
            Response(200, {'Content-Length': '100'}, [b'short']),
            Response(200, {}, [b'<html>PRIVATE-LICENSE-SECRET</html>']),
            Response(200, {}, [body + b'too\\tfew\\tcolumns\\n']),
            Response(200, {}, [TimeoutError('PRIVATE-LICENSE-SECRET')]),
        ]
        for failing in responses:
            with self.subTest(response=failing.status), \
                    patch.object(acquire.http.client, 'HTTPSConnection') as connect:
                # A later failure must not publish an earlier successful download.
                connect.return_value.getresponse.side_effect = [
                    Response(200, {}, [body]), failing,
                    *[Response(200, {}, [body]) for _ in acquire.SNAPSHOT_CATEGORIES[2:]]]
                with self.assertRaises(ValueError) as error:
                    acquire.fetch_snapshots(self.work, 1)
                self.assertNotIn('PRIVATE-LICENSE-SECRET', str(error.exception))
                self.assertEqual(list(cache.iterdir()), [previous])
                self.assertEqual(previous.read_bytes(), body)
                self.assertEqual(list(self.work.glob('.snapshots-*')), [])

    def test_snapshot_size_limit_applies_without_content_length(self):
        with patch.object(acquire, 'SNAPSHOT_LIMIT', 32), \
                patch.object(acquire.http.client, 'HTTPSConnection') as connect:
            connect.return_value.getresponse.return_value = Response(200, {}, [b'x' * 33])
            with self.assertRaises(ValueError):
                acquire.fetch_snapshots(self.work, 1)
        self.assertEqual(list((self.work / 'snapshots').iterdir()), [])

    def test_snapshot_attribution_conflicts_unknowns_and_private_columns(self):
        a, b = 'a' * 64, 'b' * 64
        rows = [{'File Size': '512', 'SHA256': a}, {'File Size': '513', 'SHA256': b},
                {'File Size': '', 'SHA256': ''}, {'PKG direct link': 'MISSING'}]
        first = self.snapshot('PSP_GAMES.tsv', rows)
        duplicate = self.root / 'PSP_DEMOS.tsv'
        duplicate.write_bytes(first.read_bytes())
        distinct = self.snapshot('PSX_GAMES.tsv', [{'File Size': '512', 'SHA256': a}])
        with patch.dict('os.environ', {'PSPDB_RAP_DIR': str(self.rap_dir)}):
            data = acquire.inventory([first, duplicate, distinct])
        self.assertNotIn('licenses', data)
        self.assertFalse(self.rap_dir.exists())
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

    def test_cli_inventory_imports_private_raps_without_downloads_and_is_idempotent(self):
        key = bytes(range(16))
        missing_id = CONTENT_ID[:-1] + 'Q'
        payload = pkg_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        path = self.snapshot('PSP_GAMES.tsv', [
            {'Content ID': CONTENT_ID, 'RAP': key.hex(), 'File Size': str(len(payload)), 'SHA256': digest},
            {'Content ID': missing_id, 'RAP': 'MISSING', 'PKG direct link': 'MISSING'}])
        self.catalog_pair(digest, len(payload))
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '0', '--category', 'PSX_GAMES', '--no-progress']
        for status in ('imported', 'present'):
            output = io.StringIO()
            with patch('sys.argv', argv), patch('sys.stdout', new=output), patch.object(acquire, 'request') as request:
                acquire.main()
                request.assert_not_called()
            report_text = (self.work / 'report.json').read_text()
            report = json.loads(report_text)
            licenses = report['licenses']
            self.assertEqual({entry['content_id']: entry['status'] for entry in licenses['entries']},
                             {CONTENT_ID: status, missing_id: 'missing'})
            self.assertEqual(licenses['counts'][status], 1)
            self.assertEqual(licenses['counts']['missing'], 1)
            self.assertEqual(licenses['directory'], str(self.rap_dir))
            self.assertEqual(report['summary']['package_states'], {'already_ingested': 1, 'missing_url': 1})
            self.assertEqual(report['attempted_this_run'], 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary['licenses'], {'directory': str(self.rap_dir), 'counts': licenses['counts']})
            for serialized in (report_text, output.getvalue(), (self.work / 'state.json').read_text()):
                self.assertNotIn(key.hex(), serialized)
                self.assertNotIn('PRIVATE-LICENSE-LINK', serialized)
            self.assertEqual((self.rap_dir / f'{CONTENT_ID}.rap').read_bytes(), key)
            self.assertFalse((self.rap_dir / f'{missing_id}.rap').exists())

    def test_inventory_aggregates_conflicts_across_snapshots_and_skips_malformed_rows(self):
        key = bytes(range(16))
        first = self.snapshot('PSP_GAMES.tsv', [{'Content ID': CONTENT_ID, 'RAP': key.hex()}])
        self.snapshot('PSP_DEMOS.tsv', [{'Content ID': CONTENT_ID, 'RAP': bytes(reversed(key)).hex()}])
        malformed_id = CONTENT_ID[:-1] + 'Q'
        short_id = CONTENT_ID[:-1] + 'R'
        with first.open('a', newline='') as stream:
            writer = csv.writer(stream, delimiter='\t')
            writer.writerow(['TITLE', 'Name', malformed_id, URL, '', '', key.hex(), '', 'EXTRA'])
            writer.writerow(['TITLE', 'Name', short_id, URL, '', '', key.hex()])
        data = acquire.inventory([self.root], self.rap_dir)
        self.assertEqual(data['licenses']['entries'], [{'content_id': CONTENT_ID, 'status': 'conflict'}])
        self.assertEqual(sum('malformed_row' in row['issues'] for row in data['rows']), 2)
        for content_id in (CONTENT_ID, malformed_id, short_id):
            self.assertFalse((self.rap_dir / f'{content_id}.rap').exists())

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
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--no-progress']
        with patch('sys.argv', argv), patch.object(acquire, 'request') as request, patch('sys.stdout', new=io.StringIO()):
            acquire.main()
            request.assert_not_called()
        with patch('sys.argv', argv + ['--limit', '1', '--no-progress']), patch('sys.stdout', new=io.StringIO()), patch.object(acquire, 'request',
                return_value=(Mock(), Response(200, {'Content-Length': str(len(payload))}, [payload]))):
            acquire.main()
        report = json.loads((self.work / 'report.json').read_text())
        self.assertEqual(report['summary']['package_states'], {'pending': 1, 'verified': 1})
        candidate = next(p['id'] for p in report['packages'] if p['status'] == 'verified')
        key = bytes(range(16))
        self.snapshot('PSP_THEMES.tsv', [
            {'Content ID': CONTENT_ID, 'RAP': key.hex(), 'File Size': str(len(payload)), 'SHA256': digest},
            {'File Size': str(len(payload) + 1), 'SHA256': 'b' * 64}])
        with patch('sys.argv', argv + ['--limit', '1', '--package', candidate]), patch('sys.stdout', new=io.StringIO()), patch.object(acquire, 'request') as request:
            acquire.main()
            request.assert_not_called()
        self.assertEqual(json.loads((self.work / 'report.json').read_text())['attempted_this_run'], 0)
        self.assertEqual((self.rap_dir / f'{CONTENT_ID}.rap').read_bytes(), key)

    def test_progress_log_names_each_package_without_polluting_machine_output(self):
        payload = pkg_bytes()
        path = self.snapshot('PSP_THEMES.tsv', [{'Name': 'Patapon 2', 'Content ID': CONTENT_ID,
            'File Size': str(len(payload)), 'SHA256': hashlib.sha256(payload).hexdigest()}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '1']
        out, log = io.StringIO(), io.StringIO()
        with patch('sys.argv', argv), patch('sys.stdout', new=out), patch('sys.stderr', new=log), \
                patch.object(acquire, 'request', return_value=(Mock(), Response(
                    200, {'Content-Length': str(len(payload))}, [payload]))):
            acquire.main()
        # Redirected output stays plain text: startup phases, then a start and a result line.
        lines = [line for line in log.getvalue().splitlines() if line.startswith('[1/1]')]
        self.assertEqual(lines[0], f'[1/1] start Patapon 2 [{CONTENT_ID}] (512 B)')
        self.assertRegex(lines[1], rf'^\[1/1\] verified Patapon 2 \[{CONTENT_ID}\] - 512 B in \d+s at .+/s$')
        self.assertNotIn('\x1b', log.getvalue())
        self.assertEqual(json.loads(out.getvalue())['attempted_this_run'], 1)

    def test_progress_is_silenced_on_request_and_reports_failure_cause(self):
        payload = pkg_bytes()
        path = self.snapshot('PSP_THEMES.tsv', [{'Name': 'Patapon 2', 'File Size': str(len(payload)),
                                                 'SHA256': hashlib.sha256(payload).hexdigest()}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '1']
        for quiet in (False, True):
            log = io.StringIO()
            with self.subTest(quiet=quiet), patch('sys.argv', argv + (['--no-progress'] if quiet else [])), \
                    patch('sys.stdout', new=io.StringIO()), patch('sys.stderr', new=log), \
                    patch.object(acquire, 'request', return_value=(Mock(), Response(404, {}, []))):
                acquire.main()
            if quiet:
                self.assertEqual(log.getvalue(), '')
            else:
                self.assertIn('[1/1] unavailable Patapon 2 [REFERENCE-ID] (HTTP 404)', log.getvalue())

    def test_interrupt_checkpoints_a_resumable_prefix_and_exits_without_traceback(self):
        payload = pkg_bytes(b'y' * 1024)
        digest = hashlib.sha256(payload).hexdigest()
        head, tail = payload[:512], payload[512:]
        path = self.snapshot('PSP_GAMES.tsv', [{'Name': 'Patapon 2', 'File Size': str(len(payload)),
                                                'SHA256': digest}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '1']
        out, log = io.StringIO(), io.StringIO()
        with patch('sys.argv', argv), patch('sys.stdout', new=out), patch('sys.stderr', new=log), \
                patch.object(acquire, 'request', return_value=(Mock(), Response(200, {
                    'Content-Length': str(len(payload)), 'ETag': '"v1"'}, [head, KeyboardInterrupt()]))):
            self.assertEqual(acquire.main(), 130)
        self.assertNotIn('Traceback', log.getvalue())
        self.assertIn('[1/1] interrupted Patapon 2', log.getvalue())
        self.assertTrue(json.loads(out.getvalue())['interrupted'])
        self.assertTrue((self.work / 'report.json').is_file())
        self.assertEqual(list((self.work / 'completed').iterdir()), [])
        entry = next(iter(json.loads((self.work / 'state.json').read_text())['packages'].values()))
        self.assertEqual(entry['status'], 'interrupted')
        self.assertEqual((entry['partial_size'], entry['partial_sha256']),
                         (len(head), hashlib.sha256(head).hexdigest()))
        # The checkpoint exists to be resumed: the next run must transfer only the missing tail.
        with patch('sys.argv', argv), patch('sys.stdout', new=io.StringIO()), \
                patch('sys.stderr', new=io.StringIO()), patch.object(acquire, 'request',
                return_value=(Mock(), Response(206, {'Content-Length': str(len(tail)), 'ETag': '"v1"',
                    'Content-Range': f'bytes {len(head)}-{len(payload) - 1}/{len(payload)}'}, [tail]))):
            self.assertEqual(acquire.main(), 0)
        self.assertEqual((self.work / 'completed' / f'{digest}-{len(payload)}.pkg').read_bytes(), payload)

    def test_local_packages_are_hashed_once_per_run_and_verification_is_reported(self):
        payload = pkg_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        (self.work / 'completed' / f'{digest}-{len(payload)}.pkg').write_bytes(payload)
        path = self.snapshot('PSP_GAMES.tsv', [{'Name': 'Patapon 2', 'File Size': str(len(payload)),
                                                'SHA256': digest}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '0']
        hashed, original = [], acquire.inspect_package
        def counted(target, package, progress=None):
            hashed.append(target.name)
            return original(target, package, progress)
        log = io.StringIO()
        with patch('sys.argv', argv), patch('sys.stdout', new=io.StringIO()), patch('sys.stderr', new=log), \
                patch.object(acquire, 'inspect_package', counted):
            acquire.main()
        # Both reconcile passes see this file; re-reading unchanged bytes is pure NAS/disk cost.
        self.assertEqual(hashed, [f'{digest}-{len(payload)}.pkg'])
        self.assertIn('verifying 1 local package(s)', log.getvalue())
        self.assertTrue((self.work / 'report.json').is_file())

    def test_changed_completed_file_is_rehashed_and_quarantined(self):
        payload = pkg_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        target = self.work / 'completed' / f'{digest}-{len(payload)}.pkg'
        target.write_bytes(payload)
        path = self.snapshot('PSP_GAMES.tsv', [{'File Size': str(len(payload)), 'SHA256': digest}])
        argv = ['psn-acquire', str(path), '--work', str(self.work), '--catalog', str(self.catalog),
                '--rap-dir', str(self.rap_dir), '--limit', '0', '--no-progress']
        data = acquire.inventory([path])
        state = {'version': 1, 'packages': {}}
        cache = {}
        acquire.reconcile(data, state, self.work, {}, None, cache)
        # The cache is keyed by size and mtime, never by name alone: changed bytes must not pass.
        target.write_bytes(payload[:-1] + b'y')
        os.utime(target, ns=(0, 0))
        data = acquire.inventory([path])
        acquire.reconcile(data, state, self.work, {}, None, cache)
        self.assertEqual(list((self.work / 'completed').iterdir()), [])
        self.assertTrue((self.work / 'partial' / f'{target.name}.corrupt').is_file())


if __name__ == '__main__':
    unittest.main()
