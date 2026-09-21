import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from tools import serialstation_acquire as acquire

CONTENT_ID = 'UP0555-NPUF30007_00-BOMBERMAN940EH01'
FIRST = '7029b24c-1c28-480f-94ff-3e6351c77101'
SECOND = 'e7ad0c55-02d3-414e-a4fb-d2254e42c8b8'


def content_page(*ids):
    links = ''.join(f'<tr><td><a href="/pkgs/{pkg_id}/">PKG</a></td></tr>' for pkg_id in ids)
    return (f'<main><h1>{CONTENT_ID}</h1><h5>PKGs with this content ID</h5>'
            f'<table>{links}</table></main>')


def package_page(sha1, size, content_id=CONTENT_ID):
    return (f'<main><h1>PKG <small>{content_id}</small></h1><dl>'
            f'<dt>Size</dt><dd>17.8 MB ({size} bytes)</dd>'
            f'<dt>SHA1</dt><dd>{sha1}</dd><dt>Content ID</dt>'
            f'<dd><a href="/contents/groups/example">{content_id}</a></dd>'
            '<dt>Metadata</dt><dd><dl><dt>Package Size</dt><dd>000012</dd></dl></dd>'
            '</dl></main>')


class AcquisitionTests(unittest.TestCase):
    def test_same_content_id_matches_each_byte_variant_not_first_candidate(self):
        packages = {
            'a' * 64: {'sha1': '1' * 40, 'size_bytes': 100, 'content_id': CONTENT_ID},
            'b' * 64: {'sha1': '2' * 40, 'size_bytes': 200, 'content_id': CONTENT_ID},
            'c' * 64: {'sha1': '1' * 40, 'size_bytes': 101, 'content_id': CONTENT_ID},
        }
        pages = {'/contents/ids/' + CONTENT_ID: content_page(SECOND, FIRST),
                 f'/pkgs/{FIRST}/': package_page('1' * 40, 100),
                 f'/pkgs/{SECOND}/': package_page('2' * 40, 200)}
        with patch.object(acquire, 'fetch_html', side_effect=lambda path, *_: pages[path]):
            entries, missing = acquire.fetch(CONTENT_ID, packages, 1, 0)
        self.assertEqual({key: entry['id'] for key, entry in entries.items()},
                         {'a' * 64: FIRST, 'b' * 64: SECOND})
        self.assertEqual(missing, ['c' * 64])

    def test_observed_sha1_is_left_padded_and_exact_decimal_size_used(self):
        entry = acquire.parse_package(package_page('abcdef012345' * 3, 18637808))
        self.assertEqual(entry, {'sha1': '0000' + 'abcdef012345' * 3,
                                 'size_bytes': 18637808, 'content_id': CONTENT_ID})

    def test_ambiguous_packages_are_errors_not_first_candidate_matches(self):
        package = {'sha1': '1' * 40, 'size_bytes': 100, 'content_id': CONTENT_ID}
        with patch.object(acquire, 'fetch_html', side_effect=[
                content_page(FIRST, SECOND), package_page('1' * 40, 100), package_page('1' * 40, 100)]):
            with self.assertRaises(acquire.AcquisitionError):
                acquire.fetch(CONTENT_ID, {'a' * 64: package}, 1, 0)

    def test_challenges_and_malformed_package_pages_are_not_misses(self):
        package = {'sha1': '1' * 40, 'size_bytes': 100, 'content_id': CONTENT_ID}
        for pages in (["<html><title>Just a moment...</title></html>"],
                      [content_page(FIRST), package_page('1' * 41, 100)],
                      [content_page(FIRST), package_page('1' * 40, 100).replace('(100 bytes)', '')]):
            with self.subTest(pages=pages), patch.object(acquire, 'fetch_html', side_effect=pages):
                with self.assertRaises(acquire.AcquisitionError):
                    acquire.fetch(CONTENT_ID, {'a' * 64: package}, 1, 0)

    def test_only_strict_same_origin_package_links_supply_candidates(self):
        html = content_page(FIRST).replace('</table>',
            f'<a href="https://elsewhere.invalid/pkgs/{SECOND}/">External</a>'
            f'<a href="https://serialstation.com.evil.invalid/pkgs/{SECOND}/">Spoof</a></table>')
        self.assertEqual(acquire.candidate_ids(html, CONTENT_ID), [FIRST])
        with self.assertRaises(acquire.AcquisitionError):
            acquire.candidate_ids(content_page(FIRST).replace(f'{FIRST}/', f'{FIRST}/?other=1'), CONTENT_ID)

    def test_http_errors_and_redirects_cannot_become_missing_or_forward_clearance(self):
        for code in (403, 429, 500):
            error = urllib.error.HTTPError(acquire.ORIGIN, code, 'unavailable', {}, None)
            with self.subTest(code=code), patch.object(acquire.urllib.request.OpenerDirector, 'open', side_effect=error):
                with self.assertRaises(acquire.AcquisitionError):
                    acquire.fetch_html('/contents/ids/' + CONTENT_ID, 1, 0)
        with self.assertRaises(acquire.AcquisitionError):
            acquire.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid/')
        error = urllib.error.HTTPError(acquire.ORIGIN, 404, 'not found', {}, None)
        with patch.object(acquire.urllib.request.OpenerDirector, 'open', side_effect=error):
            self.assertIsNone(acquire.fetch_html('/contents/ids/' + CONTENT_ID, 1, 0))
        challenge = urllib.error.HTTPError(acquire.ORIGIN, 404, 'challenge',
                                           {'cf-mitigated': 'challenge'}, None)
        with patch.object(acquire.urllib.request.OpenerDirector, 'open', side_effect=challenge):
            with self.assertRaises(acquire.AcquisitionError):
                acquire.fetch_html('/contents/ids/' + CONTENT_ID, 1, 0)

    def test_incremental_snapshot_and_failed_refresh_preserve_exact_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            catalog = root / 'catalog' / 'pkg' / 'v1'
            catalog.mkdir(parents=True)
            digest = 'a' * 64
            record = {'kind': 'pkg', 'sha256': digest, 'sha1': '1', 'size_bytes': 100,
                      'metadata': {'content_id': CONTENT_ID}}
            (catalog / 'pkg.json').write_text(json.dumps(record))
            output = root / 'matches.json'
            argv = ['serialstation-acquire', '--catalog', str(root / 'catalog'), '--output', str(output)]
            with patch('sys.argv', argv), patch('sys.stderr', new=io.StringIO()), \
                    patch.object(acquire, 'fetch_html', side_effect=[content_page(FIRST), package_page('1', 100)]):
                self.assertEqual(acquire.main(), 0)
            with patch('sys.argv', argv), patch('sys.stderr', new=io.StringIO()), \
                    patch.object(acquire, 'fetch_html', side_effect=AssertionError('unexpected request')):
                self.assertEqual(acquire.main(), 0)
            self.assertEqual(json.loads(output.read_bytes())['entries'][digest]['id'], FIRST)
            saved = output.read_bytes()
            with patch('sys.argv', argv + ['--refresh']), patch('sys.stderr', new=io.StringIO()), \
                    patch.object(acquire, 'fetch_html', side_effect=acquire.AcquisitionError('HTTP 403')):
                self.assertEqual(acquire.main(), 1)
            self.assertEqual(output.read_bytes(), saved)
            old = {'schema_version': 1, 'entries': {}, 'missing': []}
            output.write_text(json.dumps(old))
            with self.assertRaises(acquire.AcquisitionError):
                acquire.load_snapshot(output)
            with patch('sys.argv', argv + ['--refresh']), patch('sys.stderr', new=io.StringIO()), \
                    patch.object(acquire, 'fetch_html', return_value=None):
                self.assertEqual(acquire.main(), 0)
            self.assertEqual(json.loads(output.read_bytes())['missing'], [digest])


if __name__ == '__main__':
    unittest.main()
