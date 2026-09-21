"""Resolve catalog PKGs to observed, byte-specific SerialStation package pages.

Content-ID pages supply candidate links, never matches. Each candidate must have
an exact SHA1, byte size and content ID match. Only genuine 404s or successfully
parsed pages without a matching package become misses; errors leave the previous
snapshot untouched. Re-runs reuse schema-2 results keyed by local PKG SHA256.
"""
import argparse
import http.client
import json
import math
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ORIGIN = 'https://serialstation.com'
CONTENT_ID = re.compile(r'[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Za-z0-9_-]{16}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SHA1 = re.compile(r'[0-9a-f]{40}\Z')
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
PKG_PATH = re.compile(r'/pkgs/(' + UUID + r')/\Z')
USER_AGENT = 'pspdb-serialstation-acquire/2 (+https://github.com/ryp/pspdb)'
RESPONSE_LIMIT = 2 * 1024 * 1024
CANDIDATE_LIMIT = 256


class AcquisitionError(Exception):
    pass


def normalize_sha1(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{1,40}', value):
        raise AcquisitionError('Invalid SHA1')
    return value.lower().zfill(40)


def valid_identity(entry):
    return (isinstance(entry, dict)
            and isinstance(entry.get('sha1'), str) and SHA1.fullmatch(entry['sha1'])
            and type(entry.get('size_bytes')) is int and entry['size_bytes'] > 0
            and isinstance(entry.get('content_id'), str)
            and CONTENT_ID.fullmatch(entry['content_id']))


def identity(entry):
    return entry['sha1'], entry['size_bytes'], entry['content_id']


def catalog_packages(catalog):
    """Deduplicate versioned ingest records by their local package SHA256."""
    folder = Path(catalog) / 'pkg'
    if not folder.is_dir():
        raise AcquisitionError(f'No PKG records to resolve: {folder}')
    found = {}
    for path in sorted(folder.glob('**/*.json')):
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise AcquisitionError(f'Unreadable catalog record {path}') from error
        if not isinstance(record, dict):
            raise AcquisitionError(f'Malformed catalog record {path}')
        if record.get('kind') != 'pkg':
            continue
        metadata = record.get('metadata')
        entry = {'sha1': normalize_sha1(record.get('sha1')),
                 'size_bytes': record.get('size_bytes'),
                 'content_id': metadata.get('content_id') if isinstance(metadata, dict) else None}
        digest = record.get('sha256')
        if not isinstance(digest, str) or not SHA256.fullmatch(digest) or not valid_identity(entry):
            raise AcquisitionError(f'Invalid PKG identity: {path}')
        if digest in found and found[digest] != entry:
            raise AcquisitionError(f'Conflicting catalog identities for {digest}')
        found[digest] = entry
    return found


def load_snapshot(path):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as error:
        raise AcquisitionError(f'Unreadable snapshot {path}') from error
    if not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 2:
        raise AcquisitionError(f'Unsupported snapshot schema: {path}; use --refresh')
    entries, missing = data.get('entries'), data.get('missing')
    if not isinstance(entries, dict) or not isinstance(missing, list):
        raise AcquisitionError(f'Malformed snapshot: {path}')
    matches, ids = {}, {}
    for digest, entry in entries.items():
        if (not SHA256.fullmatch(digest) or not valid_identity(entry)
                or not isinstance(entry.get('id'), str) or not re.fullmatch(UUID, entry['id'])
                or not isinstance(entry.get('name'), str) or not entry['name'].strip()):
            raise AcquisitionError(f'Invalid snapshot entry: {path}')
        key = identity(entry)
        if key in matches and matches[key] != entry['id']:
            raise AcquisitionError(f'Ambiguous snapshot identity: {path}')
        if entry['id'] in ids and ids[entry['id']] != key:
            raise AcquisitionError(f'Conflicting snapshot package: {path}')
        matches[key], ids[entry['id']] = entry['id'], key
    if any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in missing):
        raise AcquisitionError(f'Invalid snapshot misses: {path}')
    if len(set(missing)) != len(missing) or set(entries).intersection(missing):
        raise AcquisitionError(f'Conflicting snapshot results: {path}')
    return entries, missing


def validate_disc_fields(data):
    """Validate the optional disc index shared by both snapshot acquirers."""
    fields = {key: data[key] for key in ('discs', 'disc_index_complete', 'discs_retrieved') if key in data}
    discs = fields.get('discs', {})
    if not isinstance(discs, dict):
        raise AcquisitionError('Invalid SerialStation disc index')
    for redump_id, matches in discs.items():
        if not isinstance(redump_id, str) or not re.fullmatch(r'[1-9][0-9]*', redump_id):
            raise AcquisitionError('Invalid Redump ID in SerialStation disc index')
        if not isinstance(matches, list) or not matches:
            raise AcquisitionError(f'Invalid SerialStation disc matches for {redump_id}')
        seen = set()
        for match in matches:
            if (not isinstance(match, dict) or not isinstance(match.get('id'), str)
                    or not re.fullmatch(UUID, match['id'])
                    or not isinstance(match.get('name'), str) or not match['name'].strip()
                    or match['id'] in seen):
                raise AcquisitionError(f'Invalid SerialStation disc entry for {redump_id}')
            seen.add(match['id'])
    if 'disc_index_complete' in fields and type(fields['disc_index_complete']) is not bool:
        raise AcquisitionError('Invalid SerialStation disc completeness flag')
    if 'discs_retrieved' in fields and (
            not isinstance(fields['discs_retrieved'], str) or not fields['discs_retrieved'].strip()):
        raise AcquisitionError('Invalid SerialStation disc retrieval timestamp')
    return fields


class PageParser(HTMLParser):
    """Collect headings, links and paired dt/dd values, keeping nested DLs separate."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_main = False
        self.complete = False
        self.headings = []
        self.heading = None
        self.links = []
        self.definitions = []
        self.dls = []
        self.tables = 0

    def handle_starttag(self, tag, attrs):
        if tag == 'main':
            if self.in_main or self.complete:
                raise AcquisitionError('Malformed page main element')
            self.in_main = True
        if not self.in_main:
            return
        if tag in ('h1', 'h5'):
            self.heading = (tag, [])
        elif tag == 'a':
            self.links.extend(value for name, value in attrs if name == 'href' and value)
        elif tag == 'dl':
            self.dls.append({'term': None, 'kind': None, 'text': []})
        elif tag in ('dt', 'dd'):
            if not self.dls or self.dls[-1]['kind'] is not None:
                raise AcquisitionError('Malformed page definition list')
            current = self.dls[-1]
            if tag == 'dd' and current['term'] is None:
                raise AcquisitionError('Unpaired page definition')
            current['kind'], current['text'] = tag, []

    def handle_data(self, data):
        if self.in_main and self.heading is not None:
            self.heading[1].append(data)
        if self.in_main and self.dls and self.dls[-1]['kind'] is not None:
            self.dls[-1]['text'].append(data)

    def handle_endtag(self, tag):
        if not self.in_main:
            return
        if tag == 'main':
            if self.dls or self.heading is not None:
                raise AcquisitionError('Incomplete page details')
            self.in_main, self.complete = False, True
        elif tag in ('h1', 'h5') and self.heading is not None:
            if self.heading[0] != tag:
                raise AcquisitionError('Malformed page heading')
            self.headings.append((tag, ' '.join(''.join(self.heading[1]).split())))
            self.heading = None
        elif tag == 'table':
            self.tables += 1
        elif tag in ('dt', 'dd'):
            if not self.dls or self.dls[-1]['kind'] != tag:
                raise AcquisitionError('Malformed page definition list')
            current = self.dls[-1]
            text = ' '.join(''.join(current['text']).split())
            if tag == 'dt':
                current['term'] = text
            else:
                self.definitions.append((current['term'], text))
                current['term'] = None
            current['kind'] = None
        elif tag == 'dl':
            if not self.dls or self.dls[-1]['kind'] is not None or self.dls[-1]['term'] is not None:
                raise AcquisitionError('Incomplete page definition list')
            self.dls.pop()


def parse_page(html):
    page = PageParser()
    page.feed(html)
    page.close()
    if not page.complete or page.in_main:
        raise AcquisitionError('Not a complete SerialStation detail page (possibly a challenge)')
    return page


def candidate_ids(html, content_id):
    page = parse_page(html)
    if (('h1', content_id) not in page.headings
            or ('h5', 'PKGs with this content ID') not in page.headings or not page.tables):
        raise AcquisitionError(f'Unexpected content-ID page for {content_id}')
    found = set()
    for href in page.links:
        url = urllib.parse.urlsplit(urllib.parse.urljoin(ORIGIN, href))
        if url.scheme != 'https' or url.netloc != 'serialstation.com':
            continue
        if not url.path.startswith('/pkgs/'):
            continue
        match = PKG_PATH.fullmatch(url.path)
        if not match or url.query or url.fragment:
            raise AcquisitionError(f'Malformed PKG link for {content_id}')
        found.add(match[1])
    if len(found) > CANDIDATE_LIMIT:
        raise AcquisitionError(f'Too many PKG candidates for {content_id}')
    return sorted(found)


def parse_package(html):
    page = parse_page(html)
    if not any(tag == 'h1' and text.startswith('PKG ') for tag, text in page.headings):
        raise AcquisitionError('Unexpected PKG page')
    fields = {}
    for term, text in page.definitions:
        if term not in ('SHA1', 'Size', 'Content ID'):
            continue
        if term in fields:
            raise AcquisitionError(f'Duplicate PKG field: {term}')
        fields[term] = text
    if set(fields) != {'SHA1', 'Size', 'Content ID'}:
        raise AcquisitionError('Missing PKG identity fields')
    size = re.fullmatch(r'(?:[^()]+\s)?\(([0-9]+) bytes\)', fields['Size'])
    if not size:
        raise AcquisitionError('PKG page lacks exact byte size')
    entry = {'sha1': normalize_sha1(fields['SHA1']), 'size_bytes': int(size[1]),
             'content_id': fields['Content ID']}
    if not valid_identity(entry):
        raise AcquisitionError('Invalid PKG identity fields')
    return entry


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the optional browser clearance to another URL.
        raise AcquisitionError('SerialStation redirected a detail request')


def fetch_html(path, timeout, retries):
    if not (PKG_PATH.fullmatch(path)
            or re.fullmatch(r'/discs/' + UUID, path)
            or re.fullmatch(r'/ajax/table/discs\?systems=ab637dee-0616-4bc1-87aa-9853f38d5e73&page=[1-9][0-9]*', path)
            or (path.startswith('/contents/ids/')
                and CONTENT_ID.fullmatch(path[len('/contents/ids/'):]))):
        raise AcquisitionError('Refusing non-reference SerialStation request')
    headers = {'User-Agent': os.environ.get('SERIALSTATION_USER_AGENT', USER_AGENT),
               'Accept': 'text/html'}
    cookie = os.environ.get('SERIALSTATION_COOKIE')
    if cookie:
        headers['Cookie'] = cookie
    if any('\r' in value or '\n' in value for value in headers.values()):
        raise AcquisitionError('Invalid SerialStation request header')
    if any(not value.isascii() for value in headers.values()):
        raise AcquisitionError('Invalid SerialStation request header')
    request = urllib.request.Request(ORIGIN + path, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(retries + 1):
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.headers.get('cf-mitigated') == 'challenge':
                    raise AcquisitionError(f'{path}: challenge response')
                if response.status != 200:
                    raise AcquisitionError(f'{path}: unexpected HTTP {response.status}')
                if response.headers.get_content_type() != 'text/html':
                    raise AcquisitionError(f'{path}: expected HTML')
                body = response.read(RESPONSE_LIMIT + 1)
            if len(body) > RESPONSE_LIMIT:
                raise AcquisitionError(f'{path}: oversized HTML response')
            try:
                return body.decode('utf-8')
            except UnicodeError as error:
                raise AcquisitionError(f'{path}: invalid HTML encoding') from error
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            if error.headers and error.headers.get('cf-mitigated') == 'challenge':
                raise AcquisitionError(f'{path}: challenge response') from error
            if code == 404:
                return None
            if (code != 429 and not 500 <= code < 600) or attempt == retries:
                raise AcquisitionError(f'{path}: HTTP {code}') from error
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            if attempt == retries:
                raise AcquisitionError(f'{path}: network request failed') from error
        time.sleep(min(2 ** min(attempt, 5), 30))
    raise AcquisitionError(f'{path}: exhausted retries')


def fetch(content_id, packages, timeout, retries):
    """Resolve all local byte variants of one content ID from one candidate list."""
    html = fetch_html('/contents/ids/' + content_id, timeout, retries)
    observed = {}
    if html is not None:
        for pkg_id in candidate_ids(html, content_id):
            package_html = fetch_html('/pkgs/' + pkg_id + '/', timeout, retries)
            if package_html is None:
                continue
            entry = parse_package(package_html)
            key = identity(entry)
            if key in observed and observed[key]['id'] != pkg_id:
                raise AcquisitionError(f'Ambiguous PKG identity for {content_id}')
            observed[key] = dict(entry, id=pkg_id, name=entry['content_id'])
    entries, missing = {}, []
    for digest, package in packages.items():
        entry = observed.get(identity(package))
        if entry is None:
            missing.append(digest)
        else:
            entries[digest] = entry
    return entries, missing


def write_snapshot(path, entries, missing, *, disc_fields=None):
    payload = {'schema_version': 2,
               'retrieved': datetime.now(timezone.utc).isoformat(timespec='seconds'),
               'entries': dict(sorted(entries.items())), 'missing': sorted(missing)}
    path = Path(path)
    if disc_fields is None:
        try:
            previous = json.loads(path.read_text(encoding='utf-8'))
        except (FileNotFoundError, ValueError):
            previous = {}
        disc_fields = validate_disc_fields(previous) if isinstance(previous, dict) and previous.get('schema_version') == 2 else {}
    payload.update(validate_disc_fields(disc_fields))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--catalog', default='catalog', help='Catalog directory holding PKG records')
    parser.add_argument('--output', required=True, help='Snapshot JSON to create or update')
    parser.add_argument('--refresh', action='store_true', help='Re-query all PKGs, ignoring any old snapshot')
    parser.add_argument('--workers', type=int, default=4, help='Concurrent content-ID lookups, 1–32 (default: 4)')
    parser.add_argument('--timeout', type=float, default=30.0, help='Per-request timeout in seconds')
    parser.add_argument('--retries', type=int, default=3, help='Retries for network errors, 429 and 5xx responses')
    args = parser.parse_args()
    if not 1 <= args.workers <= 32:
        parser.error('--workers must be between 1 and 32')
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.retries < 0:
        parser.error('--timeout must be finite and positive and --retries must be nonnegative')
    try:
        packages = catalog_packages(args.catalog)
        entries, missing = ({}, []) if args.refresh else load_snapshot(args.output)
        entries = {digest: entry for digest, entry in entries.items() if digest in packages}
        missing = [digest for digest in missing if digest in packages]
        for digest, entry in entries.items():
            if identity(entry) != identity(packages[digest]):
                raise AcquisitionError(f'Snapshot/catalog identity conflict for {digest}; use --refresh')
        known = set(entries) | set(missing)
        pending = {}
        for digest, package in packages.items():
            if digest not in known:
                pending.setdefault(package['content_id'], {})[digest] = package
        print(f'{len(packages)} catalog PKGs, {sum(map(len, pending.values()))} to resolve '
              f'across {len(pending)} content IDs', file=sys.stderr)
        with ThreadPoolExecutor(args.workers) as pool:
            try:
                for found, absent in pool.map(
                        lambda cid: fetch(cid, pending[cid], args.timeout, args.retries), pending):
                    entries.update(found)
                    missing.extend(absent)
            except BaseException:
                pool.shutdown(wait=True, cancel_futures=True)
                raise
        matches, ids = {}, {}
        for entry in entries.values():
            key = identity(entry)
            if key in matches and matches[key] != entry['id']:
                raise AcquisitionError('New observation conflicts with retained package; use --refresh')
            if entry['id'] in ids and ids[entry['id']] != key:
                raise AcquisitionError('New observation conflicts with retained identity; use --refresh')
            matches[key], ids[entry['id']] = entry['id'], key
        write_snapshot(args.output, entries, missing)
        print(f'{len(entries)} present, {len(missing)} absent -> {args.output}', file=sys.stderr)
    except (AcquisitionError, OSError) as error:
        print(f'serialstation-acquire: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
