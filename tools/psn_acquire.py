"""Inventory PSP/PSX TSV snapshots and acquire bounded public Sony packages.

With no local snapshots, fetch the current PSP/PSX TSVs from NoPayStation.
PKG downloads require --limit N. This does not run ingestion or write the catalog.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
import time
from urllib.parse import urlsplit

if __package__:
    from .rap import import_raps, license_directory
else:
    from rap import import_raps, license_directory

HASH = re.compile(r'[0-9a-fA-F]{64}\Z')
SNAPSHOT = re.compile(r'(PSP_(?:GAMES|DEMOS|DLCS|THEMES|UPDATES)|PSX_GAMES)(?:\(\d+\))?\.tsv\Z', re.I)
SNAPSHOT_CATEGORIES = ('PSP_GAMES', 'PSP_DEMOS', 'PSP_DLCS', 'PSP_THEMES', 'PSP_UPDATES', 'PSX_GAMES')
SNAPSHOT_BASE = 'https://nopaystation.com/tsv/'
SNAPSHOT_LIMIT = 16 * 1024 * 1024
HOST_PATHS = {
    'zeus.dl.playstation.net': re.compile(r'/cdn/[A-Za-z0-9_./-]+\.pkg'),
    'b0.ww.np.dl.playstation.net': re.compile(r'/tppkg/np/[A-Za-z0-9_./-]+\.pkg'),
}
CHUNK = 1024 * 1024
FIELDS = {'Title ID': 'title_id', 'Region': 'region', 'Name': 'name',
          'Content ID': 'content_id', 'Last Modification Date': 'modified',
          'Type': 'type', 'Original Name': 'original_name'}


class AcquisitionError(Exception):
    def __init__(self, status, detail, observed=None):
        super().__init__(detail)
        self.status = status
        self.observed = observed


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def safe_url(url):
    """Reject credentials, private hosts, query strings and non-package paths."""
    try:
        parts = urlsplit(url)
        if (parts.scheme not in ('http', 'https') or
                parts.username is not None or parts.password is not None or
                parts.port is not None or parts.query or parts.fragment or
                '..' in parts.path or any(ord(c) <= 32 for c in url)):
            raise ValueError
    except ValueError:
        raise ValueError('unsafe_url') from None
    if parts.hostname == 'ares.dl.playstation.net':
        raise ValueError('unsupported_host')
    pattern = HOST_PATHS.get(parts.hostname)
    if pattern is None or not pattern.fullmatch(parts.path):
        raise ValueError('unsafe_url')
    return parts


def public_connection(address, timeout=30, source_address=None):
    """Connect directly to a validated DNS answer, preventing a second DNS lookup."""
    host, port = address
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        raise AcquisitionError('unsafe_url', 'DNS contains a non-public address')
    last = None
    for family, kind, proto, _, target in answers:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(target)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last


def request(url, headers, timeout):
    parts = safe_url(url)
    cls = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
    connection = cls(parts.hostname, timeout=timeout)
    connection._create_connection = public_connection
    try:
        connection.request('GET', parts.path, headers=headers)
        return connection, connection.getresponse()
    except BaseException:
        connection.close()
        raise


def fetch_snapshots(work, timeout):
    """Validate a fresh batch before replacing the private local TSV cache."""
    cache = work / 'snapshots'
    cache.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.snapshots-', dir=work) as temporary:
        staged = Path(temporary)
        for category in SNAPSHOT_CATEGORIES:
            filename = category + '.tsv'
            connection = http.client.HTTPSConnection('nopaystation.com', timeout=timeout)
            connection._create_connection = public_connection
            try:
                connection.request('GET', '/tsv/' + filename,
                                   headers={'User-Agent': 'pspdb-psn-acquire/1', 'Accept-Encoding': 'identity'})
                response = connection.getresponse()
                if response.status != 200:
                    raise ValueError(f'TSV fetch {filename}: HTTP {response.status}; cached snapshots were not used')
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise ValueError(f'TSV fetch {filename}: unexpected content encoding')
                length = response.getheader('Content-Length')
                if length is not None and (not length.isascii() or not length.isdigit() or int(length) > SNAPSHOT_LIMIT):
                    raise ValueError(f'TSV fetch {filename}: invalid or excessive content length')
                received = 0
                fd = os.open(staged / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    while block := response.read(min(CHUNK, SNAPSHOT_LIMIT + 1 - received)):
                        received += len(block)
                        if received > SNAPSHOT_LIMIT:
                            raise ValueError(f'TSV fetch {filename}: exceeds snapshot size limit')
                        stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
                if length is not None and received != int(length):
                    raise ValueError(f'TSV fetch {filename}: truncated response')
            except (OSError, http.client.HTTPException) as exc:
                # Do not log response bodies or server-controlled exception text.
                raise ValueError(f'TSV fetch {filename}: {type(exc).__name__}; cached snapshots were not used') from None
            finally:
                connection.close()
        try:
            data = inventory([staged])
            if any('malformed_row' in row['issues'] for row in data['rows']):
                raise ValueError('Malformed TSV rows')
        except (ValueError, csv.Error):
            raise ValueError('Fetched TSVs have invalid UTF-8, headers, or rows; cached snapshots were not replaced') from None
        paths = []
        for category in SNAPSHOT_CATEGORIES:
            target = cache / (category + '.tsv')
            (staged / target.name).replace(target)
            paths.append(target)
    return paths


def inventory(inputs, rap_directory=None):
    paths = set()
    for item in inputs:
        item = Path(item).expanduser()
        if not item.exists():
            raise ValueError(f'Snapshot input does not exist: {item}')
        if item.is_dir():
            paths.update(p.resolve() for p in item.iterdir() if p.is_file() and SNAPSHOT.fullmatch(p.name))
        elif SNAPSHOT.fullmatch(item.name):
            paths.add(item.resolve())
        else:
            raise ValueError(f'Not an in-scope PSP/PSX snapshot filename: {item.name}')
    if not paths:
        raise ValueError('No in-scope PSP/PSX TSV snapshots found')
    snapshots, rows, packages = {}, [], {}
    licenses = [] if rap_directory is not None else None
    for path in sorted(paths):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        category = SNAPSHOT.fullmatch(path.name)[1].upper()
        origin = {'path': str(path), 'category': category, 'status': None}
        if digest in snapshots:
            snapshots[digest]['origins'].append(origin)
            continue
        # DictReader fields are never serialized: RAP/zRIF/license columns stay private.
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''), delimiter='\t')
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)) or not {'PKG direct link', 'File Size', 'SHA256'} <= set(headers):
            raise ValueError(f'Unsupported TSV header: {path}')
        snapshot = {'sha256': digest, 'size_bytes': len(raw), 'origins': [origin], 'rows': 0}
        snapshots[digest] = snapshot
        for number, source in enumerate(reader, 2):
            issues = []
            if None in source or any(value is None for value in source.values()):
                issues.append('malformed_row')
            elif licenses is not None:
                licenses.append((source.get('Content ID', ''), source.get('RAP', '')))
            values = {key: (value or '').strip() for key, value in source.items() if key is not None}
            row = {name: values.get(key) or None for key, name in FIELDS.items()}
            row.update(id=f'{digest}:{number}', snapshot=digest, row=number)
            url = values.get('PKG direct link', '')
            missing = url.upper() in ('', 'MISSING', 'N/A', 'NULL')
            row['url_present'] = not missing
            row['url'] = None
            if not missing:
                try:
                    safe_url(url)
                    row['url'] = url
                except ValueError as exc:
                    issues.append(str(exc))
                    # A digest retains distinctions without leaking rejected URL secrets.
                    row['rejected_url_sha256'] = hashlib.sha256(url.encode()).hexdigest()
            size, sha = values.get('File Size', ''), values.get('SHA256', '')
            row['expected_size'] = int(size) if size.isascii() and size.isdigit() else None
            row['expected_sha256'] = sha.lower() if HASH.fullmatch(sha) else None
            if size and row['expected_size'] is None:
                issues.append('invalid_size')
            if sha and row['expected_sha256'] is None:
                issues.append('invalid_sha256')
            row['issues'] = issues
            # Exact hash+size can deduplicate mirrors; weaker references never inherit
            # stronger constraints or merge on a title/content ID alone.
            identity = ([row['expected_sha256'], row['expected_size']]
                        if row['expected_sha256'] and row['expected_size'] is not None else
                        [row['url'], row.get('rejected_url_sha256'), row['expected_sha256'], row['expected_size']])
            if not row['url']:
                identity.append(row['id'])
            key = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
            row['package'] = key
            package = packages.setdefault(key, {'id': key, 'expected_sha256': row['expected_sha256'],
                'expected_size': row['expected_size'], 'urls': [], 'references': [], 'issues': [], 'conflicts': []})
            if row['url'] and row['url'] not in package['urls']:
                package['urls'].append(row['url'])
            package['references'].append(row['id'])
            package['issues'] = sorted(set(package['issues']) | set(issues))
            rows.append(row)
            snapshot['rows'] += 1
    conflicts = []
    for field in ('url', 'content_id'):
        groups = defaultdict(list)
        for row in rows:
            if row[field]:
                groups[row[field]].append(row)
        for value, members in sorted(groups.items()):
            differing = [field_name for field_name in ('expected_sha256', 'expected_size')
                         if len({r[field_name] for r in members if r[field_name] is not None}) > 1]
            if not differing:
                continue
            conflict = {'field': field, 'value': value, 'differing': differing,
                        'references': [r['id'] for r in members]}
            index = len(conflicts)
            conflicts.append(conflict)
            for key in {r['package'] for r in members}:
                packages[key]['conflicts'].append(index)
    data = {'snapshots': list(snapshots.values()), 'rows': rows,
            'packages': sorted(packages.values(), key=lambda p: p['id']), 'conflicts': conflicts}
    if licenses is not None:
        data['licenses'] = import_raps(rap_directory, licenses)
    return data


def catalog_identities(root):
    """Only complete PKG pairs with exact byte identity; no title/content-ID joins."""
    if not root.is_dir():
        raise ValueError(f'Catalog directory does not exist: {root}')
    identities = {}
    for path in sorted((root / 'pkg').glob('v*/*-ingest.json')):
        match = re.fullmatch(r'v([1-9][0-9]*)', path.parent.name)
        digest = path.name.removesuffix('-ingest.json')
        if not match or not HASH.fullmatch(digest):
            continue
        partner = path.with_name(digest + '-tree.json')
        if not partner.is_file():
            continue
        record, tree = json.loads(path.read_text()), json.loads(partner.read_text())
        size = record.get('size_bytes')
        if (record.get('kind') != 'pkg' or tree.get('kind') != 'tree' or
                any(v.get('schema_version') != 1 or v.get('sha256') != digest for v in (record, tree)) or
                type(size) is not int or size < 0 or tree.get('size_bytes') != size or
                tree.get('extractor', {}).get('version') != match[1] or not isinstance(tree.get('entries'), list)):
            raise ValueError(f'Invalid PKG catalog pair: {path}')
        identity = (digest, size)
        revision = int(match[1])
        if revision > identities.get(identity, {}).get('revision', 0):
            identities[identity] = {'revision': revision, 'record': str(path),
                                    'content_id': record.get('metadata', {}).get('content_id')}
    return identities


def inspect_package(path, package):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        header = stream.read(128)
        if len(header) < 128 or header[:4] != b'\x7fPKG':
            raise AcquisitionError('unsupported_format', 'Not a complete PKG header')
        digest.update(header)
        size = len(header)
        while block := stream.read(CHUNK):
            size += len(block)
            digest.update(block)
    sha = digest.hexdigest()
    observed = {'sha256': sha, 'size_bytes': size, 'pkg_magic': True,
                'content_id': header[48:96].split(b'\0', 1)[0].decode('ascii', errors='replace') or None,
                'key_type': header[7],
                'hash_confirmed': package['expected_sha256'] == sha,
                'size_confirmed': package['expected_size'] == size}
    if int.from_bytes(header[24:32], 'big') != size:
        raise AcquisitionError('integrity_mismatch', 'PKG header total size differs from observed bytes', observed)
    if package['expected_size'] is not None and size != package['expected_size']:
        raise AcquisitionError('integrity_mismatch', 'Reference size differs from observed bytes', observed)
    if package['expected_sha256'] is not None and sha != package['expected_sha256']:
        raise AcquisitionError('integrity_mismatch', 'Reference SHA-256 differs from observed bytes', observed)
    return observed


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capacity(directory, floor, needed=0):
    if shutil.disk_usage(directory).free - needed < floor:
        raise AcquisitionError('capacity_blocked', 'Free-space floor would be crossed')


def download(package, work, state, save, timeout, retries, floor):
    part = work / 'partial' / (package['id'] + '.part')
    completed = work / 'completed'
    url = package['urls'][0]
    for attempt in range(retries + 1):
        connection = None
        try:
            offset = part.stat().st_size if part.exists() else 0
            # Both remote identity and the saved local prefix must still match.
            # An uncheckpointed process crash safely restarts instead of guessing.
            etag = state.get('etag')
            if offset and (not etag or state.get('url') != url or
                           state.get('partial_size') != offset or
                           state.get('partial_sha256') != file_hash(part)):
                part.unlink()
                offset = 0
            headers = {'User-Agent': 'pspdb-psn-acquire/1', 'Accept-Encoding': 'identity'}
            if offset:
                headers.update(Range=f'bytes={offset}-', **{'If-Range': etag})
            expected = package['expected_size']
            capacity(work, floor, max(0, expected - offset) if expected is not None else CHUNK)
            connection, response = request(url, headers, timeout)
            if response.status not in (200, 206):
                status = 'unavailable' if response.status in (401, 403, 404, 410) else 'network_failure'
                # No redirects are followed, even to another public host.
                if 300 <= response.status < 400:
                    status = 'redirect_blocked'
                raise AcquisitionError(status, f'HTTP {response.status}')
            if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                raise AcquisitionError('integrity_mismatch', 'Unexpected HTTP content encoding')
            length = response.getheader('Content-Length')
            if length is not None and not re.fullmatch(r'[0-9]+', length):
                raise AcquisitionError('integrity_mismatch', 'Invalid HTTP content length')
            length = int(length) if length is not None else None
            total = length
            if response.status == 206:
                match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.getheader('Content-Range', ''))
                if (not offset or not match or int(match[1]) != offset or
                        int(match[2]) + 1 != int(match[3]) or
                        response.getheader('ETag') != etag):
                    raise AcquisitionError('integrity_mismatch', 'Invalid or changed ranged response')
                total = int(match[3])
                if length is not None and length != total - offset:
                    raise AcquisitionError('integrity_mismatch', 'Ranged response length mismatch')
            else:
                offset = 0
            if expected is not None and total is not None and total != expected:
                raise AcquisitionError('integrity_mismatch', 'HTTP size differs from reference')
            capacity(work, floor, max(0, total - offset) if total is not None else CHUNK)
            validator = response.getheader('ETag', '')
            state.pop('partial_sha256', None)
            state.pop('partial_size', None)
            state.update(status='downloading', url=url,
                         etag=validator if re.fullmatch(r'"[^"\r\n]*"', validator) else None)
            save()
            received = offset
            with part.open('ab' if offset else 'wb') as stream:
                while block := response.read(CHUNK):
                    received += len(block)
                    if ((total is not None and received > total) or
                            (expected is not None and received > expected)):
                        raise AcquisitionError('integrity_mismatch', 'HTTP body exceeds declared size')
                    capacity(work, floor, len(block))
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
            if total is not None and received != total:
                raise AcquisitionError('network_failure', 'Truncated HTTP body')
            observed = inspect_package(part, package)
            target = completed / f"{observed['sha256']}-{observed['size_bytes']}.pkg"
            part.replace(target)
            state.clear()
            state.update(status='verified', observed=observed, file=target.name, url=url, verified_at=now())
            save()
            return
        except (OSError, http.client.HTTPException, AcquisitionError) as exc:
            status = exc.status if isinstance(exc, AcquisitionError) else 'network_failure'
            # Never persist raw network exceptions: they may contain server-controlled data.
            detail = str(exc) if isinstance(exc, AcquisitionError) else type(exc).__name__
            state.update(status=status, detail=detail, attempted_at=now())
            if isinstance(exc, AcquisitionError) and exc.observed:
                state['mismatch_observed'] = exc.observed
            if status in ('integrity_mismatch', 'unsupported_format') and part.exists():
                part.unlink()
                state.pop('etag', None)
            elif part.exists():
                state['partial_size'] = part.stat().st_size
                state['partial_sha256'] = file_hash(part)
            save()
            if status != 'network_failure' or attempt == retries:
                return
            time.sleep(min(2 ** attempt, 8))
        finally:
            if connection:
                connection.close()


def reconcile(data, state, work, identities):
    checked = {}
    # Include orphaned publications after a crash, not only files named by state.
    for path in sorted((work / 'completed').glob('*.pkg')):
        match = re.fullmatch(r'([0-9a-f]{64})-([0-9]+)\.pkg', path.name)
        if not match:
            raise ValueError(f'Unexpected file in completed directory: {path.name}')
        try:
            checked[path.name] = inspect_package(path, {'expected_sha256': match[1],
                                                       'expected_size': int(match[2])})
        except AcquisitionError:
            path.replace(work / 'partial' / (path.name + '.corrupt'))
    for package in data['packages']:
        previous = state['packages'].get(package['id'], {})
        observed = None
        filename = previous.get('file')
        if filename:
            candidate = checked.get(filename)
            if (candidate and
                    (package['expected_sha256'] is None or candidate['sha256'] == package['expected_sha256']) and
                    (package['expected_size'] is None or candidate['size_bytes'] == package['expected_size'])):
                observed = dict(candidate, hash_confirmed=package['expected_sha256'] is not None,
                                size_confirmed=package['expected_size'] is not None)
            else:
                previous.update(status='local_corrupt', detail='Previously verified file is missing or changed')
                previous.pop('observed', None)
        identity = (observed['sha256'], observed['size_bytes']) if observed else (
            package['expected_sha256'], package['expected_size'])
        package['catalog'] = identities.get(identity)
        package['observed'] = observed
        package['file'] = str(work / 'completed' / filename) if observed else None
        package['acquisition'] = 'verified' if observed else previous.get('status', 'pending')
        package['acquisition_url'] = previous.get('url')
        package['reused_from'] = previous.get('reused_from')
        package['verified_at'] = previous.get('verified_at') if observed else None
        if package['catalog']:
            package['status'] = 'already_ingested'
            package['catalog_match_basis'] = 'observed_sha256_size' if observed else 'reference_sha256_size'
        elif observed:
            package['status'] = 'verified'
        elif package['issues']:
            package['status'] = package['issues'][0]
        elif not package['urls']:
            package['status'] = 'missing_url'
        else:
            package['status'] = previous.get('status', 'pending')
        if previous.get('detail'):
            package['detail'] = previous['detail']
        package['mismatch_observed'] = previous.get('mismatch_observed')
    by_id = {p['id']: p for p in data['packages']}
    for row in data['rows']:
        package = by_id[row['package']]
        actual_id = (package['observed'] or package['catalog'] or {}).get('content_id')
        row['observed_content_id'] = actual_id
        row['content_id_conflict'] = bool(row['content_id'] and actual_id and row['content_id'] != actual_id)
    states = {p['id']: p['status'] for p in data['packages']}
    counts = Counter(states[row['package']] for row in data['rows'])
    source_copies = sum(len(s['origins']) for s in data['snapshots'])
    data['summary'] = {'snapshot_copies': source_copies, 'unique_snapshots': len(data['snapshots']),
        'source_rows_including_copies': sum(s['rows'] * len(s['origins']) for s in data['snapshots']),
        'unique_snapshot_rows': len(data['rows']), 'package_candidates': len(data['packages']),
        'conflict_groups': len(data['conflicts']), 'row_states': dict(sorted(counts.items())),
        'package_states': dict(sorted(Counter(states.values()).items())),
        'rows_missing_sha256': sum(r['expected_sha256'] is None for r in data['rows']),
        'rows_missing_size': sum(r['expected_size'] is None for r in data['rows'])}
    data['completed_directory'] = str(work / 'completed')
    data['coverage_scope'] = 'Exact PKG pairs only; revisions may be stale. No inference of extraction failure from absent catalog pairs.'
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshots', nargs='*', type=Path, help='Local TSV files/directories; omit to fetch current PSP/PSX snapshots from NoPayStation')
    parser.add_argument('--work', type=Path, default=Path('.work/psn-acquire'), help='Machine-local state and completed/partial directories')
    parser.add_argument('--catalog', type=Path, default=Path('catalog'), help='Read-only catalog to reconcile exact PKG identities')
    parser.add_argument('--rap-dir', type=Path, help='Private inline RAP store (default: PSPDB_RAP_DIR, then ${XDG_DATA_HOME:-~/.local/share}/pspdb/licenses)')
    parser.add_argument('--limit', type=int, default=0, help='Maximum PKG attempts; 0 inventories and imports RAPs only (default)')
    parser.add_argument('--package', action='append', default=[], help='Restrict downloads to candidate ID from report.json; repeatable')
    parser.add_argument('--category', choices=SNAPSHOT_CATEGORIES, help='Restrict PKG downloads, not snapshot fetching or inventory denominator')
    parser.add_argument('--reuse', action='append', type=Path, default=[], help='Read-only local PKG or directory to hash and reuse; repeatable')
    parser.add_argument('--timeout', type=float, default=30, help='Network socket timeout in seconds')
    parser.add_argument('--retries', type=int, default=2, help='Retries per attempted package (0..5)')
    parser.add_argument('--retry-failed', action='store_true', help='Retry prior unavailable/integrity/format/redirect failures; transient interrupted downloads resume normally')
    parser.add_argument('--min-free-gib', type=float, default=2, help='Preserve this much free space during acquisition')
    args = parser.parse_args()
    if (args.limit < 0 or not 0 < args.timeout <= 300 or not 0 <= args.retries <= 5 or
            not 0 <= args.min_free_gib < 1024 * 1024):
        parser.error('Invalid limit, timeout, retries, or capacity floor')
    try:
        work = args.work.expanduser().resolve()
        work.mkdir(parents=True, exist_ok=True)
        for name in ('partial', 'completed'):
            (work / name).mkdir(exist_ok=True)
        with (work / 'lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another acquisition process owns this work directory') from None
            snapshots = args.snapshots or fetch_snapshots(work, args.timeout)
            data = inventory(snapshots, license_directory(args.rap_dir))
            if not args.snapshots:
                for snapshot in data['snapshots']:
                    for origin in snapshot['origins']:
                        origin['url'] = SNAPSHOT_BASE + Path(origin['path']).name
            identities = catalog_identities(args.catalog.expanduser())
            state_path = work / 'state.json'
            state = json.loads(state_path.read_text()) if state_path.exists() else {'version': 1, 'packages': {}}
            if state.get('version') != 1 or not isinstance(state.get('packages'), dict):
                raise ValueError('Unsupported acquisition state')
            def save():
                atomic_json(state_path, state)
            reconcile(data, state, work, identities)
            requested = set(args.package)
            if requested - {p['id'] for p in data['packages']}:
                raise ValueError('Unknown --package candidate ID')
            category_by_snapshot = {s['sha256']: {o['category'] for o in s['origins']} for s in data['snapshots']}
            categories = {r['id']: category_by_snapshot[r['snapshot']] for r in data['rows']}
            candidates = [p for p in data['packages'] if not p['catalog'] and not p['observed'] and p['urls'] and not p['issues']
                          and (not requested or p['id'] in requested)
                          and (args.retry_failed or p['status'] not in
                               ('unavailable', 'integrity_mismatch', 'unsupported_format', 'redirect_blocked'))
                          and (not args.category or any(args.category in categories[r] for r in p['references']))]
            candidates.sort(key=lambda p: (p['status'] == 'network_failure', p['expected_size'] is None,
                                            p['expected_size'] or 0, p['id']))
            local = {}
            # Reuse is explicit; do not crawl source media or the object store implicitly.
            for item in args.reuse:
                item = item.expanduser()
                for path in sorted(item.glob('*.pkg')) if item.is_dir() else [item]:
                    try:
                        observed = inspect_package(path, {'expected_sha256': None, 'expected_size': None})
                        local[(observed['sha256'], observed['size_bytes'])] = path
                    except AcquisitionError:
                        continue
            # Completed files can also be reused after a crash before state publication.
            for path in sorted((work / 'completed').glob('*.pkg')):
                match = re.fullmatch(r'([0-9a-f]{64})-([0-9]+)\.pkg', path.name)
                if match:
                    local.setdefault((match[1], int(match[2])), path)
            attempted = 0
            for package in candidates:
                if attempted >= args.limit:
                    break
                attempted += 1
                entry = state['packages'].setdefault(package['id'], {})
                source = local.get((package['expected_sha256'], package['expected_size']))
                if source:
                    try:
                        observed = inspect_package(source, package)
                        target = work / 'completed' / f"{observed['sha256']}-{observed['size_bytes']}.pkg"
                        if source.resolve() != target.resolve():
                            capacity(work, int(args.min_free_gib * 1024 ** 3), observed['size_bytes'])
                            part = work / 'partial' / (package['id'] + '.part')
                            shutil.copyfile(source, part)
                            inspect_package(part, package)
                            part.replace(target)
                        entry.clear()
                        entry.update(status='verified', observed=observed, file=target.name,
                                     reused_from=str(source.resolve()), verified_at=now())
                        save()
                        continue
                    except (AcquisitionError, OSError):
                        # A corrupt reuse source is not evidence; acquire the listed URL instead.
                        pass
                download(package, work, entry, save, args.timeout, args.retries, int(args.min_free_gib * 1024 ** 3))
                if entry.get('observed'):
                    observed = entry['observed']
                    local[(observed['sha256'], observed['size_bytes'])] = work / 'completed' / entry['file']
            reconcile(data, state, work, identities)
            data['attempted_this_run'] = attempted
            save()
            atomic_json(work / 'report.json', data)
            print(json.dumps({'summary': data['summary'], 'attempted_this_run': attempted,
                              'licenses': {key: data['licenses'][key] for key in ('directory', 'counts')},
                              'report': str(work / 'report.json'), 'completed_directory': data['completed_directory']}, sort_keys=True))
    except (OSError, ValueError, csv.Error) as exc:
        parser.exit(2, f'psn-acquire: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
