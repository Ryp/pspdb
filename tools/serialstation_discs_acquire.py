"""Acquire explicitly published PSP UMD-to-Redump links from SerialStation.

Run with python -m tools.serialstation_discs_acquire --output SNAPSHOT.json.
Validated public HTML is cached for resumable scans; --refresh ignores that cache.
"""
import argparse
import json
import math
import os
import re
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from itertools import islice
from pathlib import Path

if __package__:
    from . import serialstation_acquire as packages
else:
    import serialstation_acquire as packages

AcquisitionError = packages.AcquisitionError
PSP_SYSTEM = 'ab637dee-0616-4bc1-87aa-9853f38d5e73'
DISC_PATH = re.compile(r'/discs/(' + packages.UUID + r')\Z')
REDUMP_LINK = re.compile(r'https?://(?:www\.)?redump\.(?:org|info)/disc/([1-9][0-9]*)/?\Z')


class ListingParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.tables = 0
        self.rows = []
        self.row = None
        self.cell = None
        self.small = None
        self.ranges = []
        self.pages = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'data-page' in attrs:
            if not re.fullmatch(r'[1-9][0-9]*', attrs['data-page']):
                raise AcquisitionError('Invalid listing pagination')
            self.pages.add(int(attrs['data-page']))
        if tag == 'small':
            self.small = []
        if tag in ('table', 'thead', 'tbody', 'tr', 'th', 'td'):
            parent = self.stack[-1] if self.stack else None
            expected = {'table': (None,), 'thead': ('table',), 'tbody': ('table',),
                        'tr': ('thead', 'tbody'), 'th': ('tr',), 'td': ('tr',)}
            if parent not in expected[tag]:
                raise AcquisitionError('Malformed disc listing table')
            self.stack.append(tag)
            if tag == 'tr' and 'tbody' in self.stack:
                self.row = []
            elif tag == 'td':
                self.cell = {'text': [], 'links': []}
        if tag == 'a' and self.cell is not None:
            self.cell['links'].append(attrs.get('href', ''))

    def handle_data(self, data):
        if self.small is not None:
            self.small.append(data)
        if self.cell is not None:
            self.cell['text'].append(data)

    def handle_endtag(self, tag):
        if tag == 'small' and self.small is not None:
            text = ''.join(self.small).strip()
            match = re.fullmatch(r'([0-9]+)-([0-9]+) of ([0-9]+)', text)
            if match:
                self.ranges.append(tuple(map(int, match.groups())))
            self.small = None
        if tag not in ('table', 'thead', 'tbody', 'tr', 'th', 'td'):
            return
        if not self.stack or self.stack.pop() != tag:
            raise AcquisitionError('Malformed disc listing table')
        if tag == 'td':
            if self.row is None or self.cell is None:
                raise AcquisitionError('Malformed disc listing row')
            self.row.append(self.cell)
            self.cell = None
        elif tag == 'tr' and self.row is not None:
            self.rows.append(self.row)
            self.row = None
        elif tag == 'table':
            self.tables += 1


def parse_listing(html, page):
    if not isinstance(html, str):
        raise AcquisitionError('Missing disc listing page')
    parser = ListingParser()
    parser.feed(html)
    parser.close()
    if (parser.stack or parser.tables != 1 or not parser.ranges
            or len(set(parser.ranges)) != 1):
        raise AcquisitionError('Incomplete disc listing (possibly a challenge)')
    start, end, total = parser.ranges[0]
    if not 1 <= start <= end <= total or page not in parser.pages:
        raise AcquisitionError('Invalid disc listing range or pagination')
    ids = []
    for row in parser.rows:
        if len(row) != 6 or ' '.join(''.join(row[2]['text']).split()) != 'PSP':
            raise AcquisitionError('Malformed or non-PSP disc listing row')
        links = row[0]['links']
        if len(links) != 1 or not (match := DISC_PATH.fullmatch(links[0])):
            raise AcquisitionError('Invalid disc listing UUID link')
        ids.append(match[1])
    if len(ids) != end - start + 1 or len(set(ids)) != len(ids):
        raise AcquisitionError('Incomplete or duplicate disc listing rows')
    return ids, start, end, total, parser.pages


class DiscParser(packages.PageParser):
    def __init__(self):
        super().__init__()
        self.redump_links = []

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if (tag == 'a' and self.in_main and self.dls
                and self.dls[-1]['term'] == 'Redump' and self.dls[-1]['kind'] == 'dd'):
            self.redump_links.append(dict(attrs).get('href', ''))


def parse_disc(html):
    if not isinstance(html, str):
        raise AcquisitionError('Missing disc detail page')
    page = DiscParser()
    page.feed(html)
    page.close()
    if not page.complete or page.in_main:
        raise AcquisitionError('Incomplete disc details (possibly a challenge)')
    headings = [text for tag, text in page.headings if tag == 'h1']
    definitions = {}
    for term, text in page.definitions:
        if term in ('System', 'Disc Format', 'Games on disc', 'Label Edition', 'Redump'):
            if term in definitions:
                raise AcquisitionError(f'Duplicate disc field: {term}')
            definitions[term] = text
    if len(headings) != 1 or not headings[0] or definitions.get('System') != 'PSP':
        raise AcquisitionError('Not a PSP disc detail page')
    if definitions.get('Disc Format') not in ('UMD', 'UMDSL', 'UMDDL'):
        raise AcquisitionError('Not a UMD disc detail page')
    redump = set()
    for link in page.redump_links:
        match = REDUMP_LINK.fullmatch(link)
        if not match:
            raise AcquisitionError('Invalid published Redump disc link')
        redump.add(int(match[1]))
    if 'Redump' in definitions and not redump:
        raise AcquisitionError('Redump field has no explicit disc link')
    name = definitions.get('Games on disc') or headings[0]
    if definitions.get('Label Edition'):
        name += ' (' + definitions['Label Edition'] + ')'
    return name, sorted(redump)


def load_snapshot(path):
    packages.load_snapshot(path)
    try:
        payload = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {'schema_version': 2, 'entries': {}, 'missing': []}
    discs = payload.get('discs', {})
    if not isinstance(discs, dict):
        raise AcquisitionError('Malformed snapshot discs')
    for redump, editions in discs.items():
        if (not re.fullmatch(r'[1-9][0-9]*', redump)
                or not isinstance(editions, list) or not editions):
            raise AcquisitionError('Invalid snapshot Redump mapping')
        seen = set()
        for edition in editions:
            if (not isinstance(edition, dict) or not isinstance(edition.get('id'), str)
                    or not re.fullmatch(packages.UUID, edition['id'])
                    or not isinstance(edition.get('name'), str) or not edition['name'].strip()
                    or edition['id'] in seen):
                raise AcquisitionError('Invalid snapshot disc edition')
            seen.add(edition['id'])
    if 'disc_index_complete' in payload and type(payload['disc_index_complete']) is not bool:
        raise AcquisitionError('Invalid snapshot disc completion state')
    if 'discs_retrieved' in payload:
        try:
            if not isinstance(payload['discs_retrieved'], str):
                raise ValueError
            datetime.fromisoformat(payload['discs_retrieved'])
        except ValueError as error:
            raise AcquisitionError('Invalid snapshot discs timestamp') from error
    return payload


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def cached_page(path, cache, parse, args):
    try:
        html = None if args.refresh else cache.read_text(encoding='utf-8')
    except FileNotFoundError:
        html = None
    except UnicodeError as error:
        raise AcquisitionError(f'Invalid cached HTML: {cache}; use --refresh') from error
    if html is not None:
        return parse(html)
    html = packages.fetch_html(path, args.timeout, args.retries)
    result = parse(html)
    atomic_write(cache, html)
    return result


def scan(args, found):
    work = Path(args.work)
    seen = set()
    page, total, page_size = 1, None, None

    def detail(disc_id):
        name, redump = cached_page('/discs/' + disc_id, work / (disc_id + '.html'), parse_disc, args)
        return disc_id, name, redump

    with ThreadPoolExecutor(args.workers) as pool:
        while True:
            path = f'/ajax/table/discs?systems={PSP_SYSTEM}&page={page}'
            ids, start, end, observed_total, pages = cached_page(
                path, work / f'listing-{page}.html', lambda html: parse_listing(html, page), args)
            if total is None:
                total, page_size = observed_total, end
            last_page = (total + page_size - 1) // page_size
            if (observed_total != total or start != (page - 1) * page_size + 1
                    or end != min(page * page_size, total) or max(pages) != last_page
                    or seen.intersection(ids)):
                raise AcquisitionError('Disc listing changed or pagination is incomplete; use --refresh')
            seen.update(ids)
            remaining = iter(ids)
            while batch := list(islice(remaining, args.workers)):
                futures = [pool.submit(detail, disc_id) for disc_id in batch]
                failure = None
                for future in as_completed(futures):
                    if future.cancelled():
                        continue
                    try:
                        disc_id, name, redump = future.result()
                        for redump_id in redump:
                            found.setdefault(str(redump_id), {})[disc_id] = name
                    except (AcquisitionError, OSError) as error:
                        failure = failure or error
                        for pending in futures:
                            pending.cancel()
                if failure is not None:
                    raise failure
            if page == last_page:
                return
            page += 1


def publish(path, payload, found, complete):
    discs = {} if complete else {
        redump: {edition['id']: edition['name'] for edition in editions}
        for redump, editions in payload.get('discs', {}).items()}
    for redump, editions in found.items():
        discs.setdefault(redump, {}).update(editions)
    payload = dict(payload, discs={
        redump: [{'id': disc_id, 'name': name} for disc_id, name in sorted(discs[redump].items())]
        for redump in sorted(discs, key=int)}, disc_index_complete=complete,
        discs_retrieved=datetime.now(timezone.utc).isoformat(timespec='seconds'))
    atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='Unified schema-2 snapshot to create or update')
    parser.add_argument('--work', default='.work/serialstation/discs', help='Validated public HTML cache')
    parser.add_argument('--refresh', action='store_true', help='Ignore saved HTML and fetch every page again')
    parser.add_argument('--workers', type=int, default=2, help='Concurrent detail requests, 1–32 (default: 2)')
    parser.add_argument('--timeout', type=float, default=30.0, help='Per-request timeout in seconds')
    parser.add_argument('--retries', type=int, default=3, help='Retries for network errors, 429 and 5xx responses')
    args = parser.parse_args()
    if not 1 <= args.workers <= 32:
        parser.error('--workers must be between 1 and 32')
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.retries < 0:
        parser.error('--timeout must be finite and positive and --retries must be nonnegative')
    try:
        payload = load_snapshot(args.output)
        found = {}
        try:
            scan(args, found)
        except (AcquisitionError, OSError) as error:
            if found:
                publish(args.output, payload, found, complete=False)
                print(f'serialstation-discs-acquire: PARTIAL scan: {error}; verified mappings merged, '
                      'prior mappings retained; disc index is incomplete', file=sys.stderr)
            else:
                print(f'serialstation-discs-acquire: {error}; no new mappings; snapshot unchanged', file=sys.stderr)
            return 1
        publish(args.output, payload, found, complete=True)
        print(f'{len(found)} Redump IDs with verified UMD mappings -> {args.output}', file=sys.stderr)
    except (AcquisitionError, OSError) as error:
        print(f'serialstation-discs-acquire: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
