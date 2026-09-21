"""Index NoPayStation TSV snapshots as the PSN package population; licence columns are never read."""
import csv
import hashlib
import io
from pathlib import Path
import re

CATEGORIES = ('PSP_GAMES', 'PSP_DEMOS', 'PSP_DLCS', 'PSP_THEMES', 'PSP_UPDATES', 'PSX_GAMES')
SNAPSHOT = re.compile(r'(PSP_GAMES|PSP_DEMOS|PSP_DLCS|PSP_THEMES|PSP_UPDATES|PSX_GAMES)(\(\d+\))?\.tsv', re.I)


def load_population(source):
    """Index NPS TSV snapshots by content ID; a directory or a single .tsv file."""
    source = Path(source)
    if source.is_dir():
        paths = sorted(path for path in source.iterdir()
                       if path.is_file() and path.suffix.lower() == '.tsv')
    else:
        paths = [source]
    lists = {}
    packages = {}
    for path in paths:
        name = SNAPSHOT.fullmatch(path.name)
        if name is None:
            raise ValueError(f'Unexpected NoPayStation snapshot name: {path.name}')
        category = name.group(1).upper()
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        entry = lists.setdefault(category, {'snapshots': [], 'content_ids': set()})
        if digest in entry['snapshots']:
            continue
        entry['snapshots'].append(digest)
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')), delimiter='\t')
        if not reader.fieldnames or 'Content ID' not in reader.fieldnames:
            raise ValueError(f'Missing Content ID column: {path.name}')
        for row in reader:
            content_id = (row.get('Content ID') or '').strip()
            if not content_id:
                continue
            entry['content_ids'].add(content_id)
            package = packages.setdefault(content_id, {'lists': set(), 'type': None,
                                                       'sha256': None, 'size_bytes': None})
            package['lists'].add(category)
            package['type'] = package['type'] or (row.get('Type') or '').strip() or None
            if package['sha256'] is None:
                package['sha256'] = _sha256(row.get('SHA256'))
            if package['size_bytes'] is None:
                package['size_bytes'] = _size(row.get('File Size'))
    return {
        'lists': {category: {'snapshots': sorted(lists[category]['snapshots']),
                             'content_ids': sorted(lists[category]['content_ids'])}
                  for category in CATEGORIES if category in lists},
        'packages': {content_id: {'lists': sorted(package['lists']), 'type': package['type'],
                                  'sha256': package['sha256'], 'size_bytes': package['size_bytes']}
                     for content_id, package in sorted(packages.items())},
    }


def _sha256(value):
    value = (value or '').strip()
    return value.lower() if re.fullmatch('[0-9a-fA-F]{64}', value) else None


def _size(value):
    value = (value or '').strip()
    return int(value) if value.isascii() and value.isdecimal() else None
