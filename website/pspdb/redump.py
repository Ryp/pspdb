"""Load exact ISO SHA-1 and size matches from a Redump DAT or ZIP."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile


def load_matches(source):
    """Index exact disc bytes; serials and UMD UIDs are not match keys."""
    source = Path(source)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            names = [name for name in archive.namelist()
                     if name.lower().endswith(('.dat', '.xml')) and not name.endswith('/')]
            if len(names) != 1:
                raise ValueError('Expected exactly one DAT/XML member')
            data = archive.read(names[0])
    else:
        data = source.read_bytes()
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Redump XML: {exc}") from exc
    if root.tag != 'datafile':
        raise ValueError('Expected a Redump datafile')
    matches = {}
    seen = set()
    for game in root.findall('game'):
        identifier = game.get('id', '')
        if not identifier.isascii() or not identifier.isdecimal() or int(identifier) <= 0:
            raise ValueError('Missing or invalid Redump disc ID')
        for rom in game.findall('rom'):
            if not rom.get('name', '').lower().endswith('.iso'):
                continue
            sha1 = rom.get('sha1', '').lower()
            size = int(rom.get('size', '-1'))
            if size < 0 or not re.fullmatch('[0-9a-f]{40}', sha1):
                raise ValueError('Invalid ISO size or SHA-1')
            disc_id = int(identifier)
            key = disc_id, size, sha1
            if key not in seen:
                matches.setdefault((sha1, size), []).append(dict(id=disc_id, name=game.get('name', '')))
                seen.add(key)
    for discs in matches.values():
        discs.sort(key=lambda disc: disc['id'])
    return matches


def load_psx_matches(source=None):
    """Reviewed Redump associations keyed by full reconstructed-image SHA256+size."""
    import json
    source = Path(source) if source is not None else Path(__file__).with_name('data') / 'redump-psx.json'
    data = json.loads(source.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1:
        raise ValueError('Invalid PSX Redump reference schema')
    matches = {}
    for row in data['matches']:
        digest, size = row['sha256'], row['size_bytes']
        url = re.fullmatch(r'https?://redump\.org/disc/([1-9][0-9]*)/', row['redump_url'])
        if (not re.fullmatch(r'[0-9a-f]{64}', digest) or not isinstance(size, int) or size <= 0
                or not url or row['track_count'] != 1
                or set(row['matched_fields']) != {'size_bytes', 'crc32', 'md5', 'sha1'}):
            raise ValueError('Invalid whole-disc PSX Redump reference')
        match = dict(id=int(url[1]), name=row['title'])
        bucket = matches.setdefault((digest, size), [])
        if match not in bucket:
            bucket.append(match)
    return matches


def annotate_file_matches(trees, matches):
    def walk(entries):
        for entry in entries:
            if entry.get('type') == 'file':
                found = matches.get((entry.get('sha256'), entry.get('size_bytes')))
                if found:
                    entry['redump'] = found
            if entry.get('extraction'):
                walk(entry['extraction']['entries'])
            if 'entries' in entry:
                walk(entry['entries'])
    for sources in trees.values():
        for tree in sources.values():
            walk(tree['entries'])
