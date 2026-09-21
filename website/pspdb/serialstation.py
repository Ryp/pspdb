"""Load verified SerialStation package and disc identities from a version 2 snapshot."""
import json
from pathlib import Path
import re
from uuid import UUID

CONTENT_ID = re.compile(r'[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Za-z0-9_-]{16}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SHA1 = re.compile(r'[0-9a-f]{40}\Z')


def load_matches(source):
    """Index verified PKGs by byte identity and discs by exact Redump ID."""
    source = Path(source)
    try:
        data = json.loads(source.read_text(encoding='utf-8'))
    except ValueError as exc:
        raise ValueError(f'Invalid SerialStation snapshot: {exc}') from exc
    if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
            or data['schema_version'] != 2):
        raise ValueError('Invalid SerialStation snapshot schema: expected version 2')
    entries = data.get('entries')
    if not isinstance(entries, dict):
        raise ValueError('SerialStation snapshot has no entries')
    matches = {}
    for sha256, entry in entries.items():
        if not SHA256.fullmatch(sha256):
            raise ValueError(f'Invalid SerialStation SHA256: {sha256}')
        if not isinstance(entry, dict):
            raise ValueError(f'Invalid SerialStation entry: {sha256}')
        sha1 = entry.get('sha1')
        if not isinstance(sha1, str) or not SHA1.fullmatch(sha1):
            raise ValueError(f'Invalid SerialStation SHA1: {sha256}')
        size = entry.get('size_bytes')
        if type(size) is not int or size <= 0:
            raise ValueError(f'Invalid SerialStation byte size: {sha256}')
        content_id = entry.get('content_id')
        if not isinstance(content_id, str) or not CONTENT_ID.fullmatch(content_id):
            raise ValueError(f'Invalid SerialStation content ID: {sha256}')
        pkg_id = entry.get('id')
        try:
            canonical_id = str(UUID(pkg_id)) if isinstance(pkg_id, str) else None
        except ValueError:
            canonical_id = None
        if canonical_id is None or canonical_id != pkg_id:
            raise ValueError(f'Invalid SerialStation PKG UUID: {sha256}')
        name = entry.get('name')
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f'Missing SerialStation entry name: {sha256}')
        identity = (sha1, size, content_id)
        match = {'id': pkg_id, 'name': name.strip()}
        if identity in matches and matches[identity] != match:
            raise ValueError(f'Conflicting SerialStation PKG identity: {sha256}')
        matches[identity] = match
    discs = data.get('discs', {})
    if not isinstance(discs, dict):
        raise ValueError('Invalid SerialStation disc mapping')
    disc_matches = {}
    for redump_id, editions in discs.items():
        if not re.fullmatch(r'[1-9][0-9]*', redump_id):
            raise ValueError(f'Invalid SerialStation Redump ID: {redump_id}')
        if not isinstance(editions, list) or not editions:
            raise ValueError(f'Invalid SerialStation disc editions: {redump_id}')
        seen = set()
        verified = []
        for edition in editions:
            if not isinstance(edition, dict):
                raise ValueError(f'Invalid SerialStation disc edition: {redump_id}')
            disc_id = edition.get('id')
            try:
                canonical_id = str(UUID(disc_id)) if isinstance(disc_id, str) else None
            except ValueError:
                canonical_id = None
            if canonical_id is None or canonical_id != disc_id:
                raise ValueError(f'Invalid SerialStation disc UUID: {redump_id}')
            name = edition.get('name')
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f'Missing SerialStation disc name: {redump_id}')
            if disc_id in seen:
                raise ValueError(f'Duplicate SerialStation disc UUID: {redump_id}')
            seen.add(disc_id)
            verified.append({'id': disc_id, 'name': name.strip()})
        disc_matches[int(redump_id)] = verified
    return {'packages': matches, 'discs': disc_matches}
