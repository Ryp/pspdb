"""Compact transport encoding for the catalog payload.

Catalog files on disk stay readable and self-describing. The website payload is
dominated by extraction trees, which repeat three things: field names and type
strings on every entry, the full ancestor path on every nested entry, and the
same extractor description on every tree. This module emits each directory name
once by mirroring the inventory layout, interns hashes and tree metadata in
shared dictionaries, and keeps files as positional rows. The decoded result is
the structure the rest of the viewer works with.

An encoded directory is an object keyed by child name; an encoded file is
`[size_bytes, hash_id]`, optionally followed by an object holding rarer fields
such as a contextual extraction or Redump matches. Inventories therefore may
not use one name for two different children of the same directory.
"""
import json

WIRE_SCHEMA = 3

_FILE = {'path', 'type', 'size_bytes', 'sha256'}


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


class _Pool:
    """Intern repeated values, preserving first-seen order."""

    def __init__(self, key=_key):
        self.values, self.ids = [], {}
        self.key = key

    def add(self, value):
        key = self.key(value)
        identifier = self.ids.get(key)
        if identifier is None:
            identifier = len(self.values)
            self.ids[key] = identifier
            self.values.append(value)
        return identifier


def encode_catalog(data):
    """Encode a catalog snapshot for transport; `decode_catalog` reverses it."""
    # Hashes are already immutable strings; JSON-serializing each occurrence is redundant.
    hashes, profiles = _Pool(key=lambda digest: digest), _Pool()

    def encode_file(entry):
        extras = {name: value for name, value in entry.items() if name not in _FILE}
        if 'extraction' in extras:
            extras['extraction'] = encode_tree(extras['extraction'])
        if entry.get('type') != 'file':
            extras['type'] = entry.get('type')
        row = [entry.get('size_bytes'),
               hashes.add(entry['sha256']) if 'sha256' in entry else None]
        return row + [extras] if extras else row

    def place(root, entry):
        """Attach one entry at its path, creating the directories it names."""
        *parents, name = entry['path'].split('/')
        node = root
        for parent in parents:
            node = node.setdefault(parent, {})
            if not isinstance(node, dict):
                raise ValueError(f"Inventory path traverses a file: {entry['path']}")
        if entry.get('type') == 'directory' and set(entry) == {'path', 'type'}:
            existing = node.setdefault(name, {})
            if not isinstance(existing, dict):
                raise ValueError(f"Inventory name is both a file and a directory: {entry['path']}")
            return
        if name in node:
            raise ValueError(f'Conflicting inventory entries: {entry["path"]}')
        node[name] = encode_file(entry)

    def encode_tree(tree):
        profile = {name: value for name, value in tree.items()
                   if name not in ('size_bytes', 'sha256', 'entries')}
        # Intern the source before its contents so ids follow the readable order.
        identifier = profiles.add(profile)
        digest = hashes.add(tree['sha256']) if 'sha256' in tree else None
        root = {}
        for entry in tree.get('entries', ()):
            place(root, entry)
        return [tree.get('size_bytes'), identifier, digest, root]

    payload = {name: value for name, value in data.items() if name != 'trees'}
    payload['wire_schema'] = WIRE_SCHEMA
    payload['trees'] = {kind: {digest: encode_tree(tree) for digest, tree in sources.items()}
                        for kind, sources in data['trees'].items()}
    payload['hashes'] = hashes.values
    payload['profiles'] = profiles.values
    return payload


def decode_catalog(payload):
    """Rebuild the catalog snapshot an encoded payload describes."""
    if payload.get('wire_schema') != WIRE_SCHEMA:
        raise ValueError('Unsupported catalog wire schema')
    hashes, profiles = payload['hashes'], payload['profiles']

    def decode_file(path, row):
        entry = {'path': path, 'type': 'file'}
        if row[0] is not None:
            entry['size_bytes'] = row[0]
        if row[1] is not None:
            entry['sha256'] = hashes[row[1]]
        for name, value in (row[2] if len(row) > 2 else {}).items():
            entry[name] = decode_tree(value) if name == 'extraction' else value
        if entry.get('type') is None:
            del entry['type']
        return entry

    def walk(node, prefix, entries):
        for name, child in node.items():
            path = prefix + name
            if isinstance(child, dict):
                entries.append({'path': path, 'type': 'directory'})
                walk(child, path + '/', entries)
            else:
                entries.append(decode_file(path, child))
        return entries

    def decode_tree(row):
        size, profile, digest, root = row
        tree = dict(profiles[profile])
        if size is not None:
            tree['size_bytes'] = size
        if digest is not None:
            tree['sha256'] = hashes[digest]
        tree['entries'] = walk(root, '', [])
        return tree

    data = {name: value for name, value in payload.items()
            if name not in ('wire_schema', 'hashes', 'profiles', 'trees')}
    data['trees'] = {kind: {digest: decode_tree(tree) for digest, tree in sources.items()}
                     for kind, sources in payload['trees'].items()}
    return data
