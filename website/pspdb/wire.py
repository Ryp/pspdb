"""Binary columnar transport container for the catalog payload ("wire v4").

Catalog files on disk stay readable and self-describing. The website payload is
dominated by extraction trees, which repeat names, sizes, hashes and whole
subtrees (the same game assets under every regional ISO). This module emits the
tree structure as varint columns, stores every distinct SHA-256 once, sends only
an 8-byte prefix of each digest up front and lets the viewer fetch the full
digests lazily in chunks. `encode_container` produces the bytes, `decode_container`
is the reference decoder the tests use to prove the container is lossless.

Layout (all integers little-endian)
-----------------------------------
Container::

    "PSPDBW"  u16 format version (4)  u32 section count
    per section: u8 name length, ASCII name, u32 body length
    zero padding to a multiple of 8, then the bodies in table order, each
    padded with zeros to a multiple of 8 (padding is not part of the length).

Section offsets are therefore aligned to 8 bytes relative to the container
start, so typed-array views (`Uint32Array` over `prefixes`) need no copy.
Sections, all always present (possibly empty):

    meta        UTF-8 JSON (see below)
    names_lens  varints: UTF-8 byte length of each dictionary name
    names_blob  concatenated UTF-8 names; dictionary order is by descending use
                count, then by code point order
    names_ids   varints, one dictionary index per child node, in child order
    kids        varints, one per child node (see "Tree stream")
    size        varints, one per *stored* file size
    href        varints, one per file node: hash reference
    refs        varints: ordinals of earlier inline directories (see below)
    tsize       varints, one per tree header: 0 = null, else size + 1
    tprof       varints, one per tree header: index into meta.profiles
    thash       varints, one per tree header: hash reference of the tree's sha256
    tkids       varints, one per tree header: 0 = directory reference, else
                children count + 1
    tkey        varints, one per *root* tree: hash reference of the dictionary
                key (the source sha256) the tree is filed under
    prefixes    8 bytes per hash slot: the first 8 bytes of the digest

A varint is unsigned LEB128: 7 bits per byte, least significant group first,
high bit set on every byte but the last.

Hash slots and references
-------------------------
Every distinct SHA-256 gets a *slot* in first-use order (the order the streams
below are read). A hash reference is a varint: 0 = no hash, 1 = fresh hash (the
next unused slot; a reader keeps a counter), k + 2 = existing slot k. The
`tkey` and `thash` columns and the `href` column draw from the same slot
numbering; a reader processes them in stream order (tree key, then tree hash,
then the tree's directory, with nested file nodes in between exactly as in the
Tree stream). Distinct digests never share an 8-byte prefix; the encoder raises
`ValueError` otherwise. `meta.hash_count` slots exist.

Full digests: slot ``i`` lives in chunk ``i // 4096`` at byte offset
``(i % 4096) * 32``; a chunk is the raw concatenation of 32-byte digests, the
last chunk is short. `meta.hash_chunk_size` is 4096. `meta.generation` names the
digest table (sha256 of all digests, first 16 hex); the live server serves
``/api/hashes/<generation>/<chunk>`` and answers 409 for any other generation,
the static export writes ``hashes/<chunk>.bin`` next to the catalog file. A
reader should check the first 8 bytes of every digest it fetches against the
`prefixes` section.

Tree stream
-----------
The catalog trees are ``kind -> source sha256 -> tree`` (`meta.kinds` lists the
kinds in order with their tree counts; each root tree is read in order). A tree
is a *header* (one entry in each of tsize/tprof/thash/tkids, plus tkey for a
root tree) followed by its root directory. A directory lists its children in
order; the `kids` value of each child node is

    0   plain file                 1   file with extras (see below)
    2   directory reference        n+3 inline directory with n children

Reading is preorder; every child consumes one `names_ids` entry, in the same
order, including children of nested extraction trees. A *file* consumes one
`href` entry. Its size is read from `size` (0 = null, else size + 1) unless the
`href` is a back reference (>= 2) to a slot whose size is already known, in
which case the size is that slot's size; the first time a slot is given a size
(by a file node) it is remembered. Hash-less files (href 0) always store a size.
Sizes are therefore a function of the hash; the encoder raises `ValueError` for
one digest with two sizes.

A *file with extras* additionally consumes the next entry of `meta.extras`: a
JSON object holding the entry fields that are not path/size/sha256 (for
example `redump` file matches, a `type` other than "file"). When it has the key
`extraction` (value null in the JSON) a complete *nested tree* (header without
tkey, then its root directory) immediately follows in the stream, inside the
child position of that file, before its next sibling; the reader stores it as
the `extraction` value.

Children of every directory (also in nested trees) are ordered directories
first, then by name ascending in UTF-16 code unit order, the order the viewer
shows, so readers need not sort; decoded entry lists follow that order.

Directory deduplication: each inline directory (child kids n+3, or a tree whose
tkids is not 0) gets the next *ordinal*, counted in preorder over the whole
catalog. An identical later subtree (same names, sizes, hashes, extras and
nested trees; dedup applies to subtrees with at least two descendant entries)
is a reference: child kids = 2, or tree tkids = 0; it consumes the next `refs`
entry, the ordinal of the earlier directory. Referenced directories are shared,
so one unique directory may appear under many parents; the viewer expands
occurrences.

Profiles and meta
-----------------
`meta` is compact JSON with every catalog key except `trees` at the top level
(`records`, `coverage`, `downloads_enabled`, ...) plus:

    records        as in the catalog, but every record that has a `sha256` also
                   carries an integer `slot`: that digest's slot (registered
                   after the tree stream, so a record without tree gets a slot
                   past the stream's fresh counter)
    kinds          [[kind, tree count], ...] in encoding order
    profiles       tree objects without size_bytes, sha256 and entries: kind,
                   schema_version, extractor, extraction_kind, name_rule,
                   stale_extraction, error, ...; `tprof` indexes this list
    extras         per-file extras objects, in stream order, see above
    name_count     number of child nodes (length of names_ids)
    hash_count, hash_chunk_size, generation   see "Full digests"

Record `sha256`/`sha1` stay full hex inside `records`. A decoded tree is the
dict ``{**profile, size_bytes, sha256, entries}`` (size/sha omitted when null);
entries list every directory (`{path, type: directory}`) before its children,
files as ``{path, type: file, size_bytes, sha256, **extras}``, and names
containing '/' cannot be represented as a single directory child.
"""
from collections import Counter, namedtuple
import hashlib
import json
import re
import struct

FORMAT_VERSION = 4
MAGIC = b'PSPDBW'
PREFIX_BYTES = 8
DIGEST_BYTES = 32
HASH_CHUNK_SLOTS = 4096
HASH_CHUNK_BYTES = HASH_CHUNK_SLOTS * DIGEST_BYTES
DEDUP_MIN_NODES = 2

SECTIONS = ('meta', 'names_lens', 'names_blob', 'names_ids', 'kids', 'size', 'href', 'refs',
            'tsize', 'tprof', 'thash', 'tkids', 'tkey', 'prefixes')
_RESERVED = {'trees', 'kinds', 'profiles', 'extras', 'name_count',
             'hash_count', 'hash_chunk_size', 'generation'}
_FILE = {'path', 'type', 'size_bytes', 'sha256'}
_HEX = re.compile(r'[0-9a-f]{64}')
_HEADER = struct.Struct('<6sHI')

Encoded = namedtuple('Encoded', 'container hashes generation')


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def _put(buf, number):
    while number >= 128:
        buf.append((number & 127) | 128)
        number >>= 7
    buf.append(number)


def _varints(data):
    """Decode a whole varint column."""
    out, number, shift = [], 0, 0
    append = out.append
    for byte in data:
        if byte < 128:
            append(number | (byte << shift))
            number = shift = 0
        else:
            number |= (byte & 127) << shift
            shift += 7
    return out


def _pad(length):
    return -length % 8


def hash_chunk_count(hashes):
    return -(-len(hashes) // HASH_CHUNK_BYTES)


def hash_chunk(hashes, index):
    """Raw digests of chunk `index`, or None when the chunk does not exist."""
    if not isinstance(index, int) or index < 0 or index >= hash_chunk_count(hashes):
        return None
    return hashes[index * HASH_CHUNK_BYTES:(index + 1) * HASH_CHUNK_BYTES]


# ---- encoding ---------------------------------------------------------------------------


class _Pool:
    """Intern repeated values, preserving first-seen order."""

    def __init__(self):
        self.values, self.ids = [], {}

    def add(self, value):
        key = _key(value)
        identifier = self.ids.get(key)
        if identifier is None:
            identifier = self.ids[key] = len(self.values)
            self.values.append(value)
        return identifier


def ordered(node):
    """Directories first, then names ascending by UTF-16 code unit, in every directory."""
    return {name: ordered(child) if isinstance(child, dict) else child
            for name, child in sorted(node.items(), key=lambda item: (not isinstance(item[1], dict),
                                                                    item[0].encode('utf-16-be', 'surrogatepass')))}


def _rows(data):
    """Nested rows per source: tree = (size, profile, sha256, root), file = (size, sha256[, extras]).

    A directory is a dict keyed by child name. Inventories may not use one
    name for two different children of the same directory.
    """
    profiles = _Pool()

    def file_row(entry):
        extras = {name: value for name, value in entry.items() if name not in _FILE}
        if 'extraction' in extras:
            extras['extraction'] = tree_row(extras['extraction'])
        if entry.get('type') != 'file':
            extras['type'] = entry.get('type')
        row = (entry.get('size_bytes'), entry.get('sha256'))
        return row + (extras,) if extras else row

    def place(root, entry):
        *parents, name = entry['path'].split('/')
        node = root
        for parent in parents:
            node = node.setdefault(parent, {})
            if not isinstance(node, dict):
                raise ValueError(f"Inventory path traverses a file: {entry['path']}")
        if entry.get('type') == 'directory' and set(entry) == {'path', 'type'}:
            if not isinstance(node.setdefault(name, {}), dict):
                raise ValueError(f"Inventory name is both a file and a directory: {entry['path']}")
            return
        if name in node:
            raise ValueError(f'Conflicting inventory entries: {entry["path"]}')
        node[name] = file_row(entry)

    def tree_row(tree):
        profile = {name: value for name, value in tree.items()
                   if name not in ('size_bytes', 'sha256', 'entries')}
        identifier = profiles.add(profile)
        root = {}
        for entry in tree.get('entries', ()):
            place(root, entry)
        return (tree.get('size_bytes'), identifier, tree.get('sha256'), ordered(root))

    trees = {kind: {key: tree_row(tree) for key, tree in sources.items()}
             for kind, sources in data['trees'].items()}
    return trees, profiles.values


class _Canon:
    """Canonical ids for directory subtrees (order sensitive), to find repeats."""

    def __init__(self):
        self.leaves, self.dirs, self.trees = {}, {}, {}
        self.weight, self.leaf_weight, self.tree_weight = [], [], []
        self.by_obj = {}

    def tree(self, row):
        root = self.dir(row[3])
        key = (row[0], row[1], row[2], root)
        identifier = self.trees.get(key)
        if identifier is None:
            identifier = self.trees[key] = len(self.trees)
            self.tree_weight.append(self.weight[root])
        return identifier

    def file(self, row):
        extras = row[2] if len(row) > 2 else None
        weight = 1
        if extras:
            parts = []
            for name, value in extras.items():
                if name == 'extraction':
                    tree = self.tree(value)
                    weight += self.tree_weight[tree]
                    parts.append((name, ('T', tree)))
                else:
                    parts.append((name, _key(value)))
            key = (row[0], row[1], tuple(parts))
        else:
            key = (row[0], row[1])
        identifier = self.leaves.get(key)
        if identifier is None:
            identifier = self.leaves[key] = len(self.leaves)
            self.leaf_weight.append(weight)
        return identifier

    def dir(self, node):
        known = self.by_obj.get(id(node))
        if known is not None:
            return known
        items, weight = [], 0
        for name, child in node.items():
            if isinstance(child, dict):
                identifier = self.dir(child)
                weight += 1 + self.weight[identifier]
                items.append((name, 'D', identifier))
            else:
                identifier = self.file(child)
                weight += self.leaf_weight[identifier]
                items.append((name, 'F', identifier))
        key = tuple(items)
        identifier = self.dirs.get(key)
        if identifier is None:
            identifier = self.dirs[key] = len(self.dirs)
            self.weight.append(weight)
        self.by_obj[id(node)] = identifier
        return identifier


def _size_code(size):
    if size is None:
        return 0
    if type(size) is not int or size < 0:
        raise ValueError(f'Invalid size: {size!r}')
    return size + 1


def encode_container(data):
    """Encode a catalog snapshot; returns `Encoded(container, hashes, generation)`."""
    reserved = _RESERVED.intersection(name for name in data if name != 'trees')
    if reserved:
        raise ValueError(f'Catalog uses reserved wire keys: {sorted(reserved)}')
    trees, profiles = _rows(data)
    canon = _Canon()
    for sources in trees.values():
        for row in sources.values():
            canon.tree(row)

    slots, digests, prefixes = {}, [], {}

    def reference(digest):
        if digest is None:
            return 0
        slot = slots.get(digest)
        if slot is None:
            if not isinstance(digest, str) or not _HEX.fullmatch(digest):
                raise ValueError(f'Invalid SHA-256: {digest!r}')
            other = prefixes.setdefault(digest[:2 * PREFIX_BYTES], digest)
            if other != digest:
                raise ValueError(f'SHA-256 prefix collision: {other} and {digest}')
            slots[digest] = len(digests)
            digests.append(digest)
            return 1
        return slot + 2

    kids, size, href, refs = bytearray(), bytearray(), bytearray(), bytearray()
    tsize, tprof, thash, tkids, tkey = (bytearray() for _ in range(5))
    names, extras = [], []
    seen, sizes = {}, {}
    ordinal = 0

    def directory(node, header):
        """Emit a directory header; True when its children must follow."""
        nonlocal ordinal
        identifier = canon.dir(node)
        first = seen.get(identifier)
        if first is not None and canon.weight[identifier] >= DEDUP_MIN_NODES:
            _put(tkids if header else kids, 0 if header else 2)
            _put(refs, first)
            return False
        seen.setdefault(identifier, ordinal)
        ordinal += 1
        _put(tkids if header else kids, len(node) + (1 if header else 3))
        return True

    def tree(row, key=None):
        if key is not None:
            _put(tkey, reference(key))
        _put(tsize, _size_code(row[0]))
        _put(tprof, row[1])
        _put(thash, reference(row[2]))
        if directory(row[3], True):
            children(row[3])

    def children(node):
        for name, child in node.items():
            names.append(name)
            if isinstance(child, dict):
                if directory(child, False):
                    children(child)
                continue
            extra = child[2] if len(child) > 2 else None
            _put(kids, 1 if extra else 0)
            code = reference(child[1])
            slot = len(digests) - 1 if code == 1 else code - 2
            if code >= 2 and slot in sizes:
                if sizes[slot] != child[0]:
                    raise ValueError(f'SHA-256 {child[1]} has two sizes')
            else:
                if code >= 1:
                    sizes[slot] = child[0]
                _put(size, _size_code(child[0]))
            _put(href, code)
            if extra:
                stored = dict(extra)
                if 'extraction' in extra:
                    stored['extraction'] = None
                extras.append(stored)
                if 'extraction' in extra:
                    tree(extra['extraction'])

    kinds = []
    for kind, sources in trees.items():
        kinds.append([kind, len(sources)])
        for key, row in sources.items():
            tree(row, key)

    frequency = Counter(names)
    order = sorted(frequency, key=lambda name: (-frequency[name], name))
    index = {name: number for number, name in enumerate(order)}
    name_ids, name_lens, name_blob = bytearray(), bytearray(), bytearray()
    for name in names:
        _put(name_ids, index[name])
    for name in order:
        encoded = name.encode('utf-8')
        _put(name_lens, len(encoded))
        name_blob += encoded

    # Records get a slot after the tree stream, so record-only digests never disturb it.
    records = {}
    for kind, listed in data.get('records', {}).items():
        records[kind] = stamped = []
        for record in listed:
            if 'slot' in record:
                raise ValueError('Catalog records may not carry a "slot" field')
            reference(record.get('sha256'))
            stamped.append(record if record.get('sha256') is None
                           else dict(record, slot=slots[record['sha256']]))

    hashes = b''.join(bytes.fromhex(digest) for digest in digests)
    generation = hashlib.sha256(hashes).hexdigest()[:16]
    meta = {name: value for name, value in data.items() if name != 'trees'}
    if 'records' in data:
        meta['records'] = records
    meta.update(kinds=kinds, profiles=profiles, extras=extras, name_count=len(names),
                hash_count=len(digests), hash_chunk_size=HASH_CHUNK_SLOTS, generation=generation)
    sections = {
        'meta': _json(meta).encode('utf-8'),
        'names_lens': bytes(name_lens), 'names_blob': bytes(name_blob), 'names_ids': bytes(name_ids),
        'kids': bytes(kids), 'size': bytes(size), 'href': bytes(href), 'refs': bytes(refs),
        'tsize': bytes(tsize), 'tprof': bytes(tprof), 'thash': bytes(thash), 'tkids': bytes(tkids),
        'tkey': bytes(tkey),
        'prefixes': b''.join(hashes[start:start + PREFIX_BYTES]
                             for start in range(0, len(hashes), DIGEST_BYTES)),
    }
    return Encoded(pack(sections), hashes, generation)


def pack(sections):
    """Serialise named sections into the container layout."""
    head = bytearray(_HEADER.pack(MAGIC, FORMAT_VERSION, len(sections)))
    for name, body in sections.items():
        if len(body) >= 1 << 32:
            raise ValueError(f'Section too large: {name}')
        label = name.encode('ascii')
        head += struct.pack('<B', len(label)) + label + struct.pack('<I', len(body))
    out = [bytes(head), bytes(_pad(len(head)))]
    for body in sections.values():
        out += (body, bytes(_pad(len(body))))
    return b''.join(out)


# ---- reference decoder --------------------------------------------------------------------


def unpack(container):
    """Split a container into `{name: memoryview}`."""
    view = memoryview(container)
    if len(view) < _HEADER.size:
        raise ValueError('Truncated catalog container')
    magic, version, count = _HEADER.unpack_from(view)
    if magic != MAGIC or version != FORMAT_VERSION:
        raise ValueError('Unsupported catalog container')
    position, table = _HEADER.size, []
    for _ in range(count):
        length = view[position]
        name = bytes(view[position + 1:position + 1 + length]).decode('ascii')
        position += 1 + length
        table.append((name, struct.unpack_from('<I', view, position)[0]))
        position += 4
    position += _pad(position)
    sections = {}
    for name, length in table:
        if position + length > len(view):
            raise ValueError('Truncated catalog container')
        sections[name] = view[position:position + length]
        position += length + _pad(length)
    if set(sections) != set(SECTIONS):
        raise ValueError('Unexpected catalog container sections')
    return sections


def iter_trees(container, hashes):
    """Reference decoder. Returns `(data, iterator of (kind, key, tree))`.

    `data['trees']` already holds every kind (empty); the iterator yields the trees.

    `hashes` is the concatenated digest table (all chunks). The structure is
    read eagerly (directories stay shared); trees are expanded to entry lists
    lazily, one at a time, so a whole catalog can be compared piecewise.
    """
    sections = unpack(container)
    meta = json.loads(bytes(sections['meta']))
    slots = meta['hash_count']
    if len(hashes) != slots * DIGEST_BYTES:
        raise ValueError('Hash table does not match the catalog container')
    if hashlib.sha256(hashes).hexdigest()[:16] != meta['generation']:
        raise ValueError('Hash table belongs to another catalog generation')
    prefixes = sections['prefixes']
    for slot in range(slots):
        if hashes[slot * DIGEST_BYTES:slot * DIGEST_BYTES + PREFIX_BYTES] != prefixes[slot * PREFIX_BYTES:(slot + 1) * PREFIX_BYTES]:
            raise ValueError('Hash table does not match the catalog prefixes')
    hexes = hashes.hex()
    digest = [hexes[slot * 64:(slot + 1) * 64] for slot in range(slots)]

    lengths, blob, position = _varints(sections['names_lens']), bytes(sections['names_blob']), 0
    dictionary = []
    for length in lengths:
        dictionary.append(blob[position:position + length].decode('utf-8'))
        position += length
    names = [dictionary[number] for number in _varints(sections['names_ids'])]
    columns = {name: _varints(sections[name]) for name in
               ('kids', 'size', 'href', 'refs', 'tsize', 'tprof', 'thash', 'tkids', 'tkey')}
    kids, size, href, refs = columns['kids'], columns['size'], columns['href'], columns['refs']
    tsize, tprof, thash, tkids, tkey = (columns[name] for name in ('tsize', 'tprof', 'thash', 'tkids', 'tkey'))
    cursor = dict(kid=0, name=0, size=0, href=0, ref=0, tree=0, key=0, fresh=0)
    directories, sizes, extras = [], {}, iter(meta['extras'])

    def slot_of(code):
        if code == 0:
            return None
        if code == 1:
            cursor['fresh'] += 1
            return cursor['fresh'] - 1
        return code - 2

    def read_tree(root):
        index = cursor['tree']
        cursor['tree'] += 1
        key = None
        if root:
            key = slot_of(tkey[cursor['key']])
            cursor['key'] += 1
        code = tsize[index]
        head = (None if code == 0 else code - 1, tprof[index], slot_of(thash[index]))
        count = tkids[index]
        if count == 0:
            node = directories[refs[cursor['ref']]]
            cursor['ref'] += 1
        else:
            node = {}
            directories.append(node)
            read_children(node, count - 1)
        return key, head + (node,)

    def read_children(node, count):
        for _ in range(count):
            name = names[cursor['name']]
            cursor['name'] += 1
            kind = kids[cursor['kid']]
            cursor['kid'] += 1
            if kind <= 1:
                code = href[cursor['href']]
                cursor['href'] += 1
                if code >= 2 and code - 2 in sizes:
                    slot, value = code - 2, sizes[code - 2]
                else:
                    stored = size[cursor['size']]
                    cursor['size'] += 1
                    value = None if stored == 0 else stored - 1
                    slot = slot_of(code)
                    if slot is not None:
                        sizes[slot] = value
                row = [value, slot]
                if kind == 1:
                    extra = next(extras)
                    if 'extraction' in extra:
                        extra['extraction'] = read_tree(False)[1]
                    row.append(extra)
                node[name] = row
            elif kind == 2:
                node[name] = directories[refs[cursor['ref']]]
                cursor['ref'] += 1
            else:
                child = node[name] = {}
                directories.append(child)
                read_children(child, kind - 3)

    profiles = meta['profiles']
    rows = []
    for kind, count in meta['kinds']:
        for _ in range(count):
            key, row = read_tree(True)
            rows.append((kind, digest[key], row))

    def decode_file(path, row):
        entry = {'path': path, 'type': 'file'}
        if row[0] is not None:
            entry['size_bytes'] = row[0]
        if row[1] is not None:
            entry['sha256'] = digest[row[1]]
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
        total, profile, slot, root = row
        tree = dict(profiles[profile])
        if total is not None:
            tree['size_bytes'] = total
        if slot is not None:
            tree['sha256'] = digest[slot]
        tree['entries'] = walk(root, '', [])
        return tree

    data = {name: value for name, value in meta.items() if name not in _RESERVED}
    for listed in data.get('records', {}).values():
        for record in listed:
            record.pop('slot', None)
    data['trees'] = {kind: {} for kind, _ in meta['kinds']}
    return data, ((kind, key, decode_tree(row)) for kind, key, row in rows)


def decode_container(container, hashes):
    """Rebuild the catalog snapshot (as `catalog_data` returns it) a container describes."""
    data, trees = iter_trees(container, hashes)
    for kind, key, tree in trees:
        data['trees'][kind][key] = tree
    return data


def main(argv=None):
    """`python -m pspdb.wire data.json OUTDIR`: encode a catalog data dict (tests, tooling)."""
    import sys
    from pathlib import Path
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        raise SystemExit('usage: python -m pspdb.wire data.json OUTDIR')
    encoded = encode_container(json.loads(Path(arguments[0]).read_text(encoding='utf-8')))
    out = Path(arguments[1])
    (out / 'hashes').mkdir(parents=True, exist_ok=True)
    (out / 'catalog.bin').write_bytes(encoded.container)
    for index in range(hash_chunk_count(encoded.hashes)):
        (out / 'hashes' / f'{index}.bin').write_bytes(hash_chunk(encoded.hashes, index))
    print(encoded.generation)


if __name__ == '__main__':
    main()
