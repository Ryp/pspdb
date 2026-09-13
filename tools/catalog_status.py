"""Report extractor provenance changes without modifying the catalog or source files."""
import argparse
from collections import defaultdict, deque
import json
from pathlib import Path
import re

if __package__:
    from . import extract_external
else:
    import extract_external

HASH = re.compile(r'[0-9a-f]{64}\Z')
DEPENDENCY_PATH = re.compile(r'^(?!/)(?!.*(?:^|/)\.{1,2}(?:/|$))[^\\:\x00-\x1f]+$')
CONTEXTUAL_KINDS = {
    'PSXtract-2': 'psx',
    'pops': 'pops',
    'pspdb-pops': 'pops',
    'PSP-DOCUMENT.DAT': 'document',
}


def validate_inline_dependencies(entry, inventory):
    """Bind contextual inputs only within the source entry's immediate inventory."""
    contextual = entry['extraction']
    if contextual['sha256'] != entry['sha256'] or contextual['size_bytes'] != entry['size_bytes']:
        raise ValueError('Contextual extraction source mismatch')
    if 'dependencies' not in contextual:
        return ()
    dependencies = contextual['dependencies']
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError('Contextual dependencies must be a nonempty array')
    seen = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {'path', 'sha256', 'size_bytes'}:
            raise ValueError('Invalid contextual dependency identity')
        path, digest, size = dependency['path'], dependency['sha256'], dependency['size_bytes']
        if (not isinstance(path, str) or not DEPENDENCY_PATH.fullmatch(path)
                or '//' in path or path.endswith('/')):
            raise ValueError('Invalid contextual dependency path')
        if not isinstance(digest, str) or not HASH.fullmatch(digest) or type(size) is not int or size < 0:
            raise ValueError('Invalid contextual dependency hash/size')
        if path in seen:
            raise ValueError('Duplicate contextual dependency path')
        seen.add(path)
        if path == entry['path']:
            raise ValueError('Contextual dependency self-reference')
        sibling = inventory.get(path)
        if sibling is None or sibling['type'] != 'file':
            raise ValueError('Missing contextual dependency file')
        if sibling['sha256'] != digest or sibling['size_bytes'] != size:
            raise ValueError('Contextual dependency identity mismatch')
    return dependencies


def catalog_status(root, current=None, unavailable=None):
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f'Catalog directory does not exist: {root}')
    if current is None:
        current, unavailable = extract_external.current_provenance()
    unavailable = unavailable or {}
    records, trees, parents, selected, kinds = {}, {}, defaultdict(set), {}, {}
    for kind in extract_external.versions():
        directory = root / kind
        candidates = {(0, path.stem) for path in directory.glob('*.json')}
        for folder in directory.iterdir() if directory.is_dir() else []:
            if folder.is_dir() and re.fullmatch(r'v[1-9][0-9]*', folder.name):
                for path in folder.glob('*.json'):
                    for suffix in ('-ingest', '-tree'):
                        if path.stem.endswith(suffix):
                            candidates.add((int(folder.name[1:]), path.stem.removesuffix(suffix)))
        for revision, digest in sorted(candidates):
            if not HASH.fullmatch(digest):
                raise ValueError(f'Invalid source hash: {digest}')
            base = directory / f'v{revision}'
            record_path = base / (digest + '-ingest.json') if revision else directory / (digest + '.json')
            tree_path = base / (digest + '-tree.json') if revision else root / 'trees' / (digest + '.json')
            record = json.loads(record_path.read_text()) if record_path.exists() else None
            tree = json.loads(tree_path.read_text()) if tree_path.exists() else None
            for value, expected_kind, path in [(record, kind, record_path), (tree, 'tree', tree_path)]:
                if value is not None and (value.get('sha256') != digest or value.get('kind') != expected_kind or value.get('schema_version') != 1):
                    raise ValueError(f'Invalid catalog identity: {path}')
            if tree and (not isinstance(tree.get('entries'), list) or revision and tree.get('extractor', {}).get('version') != str(revision)):
                raise ValueError(f'Invalid versioned extraction: {tree_path}')
            if record and tree and record['size_bytes'] != tree['size_bytes']:
                raise ValueError(f'Catalog size conflict: {record_path}')
            if digest in kinds and kinds[digest] != kind:
                raise ValueError(f'Ambiguous source kind: {digest}')
            previous = records.get(digest) or trees.get(digest)
            if previous and previous['size_bytes'] != (record or tree)['size_bytes']:
                raise ValueError(f'Conflicting source size: {digest}')
            kinds[digest] = kind
            records[digest] = record
            if tree:
                trees[digest] = tree
            else:
                trees.pop(digest, None)
            selected[digest] = revision
    def nested_entries(tree):
        inventory = {entry['path']: entry for entry in tree['entries']}
        if len(inventory) != len(tree['entries']):
            raise ValueError('Tree paths must be unique')
        for entry in tree['entries']:
            yield entry
            if entry.get('extraction'):
                validate_inline_dependencies(entry, inventory)
                yield from nested_entries(entry['extraction'])

    for digest, tree in trees.items():
        for entry in nested_entries(tree):
            if entry['type'] == 'file':
                child = entry['sha256']
                if not HASH.fullmatch(child):
                    raise ValueError(f'Invalid child hash: {digest}')
                if not entry.get('extraction'):
                    parents[child].add(digest)
    stale, fresh = [], {}
    for digest in sorted(records.keys() | trees.keys()):
        record, tree = records.get(digest), trees.get(digest)
        kind = kinds[digest]
        actual = tree.get('extractor') if tree else None
        expected = current.get(kind)
        reason = ('missing metadata' if not record else 'missing tree' if not tree else
                  'missing current revision' if str(selected[digest]) != extract_external.versions()[kind] else
                  'extractor unavailable' if expected is None else
                  'extractor changed' if actual != expected else None)
        if not reason:
            for entry in nested_entries(tree):
                contextual = entry.get('extraction')
                contextual_kind = CONTEXTUAL_KINDS.get(contextual['extractor']['name']) if contextual else None
                if contextual and contextual['extractor'] != current.get(contextual_kind):
                    reason = 'contextual extractor changed'
                    break
        if reason:
            stale.append({'sha256': digest, 'kind': kind, 'reason': reason,
                          'recorded': actual, 'expected': expected,
                          'unavailable': unavailable.get(kind), 'selected_version': selected[digest]})
        else:
            fresh[digest] = True
    affected = {item['sha256'] for item in stale}
    queue = deque(affected)
    while queue:
        for parent in parents[queue.popleft()]:
            if parent not in affected:
                affected.add(parent)
                queue.append(parent)
    roots = {digest for digest, kind in kinds.items() if kind == 'iso'}
    packages = {digest for digest, kind in kinds.items() if kind == 'pkg'}
    return {'provenance': current, 'unavailable': unavailable, 'stale': stale,
            'affected_isos': sorted(roots & affected),
            'affected_pkgs': sorted(packages & affected),
            'fresh_pkgs': {digest: True for digest in sorted(packages - affected)},
            'fresh_trees': fresh, 'fresh_isos': {digest: True for digest in sorted(roots - affected)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', default='catalog', type=Path)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--versions', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.versions:
        extract_external.VERSIONS = json.loads(args.versions)
    try:
        report = catalog_status(args.catalog)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f'catalog-status: {exc}\n')
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        for item in report['stale']:
            old = (item['recorded'] or {}).get('version', 'unversioned')
            new = (item['expected'] or {}).get('version', 'unavailable')
            print(f"{item['kind'] or 'unknown':6} {item['sha256']}  {old} -> {new}: {item['reason']}")
            if item['unavailable']:
                print(f"       {item['unavailable']}")
        print(f"{len(report['stale'])} trees need attention; {len(report['affected_isos'])} affected ISO roots.")
        print(f"{len(report['affected_pkgs'])} affected PKG roots.")
        for digest in report['affected_pkgs']:
            print(f'  pkg {digest}')
        for digest in report['affected_isos']:
            print(f'  iso {digest}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
