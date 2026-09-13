"""Validate catalog contributions without source images or external extractors."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

from jsonschema import Draft202012Validator

if __package__:
    from .catalog_status import validate_inline_dependencies
else:
    from catalog_status import validate_inline_dependencies

REPO = Path(__file__).resolve().parents[1]
RESULT = re.compile(r'([a-z][a-z0-9_-]*)/v([1-9][0-9]*)/([0-9a-f]{64})-(ingest|tree)\.json\Z')
EMPTY_HASH = hashlib.sha256(b'').hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f'Duplicate JSON key: {key}')
        value[key] = item
    return value


def read_json(path):
    def invalid_constant(value):
        raise ValueError(f'Invalid JSON constant: {value}')
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


def validate_catalog(root, versions=None):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f'Catalog must be a regular directory: {root}')
    versions = versions or read_json(REPO / 'tools/extractor_versions.json')
    validators = {role: Draft202012Validator(read_json(REPO / 'schemas' / schema))
                  for role, schema in [('ingest', 'record.schema.json'), ('tree', 'tree.schema.json')]}
    pairs, sizes = {}, {}
    def check_size(digest, size):
        if digest in sizes and sizes[digest] != size:
            raise ValueError(f'Conflicting byte sizes for {digest}')
        if (size == 0) != (digest == EMPTY_HASH):
            raise ValueError(f'Invalid empty-file hash/size for {digest}')
        sizes[digest] = size
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'Catalog symlinks are not allowed: {path}')
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        match = RESULT.fullmatch(relative)
        if not match or not path.is_file():
            raise ValueError(f'Unexpected catalog path: {relative}')
        kind, version, digest, role = match.groups()
        if kind not in versions or int(version) > int(versions[kind]):
            raise ValueError(f'Unregistered extractor revision: {relative}')
        value = read_json(path)
        errors = sorted(validators[role].iter_errors(value), key=lambda e: str(list(e.path)))
        if errors:
            raise ValueError(f'{relative}: {errors[0].message}')
        if value['sha256'] != digest or value['kind'] != ('tree' if role == 'tree' else kind):
            raise ValueError(f'Catalog identity does not match path: {relative}')
        check_size(digest, value['size_bytes'])
        if role == 'tree':
            if value['extractor'].get('version') != version:
                raise ValueError(f'Extractor revision does not match directory: {relative}')
            if kind in ('psar', 'rco', 'prx', 'kl3e', 'kl4e', 'edat') and 'sha256' not in value['extractor']:
                raise ValueError(f'Missing external executable hash: {relative}')
            def check_entries(tree):
                entries = tree['entries']
                names = [entry['path'] for entry in entries]
                if names != sorted(set(names)):
                    raise ValueError(f'Tree paths must be unique and sorted: {relative}')
                directories = {entry['path'] for entry in entries if entry['type'] == 'directory'}
                inventory = {entry['path']: entry for entry in entries}
                for entry in entries:
                    parent = str(PurePosixPath(entry['path']).parent)
                    if parent != '.' and parent not in directories:
                        raise ValueError(f'Missing parent directory for {entry["path"]}: {relative}')
                    if entry['type'] == 'file':
                        check_size(entry['sha256'], entry['size_bytes'])
                        if entry.get('extraction'):
                            child = entry['extraction']
                            for dependency in validate_inline_dependencies(entry, inventory):
                                check_size(dependency['sha256'], dependency['size_bytes'])
                            check_entries(child)
            check_entries(value)
        pairs.setdefault((kind, version, digest), {})[role] = value
    if not pairs:
        raise ValueError('Catalog contains no result pairs')
    for identity, pair in pairs.items():
        if set(pair) != {'ingest', 'tree'}:
            raise ValueError(f'Missing metadata/tree partner: {identity}')
    return {'pairs': len(pairs), 'isos': len({digest for kind, _, digest in pairs if kind == 'iso'})}


def validate_changes(repo, base):
    """Existing result paths are immutable; new revisions use new paths."""
    result = subprocess.run(['git', 'diff', '--no-renames', '--name-status', '-z', base, '--', 'catalog/'],
                            cwd=repo, check=True, capture_output=True)
    tokens = result.stdout.decode('utf-8').split('\0')
    for status, path in zip(tokens[0::2], tokens[1::2]):
        if status != 'A':
            raise ValueError(f'Existing catalog results are immutable ({status}): {path}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=REPO / 'catalog')
    parser.add_argument('--base', help='Git base commit/ref; reject changes or deletions to existing catalog files')
    args = parser.parse_args()
    try:
        summary = validate_catalog(args.catalog)
        if args.base:
            validate_changes(REPO, args.base)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'catalog-validation: {exc}\n')
    print(f"Validated {summary['pairs']} metadata/tree pairs ({summary['isos']} unique ISO images).")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
