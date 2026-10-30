"""Extract PSP resources into a caller-owned directory; Zig owns traversal and cleanup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess



VERSIONS = None



def versions():
    global VERSIONS
    if VERSIONS is None:
        VERSIONS = json.loads(Path(__file__).with_name('extractor_versions.json').read_text())
    if not isinstance(VERSIONS, dict) or any(not isinstance(v, str) or not re.fullmatch(r'[1-9][0-9]*', v) for v in VERSIONS.values()):
        raise ValueError('Extractor revisions must be positive integer strings')
    return VERSIONS


def tool_provenance(kind, tool=None):
    result = {'name': 'pspdb-ingest', 'version': versions()[kind], 'options': []}
    if kind == 'pbp':
        return dict(result, name='Zig-PSP zPBPTool', options=['in-memory'])
    if kind == 'nand':
        return dict(result, name='pspdb-nand')
    if kind == 'update':
        return dict(result, name='pspdb-update')
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip', 'vmp', 'prx', 'kl3e', 'kl4e', 'edat', 'npumdimg', 'psar', 'rco', 'pgd', 'pspedat'):
        return result
    if kind == 'pops':
        return dict(result, name='pspdb-pops', options=['in-memory'])
    if kind == 'pce':
        # One static record covers both contextual inputs; it states each one's trust level.
        return dict(result, name='pspdb-pce', options=[
            'in-memory', 'xor-table:b2d7084c', 'content-dat:structure-checked', 'content1-sdat:mac-verified'])
    if kind == 'pcecd':
        return dict(result, name='pspdb-pcecd', options=['in-memory', 'toc-bound', 'sector-image-2048'])
    if kind == 'psx':
        return dict(result, name='pspdb-psx', options=['in-memory'])
    if kind != 'document':
        raise ValueError(f'Unknown extractor kind: {kind}')
    with tool.open('rb') as stream:
        if kind == 'document':
            command = f'/proc/self/fd/{stream.fileno()}'
            reported = json.loads(subprocess.check_output(
                [command, '--provenance'], pass_fds=(stream.fileno(),), text=True, timeout=30),
                object_pairs_hook=manifest_object)
            manifest_fields(reported, ('name', 'options'))
            if (reported['name'] != 'PSP-DOCUMENT.DAT' or not isinstance(reported['options'], list)
                    or any(not isinstance(option, str) for option in reported['options'])
                    or 'page-files-only:1' not in reported['options']):
                raise ValueError('Invalid DOCUMENT helper provenance: page-only output required')
            result.update(reported)
        result['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return result


def current_provenance():
    current, unavailable = {}, {}
    for kind in versions():
        try:
            tool = None
            if kind == 'document':
                tool = executable('PSPDB_DOCUMENT', 'pspdb-document')
            current[kind] = tool_provenance(kind, tool)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            unavailable[kind] = str(exc)
    return current, unavailable


def extract_document(source, output, tool, docinfo=None):
    tool = tool.resolve(strict=True)
    with tool.open('rb') as binary:
        # Metadata, executable hash and extraction must describe the same inode.
        executable_path = Path(f'/proc/self/fd/{binary.fileno()}')
        provenance = tool_provenance('document', executable_path)
        command = [str(executable_path), str(source.resolve(strict=True)), '--output', str(output.resolve())]
        if docinfo is not None:
            command.extend(('--docinfo', str(docinfo.resolve(strict=True))))
        try:
            result = subprocess.run(command, pass_fds=(binary.fileno(),),
                                    capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired as error:
            raise ValueError('Document extraction exceeded 120 seconds') from error
        if result.returncode:
            raise ValueError(result.stderr.strip() or 'Document extraction failed')
    return provenance


def manifest_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest key')
        result[key] = value
    return result


def manifest_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('Invalid manifest fields')




def executable(variable, name):
    return Path(os.environ.get(variable) or shutil.which(name) or name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['document'])
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--docinfo', type=Path)
    parser.add_argument('--versions', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.docinfo is not None and args.kind != 'document':
        parser.error('--docinfo is only supported for document extraction')
    if args.versions:
        global VERSIONS
        VERSIONS = json.loads(args.versions)
    try:
        provenance = extract_document(args.source, args.output, executable('PSPDB_DOCUMENT', 'pspdb-document'), args.docinfo)
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
