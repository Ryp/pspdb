"""Extract PSP resources into a caller-owned directory; Zig owns traversal and cleanup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile



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
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip', 'vmp', 'prx', 'kl3e', 'kl4e', 'edat', 'npumdimg', 'psar', 'rco'):
        return result
    if kind == 'pops':
        return dict(result, name='pspdb-pops', options=['in-memory'])
    if kind not in ('document', 'psx'):
        raise ValueError(f'Unknown extractor kind: {kind}')
    tool = tool.resolve(strict=True)
    if kind == 'document':
        reported = json.loads(subprocess.check_output([str(tool), '--provenance'], text=True, timeout=30),
                              object_pairs_hook=manifest_object)
        manifest_fields(reported, ('name', 'options'))
        if (reported['name'] != 'PSP-DOCUMENT.DAT' or not isinstance(reported['options'], list)
                or any(not isinstance(option, str) for option in reported['options'])
                or 'page-files-only:1' not in reported['options']):
            raise ValueError('Invalid DOCUMENT helper provenance: page-only output required')
        result.update(reported)
    else:
        result.update(name='PSXtract-2',
                      options=['<parent.pbp>', 'reconstructed-disc', 'native-linux'])
    with tool.open('rb') as stream:
        result['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return result


def current_provenance():
    current, unavailable = {}, {}
    for kind in versions():
        try:
            tool = None
            if kind == 'psx':
                tool = executable('PSPDB_PSXTRACT', 'pspdb-psxtract')
            elif kind == 'document':
                tool = executable('PSPDB_DOCUMENT', 'pspdb-document')
            current[kind] = tool_provenance(kind, tool)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            unavailable[kind] = str(exc)
    return current, unavailable


def extract_psx(source, output, tool):
    # Whole-PBP context belongs under DATA.BIN in the parent inventory.
    tool = tool.resolve(strict=True)
    provenance = tool_provenance('psx', tool)
    with tempfile.TemporaryDirectory(prefix='pspdb-psxtract-') as tmp:
        work = Path(tmp)
        result = subprocess.run([str(tool), str(source.resolve())], cwd=work,
                                capture_output=True, text=True, errors='replace', timeout=900)
        log = result.stdout + result.stderr
        discs = sorted(work.glob('*.bin'))
        # A Redump MD5 mismatch is a known cosmetic limitation for some titles.
        if result.returncode or not discs or re.search(r'ERROR:|audio conversion.*failed|cannot be opened', log, re.I):
            raise ValueError('PSXtract-2 failed: ' + log[-6000:])
        for disc in discs:
            size = disc.stat().st_size
            if not size or size % 2352:
                raise ValueError('Invalid reconstructed CD sector count')
            with disc.open('rb') as stream:
                stream.seek(16 * 2352 + 24)
                if stream.read(7) != b'\x01CD001\x01':
                    raise ValueError('Reconstructed disc lacks ISO9660 descriptor')
        for i, disc in enumerate(discs, 1):
            shutil.move(disc, output / ('disc.bin' if len(discs) == 1 else f'disc-{i}.bin'))
        # Keep decoded source-backed auxiliary containers; CUE/logs stay tool outputs.
        for name in ('ISO_HEADER.BIN', *(f'ISO_HEADER_{i}.BIN' for i in range(1, 6)),
                     'ISO_MAP.BIN', 'STARTDAT.BIN', 'SPECIAL_DATA.BIN', 'TRASH.BIN', 'OVERDUMP.BIN'):
            path = work / 'TEMP' / name
            if path.is_file() and path.stat().st_size:
                shutil.copyfile(path, output / name)
    return provenance


def extract_document(source, output, tool, docinfo=None):
    tool = tool.resolve(strict=True)
    provenance = tool_provenance('document', tool)
    command = [str(tool), str(source.resolve(strict=True)), '--output', str(output.resolve())]
    if docinfo is not None:
        command.extend(('--docinfo', str(docinfo.resolve(strict=True))))
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
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
    parser.add_argument('kind', choices=['psx', 'document'])
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
        if args.kind == 'psx':
            provenance = extract_psx(args.source, args.output, executable('PSPDB_PSXTRACT', 'pspdb-psxtract'))
        else:
            provenance = extract_document(args.source, args.output, executable('PSPDB_DOCUMENT', 'pspdb-document'), args.docinfo)
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
