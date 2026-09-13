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
import xml.etree.ElementTree as ET



VERSIONS = None



def versions():
    global VERSIONS
    if VERSIONS is None:
        VERSIONS = json.loads(Path(__file__).with_name('extractor_versions.json').read_text())
    if not isinstance(VERSIONS, dict) or any(not isinstance(v, str) or not re.fullmatch(r'[1-9][0-9]*', v) for v in VERSIONS.values()):
        raise ValueError('Extractor revisions must be positive integer strings')
    return VERSIONS


def tool_provenance(kind, tool=None, data=None):
    result = {'name': 'pspdb-ingest', 'version': versions()[kind], 'options': []}
    if kind == 'pbp':
        return dict(result, name='Zig-PSP zPBPTool', options=['in-memory'])
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip', 'vmp', 'prx', 'kl3e', 'kl4e', 'edat', 'npumdimg'):
        return result
    if kind == 'pops':
        return dict(result, name='pspdb-pops', options=['in-memory'])
    if kind == 'document':
        tool = tool.resolve(strict=True)
        reported = json.loads(subprocess.check_output([str(tool), '--provenance'], text=True, timeout=30),
                              object_pairs_hook=manifest_object)
        manifest_fields(reported, ('name', 'options'))
        if (reported['name'] != 'PSP-DOCUMENT.DAT' or not isinstance(reported['options'], list)
                or any(not isinstance(option, str) for option in reported['options'])
                or 'page-files-only:1' not in reported['options']):
            raise ValueError('Invalid DOCUMENT helper provenance: page-only output required')
        result.update(reported)
        result['sha256'] = hashlib.sha256(tool.read_bytes()).hexdigest()
        return result
    result['name'] = 'rcomage' if kind == 'rco' else 'pspdecrypt'
    result['sha256'] = hashlib.sha256(tool.resolve(strict=True).read_bytes()).hexdigest()
    result['options'] = ['-O' if kind == 'psar' else '-o', '<output>', '<source>']
    if kind == 'psx':
        result['name'] = 'PSXtract-2'
        result['options'] = ['<parent.pbp>', 'reconstructed-disc', 'wine-sha256:' + hashlib.sha256(executable('PSPDB_WINE', 'wine').resolve(strict=True).read_bytes()).hexdigest()]
    if kind == 'rco':
        paths = sorted(data.resolve(strict=True).glob('*.ini'))
        if not paths:
            raise ValueError('Missing RCOMage INI configuration')
        config_hash = hashlib.sha256()
        for path in paths:
            config_hash.update(path.name.encode() + b'\0' + path.read_bytes())
        result['options'] = ['dump', '<source>', 'structure.xml', '--resdir', 'resources',
                             '--ini-dir', 'sha256:' + config_hash.hexdigest()]
    return result


def current_provenance():
    current, unavailable = {}, {}
    for kind in versions():
        try:
            tool = data = None
            if kind == 'psar':
                tool = executable('PSPDECRYPT', 'pspdecrypt')
            elif kind == 'psx':
                tool = executable('PSPDB_PSXTRACT2', 'psxtract.exe')
            elif kind == 'document':
                tool = executable('PSPDB_DOCUMENT', 'pspdb-document')
            elif kind == 'rco':
                tool = executable('RCOMAGE', 'rcomage').resolve(strict=True)
                data = Path(os.environ.get('RCOMAGE_DATA', tool.parent.parent / 'share' / 'rcomage'))
            current[kind] = tool_provenance(kind, tool, data)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            unavailable[kind] = str(exc)
    return current, unavailable




def extract_psar(source, output, tool):
    with source.open('rb') as stream:
        if stream.read(4) != b'PSAR':
            raise ValueError('Source is not a firmware PSAR')
    tool = tool.resolve(strict=True)
    result = subprocess.run([str(tool), '-O', str(output), str(source.resolve())],
                            capture_output=True, text=True, errors='replace')
    log = result.stdout + result.stderr
    # Upstream sometimes reports failures only in its log, with a zero exit.
    if result.returncode or 'Done!' not in log or re.search(r'error|fail', log, re.I):
        raise ValueError(f'Extractor did not complete cleanly:\n{log}')
    return tool_provenance('psar', tool)



def extract_rco(source, output, tool, data):
    tool = tool.resolve(strict=True)
    data = data.resolve(strict=True)
    provenance = tool_provenance('rco', tool, data)
    (output / 'resources').mkdir()
    result = subprocess.run([str(tool), 'dump', str(source.resolve()), 'structure.xml',
                            '--resdir', 'resources', '--ini-dir', str(data)], cwd=output,
                            capture_output=True, text=True, errors='replace')
    log = result.stdout + result.stderr
    if result.returncode or re.search(r'^(?:Warning|Error):', log, re.M):
        raise ValueError(f'RCO extraction did not complete cleanly:\n{log}')
    ET.parse(output / 'structure.xml')
    for path in (output / 'resources').glob('*.xml'):
        ET.parse(path)
    return provenance






def extract_psx(source, output, tool):
    # Whole-PBP context belongs under DATA.BIN in the parent inventory.
    tool = tool.resolve(strict=True)
    wine = executable('PSPDB_WINE', 'wine').resolve(strict=True)
    provenance = tool_provenance('psx', tool)
    env = dict(os.environ, WINEDEBUG='-all', WINEDLLOVERRIDES='mscoree,mshtml,winemenubuilder.exe=d')
    env.setdefault('WINEPREFIX', str(Path.home() / '.cache/pspdb/wine-psxtract2'))
    with tempfile.TemporaryDirectory(prefix='pspdb-psxtract2-') as tmp:
        work = Path(tmp)
        result = subprocess.run([str(wine), str(tool), str(source.resolve())], cwd=work,
                                env=env, capture_output=True, text=True, errors='replace', timeout=900)
        log = result.stdout + result.stderr
        discs = sorted(work.glob('*.bin'))
        # A Redump MD5 mismatch is a known cosmetic limitation for some titles.
        if result.returncode or not discs or 'Disc successfully converted' not in log or re.search(r'ERROR:|audio conversion.*failed|cannot be opened', log, re.I):
            raise ValueError('PSXtract-2 failed: ' + log[-6000:])
        for i, disc in enumerate(discs, 1):
            size = disc.stat().st_size
            if not size or size % 2352:
                raise ValueError('Invalid reconstructed CD sector count')
            with disc.open('rb') as stream:
                stream.seek(16 * 2352 + 24)
                if stream.read(7) != b'\x01CD001\x01':
                    raise ValueError('Reconstructed disc lacks ISO9660 descriptor')
            shutil.move(disc, output / ('disc.bin' if len(discs) == 1 else f'disc-{i}.bin'))
        # Keep decoded source-backed auxiliary containers; CUE/logs stay tool outputs.
        for name in ('ISO_HEADER.BIN', 'ISO_MAP.BIN', 'STARTDAT.BIN', 'SPECIAL_DATA.BIN', 'TRASH.BIN', 'OVERDUMP.BIN'):
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
    parser.add_argument('kind', choices=['psar', 'rco', 'psx', 'document'])
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
        if args.kind == 'psar':
            provenance = extract_psar(args.source, args.output, executable('PSPDECRYPT', 'pspdecrypt'))
        elif args.kind == 'psx':
            provenance = extract_psx(args.source, args.output, executable('PSPDB_PSXTRACT2', 'psxtract.exe'))
        elif args.kind == 'document':
            provenance = extract_document(args.source, args.output, executable('PSPDB_DOCUMENT', 'pspdb-document'), args.docinfo)
        else:
            tool = executable('RCOMAGE', 'rcomage').resolve(strict=True)
            data = Path(os.environ['RCOMAGE_DATA']) if 'RCOMAGE_DATA' in os.environ else tool.parent.parent / 'share' / 'rcomage'
            provenance = extract_rco(args.source, args.output, tool, data)
    except (OSError, ValueError, ET.ParseError, EOFError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
