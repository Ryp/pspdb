"""Extract PSP resources into a caller-owned directory; Zig owns traversal and cleanup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip'):
        return result
    result['name'] = 'rcomage' if kind == 'rco' else 'pspdecrypt-kle' if kind in ('kl3e', 'kl4e') else 'pspdecrypt'
    result['sha256'] = hashlib.sha256(tool.resolve(strict=True).read_bytes()).hexdigest()
    result['options'] = ['-O' if kind == 'psar' else '-o', '<output>', '<source>']
    if kind == 'psx':
        result['name'] = 'PSXtract-2'
        result['options'] = ['<parent.pbp>', 'reconstructed-disc', 'wine-sha256:' + hashlib.sha256(executable('PSPDB_WINE', 'wine').resolve(strict=True).read_bytes()).hexdigest()]
    if kind == 'pops':
        result['name'] = 'pspdb-pops'
        result['options'] = ['<parent.pbp>', '<output>']
    if kind == 'npumdimg':
        result['name'] = 'pkg2zip-npumdimg'
        result['options'] = ['<source>', '<output.iso>']
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
            if kind in ('psar', 'prx'):
                tool = executable('PSPDECRYPT', 'pspdecrypt')
            elif kind in ('kl3e', 'kl4e'):
                tool = executable('PSPDECRYPT_KLE', 'pspdecrypt-kle')
            elif kind == 'psx':
                tool = executable('PSPDB_PSXTRACT2', 'psxtract.exe')
            elif kind == 'pops':
                tool = executable('PSPDB_POPS', 'pspdb-pops')
            elif kind == 'npumdimg':
                tool = executable('PKG2ZIP_NPUMDIMG', 'pkg2zip-npumdimg')
            elif kind == 'rco':
                tool = executable('RCOMAGE', 'rcomage').resolve(strict=True)
                data = Path(os.environ.get('RCOMAGE_DATA', tool.parent.parent / 'share' / 'rcomage'))
            current[kind] = tool_provenance(kind, tool, data)
        except (OSError, ValueError) as exc:
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


def extract_npumdimg(source, output, tool):
    with source.open('rb') as stream:
        if stream.read(8) != b'NPUMDIMG':
            raise ValueError('Source is not NPUMDIMG')
    tool = tool.resolve(strict=True)
    target = output / 'disc.iso'
    result = subprocess.run([str(tool), str(source.resolve()), str(target.resolve())],
                            capture_output=True, text=True, errors='replace')
    log = result.stdout + result.stderr
    if result.returncode or re.search(r'error|fail', log, re.I) or not target.is_file():
        raise ValueError(f'NPUMDIMG extraction failed:\n{log}')
    with target.open('rb') as stream:
        stream.seek(32768)
        descriptor = stream.read(7)
    if target.stat().st_size % 2048 or descriptor != b'\x01CD001\x01':
        raise ValueError('NPUMDIMG extractor did not produce an ISO filesystem')
    return tool_provenance('npumdimg', tool)


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


def payload_name(header):
    if header.startswith(b'\x7fELF'):
        if len(header) >= 18 and int.from_bytes(header[16:18], 'little') in (0xffa0, 0xffa1):
            return 'module.prx'
        return 'module.elf'
    if header.startswith(b'\x1f\x8b\x08'):
        return 'payload.gz'
    return 'payload.bin'


def decoded_payload_name(header):
    # Name decoded objects by byte format. PRX is an ELF module subtype,
    # not another encoding to unwrap after ELF has been recovered.
    if header.startswith(b'\x7fELF'):
        return 'module.elf'
    return payload_name(header)


def prx_payload_name(payload_header, psp_header):
    compression = next((suffix for magic, suffix in
        [(b'\x1f\x8b\x08', '.gz'), (b'KL4E', '.kl4e'), (b'KL3E', '.kl3e')]
        if payload_header.startswith(magic)), None)
    if compression:
        attributes = int.from_bytes(psp_header[6:8], 'little')
        extension = '.elf' if attributes & 2 else '.prx'
        # Raw reboot images also use the wrapper, without the module compression flag.
        if not attributes & 1:
            extension = '.bin'
        return 'module' + extension + compression
    return decoded_payload_name(payload_header)


def extract_prx(source, output, tool):
    with source.open('rb') as stream:
        header = stream.read(0x150)
    if len(header) != 0x150 or header[:4] != b'~PSP':
        raise ValueError('Invalid PSP executable header')
    expected = int.from_bytes(header[0xb0:0xb4], 'little')
    if not 0 < expected <= source.stat().st_size:
        raise ValueError('Invalid PSP decrypted size')
    tool = tool.resolve(strict=True)
    target = output / 'payload.bin'
    result = subprocess.run([str(tool), '-o', str(target), str(source.resolve())],
                            capture_output=True, text=True, errors='replace')
    log = result.stdout + result.stderr
    if result.returncode or 'Decryption successful' not in log:
        raise ValueError(f'PRX decryption failed:\n{log}')
    if target.stat().st_size != expected:
        raise ValueError('Unexpected decrypted PSP size')
    with target.open('rb') as stream:
        name = prx_payload_name(stream.read(20), header)
    target.rename(output / name)
    return tool_provenance('prx', tool)


def extract_pops(source, output, tool):
    tool = tool.resolve(strict=True)
    target = output / 'payload.bin'
    result = subprocess.run([str(tool), str(source.resolve()), str(target.resolve())],
                            capture_output=True, text=True, errors='replace')
    if result.returncode:
        raise ValueError(f'POPS decryption failed: {result.stdout}{result.stderr}')
    with target.open('rb') as stream:
        header = stream.read(20)
    if not (header.startswith(b'\x1f\x8b\x08') or header.startswith(b'\x7fELF')):
        raise ValueError('Unexpected decrypted POPS payload')
    target.rename(output / decoded_payload_name(header))
    return tool_provenance('pops', tool)


def extract_gzip(source, output):
    import gzip
    with gzip.open(source, 'rb') as stream:
        data = stream.read()
    (output / decoded_payload_name(data[:20])).write_bytes(data)
    return tool_provenance('gzip')


def extract_kle(source, output, tool):
    tool = tool.resolve(strict=True)
    target = output / 'payload.bin'
    result = subprocess.run([str(tool), '-o', str(target), str(source.resolve())],
                            capture_output=True, text=True, errors='replace')
    log = result.stdout + result.stderr
    if result.returncode or 'Decompression successful' not in log or not target.is_file() or not target.stat().st_size:
        raise ValueError(f'KL decompression failed:\n{log}')
    with target.open('rb') as stream:
        name = payload_name(stream.read(20))
    target.rename(output / name)
    with source.open('rb') as stream:
        kind = 'kl3e' if stream.read(4) == b'KL3E' else 'kl4e'
    return tool_provenance(kind, tool)


def extract_psx(source, output, tool):
    import tempfile
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


def executable(variable, name):
    return Path(os.environ.get(variable) or shutil.which(name) or name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['psar', 'rco', 'prx', 'gzip', 'kl3e', 'kl4e', 'npumdimg', 'pops', 'psx'])
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--versions', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.versions:
        global VERSIONS
        VERSIONS = json.loads(args.versions)
    try:
        if args.kind == 'psar':
            provenance = extract_psar(args.source, args.output, executable('PSPDECRYPT', 'pspdecrypt'))
        elif args.kind == 'npumdimg':
            provenance = extract_npumdimg(args.source, args.output, executable('PKG2ZIP_NPUMDIMG', 'pkg2zip-npumdimg'))
        elif args.kind == 'psx':
            provenance = extract_psx(args.source, args.output, executable('PSPDB_PSXTRACT2', 'psxtract.exe'))
        elif args.kind == 'pops':
            provenance = extract_pops(args.source, args.output, executable('PSPDB_POPS', 'pspdb-pops'))
        elif args.kind == 'prx':
            provenance = extract_prx(args.source, args.output, executable('PSPDECRYPT', 'pspdecrypt'))
        elif args.kind in ('kl3e', 'kl4e'):
            provenance = extract_kle(args.source, args.output, executable('PSPDECRYPT_KLE', 'pspdecrypt-kle'))
        elif args.kind == 'gzip':
            provenance = extract_gzip(args.source, args.output)
        else:
            tool = executable('RCOMAGE', 'rcomage').resolve(strict=True)
            data = Path(os.environ['RCOMAGE_DATA']) if 'RCOMAGE_DATA' in os.environ else tool.parent.parent / 'share' / 'rcomage'
            provenance = extract_rco(args.source, args.output, tool, data)
    except (OSError, ValueError, ET.ParseError, EOFError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
