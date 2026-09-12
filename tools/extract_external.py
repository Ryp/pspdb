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
    with tool.open('rb') as stream:
        tool_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'name': 'pspdecrypt', 'sha256': tool_hash, 'options': ['-O', '<output>', '<source>']}


def extract_rco(source, output, tool, data):
    tool = tool.resolve(strict=True)
    data = data.resolve(strict=True)
    config_hash = hashlib.sha256()
    for path in sorted(data.glob('*.ini')):
        config_hash.update(path.name.encode() + b'\0' + path.read_bytes())
    if not any(data.glob('*.ini')):
        raise ValueError('Missing RCOMage INI configuration')
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
    return {'name': 'rcomage', 'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
            'options': ['dump', '<source>', 'structure.xml', '--resdir', 'resources',
                        '--ini-dir', 'sha256:' + config_hash.hexdigest()]}


def payload_name(header):
    if header.startswith(b'\x7fELF'):
        if len(header) >= 18 and int.from_bytes(header[16:18], 'little') in (0xffa0, 0xffa1):
            return 'module.prx'
        return 'module.elf'
    if header.startswith(b'\x1f\x8b\x08'):
        return 'payload.gz'
    return 'payload.bin'


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
    return payload_name(payload_header)


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
    return {'name': 'pspdecrypt', 'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
            'version': 'prx-2', 'options': ['-o', '<output>', '<source>']}


def extract_gzip(source, output):
    import gzip
    with gzip.open(source, 'rb') as stream:
        data = stream.read()
    (output / payload_name(data[:20])).write_bytes(data)
    return {'name': 'pspdb-ingest', 'version': 'gzip-2', 'options': []}


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
    return {'name': 'pspdecrypt-kle', 'sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
            'version': 'kle-1', 'options': ['-o', '<output>', '<source>']}


def executable(variable, name):
    return Path(os.environ.get(variable) or shutil.which(name) or name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['psar', 'rco', 'prx', 'gzip', 'kl3e', 'kl4e'])
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.kind == 'psar':
            provenance = extract_psar(args.source, args.output, executable('PSPDECRYPT', 'pspdecrypt'))
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
