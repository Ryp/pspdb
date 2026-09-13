"""Extract PSP resources into a caller-owned directory; Zig owns traversal and cleanup."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import mmap
from pathlib import Path
import re
import shutil
import subprocess
import stat
import tempfile
import xml.etree.ElementTree as ET


VERSIONS = None

PSMF_SOURCE_LIMIT = 128 * 1024 * 1024
PSMF_MANIFEST_LIMIT = 16 * 1024 * 1024
PSMF_UPSTREAM = 'upstream:1bc01f9ffbfb97adc9bb384c44e081398b9a93e4'


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
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip', 'vmp'):
        return result
    if kind == 'psmf':
        tool = tool.resolve(strict=True)
        reported = json.loads(run_psmf([str(tool), '--provenance'], timeout=30))
        if (not isinstance(reported, dict) or set(reported) != {'name', 'options'}
                or reported['name'] != 'pmftools' or not isinstance(reported['options'], list)
                or any(not isinstance(option, str) or not option for option in reported['options'])
                or len(set(reported['options'])) != len(reported['options'])
                or PSMF_UPSTREAM not in reported['options']
                or 'manifest-budget-env:1' not in reported['options']):
            raise ValueError('Invalid PSMF helper provenance')
        with tool.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        return dict(result, name=reported['name'], options=reported['options'], sha256=digest)
    if kind == 'document':
        tool = tool.resolve(strict=True)
        result.update(json.loads(subprocess.check_output([str(tool), '--provenance'], text=True, timeout=30)))
        result['sha256'] = hashlib.sha256(tool.read_bytes()).hexdigest()
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
            elif kind == 'document':
                tool = executable('PSPDB_DOCUMENT', 'pspdb-document')
            elif kind == 'psmf':
                tool = executable('PSPDB_PSMF', 'pspdb-psmf')
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


def decoded_payload_name(header):
    # Name decoded objects by byte format. PRX is an ELF module subtype,
    # not another encoding to unwrap after ELF has been recovered.
    if header.startswith(b'\x7fELF'):
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
        name = decoded_payload_name(stream.read(20))
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




def run_psmf(command, timeout):
    # CoreCLR's JIT uses a 2 TiB anonymous memfd: RLIMIT_FSIZE breaks startup.
    # Raw output is bounded by source spans; the reader enforces the manifest cap.
    env = dict(os.environ, DOTNET_GCHeapHardLimit='0x10000000',
               COMPlus_GCHeapHardLimit='0x10000000',
               PSPDB_PSMF_MANIFEST_LIMIT=str(PSMF_MANIFEST_LIMIT))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, env=env,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ValueError(f'PSMF helper exceeded {timeout} seconds') from error
        stderr.seek(0)
        if result.returncode:
            raise ValueError(f'PSMF helper exited {result.returncode}: ' + stderr.read(65536).decode('utf-8', errors='replace'))
        stdout.seek(0)
        data = stdout.read(65537)
        if len(data) > 65536:
            raise ValueError('PSMF helper stdout exceeds 64 KiB')
        return data


def psmf_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate PSMF manifest key')
        result[key] = value
    return result


def psmf_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('Invalid PSMF manifest fields')


def psmf_integer(value):
    if type(value) is not int or not 0 <= value <= PSMF_SOURCE_LIMIT:
        raise ValueError('Invalid PSMF manifest integer')
    return value


def psmf_regular_file(path, limit):
    # O_NONBLOCK prevents an unexpected FIFO from blocking before fstat.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('Invalid PSMF file type or size')
        return os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise


def psmf_header(data):
    if len(data) < 130 or data[:4] != b'PSMF':
        raise ValueError('Invalid PSMF header')
    if data[4:8] not in (b'0012', b'0013', b'0014', b'0015'):
        raise ValueError('Unsupported PSMF version')
    start = int.from_bytes(data[8:12], 'big')
    end = start + int.from_bytes(data[12:16], 'big')
    count = int.from_bytes(data[128:130], 'big')
    if not count or start < 130 + 16 * count or not start < end == len(data):
        raise ValueError('Invalid declared PSMF bounds or stream count')
    declared = {}
    for offset in range(130, 130 + count * 16, 16):
        sid, channel = data[offset:offset + 2]
        if 0xe0 <= sid <= 0xef and channel == 0:
            name = f'video-{sid:02x}.h264'
        elif sid == 0xbd and channel < 0x20:
            name = f'audio-bd-{channel:02x}.framed-at3'
        else:
            raise ValueError('Unsupported declared PSMF stream')
        key = f'{sid:02x}:{channel:02x}'
        if key in declared:
            raise ValueError('Duplicate declared PSMF stream')
        declared[key] = name
    return start, end, declared


def validate_psmf(data, source_hash, directory):
    start, end, declared = psmf_header(data)
    if hashlib.sha256(data).hexdigest() != source_hash:
        raise ValueError('PSMF source changed during extraction')
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValueError('Invalid PSMF helper directory')
    with psmf_regular_file(directory / 'manifest.json', PSMF_MANIFEST_LIMIT) as stream:
        manifest = json.load(stream, object_pairs_hook=psmf_object)
    psmf_fields(manifest, ('source_sha256', 'source_size_bytes', 'data_start', 'data_end',
                           'consumed_end', 'declared_streams', 'packets', 'outputs'))
    if (manifest['source_sha256'] != source_hash
            or psmf_integer(manifest['source_size_bytes']) != len(data)
            or psmf_integer(manifest['data_start']) != start
            or psmf_integer(manifest['data_end']) != end
            or psmf_integer(manifest['consumed_end']) != end):
        raise ValueError('PSMF source identity or declared range mismatch')
    streams = manifest['declared_streams']
    if (not isinstance(streams, list) or any(not isinstance(key, str) for key in streams)
            or len(streams) != len(declared) or set(streams) != set(declared)):
        raise ValueError('PSMF declared stream inventory mismatch')
    packets, outputs = manifest['packets'], manifest['outputs']
    if not isinstance(packets, list) or not isinstance(outputs, list) or len(outputs) != len(declared):
        raise ValueError('Invalid PSMF packet or output inventory')
    expected_names = set(declared.values())
    metadata = {}
    for item in outputs:
        psmf_fields(item, ('path', 'size_bytes', 'sha256'))
        name, digest = item['path'], item['sha256']
        if not isinstance(name, str) or name not in expected_names or name in metadata:
            raise ValueError('Invalid or duplicate PSMF output path')
        if (not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or not psmf_integer(item['size_bytes'])):
            raise ValueError('Invalid PSMF output identity')
        metadata[name] = item
    if {entry.name for entry in directory.iterdir()} != expected_names | {'manifest.json'}:
        raise ValueError('Unexpected or missing PSMF helper output')
    observed = set()
    consumed = start
    with ExitStack() as stack:
        files = {name: stack.enter_context(psmf_regular_file(directory / name, PSMF_SOURCE_LIMIT))
                 for name in expected_names}
        hashes = {name: hashlib.sha256() for name in expected_names}
        for name, stream in files.items():
            if os.fstat(stream.fileno()).st_size != metadata[name]['size_bytes']:
                raise ValueError('PSMF output size mismatch')
        for packet in packets:
            psmf_fields(packet, ('start', 'end', 'packet_id', 'stream', 'payload_start', 'payload_end'))
            packet_start = psmf_integer(packet['start'])
            packet_end = psmf_integer(packet['end'])
            sid = psmf_integer(packet['packet_id'])
            if (packet_start != consumed or not packet_start + 4 <= packet_end <= end
                    or data[packet_start:packet_start + 3] != b'\x00\x00\x01'
                    or data[packet_start + 3] != sid):
                raise ValueError('Invalid PSMF contiguous packet range or ID')
            key = payload_start = payload_end = None
            if sid == 0xba:
                if packet_start + 14 > end or data[packet_start + 4] & 0xc0 != 0x40:
                    raise ValueError('Invalid MPEG2 pack header')
                expected_end = packet_start + 14 + (data[packet_start + 13] & 7)
                if (expected_end > end
                        or data[packet_start + 14:expected_end] != b'\xff' * (expected_end - packet_start - 14)):
                    raise ValueError('Invalid PSMF pack stuffing')
            elif sid == 0xb9:
                expected_end = packet_start + 4
                if expected_end != end:
                    raise ValueError('Premature PSMF program end')
            elif sid in (0xbb, 0xbe, 0xbf, 0xbd) or 0xe0 <= sid <= 0xef:
                if packet_start + 6 > end:
                    raise ValueError('Short PSMF packet length')
                expected_end = packet_start + 6 + int.from_bytes(data[packet_start + 4:packet_start + 6], 'big')
                if sid == 0xbd or 0xe0 <= sid <= 0xef:
                    if packet_start + 9 > packet_end or data[packet_start + 6] & 0xc0 != 0x80:
                        raise ValueError('Invalid MPEG2 PES header')
                    payload_start = packet_start + 9 + data[packet_start + 8]
                    channel = 0
                    if sid == 0xbd:
                        if payload_start + 4 >= packet_end:
                            raise ValueError('Short PSMF private stream header or payload')
                        channel = data[payload_start]
                        payload_start += 4
                    payload_end = packet_end
                    if payload_start >= payload_end:
                        raise ValueError('Empty or out-of-range PSMF PES payload')
                    key = f'{sid:02x}:{channel:02x}'
                    if key not in declared:
                        raise ValueError('Undeclared PSMF packet stream')
            else:
                raise ValueError('Unsupported PSMF packet ID')
            if packet_end != expected_end:
                raise ValueError('PSMF packet length mismatch')
            if (packet['stream'] != key or packet['payload_start'] != payload_start
                    or packet['payload_end'] != payload_end):
                raise ValueError('PSMF payload source range mismatch')
            if key is not None:
                psmf_integer(packet['payload_start'])
                psmf_integer(packet['payload_end'])
                observed.add(key)
                name = declared[key]
                while payload_start < payload_end:
                    chunk_end = min(payload_start + 65536, payload_end)
                    chunk = files[name].read(chunk_end - payload_start)
                    if chunk != data[payload_start:chunk_end]:
                        raise ValueError('PSMF output differs from source payload bytes')
                    hashes[name].update(chunk)
                    payload_start = chunk_end
            consumed = packet_end
        if consumed != end or observed != set(declared):
            raise ValueError('Incomplete PSMF packet or stream inventory')
        for name, stream in files.items():
            if stream.read(1) or hashes[name].hexdigest() != metadata[name]['sha256']:
                raise ValueError('PSMF output hash or concatenated size mismatch')
    return sorted(expected_names)


def extract_psmf(source, output, tool):
    if not stat.S_ISDIR(output.lstat().st_mode) or any(output.iterdir()):
        raise ValueError('PSMF output must be an existing empty directory')
    with psmf_regular_file(source, PSMF_SOURCE_LIMIT) as stream, mmap.mmap(
            stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        psmf_header(data)
        source_hash = hashlib.sha256(data).hexdigest()
        tool = tool.resolve(strict=True)
        provenance = tool_provenance('psmf', tool)
        # The helper requires a new destination; no unverified artifact reaches Zig.
        with tempfile.TemporaryDirectory(prefix='pspdb-psmf-', dir=output.parent) as temporary:
            directory = Path(temporary) / 'streams'
            run_psmf([str(tool), str(source.resolve(strict=True)), str(directory.resolve())], timeout=120)
            names = validate_psmf(data, source_hash, directory)
            published = []
            try:
                for name in names + ['manifest.json']:
                    target = output / ('structure.json' if name == 'manifest.json' else name)
                    (directory / name).rename(target)
                    published.append(target)
            except BaseException:
                for target in published:
                    target.unlink()
                raise
        return provenance


def executable(variable, name):
    return Path(os.environ.get(variable) or shutil.which(name) or name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['psar', 'rco', 'prx', 'gzip', 'kl3e', 'kl4e', 'npumdimg', 'pops', 'psx', 'document', 'psmf'])
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
        elif args.kind == 'npumdimg':
            provenance = extract_npumdimg(args.source, args.output, executable('PKG2ZIP_NPUMDIMG', 'pkg2zip-npumdimg'))
        elif args.kind == 'psx':
            provenance = extract_psx(args.source, args.output, executable('PSPDB_PSXTRACT2', 'psxtract.exe'))
        elif args.kind == 'pops':
            provenance = extract_pops(args.source, args.output, executable('PSPDB_POPS', 'pspdb-pops'))
        elif args.kind == 'document':
            provenance = extract_document(args.source, args.output, executable('PSPDB_DOCUMENT', 'pspdb-document'), args.docinfo)
        elif args.kind == 'psmf':
            provenance = extract_psmf(args.source, args.output, executable('PSPDB_PSMF', 'pspdb-psmf'))
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
    except (OSError, ValueError, ET.ParseError, EOFError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(provenance))


if __name__ == '__main__':
    main()
