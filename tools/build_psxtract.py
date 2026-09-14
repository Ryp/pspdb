"""Build pinned native Linux x86_64 PSXtract-2 with exact, mandatory ATRAC3 audio.

Requires Python 3.12+, git, patch, make and GCC-compatible C/C++17 compilers.
Both source arguments are Git checkouts; only the pinned committed trees are used.
FFmpeg's minimal avcodec/avutil libraries are linked statically, with no FFmpeg
CLI, Wine, Sony ACM, or system FFmpeg development-library dependency.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

REVISION = '4691fc405698d53927df6e4f59c3e9b113c13706'
FFMPEG_REVISION = '59dd21047e86badeb1b142dff03f18acbbd074fa'
UPSTREAM = 'https://github.com/has207/psxtract-2'
FFMPEG_UPSTREAM = 'https://git.ffmpeg.org/ffmpeg.git'
ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ('native.h', 'native.cpp', 'atrac3.cpp', 'test_lz.cpp', 'test_auxiliary.cpp',
           'test_pbp.cpp', 'test_audio.cpp', 'test_container.cpp', 'test_pgd.cpp')
# The x87 arithmetic and explicit float stores in the patch are an output contract.
EXACT_CFLAGS = ('-mfpmath=387', '-fexcess-precision=fast', '-fno-fast-math',
                '-fno-associative-math', '-ffp-contract=off')


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def jobs_argument(value):
    jobs = int(value)
    if not 1 <= jobs <= 32:
        raise argparse.ArgumentTypeError('--jobs must be between 1 and 32')
    return jobs


def prepare_source(source, revision, destination, patch):
    destination.mkdir()
    archive = destination.parent / (destination.name + '.tar')
    with archive.open('wb') as stream:
        subprocess.run(['git', '-C', str(source), 'archive', '--format=tar', revision],
                       stdout=stream, check=True)
    digest = sha256(archive)
    with tarfile.open(archive) as tree:
        tree.extractall(destination, filter='data')
    archive.unlink()
    if destination.name == 'psxtract':
        # Upstream mixes CRLF and LF source files; resources must stay byte-identical.
        for path in (destination / 'src').iterdir():
            if path.suffix in ('.cpp', '.h'):
                text = path.read_text()
                path.write_text(text if text.endswith('\n') else text + '\n')
    result = subprocess.run(
        ['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
        cwd=destination, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=60,
    )
    if result.returncode or re.search(r'\b(?:offset|fuzz|FAILED|Reversed)\b', result.stdout):
        raise ValueError(f'{patch.name} did not apply exactly: {result.stdout.strip()}')
    return digest


def embed_cues(work):
    """Replace Win32 resources with byte-identical, executable-owned CUE blobs."""
    blobs = []
    entries = []
    digest = hashlib.sha256()
    for index, path in enumerate(sorted((work / 'cue').glob('*.cue')), 1):
        data = path.read_bytes()
        digest.update(path.name.encode() + b'\0' + data + b'\0')
        blobs.append(f'static const unsigned char cue_{index}[] = {{' +
                     ','.join(str(byte) for byte in data) + ',0};\n')
        entries.append(f'    {{{json.dumps(path.stem)}, {index}, cue_{index}, {len(data)}}},\n')
    if not entries:
        raise ValueError('Pinned source contains no CUE resources')
    (work / 'src/cue_lookup_table.autogen').write_text(
        ''.join(blobs) + 'static const CueResourceEntry cue_lookup[] = {\n' +
        ''.join(entries) + '    {nullptr, 0, nullptr, 0}\n};\n')
    return digest.hexdigest()


def compiler_provenance(command):
    if not command:
        raise ValueError('CC and CXX must name a compiler')
    executable = shutil.which(command[0])
    if executable is None:
        raise ValueError(f'Compiler not found: {command[0]}')
    executable = Path(executable).resolve()
    version = subprocess.check_output([*command, '--version'], text=True)
    return {'command': command, 'path': str(executable), 'sha256': sha256(executable),
            'version': version, 'version_sha256': hashlib.sha256(version.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--psxtract-source', type=Path, required=True,
                        help=f'Git checkout containing {UPSTREAM} commit {REVISION}')
    parser.add_argument('--ffmpeg-source', type=Path, required=True,
                        help=f'Git checkout containing FFmpeg commit {FFMPEG_REVISION}')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=jobs_argument, default=4)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error('Python 3.12 or newer is required')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Exact ATRAC3 requires native Linux x86_64 and GCC-compatible x87 arithmetic')
    psx_source = args.psxtract_source.expanduser().resolve()
    ff_source = args.ffmpeg_source.expanduser().resolve()
    output = args.output.expanduser().absolute()
    patch = ROOT / 'tools/patches/psxtract-native.patch'
    ff_patch = ROOT / 'tools/patches/ffmpeg-atrac3-exact.patch'
    support = ROOT / 'tools/psxtract'
    inputs = {Path(__file__).resolve(), patch, ff_patch, *(support / name for name in SUPPORT)}
    destinations = [output, output.with_name(output.name + '.LICENSE'),
                    output.with_name(output.name + '.provenance.json')]
    for destination in destinations:
        resolved = destination.resolve()
        if resolved in inputs or resolved.is_relative_to(psx_source) or resolved.is_relative_to(ff_source):
            parser.error('Output would overwrite a build input or source checkout')
    cc = shlex.split(os.environ.get('CC', 'gcc'))
    cxx = shlex.split(os.environ.get('CXX', 'g++'))
    try:
        compilers = {'cc': compiler_provenance(cc), 'cxx': compiler_provenance(cxx)}
        with tempfile.TemporaryDirectory(prefix='pspdb-psxtract-build-') as tmp:
            work = Path(tmp)
            psx = work / 'psxtract'
            ff = work / 'ffmpeg'
            psx_digest = prepare_source(psx_source, REVISION, psx, patch)
            ff_digest = prepare_source(ff_source, FFMPEG_REVISION, ff, ff_patch)
            for name in SUPPORT:
                shutil.copyfile(support / name, psx / 'src' / name)
            cue_digest = embed_cues(psx)
            ff_build = work / 'ffmpeg-build'
            ff_build.mkdir()
            configure = [str(ff / 'configure'), '--disable-everything', '--disable-autodetect',
                         '--disable-programs', '--disable-doc', '--disable-network', '--disable-asm',
                         '--disable-avdevice', '--disable-avformat', '--disable-avfilter',
                         '--disable-swscale', '--disable-swresample', '--enable-decoder=atrac3',
                         '--enable-static', '--disable-shared', '--enable-gpl', '--enable-version3',
                         '--arch=x86_64', '--target-os=linux', '--cc=' + shlex.join(cc),
                         '--cxx=' + shlex.join(cxx), '--extra-cflags=' + ' '.join(EXACT_CFLAGS)]
            subprocess.run(configure, cwd=ff_build, check=True)
            subprocess.run(['make', f'-j{args.jobs}', 'libavcodec/libavcodec.a',
                            'libavutil/libavutil.a'], cwd=ff_build, check=True)
            objects = []
            for source in sorted((psx / 'src/libkirk').glob('*.c')):
                obj = source.with_suffix('.o')
                subprocess.run([*cc, '-O2', '-fno-strict-aliasing', '-fwrapv', '-c',
                                str(source), '-o', str(obj)], check=True)
                objects.append(str(obj))
            sources = ('psxtract.cpp', 'crypto.cpp', 'lz.cpp', 'cdrom.cpp', 'utils.cpp',
                       'md5_verify.cpp', 'cue_resources.cpp', 'native.cpp', 'atrac3.cpp')
            binary = work / 'pspdb-psxtract'
            link = [*cxx, '-std=c++17', '-O2', '-fno-strict-aliasing', '-fwrapv',
                    '-fno-fast-math', '-ffp-contract=off', '-Wno-write-strings',
                    '-D_FILE_OFFSET_BITS=64', '-I', str(psx / 'src'), '-I', str(ff_build),
                    '-I', str(ff), *[str(psx / 'src' / name) for name in sources], *objects,
                    str(ff_build / 'libavcodec/libavcodec.a'),
                    str(ff_build / 'libavutil/libavutil.a'), '-lm', '-pthread', '-o', str(binary)]
            subprocess.run(link, check=True)
            # Exercise real parser/codec boundaries before publishing this build.
            for name, test_sources in (
                ('lz', ('test_lz.cpp', 'lz.cpp')),
                ('auxiliary', ('test_auxiliary.cpp', 'lz.cpp', 'utils.cpp', 'native.cpp')),
                ('pbp', ('test_pbp.cpp', 'native.cpp')),
                ('audio', ('test_audio.cpp', 'utils.cpp', 'native.cpp')),
                ('container', ('test_container.cpp', 'crypto.cpp', 'utils.cpp', 'native.cpp')),
                ('pgd', ('test_pgd.cpp', 'utils.cpp', 'native.cpp')),
            ):
                test_binary = work / ('test_' + name)
                subprocess.run([
                    *cxx, '-std=c++17', '-O2', '-fno-strict-aliasing', '-fwrapv', '-Wno-write-strings',
                    '-ffunction-sections', '-fdata-sections', '-D_FILE_OFFSET_BITS=64',
                    '-I', str(psx / 'src'), '-I', str(ff_build), '-I', str(ff),
                    *[str(psx / 'src' / source) for source in test_sources],
                    *(objects if name in ('container', 'pgd') else []),
                    '-Wl,--gc-sections', '-o', str(test_binary),
                ], check=True)
                check_directory = work / ('check_' + name)
                check_directory.mkdir()
                subprocess.run([str(test_binary)], cwd=check_directory, check=True, timeout=15)
            license_sources = {'PSXtract-2/LICENSE': psx / 'LICENSE',
                               'FFmpeg/LICENSE.md': ff / 'LICENSE.md',
                               'FFmpeg/COPYING.LGPLv2.1': ff / 'COPYING.LGPLv2.1',
                               'FFmpeg/COPYING.GPLv3': ff / 'COPYING.GPLv3'}
            license_text = ('PSXtract-2 native Linux, with statically linked FFmpeg.\n'
                            'PSPDB native support and exact ATRAC3 changes: GPL-3.0-or-later.\n\n')
            license_text += ''.join(f'===== {name} =====\n{path.read_text()}\n'
                                    for name, path in license_sources.items())
            provenance = {
                'tool': 'PSXtract-2', 'platform': 'native-linux-x86_64',
                'psxtract': {'source': UPSTREAM, 'revision': REVISION,
                            'source_archive_sha256': psx_digest, 'patch_sha256': sha256(patch)},
                'ffmpeg': {'source': FFMPEG_UPSTREAM, 'revision': FFMPEG_REVISION,
                           'source_archive_sha256': ff_digest, 'patch_sha256': sha256(ff_patch),
                           'configure': configure[1:], 'arithmetic_cflags': list(EXACT_CFLAGS)},
                'support_sha256': {name: sha256(support / name) for name in SUPPORT},
                'builder_sha256': sha256(Path(__file__)), 'cue_sha256': cue_digest,
                'compilers': compilers, 'link_command': link,
                'licenses_sha256': {name: sha256(path) for name, path in license_sources.items()},
                'executable_sha256': sha256(binary),
            }
            output.parent.mkdir(parents=True, exist_ok=True)
            # Publish the executable last: a failed build never replaces a working binary.
            with tempfile.TemporaryDirectory(prefix='.psxtract-', dir=output.parent) as publish:
                staged = Path(publish) / output.name
                shutil.copy2(binary, staged)
                staged_license = staged.with_name(staged.name + '.LICENSE')
                staged_license.write_text(license_text)
                staged_provenance = staged.with_name(staged.name + '.provenance.json')
                staged_provenance.write_text(json.dumps(provenance, indent=2) + '\n')
                os.replace(staged_license, destinations[1])
                os.replace(staged_provenance, destinations[2])
                os.replace(staged, output)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f'error: {error}\n')
    print(output)
    print(f'SHA256 {provenance["executable_sha256"]}')


if __name__ == '__main__':
    main()
