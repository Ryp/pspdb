"""Failure-atomic PNG page extraction using the pinned PSP-DOCUMENT.DAT readers."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile

import Crypto
import PIL
from PIL import Image


UPSTREAM = '8c95b37949c9a9ca183b7fd69c85d2e2dad7216d'
PREFIX = bytes.fromhex('00504744010000000100000000000000')
SIGNATURES = {bytes.fromhex('6768bd14ca5d474a'): 'ps1',
              bytes.fromhex('dff3cac794954829'): 'psp'}
MAX_SOURCE = 64 * 1024 * 1024
MAX_PIXELS = 16 * 1024 * 1024


def provenance():
    return {'name': 'PSP-DOCUMENT.DAT', 'options': [
        'upstream:' + UPSTREAM, 'fixed-key-99-slot-pages',
        'explicit-docinfo-304-byte-authenticated-8-byte-key', 'platform-ordinals',
        'page-files-only:1',
        'pycryptodome:' + Crypto.__version__, 'Pillow:' + PIL.__version__]}


def identity(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}


def verify_png(path):
    with path.open('rb') as stream:
        with Image.open(stream) as image:
            if image.format != 'PNG' or image.n_frames != 1:
                raise ValueError('Document page is not a single PNG image')
            if image.width * image.height > MAX_PIXELS:
                raise ValueError('Document page exceeds the pixel budget')
            image.verify()
        # Pillow's PNG verifier stops immediately after the IEND chunk header.
        # Require its exact CRC and EOF: rfind(IEND) alone permits trailing data.
        if stream.read(5) != b'\xaeB`\x82':
            raise ValueError('Document page has an invalid PNG end boundary')
        stream.seek(0)
        page_identity = {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(),
                         'size_bytes': os.fstat(stream.fileno()).st_size}
    with Image.open(path) as image:
        image.load()
    return page_identity


def extract(source, output, docinfo=None):
    if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
        raise ValueError('Output must be an existing empty directory')
    output = output.resolve()
    with source.open('rb') as stream:
        original = stream.read(MAX_SOURCE + 1)
    if len(original) > MAX_SOURCE:
        raise ValueError('Document exceeds the source byte budget')
    variant = SIGNATURES.get(original[16:24])
    if original[:16] != PREFIX or (variant is None and docinfo is None):
        raise ValueError('Not a supported legacy DOCUMENT wrapper')
    companion = None
    if docinfo is not None:
        with docinfo.open('rb') as stream:
            companion = stream.read(0x131)
        if len(companion) != 0x130:
            raise ValueError('Only the observed 304-byte DOCINFO.EDAT layout is supported')
        variant = 'psp'

    with tempfile.TemporaryDirectory(prefix='.pspdb-document-', dir=output.parent) as directory:
        work = Path(directory)
        # Freeze explicit input snapshots under neutral names; never discover siblings.
        staged_source = work / 'source_DOCUMENT.DAT'
        staged_source.write_bytes(original)
        staged_docinfo = None
        if companion is not None:
            staged_docinfo = work / 'source_DOCINFO.EDAT'
            staged_docinfo.write_bytes(companion)
        with open(os.devnull, 'w') as log, contextlib.chdir(work), \
                contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            if variant == 'ps1':
                from decrypt_document_ps1 import PS1Doc
                result = PS1Doc(str(staged_source)).readDocData()
            else:
                from decrypt_document_psp import PSPDoc
                result = PSPDoc(str(staged_source), staged_docinfo).readDocData()
        if result is None:
            raise ValueError('Upstream document validation failed')
        count = result.header.pages_total
        ps3_count = result.header.pages_total_ps3
        if not 1 <= count <= 99 or len(result.pages.info) != count or not 0 <= ps3_count <= count:
            raise ValueError('Unsupported or incomplete document page table')
        page_directory = work / ('out_png_' + variant) / result.file_info.name
        expected = {f'page_{index:03d}.png' for index in range(1, count + 1)}
        if not page_directory.is_dir() or {p.name for p in page_directory.iterdir()} != expected:
            raise ValueError('Incomplete document page extraction')

        publish = work / 'publish'
        publish.mkdir()
        pages, frames = [], {}
        for ordinal, info in enumerate(result.pages.info, 1):
            page = page_directory / f'page_{ordinal:03d}.png'
            if page.is_symlink() or not page.is_file():
                raise ValueError('Unexpected document output entry')
            page_identity = verify_png(page)
            frame = (info.offset, info.size)
            if info.offset < 0 or info.size <= 0 or info.offset + info.size > len(original):
                raise ValueError('Document frame exceeds its source')
            frame_identity = identity(memoryview(original)[info.offset:info.offset + info.size])
            frame_identity['offset'] = info.offset
            relative = f'psp/{ordinal:03d}.png'
            target = publish / relative
            target.parent.mkdir(exist_ok=True)
            page.rename(target)
            item = {'path': relative, **page_identity, 'source_frame': frame_identity}
            pages.append(item)
            previous = frames.get(frame)
            if previous and (previous['sha256'], previous['size_bytes']) != (item['sha256'], item['size_bytes']):
                raise ValueError('One document frame produced conflicting page bytes')
            frames[frame] = item

        for ordinal, info in enumerate(result.pages.info[:ps3_count], 1):
            item = frames.get((info.offset_ps3, info.size_ps3))
            if item is None:
                raise ValueError('Unique PS3-only document frames are not supported')
            relative = f'ps3/{ordinal:03d}.png'
            target = publish / relative
            target.parent.mkdir(exist_ok=True)
            os.link(publish / item['path'], target)
            pages.append({**item, 'path': relative})
        manifest = {'format': 'pspdb.document-pages', 'schema_version': 1,
                    'variant': variant, 'source': identity(original),
                    'document_code': result.header.code, 'pages': pages}
        if companion is not None:
            manifest['docinfo'] = identity(companion)
        # Same-filesystem rename replaces only the caller's still-empty directory.
        os.replace(publish, output)
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--docinfo', type=Path)
    parser.add_argument('--provenance', action='store_true')
    args = parser.parse_args()
    if args.provenance:
        if args.source is not None or args.output is not None or args.docinfo is not None:
            parser.error('--provenance does not accept extraction arguments')
        print(json.dumps(provenance()))
        return
    if args.source is None or args.output is None:
        parser.error('source and --output are required')
    try:
        manifest = extract(args.source, args.output, args.docinfo)
    except (OSError, ValueError, EOFError, SyntaxError, Image.DecompressionBombError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
