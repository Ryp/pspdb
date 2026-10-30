"""Failure-atomic PNG publication from bounded byte-input DOCUMENT readers."""
import argparse
import hashlib
from io import BytesIO
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
MAX_SOURCE = 128 * 1024 * 1024
MAX_PIXELS = 16 * 1024 * 1024


def provenance():
    return {'name': 'PSP-DOCUMENT.DAT', 'options': [
        'upstream:' + UPSTREAM, 'fixed-key-99-999-slot-pages',
        'explicit-docinfo-304-byte-authenticated-8-byte-key',
        'docinfo-trailing-16-bytes-unauthenticated', 'zero-page-documents',
        'distinct-ps3-frames', 'platform-ordinals',
        'page-files-only:1', 'byte-input-page-callbacks:1',
        'pycryptodome:' + Crypto.__version__, 'Pillow:' + PIL.__version__]}


def identity(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}


def verify_png(data):
    with BytesIO(data) as stream:
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
    with Image.open(BytesIO(data)) as image:
        image.load()
    return identity(data)


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
            companion = stream.read(0x141)
        if len(companion) not in (0x130, 0x140):
            raise ValueError('Only the observed 304- or 320-byte DOCINFO.EDAT layout is supported')
        variant = 'psp'

    with tempfile.TemporaryDirectory(prefix='.pspdb-document-', dir=output.parent) as directory:
        work = Path(directory)
        publish = work / 'publish'
        publish.mkdir()
        (publish / 'psp').mkdir()
        pages, frames, ps3_only = [], {}, []

        def page_item(relative, info, data):
            if info.offset < 0 or info.size <= 0 or info.offset + info.size > len(original):
                raise ValueError('Document frame exceeds its source')
            page_identity = verify_png(data)
            frame_identity = identity(memoryview(original)[info.offset:info.offset + info.size])
            frame_identity['offset'] = info.offset
            (publish / relative).write_bytes(data)
            item = {'path': relative, **page_identity, 'source_frame': frame_identity}
            frame = (info.offset, info.size)
            previous = frames.get(frame)
            if previous and (previous['sha256'], previous['size_bytes']) != (item['sha256'], item['size_bytes']):
                raise ValueError('One document frame produced conflicting page bytes')
            frames[frame] = item
            return item

        def emit_page(ordinal, info, data):
            if ordinal != len(pages) + 1 or ordinal > 999:
                raise ValueError('Incomplete or unordered document page extraction')
            pages.append(page_item(f'psp/{ordinal:03d}.png', info, data))

        def emit_ps3(ordinal, info, data):
            # Frames distinct from the PSP ones; decoded before the PS3 links are made.
            if ordinal > 999 or any(item[0] == ordinal for item in ps3_only):
                raise ValueError('Incomplete or unordered document page extraction')
            ps3_only.append((ordinal, page_item(f'ps3/{ordinal:03d}.png', info, data)))

        if variant == 'ps1':
            from decrypt_document_ps1 import PS1Doc
            (publish / 'ps3').mkdir()
            result = PS1Doc(original).read_doc_data(emit_page, emit_ps3)
        else:
            from decrypt_document_psp import PSPDoc
            result = PSPDoc(original, companion).read_doc_data(emit_page)
        count = result.header.pages_total
        ps3_count = result.header.pages_total_ps3
        if not 0 <= count <= 999 or len(result.pages.info) != count or len(pages) != count or not 0 <= ps3_count <= count:
            raise ValueError('Unsupported or incomplete document page table')
        if ps3_count and variant != 'ps1':
            (publish / 'ps3').mkdir()
        distinct = dict(ps3_only)
        for ordinal, info in enumerate(result.pages.info[:ps3_count], 1):
            relative = f'ps3/{ordinal:03d}.png'
            item = distinct.get(ordinal)
            if item is None:
                item = frames.get((info.offset_ps3, info.size_ps3))
                if item is None:
                    raise ValueError('Document PS3 frame was not decoded')
                os.link(publish / item['path'], publish / relative)
                item = {**item, 'path': relative}
            pages.append(item)
        if not ps3_count and variant == 'ps1':
            (publish / 'ps3').rmdir()
        if not pages:
            (publish / 'psp').rmdir()
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
