"""Build the pinned DOCUMENT reader; run with Python 3.12+ and user-managed dependencies."""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile

REVISION = '8c95b37949c9a9ca183b7fd69c85d2e2dad7216d'
ROOT = Path(__file__).resolve().parents[1]
SOURCE_HASHES = {
    'decrypt_document_ps1.py': '41c927945437964aac09146034e4132ce96721ff6d3bed8ad5a924a7a2740a75',
    'decrypt_document_psp.py': 'df777138839f98ad470a34e3b6191e58f2eb10d5d2b5c3c9f41a1a1f31c94ec9',
    'pspdoclib/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'pspdoclib/bbox.py': '347c3b63caa83e2a6e83bacbe1cab56c177256627c9240b924bb42bbcfbd0438',
    'pspdoclib/bboxmin.py': '5b5de6173507bfc75827cfec75940a748e40f41e05308691cb78ffdac3658fe4',
    'pspdoclib/cryptolib.py': 'c7ea7ff721e56fccb7ec09d4be7f7a1dd5c60fa4196921ee5ffa1cfd341daaf6',
    'pspdoclib/ecdsa_psp.py': '9e0c4c7c11dc3b2e960589b816db1fd2b99bf6fc85b60ab258ce8e6d7159b735',
    'pspdoclib/free_edata.py': 'd0a0cdf8f22bcf364c8361ee17b280fc9a8d87499970aed792dde04054c0d64e',
    'pspdoclib/hexdump.py': '05fb1b00b2e385c8830f2e875d57d399e5bb597447db5305e16cf164127ccb86',
    'LICENSE': '2e53eaafef22a4ca6a3ce39c9fb7887b9679ad9fcab7d06154509732e0a4f74f',
    'requirements.txt': '8726412e6b507a83e1d93fe53c30ee9fb5dc3e04f82299cc0e8e7bd5d836edd8',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error('Python 3.12 or newer is required by the upstream reader')
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().absolute()
    inputs = [source / name for name in SOURCE_HASHES]
    inputs.extend((Path(__file__), ROOT / 'tools/document.py',
                   ROOT / 'tools/patches/psp-document-safety.patch'))
    if output.resolve() in {path.resolve() for path in inputs}:
        parser.error('Output would overwrite a build input')
    try:
        with tempfile.TemporaryDirectory(prefix='pspdb-document-build-') as tmp:
            work = Path(tmp)
            names = []
            for name, expected in SOURCE_HASHES.items():
                data = (source / name).read_bytes()
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    raise ValueError(f'{name}: SHA256 mismatch for upstream {REVISION}; '
                                     f'expected {expected}, got {actual}')
                if name == 'requirements.txt':
                    continue
                destination = work / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                names.append(name)
            result = subprocess.run(
                ['patch', '--batch', '--fuzz=0', '-p1', '-i',
                 str(ROOT / 'tools/patches/psp-document-safety.patch')],
                cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=60,
            )
            if result.returncode:
                raise ValueError(f'upstream safety patch failed (exit {result.returncode}): '
                                 f'{result.stdout.strip()}')
            (work / '__main__.py').write_bytes((ROOT / 'tools/document.py').read_bytes())
            names.append('__main__.py')
            output.parent.mkdir(parents=True, exist_ok=True)
            # A sibling staging directory keeps publication atomic on this filesystem.
            with tempfile.TemporaryDirectory(prefix='.document-', dir=output.parent) as publish:
                staged = Path(publish) / 'document'
                with staged.open('wb') as stream:
                    stream.write(b'#!/usr/bin/env python3\n')
                    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
                        for name in sorted(names):
                            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                            info.create_system = 3
                            info.external_attr = (stat.S_IFREG | 0o644) << 16
                            info.compress_type = zipfile.ZIP_STORED
                            archive.writestr(info, (work / name).read_bytes())
                staged.chmod(0o755)
                with staged.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                os.replace(staged, output)
    except subprocess.TimeoutExpired:
        parser.exit(1, 'error: upstream safety patch timed out after 60 seconds\n')
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f'error: {error}\n')
    print(output)
    print(f'SHA256 {digest}')


if __name__ == '__main__':
    main()
