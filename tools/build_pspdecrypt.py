"""Build pinned pspdecrypt with current PRX recipes and exact decoded table extents."""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

REVISION = 'c156627db7634d395c380c0a9589130f603307fc'
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pspdecrypt-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    output = args.output.expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix='pspdb-decrypt-build-') as tmp:
        work = Path(tmp)
        archive = subprocess.check_output(['git', '-C', str(args.pspdecrypt_source.expanduser()), 'archive', REVISION])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        patches = ('pspdecrypt-update-xor.patch', 'pspdecrypt-prx-native.patch',
                   'pspdecrypt-prx-coverage.patch', 'pspdecrypt-table-length.patch')
        subprocess.run([sys.executable, str(ROOT / 'tools/prepare_pspdecrypt.py'),
                        str(work), str(work),
                        *(str(ROOT / 'tools/patches' / patch) for patch in patches)], check=True)
        subprocess.run(['make', f'-j{args.jobs}', 'CC=cc', 'CXX=c++',
                        'CFLAGS=-O3 -std=gnu11 -fno-strict-aliasing',
                        'CXXFLAGS=-O3 -std=c++17 -fno-strict-aliasing'], cwd=work, check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Publish only a completed executable, without changing the source checkout.
        with tempfile.TemporaryDirectory(prefix='.pspdecrypt-', dir=output.parent) as publish:
            staged = Path(publish) / 'pspdecrypt'
            shutil.copy2(work / 'pspdecrypt', staged)
            os.replace(staged, output)
    print(output)


if __name__ == '__main__':
    main()
