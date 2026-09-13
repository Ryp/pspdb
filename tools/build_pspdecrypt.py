"""Build pinned pspdecrypt with the update PRX recipe and exact decoded table extents."""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
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
        for patch in ('pspdecrypt-update-xor.patch', 'pspdecrypt-table-length.patch'):
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                            str(ROOT / 'tools/patches' / patch)], cwd=work, check=True)
        subprocess.run(['make', f'-j{args.jobs}', 'CC=cc', 'CXX=c++'], cwd=work, check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Publish only a completed executable, without changing the source checkout.
        with tempfile.TemporaryDirectory(prefix='.pspdecrypt-', dir=output.parent) as publish:
            staged = Path(publish) / 'pspdecrypt'
            shutil.copy2(work / 'pspdecrypt', staged)
            os.replace(staged, output)
    print(output)


if __name__ == '__main__':
    main()
