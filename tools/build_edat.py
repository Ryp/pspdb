"""Build pinned make-npdata crypto with the authenticated, bounded PSP EDAT reader."""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

REVISION = '5f44642fa24331da79f4bae6bea516f1784cf1c5'
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--make-npdata-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.make_npdata_source.expanduser().resolve()
    output = args.output.expanduser().absolute()
    wrapper = ROOT / 'tools/edat.c'
    patch = ROOT / 'tools/patches/make-npdata-safety.patch'
    resolved_output = output.resolve()
    if (resolved_output == source or source in resolved_output.parents
            or resolved_output in {Path(__file__).resolve(), wrapper.resolve(), patch.resolve()}):
        parser.error('--output must not overwrite the upstream checkout or build inputs')
    with tempfile.TemporaryDirectory(prefix='pspdb-edat-build-') as tmp:
        work = Path(tmp)
        archive = subprocess.check_output(['git', '-C', str(source), 'archive', REVISION])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        # The pinned Linux sources use CRLF; normalize only the archived build copy.
        for name in ('make_npdata.c', 'utils.c'):
            path = work / 'Linux' / name
            data = path.read_bytes().replace(b'\r\n', b'\n')
            path.write_bytes(data if data.endswith(b'\n') else data + b'\n')
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                       cwd=work, check=True)
        shutil.copyfile(wrapper, work / 'edat.c')
        subprocess.run([
            'cc', '-std=gnu99', '-O2', '-fno-strict-aliasing', '-D_FILE_OFFSET_BITS=64',
            '-Werror=implicit-function-declaration', f'-DPSPDB_EDAT_UPSTREAM="{REVISION}"',
            '-I', 'Linux', 'edat.c', 'Linux/aes.c', 'Linux/sha1.c', 'Linux/utils.c',
            '-o', 'pspdb-edat',
        ], cwd=work, check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Publish only a completed executable, without changing the source checkout.
        with tempfile.TemporaryDirectory(prefix='.pspdb-edat-', dir=output.parent) as publish:
            staged = Path(publish) / 'pspdb-edat'
            shutil.copy2(work / 'pspdb-edat', staged)
            os.replace(staged, output)
    print(output)


if __name__ == '__main__':
    main()
