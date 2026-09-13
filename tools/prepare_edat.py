"""Prepare pinned make-npdata crypto without mutating Zig's dependency cache."""
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    source, output, *patches = map(Path, sys.argv[1:])
    if source.resolve() == output.resolve():
        raise ValueError('EDAT preparation requires a separate output directory')
    shutil.copytree(source, output, dirs_exist_ok=True)
    for name in ('make_npdata.c', 'utils.c'):
        path = output / 'Linux' / name
        data = path.read_bytes().replace(b'\r\n', b'\n')
        path.write_bytes(data if data.endswith(b'\n') else data + b'\n')
    for patch in patches:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())],
                       cwd=output, check=True)


if __name__ == '__main__':
    main()
