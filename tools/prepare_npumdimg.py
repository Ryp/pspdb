"""Prepare pinned pkg2zip NPUMDIMG crypto without changing Zig's cache."""
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    source, output, *patches = map(Path, sys.argv[1:])
    if source.resolve() == output.resolve():
        raise ValueError('NPUMDIMG preparation requires a separate output directory')
    # Retain upstream LICENSE/README attribution along with the source.
    shutil.copytree(source, output, dirs_exist_ok=True)
    for patch in patches:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())],
                       cwd=output, check=True)


if __name__ == '__main__':
    main()
