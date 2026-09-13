"""Prepare pinned decoder sources with shared native and standalone patches."""
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    source, output, *patches = map(Path, sys.argv[1:])
    if source.resolve() != output.resolve():
        shutil.copytree(source, output, dirs_exist_ok=True)
    # These upstream files use CRLF; patches use LF like the other sources.
    for relative in ('libkirk/kirk_engine.c', 'pspdecrypt_lib.cpp'):
        target = output / relative
        target.write_bytes(target.read_bytes().replace(b'\r\n', b'\n'))
    for patch in patches:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())],
                       cwd=output, check=True)


if __name__ == '__main__':
    main()
