"""Copy pinned native sources, normalize explicit text files, and apply patches."""
import argparse
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--in-place', action='store_true',
                        help='Allow explicit patching of an already isolated source directory')
    parser.add_argument('--normalize', action='append', type=Path, default=[],
                        help='Relative text file to normalize to LF with a final newline')
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('patches', type=Path, nargs='*')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if args.in_place != (source == output):
        parser.error('Equal source/output paths require --in-place; copying requires distinct paths')
    if not args.in_place:
        shutil.copytree(source, output, dirs_exist_ok=True)
    for relative in args.normalize:
        target = output / relative
        if not target.resolve().is_relative_to(output):
            parser.error('Normalized files must remain inside the output directory')
        data = target.read_bytes().replace(b'\r\n', b'\n')
        target.write_bytes(data if data.endswith(b'\n') else data + b'\n')
    for patch in args.patches:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())],
                       cwd=output, check=True)


if __name__ == '__main__':
    main()
