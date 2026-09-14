"""Copy pinned native sources, normalize explicit text files, and apply patches."""
import argparse
import re
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--in-place', action='store_true',
                        help='Allow explicit patching of an already isolated source directory')
    parser.add_argument('--exact', action='store_true',
                        help='Reject reversed patches and hunks requiring offsets or fuzz')
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
        command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch.resolve())]
        if args.exact:
            result = subprocess.run(command + ['--forward'], cwd=output,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=60)
            if result.returncode or re.search(r'\b(?:offset|fuzz|FAILED|Reversed)\b', result.stdout):
                parser.exit(1, f'{patch.name} did not apply exactly: {result.stdout.strip()}\n')
        else:
            subprocess.run(command, cwd=output, check=True)


if __name__ == '__main__':
    main()
