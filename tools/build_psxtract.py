"""Build pinned PSXtract with a Linux DATA.BIN entry point (research draft)."""
import argparse
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

REVISION = '72618c6bc2c026e88e95d72700ec7d0238372d49'
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--psxtract-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='pspdb-psxtract-build-') as tmp:
        work = Path(tmp)
        archive = subprocess.check_output(['git', '-C', str(args.psxtract_source), 'archive', REVISION])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        src = work / 'Windows'
        subprocess.run(['patch', '--silent', str(src / 'psxtract.cpp'),
                        str(ROOT / 'tools/patches/psxtract-data.patch')], check=True)
        (src / 'lz.cpp').write_text((src / 'lz.cpp').read_text())
        subprocess.run(['patch', '--silent', str(src / 'lz.cpp'),
                        str(ROOT / 'tools/patches/psxtract-lz.patch')], check=True)
        # Port only the three Windows directory calls used by the upstream CLI.
        (src / 'direct.h').write_text('#include <sys/stat.h>\n#include <unistd.h>\n'
                                     '#define _mkdir(p) mkdir(p, 0700)\n'
                                     '#define _chdir chdir\n#define _rmdir rmdir\n')
        test = work / 'test-lz'
        subprocess.run(['c++', '-O2', '-I', str(src),
                        str(ROOT / 'tools/psxtract/test_lz.cpp'), str(src / 'lz.cpp'),
                        '-o', str(test)], check=True)
        subprocess.run([str(test)], check=True)
        objects = []
        for source in sorted((src / 'libkirk').glob('*.c')):
            obj = source.with_suffix('.o')
            subprocess.run(['cc', '-O2', '-fno-strict-aliasing', '-c', str(source), '-o', str(obj)], check=True)
            objects.append(str(obj))
        subprocess.run(['c++', '-O2', '-fno-strict-aliasing', '-Wno-write-strings', '-I', str(src),
                        str(ROOT / 'tools/psxtract/main.cpp'),
                        *[str(src / name) for name in ('crypto.cpp', 'lz.cpp', 'cdrom.cpp', 'utils.cpp')],
                        *objects, '-o', str(args.output.resolve())], check=True)


if __name__ == '__main__':
    main()
