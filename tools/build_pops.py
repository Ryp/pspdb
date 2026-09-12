"""Build the whole-PBP POPS helper from pinned public decoder and Zig-PSP sources."""
import argparse
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

REVISION = 'c156627db7634d395c380c0a9589130f603307fc'
ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pspdecrypt-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix='pspdb-pops-build-') as tmp:
        work = Path(tmp)
        archive = subprocess.check_output(['git', '-C', str(args.pspdecrypt_source), 'archive', REVISION])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        source = work / 'PrxDecrypter.cpp'
        text = source.read_text()
        constants = '''static const u8 pops_key[] = {0xCA,0x26,0x7D,0xA2,0xB9,0xCE,0x24,0x6E,0xFD,0x32,0xA8,0x97,0xF4,0x7C,0x19,0x19};
static const u8 pops_xor[] = {0x77,0x32,0x20,0x31,0xDF,0x7F,0x4B,0x1C,0x8D,0xD7,0xD2,0xC3,0x23,0xA9,0xF8,0xA9};
'''
        needle = 'static const TAG_INFO2 g_tagInfo2[] =\n{'
        assert text.count(needle) == 1
        source.write_text(text.replace(needle, constants + needle + '\n\t{0x0DAA06F0, pops_key, 0x65, 5, pops_xor},'))
        objects = []
        for src in sorted((work / 'libkirk').glob('*.c')):
            obj = src.with_suffix('.o')
            subprocess.run(['cc', '-O2', '-c', str(src), '-o', str(obj)], check=True)
            objects.append(str(obj))
        adapter = work / 'pops.o'
        subprocess.run(['c++', '-std=c++17', '-O2', '-I', str(work), '-c', str(ROOT/'tools/pops/decrypt.cpp'), '-o', str(adapter)], check=True)
        sdk = ROOT/'ingest/zig-pkg/pspsdk-0.7.0-BZphyk2bEgCFkzGUlGnNooIZmU52-Ezju6f4rU3JllQL/tools/pbp/src/main.zig'
        pbp = work/'pbp.zig'
        subprocess.run(['patch', '--silent', '--output', str(pbp), str(sdk), str(ROOT/'tools/patches/zig-psp-pbp-memory.patch')], check=True)
        subprocess.run(['zig', 'build-exe', '-O', 'ReleaseSafe', '-lc', '-lstdc++', str(adapter), *objects,
                        '--dep', 'pbp', '-Mroot='+str(ROOT/'tools/pops/main.zig'), '-Mpbp='+str(pbp),
                        '-femit-bin='+str(args.output.resolve())], check=True)


if __name__ == '__main__':
    main()
