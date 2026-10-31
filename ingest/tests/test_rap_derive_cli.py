"""Package-derived EDAT keys and --rap-output: synthetic PSN packages, invented keys.

The PS1 PGD header and the EDAT below were generated for this test with the ingester's own
libkirk and make-npdata primitives: the PGD header's version key V was chosen so that
AES-128-ECB-ENCRYPT(key_357C[0:16], rap2rif(RAP)) == V, and the EDAT is signed under
rap2rif(RAP). RAP, content ID and plaintext are invented.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest

if __package__:
    from .test_ingest_cli import BINARY, REPO, tree_path
    from .test_pkg_cli import pkg_bytes, sfo
else:
    from test_ingest_cli import BINARY, REPO, tree_path
    from test_pkg_cli import pkg_bytes, sfo

CONTENT_ID = 'UP9000-NPUG00001_00-FIXTURE000000000'
RAP = bytes(0x5a + i for i in range(16))
WRONG_RAP = bytes(0x10 + i for i in range(16))
PLAINTEXT = b'payload decrypted with a key derived from the package'
# First 0x90 bytes of a PGD (key_index 1, drm_type 1, DNAS-MAC valid) whose bbmac_getkey is V.
PGD_HEADER = bytes.fromhex(
    '00504744010000000100000000000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000000000000000000000000000000' \
    '5b21370b0370fa3916a86a48d566f5ef5925d649b6ab9aaecf338d30efe97b5754e26056be73f2c63ea33df46e8c5b2e' \
    'e71f662536cfb8b0fdb05e4bcf682f1475f67da4bd8024006f99982ca2e88acdf0dde2313db66185164c3d6371c69328')
# NPD v2, license 2, flags 0x0c, signed under rap2rif(RAP), plaintext PLAINTEXT.
EDAT = bytes.fromhex(
    '4e5044000000000200000002000000005550393030302d4e50554730303030315f30302d464958545552453030303030' \
    '303030300000000000000000000000004141414141414141414141414141414100000000000000000000000000000000' \
    '62626262626262626262626262626262000000000000000000000000000000000000000c000040000000000000000035' \
    '80a80cae354ae3f98d051583ab75ec0b4681a3f5098485d052c44332110a8bca00000000000000000000000000000000' \
    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' \
    '0000000000000000000000000000000048d40d6afceb8c58336e7b5de4502ebc098376718ce8ebddda06c7742b168fbf' \
    '951917645955fa67b0491838dd737294890bdf1e4cb9d561895ef1c466acb49d0258606a47baf1edb04b8757b4d9ab93')
assert len(PGD_HEADER) == 0x90 and EDAT[0x10:0x34].decode() == CONTENT_ID


def eboot():
    """A PBP whose DATA.PSAR starts at an unaligned offset and opens like a PS1 Classic disc."""
    param = sfo({'TITLE': 'Derived key fixture', 'DISC_ID': 'NPUG00001', 'CATEGORY': 'EG'})
    psar = b'PSISOIMG0000'.ljust(0x400, b'\0') + PGD_HEADER + bytes(0x100)
    psar_offset = 40 + len(param) + 7
    offsets = [40] + [40 + len(param)] * 6 + [psar_offset]
    return b'\0PBP' + struct.pack('<I8I', 0x10000, *offsets) + param + bytes(7) + psar


def package(with_eboot=True, edat_first=True):
    """EDAT entries may come before or after the EBOOT in the package table."""
    head = [('PARAM.SFO', sfo({'TITLE': 'Outer fixture', 'CATEGORY': 'PP'}), False),
            ('USRDIR', None, False), ('USRDIR/CONTENT', None, False)]
    edat = ('USRDIR/CONTENT/DATA.EDAT', EDAT, True)
    boot = ('USRDIR/CONTENT/EBOOT.PBP', eboot(), True)
    tail = [edat] if not with_eboot else [edat, boot] if edat_first else [boot, edat]
    return pkg_bytes(7, files_override=head + tail)[0]


class RapDeriveCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['zig', 'build', '-Doptimize=ReleaseSafe'], cwd=REPO / 'ingest', check=True)

    def workspace(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def ingest(self, base, source, *args, rap_dir=None, catalog=True):
        inputs = base / 'inputs'
        inputs.mkdir(exist_ok=True)
        (inputs / 'test.pkg').write_bytes(source)
        command = [str(BINARY), str(inputs), '--no-progress', '--threads', '2', *map(str, args)]
        if catalog:
            command += ['--catalog', str(base / 'catalog'), '--store', str(base / 'store')]
        environment = dict(os.environ, PSPDB_RAP_DIR=str(rap_dir or base / 'no-licenses'))
        run = subprocess.run(command, capture_output=True, text=True, timeout=60, env=environment)
        self.assertEqual(run.returncode, 0, run.stderr)
        for key in (RAP, WRONG_RAP):
            self.assertNotIn(key.hex(), run.stdout + run.stderr)
        return run

    def edat_tree(self, base):
        return json.loads(tree_path(base / 'catalog', hashlib.sha256(EDAT).hexdigest()).read_text())

    def assert_decrypted(self, base, option):
        tree = self.edat_tree(base)
        self.assertNotIn('error', tree)
        self.assertEqual(tree['extractor'], {'name': 'pspdb-ingest', 'version': '7', 'options': [option]})
        self.assertEqual([e['path'] for e in tree['entries']], ['payload.dat'])
        self.assertEqual(tree['entries'][0]['sha256'], hashlib.sha256(PLAINTEXT).hexdigest())
        # A decoded EDAT is a pure function of its own bytes: no sibling dependency is recorded.
        self.assertEqual(tree.get('dependencies', []), [])

    def test_edat_decrypts_with_the_derived_key_without_any_rap_file_whatever_the_entry_order(self):
        for edat_first in (True, False):
            with self.subTest(edat_first=edat_first):
                base = self.workspace()
                self.ingest(base, package(edat_first=edat_first))
                self.assert_decrypted(base, 'key:derived-eboot')
                self.assertFalse((base / 'no-licenses').exists())

    def test_rap_output_writes_the_derived_rap_privately(self):
        base = self.workspace()
        run = self.ingest(base, package(), '--rap-output', base / 'raps')
        rap_file = base / 'raps' / f'{CONTENT_ID}.rap'
        self.assertEqual(rap_file.read_bytes(), RAP)
        self.assertEqual(stat.S_IMODE(rap_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((base / 'raps').stat().st_mode), 0o700)
        self.assertEqual([p.name for p in (base / 'raps').iterdir()], [rap_file.name])
        self.assertNotIn('RAP output', run.stderr)
        self.assert_decrypted(base, 'key:derived-eboot')

    def test_rap_output_needs_no_catalog_and_never_overwrites(self):
        base = self.workspace()
        output = base / 'out' / 'raps'
        self.ingest(base, package(), '--rap-output', output, catalog=False)
        rap_file = output / f'{CONTENT_ID}.rap'
        self.assertEqual(rap_file.read_bytes(), RAP)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        inode = rap_file.stat().st_ino
        # An identical file is left alone, silently.
        run = self.ingest(base, package(), '--rap-output', output, catalog=False)
        self.assertNotIn('RAP output', run.stderr)
        self.assertEqual(rap_file.stat().st_ino, inode)
        # A different file is kept and reported by content ID only.
        rap_file.write_bytes(WRONG_RAP)
        run = self.ingest(base, package(), '--rap-output', output, catalog=False)
        self.assertEqual(rap_file.read_bytes(), WRONG_RAP)
        self.assertIn(f'RAP output {CONTENT_ID}: a different RAP file already exists', run.stderr)
        self.assertEqual([p.name for p in output.iterdir()], [rap_file.name])

    def test_no_rap_file_is_written_without_the_option(self):
        base = self.workspace()
        licenses = base / 'licenses'
        licenses.mkdir()
        self.ingest(base, package(), rap_dir=licenses)
        self.assertEqual(list(licenses.iterdir()), [])
        self.assertEqual(sorted(p.name for p in base.iterdir()), ['catalog', 'inputs', 'licenses', 'store'])

    def test_a_wrong_rap_file_is_ignored_when_the_key_is_derivable(self):
        base = self.workspace()
        licenses = base / 'licenses'
        licenses.mkdir()
        (licenses / f'{CONTENT_ID}.rap').write_bytes(WRONG_RAP)
        self.ingest(base, package(), rap_dir=licenses)
        self.assert_decrypted(base, 'key:derived-eboot')
        self.assertEqual((licenses / f'{CONTENT_ID}.rap').read_bytes(), WRONG_RAP)

    def test_a_package_without_an_eboot_still_uses_the_rap_directory(self):
        base = self.workspace()
        licenses = base / 'licenses'
        licenses.mkdir()
        (licenses / f'{CONTENT_ID}.rap').write_bytes(RAP)
        self.ingest(base, package(with_eboot=False), rap_dir=licenses)
        self.assert_decrypted(base, 'key:rap-file')

    def test_a_package_without_an_eboot_derives_nothing(self):
        base = self.workspace()
        self.ingest(base, package(with_eboot=False), '--rap-output', base / 'raps')
        self.assertEqual(list((base / 'raps').iterdir()), [])
        self.assertEqual(self.edat_tree(base)['error'], 'MissingEdatRap')

    def test_a_wrong_rap_file_does_not_unlock_a_package_without_an_eboot(self):
        base = self.workspace()
        licenses = base / 'licenses'
        licenses.mkdir()
        (licenses / f'{CONTENT_ID}.rap').write_bytes(WRONG_RAP)
        self.ingest(base, package(with_eboot=False), rap_dir=licenses)
        self.assertEqual(self.edat_tree(base)['error'], 'EdatAuthenticationFailed')


if __name__ == '__main__':
    unittest.main()
