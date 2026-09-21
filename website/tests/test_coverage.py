from pathlib import Path
import tempfile
import unittest

from pspdb.coverage import build
from pspdb.nopaystation import load_population as load_nopaystation
from pspdb.redump import load_population as load_redump

DAT = ('<datafile><header><name>Sony - PlayStation Portable</name>'
       '<version>2026-09-11 01-48-58</version></header>'
       '<game id="1" name="Held"><category>Games</category>'
       '<rom name="held.iso" size="100" sha1="' + 'a' * 40 + '"/></game>'
       '<game id="2" name="Absent"><category>Demos</category>'
       '<rom name="absent.iso" size="200" sha1="' + 'b' * 40 + '"/>'
       '<rom name="absent.cue" size="9" sha1="' + 'c' * 40 + '"/></game></datafile>')

GAME = 'UP0001-NPUG80001_00-GAME000000000001'
DEMO = 'UP9000-NPUG80135_00-ECHOCHROMEDEMO00'
MINIS = 'UP0003-NPUG80003_00-MINIS00000000001'
PSONE = 'UP0004-NPUJ00004_00-PSONE00000000001'
HEADER = 'Title ID\tRegion\tType\tName\tPKG direct link\tContent ID\tRAP\tFile Size\tSHA256\n'


def row(content_id, type_value='', size='', digest=''):
    return f'UP0001\tUS\t{type_value}\tName\thttp://example.invalid/x.pkg\t{content_id}\tNOT-A-KEY\t{size}\t{digest}\n'


class CoverageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.dat = self.root / 'redump.dat'
        self.dat.write_text(DAT)
        self.snapshots = self.root / 'nps'
        self.snapshots.mkdir()
        (self.snapshots / 'PSP_GAMES.tsv').write_text(
            HEADER + row(GAME, size='1000', digest='D' * 64) + row(DEMO) + row(MINIS, 'Minis', '3000', 'f' * 64))
        (self.snapshots / 'PSP_DEMOS.tsv').write_text(HEADER + row(DEMO))
        psx = HEADER + row(PSONE, size='4000', digest='e' * 64)
        (self.snapshots / 'PSX_GAMES.tsv').write_text(psx)
        (self.snapshots / 'PSX_GAMES(1).tsv').write_text(psx)
        (self.snapshots / 'README.md').write_text('not a snapshot')
        self.records = {
            'iso': [dict(sha1='a' * 40, size_bytes=100), dict(sha1='d' * 40, size_bytes=300)],
            'pkg': [
                dict(sha256='d' * 64, size_bytes=1000, psn_kind='game', metadata={'content_id': GAME}),
                dict(sha256='1' * 64, size_bytes=77, psn_kind='game', metadata={'content_id': DEMO}),
                dict(sha256='2' * 64, size_bytes=88, psn_kind='theme', metadata={'content_id': 'HP0000-UNLISTED'}),
            ],
        }

    def coverage(self):
        return build(self.records, load_redump(self.dat), load_nopaystation(self.snapshots))

    def test_umd_counts_reference_discs_and_local_leftovers(self):
        umd = self.coverage()['umd']
        self.assertEqual(umd['source'], {'name': 'Sony - PlayStation Portable', 'version': '2026-09-11 01-48-58'})
        self.assertEqual((umd['total'], umd['present'], umd['unmatched_local']), (2, 1, 1))
        self.assertEqual(umd['categories'], [{'name': 'Demos', 'total': 1, 'present': 0},
                                             {'name': 'Games', 'total': 1, 'present': 1}])

    def test_psn_lists_ignore_duplicate_snapshots_and_verify_bytes(self):
        psn = self.coverage()['psn']
        self.assertEqual((psn['total'], psn['present'], psn['unmatched_local']), (4, 2, 1))
        self.assertEqual(psn['lists'], [
            {'name': 'PSP_GAMES', 'total': 3, 'present': 2, 'byte_verified': 1},
            {'name': 'PSP_DEMOS', 'total': 1, 'present': 1, 'byte_verified': 0},
            {'name': 'PSX_GAMES', 'total': 1, 'present': 0, 'byte_verified': 0}])
        self.assertEqual([entry for entry in psn['kinds'] if entry['local'] or entry['reference']], [
            {'kind': 'game', 'local': 2, 'reference': 1},
            {'kind': 'demo', 'local': 0, 'reference': 1},
            {'kind': 'theme', 'local': 1, 'reference': 0},
            {'kind': 'psone_classic', 'local': 0, 'reference': 1},
            {'kind': 'minis', 'local': 0, 'reference': 1}])
        self.assertEqual(psn['conflicts'], [{'content_id': DEMO, 'kind': 'game', 'reference_kind': 'demo',
                                             'lists': ['PSP_DEMOS', 'PSP_GAMES']}])

    def test_snapshot_names_and_missing_references(self):
        self.assertIsNone(build(self.records))
        self.assertIsNone(build(self.records, load_redump(self.dat))['psn'])
        self.assertIsNone(build(self.records, nopaystation=load_nopaystation(self.snapshots))['umd'])
        (self.snapshots / 'PSP_OTHER.tsv').write_text(HEADER)
        with self.assertRaises(ValueError):
            load_nopaystation(self.snapshots)

    def test_rows_without_hashes_and_snapshot_identity(self):
        population = load_nopaystation(self.snapshots)
        self.assertEqual(population['packages'][DEMO],
                         {'lists': ['PSP_DEMOS', 'PSP_GAMES'], 'type': None, 'sha256': None, 'size_bytes': None})
        self.assertEqual(population['packages'][GAME]['sha256'], 'd' * 64)
        self.assertEqual(len(population['lists']['PSX_GAMES']['snapshots']), 1)
        self.assertNotIn('RAP', str(population))


if __name__ == '__main__':
    unittest.main()
