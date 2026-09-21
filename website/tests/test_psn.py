import unittest

from pspdb.psn import KINDS, package_kind, reference_kind

EBOOT = 'USRDIR/CONTENT/EBOOT.PBP'
PBOOT = 'USRDIR/CONTENT/PBOOT.PBP'
PARAM = 'USRDIR/CONTENT/PARAM.PBP'


class PackageKindTests(unittest.TestCase):
    def test_kind_follows_observed_boot_facts(self):
        cases = [
            ('theme', dict(content_type=9)),
            ('patch', dict(content_type=7, category='PP', boot_category='PG', boot_file=PBOOT)),
            ('dlc', dict(content_type=7, category='PP', boot_category='MG', boot_file=PARAM)),
            ('dlc', dict(content_type=7, category='PP')),
            ('psone_classic', dict(content_type=6, category='1P', boot_category='ME', boot_file=EBOOT)),
            ('minis', dict(content_type=15, category='MN', boot_category='EG', boot_file=EBOOT)),
            ('neogeo', dict(content_type=16, category='HG', boot_category='EG', boot_file=EBOOT)),
            ('unknown', dict(content_type=7, category='PP', boot_category='MG', boot_file=EBOOT)),
            ('game', dict(content_type=7, category='PP', boot_category='EG', boot_file=EBOOT)),
            ('game', dict(content_type=14, category='PP', boot_category='EG', boot_file=EBOOT)),
            ('unknown', dict(content_type=99, category='PP', boot_category='EG', boot_file=EBOOT)),
            ('unknown', dict(content_type=7, category='PP', boot_category='ZZ', boot_file=EBOOT)),
            ('unknown', dict(content_type=7, title='Un-reingested revision 5 record')),
            ('unknown', {}),
            ('unknown', None),
        ]
        for expected, metadata in cases:
            with self.subTest(metadata=metadata):
                self.assertEqual(package_kind(metadata), expected)
                self.assertIn(package_kind(metadata), KINDS)


class ReferenceKindTests(unittest.TestCase):
    def test_list_membership_precedence(self):
        cases = [
            ('patch', ['PSP_DLCS', 'PSP_UPDATES'], None),
            ('patch', ['PSP_UPDATES', 'PSP_THEMES'], None),
            ('theme', ['PSP_THEMES', 'PSP_DEMOS'], None),
            ('demo', ['PSP_DEMOS', 'PSP_GAMES'], 'Minis'),
            ('dlc', ['PSP_DLCS', 'PSP_GAMES'], None),
            ('psone_classic', ['PSX_GAMES', 'PSP_GAMES'], None),
            ('minis', ['PSP_GAMES'], 'Minis'),
            ('neogeo', ['PSP_GAMES'], 'NeoGeo'),
            ('pcengine', ['PSP_GAMES'], 'PC Engine'),
            ('game', ['PSP_GAMES'], None),
            ('game', ['PSP_GAMES'], ''),
            ('game', [], None),
        ]
        for expected, lists, type_value in cases:
            with self.subTest(lists=lists, type=type_value):
                self.assertEqual(reference_kind(lists, type_value), expected)


if __name__ == '__main__':
    unittest.main()
