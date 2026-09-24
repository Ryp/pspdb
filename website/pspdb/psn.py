"""Classify PSN packages from observed PKG facts and NoPayStation list membership."""

KINDS = ('game', 'demo', 'dlc', 'patch', 'theme', 'psone_classic', 'minis', 'neogeo', 'pcengine',
         'unknown')

LIST_KINDS = {'PSP_GAMES': 'game', 'PSP_DEMOS': 'demo', 'PSP_DLCS': 'dlc',
              'PSP_THEMES': 'theme', 'PSP_UPDATES': 'patch', 'PSX_GAMES': 'psone_classic'}
TYPE_KINDS = {'MINIS': 'minis', 'NEOGEO': 'neogeo', 'PC ENGINE': 'pcengine'}


def package_kind(metadata):
    """Kind from observed PKG facts only; never from titles or content-ID text."""
    metadata = metadata or {}
    content_type = metadata.get('content_type')
    boot_category = metadata.get('boot_category')
    boot_file = metadata.get('boot_file')
    if content_type == 9:
        return 'theme'
    if boot_category is None and boot_file is None and metadata.get('category') is None:
        # Ingest revisions before pkg 6 never observed the boot PBP; absence is not evidence.
        return 'unknown'
    if boot_category == 'PG':
        return 'patch'
    if boot_file is None or not boot_file.endswith('/EBOOT.PBP'):
        return 'dlc'
    if content_type == 6:
        return 'psone_classic'
    if content_type == 15:
        return 'minis'
    if content_type == 16:
        return 'neogeo'
    if content_type == 7 and metadata.get('category') == 'HG':
        # PC Engine shares content type 7 with plain PSP games; outer CATEGORY HG is its only marker.
        return 'pcengine'
    if content_type in (7, 14) and boot_category == 'EG':
        return 'game'
    return 'unknown'


def reference_kind(lists, type_value):
    """One kind per reference content ID; NPS rows appear in several lists."""
    lists = set(lists or ())
    for category in ('PSP_UPDATES', 'PSP_THEMES', 'PSP_DEMOS', 'PSP_DLCS', 'PSX_GAMES'):
        if category in lists:
            return LIST_KINDS[category]
    return TYPE_KINDS.get((type_value or '').strip().upper(), 'game')
