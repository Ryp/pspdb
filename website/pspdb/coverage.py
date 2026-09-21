"""Compare local holdings against reference populations; snapshots are a floor, not truth."""
from .nopaystation import CATEGORIES
from .psn import KINDS, reference_kind

CONFLICT_LIMIT = 50


def build(records, redump=None, nopaystation=None):
    """Population coverage from loaded reference snapshots; None when unavailable."""
    if redump is None and nopaystation is None:
        return None
    return {'umd': _umd(records.get('iso', []), redump) if redump is not None else None,
            'psn': _psn(records.get('pkg', []), nopaystation) if nopaystation is not None else None}


def _umd(records, population):
    discs = population['discs']
    present, unmatched_local = set(), 0
    for record in records:
        key = record.get('sha1'), record.get('size_bytes')
        if key in discs:
            present.add(key)
        else:
            unmatched_local += 1
    categories = {}
    for key, category in discs.items():
        totals = categories.setdefault(category, [0, 0])
        totals[0] += 1
        totals[1] += key in present
    return {'source': {'name': population['name'], 'version': population['version']},
            'total': len(discs), 'present': len(present), 'unmatched_local': unmatched_local,
            'categories': [{'name': name, 'total': total, 'present': found}
                           for name, (total, found) in sorted(categories.items())]}


def _psn(records, population):
    packages = population['packages']
    present, verified, conflicts = set(), set(), {}
    local, unmatched_local = {}, 0
    for record in records:
        kind = record.get('psn_kind') or 'unknown'
        local[kind] = local.get(kind, 0) + 1
        package = packages.get((record.get('metadata') or {}).get('content_id'))
        if package is None:
            unmatched_local += 1
            continue
        content_id = record['metadata']['content_id']
        present.add(content_id)
        if (package['sha256'] is not None and package['sha256'] == record.get('sha256')
                and package['size_bytes'] == record.get('size_bytes')):
            verified.add(content_id)
        expected = reference_kind(package['lists'], package['type'])
        if expected != kind and content_id not in conflicts:
            conflicts[content_id] = {'content_id': content_id, 'kind': kind,
                                     'reference_kind': expected, 'lists': package['lists']}
    reference = {}
    for package in packages.values():
        kind = reference_kind(package['lists'], package['type'])
        reference[kind] = reference.get(kind, 0) + 1
    order = list(KINDS) + sorted(set(reference) - set(KINDS))
    lists = []
    for category in CATEGORIES:
        entry = population['lists'].get(category)
        if entry is None:
            continue
        content_ids = set(entry['content_ids'])
        lists.append({'name': category, 'total': len(content_ids),
                      'present': len(content_ids & present),
                      'byte_verified': len(content_ids & verified)})
    return {'total': len(packages), 'present': len(present), 'unmatched_local': unmatched_local,
            'lists': lists,
            'kinds': [{'kind': kind, 'local': local.get(kind, 0), 'reference': reference.get(kind, 0)}
                      for kind in order],
            'conflicts': [conflicts[content_id] for content_id in sorted(conflicts)][:CONFLICT_LIMIT]}
