"""Extractor revisions and provenance shared with the ingest freshness scan."""
import json
from pathlib import Path
import re


VERSIONS = None


def versions():
    global VERSIONS
    if VERSIONS is None:
        VERSIONS = json.loads(Path(__file__).with_name('extractor_versions.json').read_text())
    if not isinstance(VERSIONS, dict) or any(not isinstance(v, str) or not re.fullmatch(r'[1-9][0-9]*', v) for v in VERSIONS.values()):
        raise ValueError('Extractor revisions must be positive integer strings')
    return VERSIONS


def tool_provenance(kind):
    result = {'name': 'pspdb-ingest', 'version': versions()[kind], 'options': []}
    if kind == 'pbp':
        return dict(result, name='Zig-PSP zPBPTool', options=['in-memory'])
    if kind == 'nand':
        return dict(result, name='pspdb-nand')
    if kind == 'update':
        return dict(result, name='pspdb-update')
    if kind in ('iso', 'iso9660', 'pkg', 'sce', 'elf', 'gzip', 'vmp', 'prx', 'kl3e', 'kl4e', 'edat', 'npumdimg', 'psar', 'rco', 'pgd', 'pspedat'):
        return result
    if kind == 'pops':
        return dict(result, name='pspdb-pops', options=['in-memory'])
    if kind == 'pce':
        # One static record covers both contextual inputs; it states each one's trust level.
        return dict(result, name='pspdb-pce', options=[
            'in-memory', 'xor-table:b2d7084c', 'content-dat:structure-checked', 'content1-sdat:mac-verified'])
    if kind == 'pcecd':
        return dict(result, name='pspdb-pcecd', options=['in-memory', 'toc-bound', 'sector-image-2048'])
    if kind == 'psx':
        return dict(result, name='pspdb-psx', options=['in-memory'])
    if kind == 'document':
        return dict(result, name='pspdb-document', options=['in-memory'])
    raise ValueError(f'Unknown extractor kind: {kind}')


def current_provenance():
    current, unavailable = {}, {}
    for kind in versions():
        try:
            current[kind] = tool_provenance(kind)
        except ValueError as exc:
            unavailable[kind] = str(exc)
    return current, unavailable
