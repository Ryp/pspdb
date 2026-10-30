"""Test helpers that read catalogs the way a browser does: container first, digests by chunk."""
import gzip
import json
from pathlib import Path

from pspdb.wire import HASH_CHUNK_SLOTS, decode_container, unpack


def container_meta(container):
    return json.loads(bytes(unpack(container)['meta']))


def chunk_count(meta):
    return -(-meta['hash_count'] // HASH_CHUNK_SLOTS)


def decode_with(container, fetch_chunk):
    """Decode a container, pulling every digest chunk through `fetch_chunk(generation, index)`."""
    meta = container_meta(container)
    hashes = b''.join(fetch_chunk(meta['generation'], index) for index in range(chunk_count(meta)))
    return decode_container(container, hashes)


def decode_payload(payload):
    """Decode a `_CatalogCache` payload."""
    return decode_container(payload['bodies']['identity'], payload['hashes'])


def decode_http(client, base):
    """Fetch /api/catalog and its hash chunks over HTTP (`client` is a urllib opener)."""
    with client.open(base + '/api/catalog', timeout=30) as response:
        container = response.read()

    def fetch(generation, index):
        with client.open(f'{base}/api/hashes/{generation}/{index}', timeout=30) as chunk:
            return chunk.read()

    return decode_with(container, fetch)


def decode_export(output):
    output = Path(output)
    container = gzip.decompress((output / 'catalog.bin.gz').read_bytes())
    return decode_with(container, lambda generation, index: (output / 'hashes' / f'{index}.bin').read_bytes())


def canonical(data):
    """Order-insensitive view of a catalog: entries sorted by path, recursively through extractions.

    The container stores every directory as the viewer shows it (directories first, UTF-16
    order), so decoded entry lists need not keep the order an ingest listed them in.
    """
    def tree(value):
        return dict(value, entries=sorted((entry(item) for item in value['entries']), key=lambda item: item['path']))

    def entry(value):
        return dict(value, extraction=tree(value['extraction'])) if 'extraction' in value else value

    return dict(data, trees={kind: {key: tree(value) for key, value in sources.items()}
                             for kind, sources in data['trees'].items()})
