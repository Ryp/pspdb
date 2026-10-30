"""Export a metadata-only snapshot for any static HTTP host."""
import gzip
from pathlib import Path
import shutil

from .server import catalog_data
from .wire import encode_container, hash_chunk, hash_chunk_count
from .redump import load_matches as load_redump, load_population as load_redump_population
from .umdatabase import load_matches as load_umdatabase
from .nopaystation import load_population as load_nopaystation
from .serialstation import load_matches as load_serialstation


def export_site(catalog, output, redump=None, umdatabase=None, nopaystation=None, serialstation=None):
    catalog = Path(catalog).expanduser().resolve()
    output = Path(output).expanduser().resolve()
    if output == catalog or output in catalog.parents or catalog in output.parents:
        raise ValueError("Export directory must be separate from the catalog")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Export directory must be empty")
    data = catalog_data(catalog,
                        load_redump(redump) if redump is not None else None,
                        load_umdatabase(umdatabase) if umdatabase is not None else None,
                        load_redump_population(redump) if redump is not None else None,
                        load_nopaystation(nopaystation) if nopaystation is not None else None,
                        load_serialstation(serialstation) if serialstation is not None else None)
    data['downloads_enabled'] = False
    encoded = encode_container(data)
    assets = Path(__file__).with_name('web')
    html = (assets / 'index.html').read_text(encoding='utf-8')
    rewrites = {'data-catalog="api/catalog"': 'data-catalog="catalog.bin.gz"',
                'data-hashes="api/hashes/{generation}/{chunk}"': 'data-hashes="hashes/{chunk}.bin"'}
    for live, static in rewrites.items():
        if live not in html:
            raise ValueError(f'index.html does not declare {live}')
        html = html.replace(live, static)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'catalog.bin.gz').write_bytes(gzip.compress(encoded.container, compresslevel=9, mtime=0))
    (output / 'hashes').mkdir()
    for index in range(hash_chunk_count(encoded.hashes)):
        (output / 'hashes' / f'{index}.bin').write_bytes(hash_chunk(encoded.hashes, index))
    for asset in sorted(assets.glob('*.js')) + sorted(assets.glob('*.css')):
        shutil.copyfile(asset, output / asset.name)
    (output / 'index.html').write_text(html, encoding='utf-8')
    (output / '.nojekyll').touch()
    return output
