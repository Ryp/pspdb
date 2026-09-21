"""Export a metadata-only snapshot for any static HTTP host."""
import gzip
import json
from pathlib import Path
import shutil

from .server import catalog_data
from .wire import encode_catalog
from .redump import load_matches as load_redump, load_population as load_redump_population
from .umdatabase import load_matches as load_umdatabase
from .nopaystation import load_population as load_nopaystation


def export_site(catalog, output, redump=None, umdatabase=None, nopaystation=None):
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
                        load_nopaystation(nopaystation) if nopaystation is not None else None)
    data['downloads_enabled'] = False
    body = json.dumps(encode_catalog(data), ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assets = Path(__file__).with_name('web')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'catalog.json.gz').write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    for name in ('app.js', 'search-worker.js', 'style.css'):
        shutil.copyfile(assets / name, output / name)
    html = (assets / 'index.html').read_text(encoding='utf-8')
    (output / 'index.html').write_text(
        html.replace('data-catalog="api/catalog"', 'data-catalog="catalog.json.gz"'), encoding='utf-8')
    (output / '.nojekyll').touch()
    return output
