"""Read-only local web browser for a catalog; no index regeneration needed."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zlib
from time import monotonic
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import coverage
from .psn import package_kind
from .wire import decode_catalog, encode_catalog


def load_extractor_registry():
    """Use live checkout revisions when available; installed viewers may not have them."""
    registry = Path(__file__).resolve().parents[2] / 'tools' / 'extractor_versions.json'
    try:
        versions = json.loads(registry.read_text(encoding='utf-8'))
    except FileNotFoundError:
        versions = {}
    contextual = Path(__file__).with_name('data') / 'contextual_extractors.json'
    return versions, json.loads(contextual.read_text(encoding='utf-8'))


def annotate_stale_extractions(trees):
    versions, contextual_kinds = load_extractor_registry()

    def annotate(tree, kind):
        tree.pop('stale_extraction', None)
        tree.pop('extraction_kind', None)
        if kind not in (None, 'tree'):
            tree['extraction_kind'] = kind
        extractor = tree.get('extractor') or {}
        version, latest = extractor.get('version'), versions.get(kind)
        if (isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*', version)
                and isinstance(latest, str) and re.fullmatch(r'[1-9][0-9]*', latest)
                and int(version) < int(latest)):
            tree['stale_extraction'] = {'kind': kind, 'version': version, 'latest_version': latest}
        for entry in tree['entries']:
            contextual = entry.get('extraction')
            if (contextual is not None and contextual.get('sha256') == entry.get('sha256')
                    and contextual.get('size_bytes') == entry.get('size_bytes')):
                name = (contextual.get('extractor') or {}).get('name')
                annotate(contextual, contextual_kinds.get(name))

    for kind, sources in trees.items():
        for tree in sources.values():
            annotate(tree, kind)


def catalog_data(catalog, redump=None, umdatabase=None, redump_population=None, nopaystation=None,
                 serialstation=None):
    records, trees, selected = {}, {}, {}
    legacy_trees, legacy_kinds, sizes = {}, {}, {}
    for directory in sorted(catalog.iterdir()):
        if not directory.is_dir():
            continue
        kind = 'tree' if directory.name == 'trees' else directory.name
        paths = [(0, path, path.stem) for path in directory.glob('*.json')]
        if kind != 'tree':
            for folder in directory.iterdir():
                if folder.is_dir() and re.fullmatch(r'v[1-9][0-9]*', folder.name):
                    paths.extend((int(folder.name[1:]), path, path.name.removesuffix('-ingest.json'))
                                 for path in folder.glob('*-ingest.json'))
        for revision, path, digest in sorted(paths):
            record = json.loads(path.read_text(encoding='utf-8'))
            if (record.get('kind') != kind or record.get('schema_version') != 1
                    or not re.fullmatch(r'[0-9a-f]{64}', digest) or record.get('sha256') != digest):
                raise ValueError(f'Invalid catalog record identity: {path}')
            size = record.get('size_bytes')
            if digest in sizes and sizes[digest] != size:
                raise ValueError(f'Conflicting source sizes: {path}')
            sizes[digest] = size
            if kind == 'tree':
                legacy_trees[digest] = record
                continue
            tree = None
            if not revision:
                legacy_kinds.setdefault(digest, []).append(kind)
            if revision:
                tree_path = path.with_name(digest + '-tree.json')
                if not tree_path.exists():
                    # A newer incomplete pair must not hide a completed result.
                    continue
                tree = json.loads(tree_path.read_text(encoding='utf-8'))
                if (tree.get('kind') != 'tree' or tree.get('schema_version') != 1
                        or tree.get('sha256') != digest or tree.get('size_bytes') != record.get('size_bytes')
                        or tree.get('extractor', {}).get('version') != str(revision)
                        or not isinstance(tree.get('entries'), list)):
                    raise ValueError(f'Invalid versioned tree identity: {tree_path}')
            selected[kind, digest] = record, tree
    selected_kinds = {}
    for kind, digest in selected:
        selected_kinds.setdefault(digest, []).append(kind)
    for digest, tree in legacy_trees.items():
        owners = legacy_kinds.get(digest, selected_kinds.get(digest, []))
        if len(owners) > 1:
            raise ValueError(f'Ambiguous legacy tree source kind: {digest}')
        trees.setdefault(owners[0] if owners else 'tree', {})[digest] = tree
    for (kind, digest), (record, tree) in sorted(selected.items()):
        if tree is not None:
            trees.setdefault(kind, {})[digest] = tree
        if kind == 'iso':
            if redump is not None:
                matches = redump.get((record.get('sha1'), record.get('size_bytes')), [])
                if matches:
                    record['redump'] = matches
            if serialstation is not None:
                discs = [
                    dict(disc, redump_id=match['id'])
                    for match in record.get('redump', [])
                    for disc in serialstation['discs'].get(match['id'], [])
                ]
                if discs:
                    record['serialstation_discs'] = discs
            if umdatabase is not None:
                matches = umdatabase.get(record.get('sha1'), [])
                if matches:
                    record['umdatabase'] = matches
        elif kind == 'pkg':
            record['psn_kind'] = package_kind(record.get('metadata'))
            if serialstation is not None:
                content_id = ((record.get('metadata') or {}).get('content_id') or '').strip()
                sha1 = record.get('sha1')
                sha1 = sha1.lower().zfill(40) if isinstance(sha1, str) and re.fullmatch(r'[0-9a-fA-F]{1,40}', sha1) else None
                match = serialstation['packages'].get((sha1, record.get('size_bytes'), content_id))
                if match:
                    record['serialstation'] = match
        records.setdefault(kind, []).append(record)
    derived_trees(trees)
    annotate_stale_extractions(trees)
    from .redump import load_psx_matches, annotate_file_matches
    annotate_file_matches(trees, load_psx_matches())
    return {'records': records, 'trees': trees,
            'coverage': coverage.build(records, redump_population, nopaystation)}


def derived_trees(trees):
    """Resolve byte references without choosing a root observation or a role arbitrarily."""
    derived, sizes, ambiguous = {}, {}, set()
    for kind, sources in trees.items():
        for digest, tree in sources.items():
            size = tree['size_bytes']
            if digest in sizes and sizes[digest] != size:
                raise ValueError(f'Conflicting source sizes: {digest}')
            sizes[digest] = size
            if kind in ('iso', 'pkg', 'nand', 'update'):
                continue
            if digest in derived:
                ambiguous.add(digest)
            derived[digest] = None if digest in derived else tree
    if not ambiguous:
        return derived
    def check(entries):
        for entry in entries:
            contextual = entry.get('extraction')
            if contextual is not None:
                if contextual.get('sha256') == entry.get('sha256') and contextual.get('size_bytes') == entry.get('size_bytes'):
                    check(contextual['entries'])
            elif entry.get('type') == 'file' and entry['sha256'] in ambiguous:
                raise ValueError(f"Ambiguous non-root extraction kinds: {entry['sha256']}")
    for sources in trees.values():
        for tree in sources.values():
            check(tree['entries'])
    return derived


def open_object(store, digest, size):
    """Read a regular blob without following links anywhere inside the store."""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise FileNotFoundError("Invalid object hash")
    directory = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in ("sha256", digest[:2], digest[2:4]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size != size:
        stream.close()
        raise FileNotFoundError("Object type/size mismatch")
    return stream


def download_index(data):
    index, expanded = {}, set()
    derived = derived_trees(data['trees'])
    valid_digest = re.compile(r"[0-9a-f]{64}").fullmatch
    unsafe_name = re.compile(r"[\x00-\x1f/\\]").search

    def add(digest, size, name, ancestors=frozenset(), contextual=None, kind=None):
        if not name or unsafe_name(name):
            return
        existing = index.get(digest)
        if existing is None:
            if not valid_digest(digest):
                return
            names = set()
            index[digest] = size, names
        else:
            if existing[0] != size:
                raise ValueError("Conflicting sizes for catalog hash")
            names = existing[1]
        names.add(name)
        if contextual is not None:
            tree = contextual
        elif kind is not None:
            tree = data['trees'].get(kind, {}).get(digest)
        else:
            tree = derived.get(digest)
        if not tree or (contextual is not None and tree.get('sha256') != digest) or tree['size_bytes'] != size or id(tree) in ancestors:
            return
        occurrence = id(tree), name
        if occurrence in expanded:
            return
        expanded.add(occurrence)
        for entry in tree['entries']:
            if entry['type'] != 'file':
                continue
            child = entry['path'].rsplit('/', 1)[-1]
            rule = tree.get('name_rule')
            if rule == 'source_stem':
                child = re.sub(r'\.[^.]*$', '', name) + child[child.index('.'):]
            elif rule == 'strip_suffix':
                child = re.sub(r'\.[^.]*$', '', name)
            elif rule == 'decoded_suffix':
                stem = re.sub(r'\.[^.]*$', '', name)
                dot = child.find('.')
                suffix = child[dot:] if dot >= 0 else ''
                if suffix == '.elf':
                    stem = re.sub(r'\.(?:elf|prx)$', '', stem, flags=re.I)
                child = stem if not suffix or suffix == '.bin' or stem.endswith(suffix) else stem + suffix
            add(entry['sha256'], entry['size_bytes'], child, ancestors | {id(tree)}, entry.get('extraction'))

    for kind, records in data["records"].items():
        for record in records:
            suffix = 'pbp' if kind == 'update' else kind
            add(record["sha256"], record["size_bytes"], f'{record["sha256"]}.{suffix}', kind=kind)
    for sources in data["trees"].values():
        for tree in sources.values():
            for entry in tree["entries"]:
                if entry["type"] == "file":
                    add(entry["sha256"], entry["size_bytes"], entry["path"].rsplit("/", 1)[-1], contextual=entry.get("extraction"))
    return index


def catalog_signature(catalog):
    """Fingerprint source records and annotation inputs during a bounded refresh."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(catalog):
        dirnames.sort()
        for name in filenames:
            if name.endswith(".json"):
                info = os.stat(os.path.join(dirpath, name))
                entries.append((dirpath, name, info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino))
    dependencies = [Path(__file__).resolve().parents[2] / "tools" / "extractor_versions.json",
                    Path(__file__).with_name("data") / "contextual_extractors.json",
                    Path(__file__).with_name("data") / "redump-psx.json"]
    for path in dependencies:
        try:
            info = path.stat()
            entries.append((str(path.parent), path.name, info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino))
        except FileNotFoundError:
            entries.append((str(path.parent), path.name, None, None, None, None))
    entries.sort()
    return tuple(entries)


def _population_digest(population):
    """Reference populations are large and may hold tuple keys; identify them by digest."""
    if population is None:
        return None
    encoded = json.dumps(population, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class _CatalogCache:
    """Single-flight snapshots, checked at most once per five seconds.

    Cold requests wait for the first complete snapshot. Warm requests start one
    background check and may use the previous snapshot for at most 30 seconds
    after its last successful check; older requests wait. A failed check is
    logged and makes subsequent requests fail until a successful retry, rather
    than concealing bad catalog records behind an indefinitely stale response.
    Payload, download index, and validators are published together, never in
    place, so readers cannot mix generations during a refresh.
    """

    refresh_seconds = 5
    max_stale_seconds = 30

    def __init__(self, catalog, store, redump, umdatabase, redump_population=None, nopaystation=None,
                 serialstation=None):
        self.catalog, self.store = catalog, store
        self.redump, self.umdatabase = redump, umdatabase
        self.redump_population, self.nopaystation = redump_population, nopaystation
        self.serialstation = serialstation
        self.condition = threading.Condition()
        self.payload = None
        self.checked_at = self.next_check = 0
        self.refreshing = False
        self.error = None
        cache_root = os.environ.get("PSPDB_WEB_CACHE_DIR")
        if cache_root is None:
            cache_root = str(Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "pspdb" / "web")
        identity = str(Path(catalog).resolve()) + ":" + str(store is not None)
        filename = hashlib.sha256(identity.encode()).hexdigest() + ".snapshot"
        self.cache_path = Path(cache_root).expanduser() / filename if cache_root else None
        implementation = hashlib.sha256(b"".join(
            Path(__file__).with_name(name).read_bytes()
            for name in ("server.py", "redump.py", "umdatabase.py", "wire.py",
                         "psn.py", "coverage.py", "nopaystation.py", "serialstation.py")
        )).hexdigest()
        self.cache_configuration = [
            implementation, store is not None,
            sorted((redump or {}).items()), sorted((umdatabase or {}).items()),
            _population_digest(redump_population and
                               (sorted([sha1, size, category]
                                       for (sha1, size), category in redump_population['discs'].items())
                                + [redump_population['name'], redump_population['version']])),
            _population_digest(nopaystation),
            _population_digest({
                'packages': sorted(serialstation['packages'].items()),
                'discs': serialstation['discs'],
            } if serialstation is not None else None),
        ]

    def _disk_key(self, signature):
        encoded = json.dumps([signature, self.cache_configuration], sort_keys=True,
                             ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest().encode("ascii")

    def _payload(self, signature, body, compressed, data=None, body_digest=None):
        if self.store is not None and data is None:
            data = decode_catalog(json.loads(body))
        return dict(signature=signature, body=body, gzip=compressed,
                    etag='"' + (body_digest or hashlib.sha256(body).hexdigest()) + '"',
                    gzip_etag='"' + hashlib.sha256(compressed).hexdigest() + '"',
                    objects=download_index(data) if self.store is not None else None)

    def _load_disk(self, signature):
        if self.cache_path is None:
            return None
        try:
            with self.cache_path.open("rb") as stream:
                if stream.readline(128) != b"PSPDB-WEB-1 " + self._disk_key(signature) + b"\n":
                    return None
                digest = stream.readline(128).strip()
                compressed = stream.read()
            body = gzip.decompress(compressed)
            if digest != hashlib.sha256(body).hexdigest().encode("ascii"):
                raise ValueError("Snapshot checksum mismatch")
            return self._payload(signature, body, compressed, body_digest=digest.decode("ascii"))
        except FileNotFoundError:
            return None
        except (OSError, EOFError, zlib.error, ValueError, KeyError, TypeError):
            logging.getLogger(__name__).warning("Ignoring unreadable website snapshot cache", exc_info=True)
            return None

    def _save_disk(self, signature, payload):
        temporary = None
        try:
            self.cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.cache_path.parent, prefix=".snapshot-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(b"PSPDB-WEB-1 " + self._disk_key(signature) + b"\n")
                stream.write(payload["etag"].strip('"').encode("ascii") + b"\n")
                stream.write(payload["gzip"])
            os.replace(temporary, self.cache_path)
        except OSError:
            logging.getLogger(__name__).warning("Unable to persist website snapshot cache", exc_info=True)
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    logging.getLogger(__name__).warning("Unable to remove temporary snapshot cache", exc_info=True)

    def _refresh(self):
        try:
            signature = catalog_signature(self.catalog)
            payload = self.payload
            if payload is None or payload["signature"] != signature:
                payload = self._load_disk(signature)
                if payload is None:
                    data = catalog_data(self.catalog, self.redump, self.umdatabase,
                                        self.redump_population, self.nopaystation, self.serialstation)
                    data["downloads_enabled"] = self.store is not None
                    body = json.dumps(encode_catalog(data), ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")
                    compressed = gzip.compress(body, compresslevel=1, mtime=0)
                    payload = self._payload(signature, body, compressed, data)
                    # Never persist a mixed generation observed during active ingestion.
                    if self.cache_path is not None and catalog_signature(self.catalog) == signature:
                        self._save_disk(signature, payload)
        except Exception as error:
            logging.getLogger(__name__).exception("Unable to refresh catalog")
            with self.condition:
                # Do not retain a traceback and its potentially large partial snapshot.
                self.error = str(error)
                self.next_check = monotonic() + self.refresh_seconds
                self.refreshing = False
                self.condition.notify_all()
        else:
            with self.condition:
                self.payload = payload
                self.checked_at = monotonic()
                self.next_check = self.checked_at + self.refresh_seconds
                self.error = None
                self.refreshing = False
                self.condition.notify_all()

    def get(self):
        with self.condition:
            while True:
                now = monotonic()
                usable = (self.payload is not None and self.error is None
                          and now - self.checked_at < self.max_stale_seconds)
                if self.refreshing:
                    if usable:
                        return self.payload
                    self.condition.wait()
                    continue
                if now < self.next_check:
                    if self.error is not None:
                        raise ValueError(self.error)
                    return self.payload
                self.refreshing = True
                if usable:
                    threading.Thread(target=self._refresh, name="catalog-refresh", daemon=True).start()
                    return self.payload
                break
        self._refresh()
        with self.condition:
            if self.error is not None:
                raise ValueError(self.error)
            return self.payload


def handler_for(catalog, store=None, redump=None, umdatabase=None, redump_population=None, nopaystation=None,
                serialstation=None):
    assets = Path(__file__).with_name("web")
    catalog = Path(catalog)
    store = Path(store).resolve() if store is not None else None
    cache = _CatalogCache(catalog, store, redump, umdatabase, redump_population, nopaystation, serialstation)

    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                # A client may cancel while receiving headers or the response body.
                self.close_connection = True

        def do_GET(self):
            request = urlsplit(self.path)
            route = request.path
            encoding = None
            try:
                if route == "/api/catalog":
                    payload = cache.get()
                    mime = "application/json; charset=utf-8"
                    accepted = {}
                    for item in self.headers.get("Accept-Encoding", "").lower().split(","):
                        coding, *parameters = item.strip().split(";")
                        quality = 1.0
                        for parameter in parameters:
                            if parameter.strip().startswith("q="):
                                try:
                                    quality = float(parameter.strip()[2:])
                                except ValueError:
                                    quality = 0.0
                        accepted[coding] = quality
                    if accepted.get("gzip", accepted.get("*", 0)) > 0:
                        body, encoding, etag = payload["gzip"], "gzip", payload["gzip_etag"]
                    else:
                        body, etag = payload["body"], payload["etag"]
                    validators = (tag.strip().removeprefix("W/") for tag in
                                  self.headers.get("If-None-Match", "").split(","))
                    if any(tag in ("*", etag) for tag in validators):
                        self.send_response(304)
                        self.send_header("ETag", etag)
                        self.send_header("Vary", "Accept-Encoding")
                        self.send_header("Cache-Control", "private, no-cache")
                        self.end_headers()
                        return
                elif route == "/api/availability" and store is not None:
                    hashes = parse_qs(request.query).get("hash", [])
                    if len(hashes) > 128:
                        self.send_error(400, "Too many hashes")
                        return
                    available = {}
                    index = cache.get()["objects"]
                    for digest in set(hashes):
                        available[digest] = False
                        if digest in index:
                            try:
                                with open_object(store, digest, index[digest][0]):
                                    available[digest] = True
                            except OSError:
                                pass
                    body = json.dumps(available, separators=(",", ":")).encode("utf-8")
                    mime = "application/json; charset=utf-8"
                elif route.startswith("/download/") and store is not None:
                    self.download(route)
                    return
                elif route in ("/", "/app.js", "/search-worker.js", "/style.css"):
                    filename, mime = {"/": ("index.html", "text/html"),
                                      "/app.js": ("app.js", "text/javascript"),
                                      "/search-worker.js": ("search-worker.js", "text/javascript"),
                                      "/style.css": ("style.css", "text/css")}[route]
                    body = (assets / filename).read_bytes()
                    mime += "; charset=utf-8"
                else:
                    self.send_error(404)
                    return
            except (BrokenPipeError, ConnectionResetError):
                raise
            except (OSError, ValueError, KeyError):
                self.send_error(500, "Unable to read catalog")
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            if route == "/api/catalog":
                self.send_header("Vary", "Accept-Encoding")
                self.send_header("ETag", etag)
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, no-cache" if route == "/api/catalog" else "no-store")
            self.end_headers()
            self.wfile.write(body)

        def download(self, route):
            match = re.fullmatch(r"/download/([0-9a-f]{64})/([^/]+)", route)
            if not match:
                self.send_error(404)
                return
            digest, encoded = match.groups()
            name = unquote(encoded)
            entry = cache.get()["objects"].get(digest)
            if entry is None or name not in entry[1]:
                self.send_error(404)
                return
            try:
                stream = open_object(store, digest, entry[0])
            except OSError:
                self.send_error(404, "File unavailable")
                return
            with stream:
                fallback = re.sub(r'[^A-Za-z0-9._ -]', '_', name)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(entry[0]))
                self.send_header("Content-Disposition", f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                shutil.copyfileobj(stream, self.wfile, length=1024 * 1024)

    return Handler


def serve(catalog, port=8000, host="127.0.0.1", store=None, redump=None, umdatabase=None, nopaystation=None,
          serialstation=None):
    catalog = Path(catalog).resolve()
    if not catalog.is_dir():
        raise ValueError(f"Catalog directory does not exist: {catalog}")
    if store is not None:
        store = Path(store).expanduser().resolve()
        if not store.is_dir():
            raise ValueError(f"Object store directory does not exist: {store}")
    from .redump import load_matches, load_population
    matches = load_matches(redump) if redump is not None else None
    population = load_population(redump) if redump is not None else None
    from .umdatabase import load_matches as load_umdatabase
    umd_matches = load_umdatabase(umdatabase) if umdatabase is not None else None
    from .nopaystation import load_population as load_nopaystation
    nps = load_nopaystation(nopaystation) if nopaystation is not None else None
    from .serialstation import load_matches as load_serialstation
    serials = load_serialstation(serialstation) if serialstation is not None else None
    handler = handler_for(catalog, store, matches, umd_matches, population, nps, serials)
    with ThreadingHTTPServer((host, port), handler) as server:
        print(f"Browse PSPDB at http://{host}:{server.server_port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
