"""Read-only local web browser for a catalog; no index regeneration needed."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import stat
from urllib.parse import parse_qs, quote, unquote, urlsplit


def catalog_data(catalog, redump=None, umdatabase=None):
    records, trees = {}, {}
    for directory in sorted(catalog.iterdir()):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            kind = "tree" if directory.name == "trees" else directory.name
            if (record.get("kind") != kind or record.get("schema_version") != 1
                    or not re.fullmatch(r"[0-9a-f]{64}", path.stem)
                    or record.get("sha256") != path.stem):
                raise ValueError(f"Invalid catalog record identity: {path}")
            if kind == "tree":
                trees[path.stem] = record
                continue
            if kind == "iso":
                if redump is not None:
                    matches = redump.get((record.get("sha1"), record.get("size_bytes")), [])
                    if matches:
                        record["redump"] = matches
                if umdatabase is not None:
                    matches = umdatabase.get(record.get("sha1"), [])
                    if matches:
                        record["umdatabase"] = matches
            records.setdefault(kind, []).append(record)
    return {"records": records, "trees": trees}


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
    index = {}
    def add(digest, size, name, ancestors=frozenset()):
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not name or any(ord(c) < 32 or c in '/\\' for c in name):
            return
        if digest in index and index[digest][0] != size:
            raise ValueError("Conflicting sizes for catalog hash")
        names = index.setdefault(digest, (size, set()))[1]
        if name in names:
            return
        names.add(name)
        tree = data['trees'].get(digest)
        if not tree or tree['size_bytes'] != size or digest in ancestors:
            return
        for entry in tree['entries']:
            if entry['type'] != 'file':
                continue
            child = entry['path'].rsplit('/', 1)[-1]
            rule = tree.get('name_rule')
            if rule == 'source_stem':
                child = re.sub(r'\.[^.]*$', '', name) + child[child.index('.'):]
            elif rule == 'strip_suffix':
                child = re.sub(r'\.[^.]*$', '', name)
            add(entry['sha256'], entry['size_bytes'], child, ancestors | {digest})

    for kind, records in data["records"].items():
        for record in records:
            add(record["sha256"], record["size_bytes"], f'{record["sha256"]}.{kind}')
    for tree in data["trees"].values():
        for entry in tree["entries"]:
            if entry["type"] == "file":
                add(entry["sha256"], entry["size_bytes"], entry["path"].rsplit("/", 1)[-1])
    return index


def handler_for(catalog, store=None, redump=None, umdatabase=None):
    assets = Path(__file__).with_name("web")
    catalog = Path(catalog)
    store = Path(store).resolve() if store is not None else None
    objects = None

    def indexed_objects():
        nonlocal objects
        if objects is None:
            objects = download_index(catalog_data(catalog))
        return objects

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal objects
            request = urlsplit(self.path)
            route = request.path
            try:
                if route == "/api/catalog":
                    data = catalog_data(catalog, redump, umdatabase)
                    if store is not None:
                        objects = download_index(data)
                    data["downloads_enabled"] = store is not None
                    body = json.dumps(data).encode("utf-8")
                    mime = "application/json; charset=utf-8"
                elif route == "/api/availability" and store is not None:
                    hashes = parse_qs(request.query).get("hash", [])
                    if len(hashes) > 128:
                        self.send_error(400, "Too many hashes")
                        return
                    available = {}
                    index = indexed_objects()
                    for digest in set(hashes):
                        available[digest] = False
                        if digest in index:
                            try:
                                with open_object(store, digest, index[digest][0]):
                                    available[digest] = True
                            except OSError:
                                pass
                    body = json.dumps(available).encode("utf-8")
                    mime = "application/json; charset=utf-8"
                elif route.startswith("/download/") and store is not None:
                    self.download(route)
                    return
                elif route in ("/", "/app.js", "/style.css"):
                    filename, mime = {"/": ("index.html", "text/html"),
                                      "/app.js": ("app.js", "text/javascript"),
                                      "/style.css": ("style.css", "text/css")}[route]
                    body = (assets / filename).read_bytes()
                    mime += "; charset=utf-8"
                else:
                    self.send_error(404)
                    return
            except (OSError, ValueError, KeyError):
                self.send_error(500, "Unable to read catalog")
                return
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def download(self, route):
            match = re.fullmatch(r"/download/([0-9a-f]{64})/([^/]+)", route)
            if not match:
                self.send_error(404)
                return
            digest, encoded = match.groups()
            name = unquote(encoded)
            entry = indexed_objects().get(digest)
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
                try:
                    shutil.copyfileobj(stream, self.wfile, length=1024 * 1024)
                except (BrokenPipeError, ConnectionResetError):
                    pass

    return Handler


def serve(catalog, port=8000, host="127.0.0.1", store=None, redump=None, umdatabase=None):
    catalog = Path(catalog).resolve()
    if not catalog.is_dir():
        raise ValueError(f"Catalog directory does not exist: {catalog}")
    if store is not None:
        store = Path(store).expanduser().resolve()
        if not store.is_dir():
            raise ValueError(f"Object store directory does not exist: {store}")
    from .redump import load_matches
    matches = load_matches(redump) if redump is not None else None
    from .umdatabase import load_matches as load_umdatabase
    umd_matches = load_umdatabase(umdatabase) if umdatabase is not None else None
    with ThreadingHTTPServer((host, port), handler_for(catalog, store, matches, umd_matches)) as server:
        print(f"Browse PSPDB at http://{host}:{server.server_port} (Ctrl+C to stop)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
