"""Private, content-ID keyed RAP storage shared by acquisition and extraction."""
from collections import Counter
import os
from pathlib import Path
import re
import secrets
import stat


CONTENT_ID = re.compile(r'[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Za-z0-9_]{16}\Z')
RAP_HEX = re.compile(r'[0-9a-fA-F]{32}\Z')
MISSING = {'', 'MISSING', 'N/A', 'NULL', '-', 'NOT REQUIRED'}


def license_directory(explicit=None):
    if explicit is not None:
        return Path(explicit).expanduser()
    configured = os.environ.get('PSPDB_RAP_DIR')
    if configured:
        return Path(configured).expanduser()
    data = os.environ.get('XDG_DATA_HOME')
    return (Path(data).expanduser() if data else Path.home() / '.local' / 'share') / 'pspdb' / 'licenses'


def _read_file(directory_fd, filename):
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != 16:
            raise ValueError('RAP must be a regular, exactly 16-byte file')
        value = stream.read(17)
        if len(value) != 16:
            raise ValueError('RAP must contain exactly 16 bytes')
        return value


def read_rap(content_id, directory=None):
    if not isinstance(content_id, str) or not CONTENT_ID.fullmatch(content_id):
        raise ValueError('Invalid EDAT content ID')
    directory = license_directory(directory)
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return _read_file(fd, content_id + '.rap')
        finally:
            os.close(fd)
    except FileNotFoundError:
        raise ValueError(f'Missing RAP for {content_id} in {directory}. '
                         'Import a local TSV containing its RAP with tools/psn_acquire.py '
                         f'--rap-dir {directory}, or point PSPDB_RAP_DIR at your license directory.') from None
    except (OSError, ValueError):
        raise ValueError(f'Invalid or unreadable RAP for {content_id} in {directory}; '
                         'expected a regular, nonsymlink, exactly 16-byte file in an accessible directory.') from None


def _publish(directory_fd, filename, value):
    temporary = '.rap-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                    follow_symlinks=False)
        except FileExistsError:
            # Concurrent imports must agree; never replace an existing key.
            try:
                return 'present' if _read_file(directory_fd, filename) == value else 'conflict'
            except (OSError, ValueError):
                return 'invalid'
        os.fsync(directory_fd)
        return 'imported'
    finally:
        os.unlink(temporary, dir_fd=directory_fd)


def import_raps(directory, entries):
    """Import inline TSV keys; return only identifiers and statuses, never key material.

    All observations are collected before publication so contradictory snapshots
    cannot select an arbitrary winner. Missing RAPs do not imply EDAT is required.
    """
    directory = license_directory(directory).absolute()
    candidates, invalid, results = {}, set(), []
    for content_id, raw in entries:
        content_id, raw = (content_id or '').strip(), (raw or '').strip()
        if not CONTENT_ID.fullmatch(content_id):
            results.append({'content_id': None, 'status': 'invalid'})
            continue
        values = candidates.setdefault(content_id, set())
        if raw.upper() in MISSING:
            continue
        if not RAP_HEX.fullmatch(raw):
            invalid.add(content_id)
            continue
        values.add(bytes.fromhex(raw))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for content_id, values in sorted(candidates.items()):
            filename = content_id + '.rap'
            if len(values) > 1:
                status = 'conflict'
            elif content_id in invalid:
                status = 'invalid'
            else:
                try:
                    existing = _read_file(fd, filename)
                except FileNotFoundError:
                    status = _publish(fd, filename, next(iter(values))) if values else 'missing'
                except (OSError, ValueError):
                    status = 'invalid'
                else:
                    status = 'conflict' if values and existing not in values else 'present'
            results.append({'content_id': content_id, 'status': status})
    finally:
        os.close(fd)
    counts = Counter(entry['status'] for entry in results)
    return {'directory': str(directory), 'counts': dict(sorted(counts.items())), 'entries': results}
