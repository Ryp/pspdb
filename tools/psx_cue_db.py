"""Generate ingest/src/psx/cue_db.bin from the pinned PSXtract-2 prebaked CUE files.

Input: the `cue/` directory of a PSXtract-2 checkout at commit
4691fc405698d53927df6e4f59c3e9b113c13706 (checked with git; any other commit, or a
dirty `cue/` tree, is refused).  Every file is parsed with a deliberately strict
grammar (the corpus is machine generated and perfectly regular); anything else
aborts the run.  Stdlib only.

Accepted file grammar (LF line endings, final newline, ASCII/UTF-8 title)::

    REM MD5 <32 lowercase hex>
    FILE "<title>.bin" BINARY
      TRACK <NN> MODE2/2352|AUDIO      (NN = 01, 02, ... consecutive, <= 99;
                                        track 01 must be MODE2/2352)
        [FLAGS DCP]                    (ignored by PSXtract, not stored)
        [INDEX 00 MM:SS:FF]            (only before INDEX 01, <= it)
        INDEX 01 MM:SS:FF              (required, strictly increasing over tracks)
    REM LEADOUT MM:SS:FF               (last line, after the last INDEX 01)

Fields PSXtract uses (psxtract.cpp check_prebaked_cue_file / parse_prebaked_cue_pregaps,
cue_resources.cpp extract_cue_md5): FILE title (without ".bin"), REM MD5, REM LEADOUT,
and per TRACK the type (AUDIO or not) plus INDEX 00 / INDEX 01 as frames
(MM*4500 + SS*75 + FF).  The key is the file stem, which must already use '-'
and match ``[A-Z0-9]+-[0-9]+(-[0-9]+)?``.

Blob format ``cue_db.bin`` (all integers little endian, no padding/alignment)::

    header (16 bytes)
        magic      "PSCD"
        version    u32 = 1
        count      u32          number of records
        total      u32          total blob length in bytes, including this header
    offsets: count x u32        absolute record offsets, keys in ascending
                                bytewise order (so binary search works on it)
    records (back to back, in key order)
        key_len    u8           1..255
        key        key_len bytes
        title_len  u16
        title      title_len bytes (UTF-8, ".bin" suffix removed)
        md5        16 bytes     REM MD5, raw
        leadout    u32          REM LEADOUT in frames
        tracks     u8           1..99
        tracks x { number u8, flags u8 (bit0 = audio, bit1 = has INDEX 00),
                   index01 u32 frames, index00 u32 frames (0 when absent) }
    trailer: crc32 u32          zlib.crc32 of every preceding byte

Usage: ``python3 tools/psx_cue_db.py [--cue-dir DIR] [--out FILE] [--check]``.
``--check`` regenerates in memory and fails if ``--out`` differs.  Every run
self-checks: the produced blob is decoded and, for every CUE file, compared with a
direct parse; the per-audio-track (pregap, length) arrays PSXtract derives are
computed two ways (a line-by-line port of the C parser run on the raw text, and
the track-model algorithm cue.zig implements) and must agree exactly.
"""
import argparse
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

PINNED_COMMIT = "4691fc405698d53927df6e4f59c3e9b113c13706"
DEFAULT_CUE_DIR = Path("/mnt/extra/psp/pspdb-work/psxtract-2/cue")
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "ingest/src/psx/cue_db.bin"
MAGIC = b"PSCD"
VERSION = 1
GAP_FRAMES = 150

KEY_RE = re.compile(r"[A-Z0-9]+-[0-9]+(?:-[0-9]+)?")
MD5_RE = re.compile(r"REM MD5 ([0-9a-f]{32})")
FILE_RE = re.compile(r'FILE "([^"\x00-\x1f]+)" BINARY')
TRACK_RE = re.compile(r"  TRACK ([0-9]{2}) (MODE2/2352|AUDIO)")
INDEX_RE = re.compile(r"    INDEX (0[01]) ([0-9]{2}):([0-9]{2}):([0-9]{2})")
LEADOUT_RE = re.compile(r"REM LEADOUT ([0-9]{2}):([0-9]{2}):([0-9]{2})")


class CueError(Exception):
    pass


def frames(mm, ss, ff, where):
    mm, ss, ff = int(mm), int(ss), int(ff)
    if ss >= 60 or ff >= 75:
        raise CueError(f"{where}: invalid MSF {mm}:{ss}:{ff}")
    return mm * 4500 + ss * 75 + ff


def parse_strict(text, name):
    """Strict parse -> dict(md5, title, leadout, tracks[{number,audio,index00,index01}])."""
    if not text.endswith("\n") or "\r" in text:
        raise CueError(f"{name}: must use LF line endings and end with a newline")
    lines = text[:-1].split("\n")
    if len(lines) < 5:
        raise CueError(f"{name}: too short")
    m = MD5_RE.fullmatch(lines[0])
    if not m:
        raise CueError(f"{name}: bad REM MD5 line {lines[0]!r}")
    md5 = bytes.fromhex(m.group(1))
    m = FILE_RE.fullmatch(lines[1])
    if not m:
        raise CueError(f"{name}: bad FILE line {lines[1]!r}")
    file_name = m.group(1)
    if not file_name.endswith(".bin") or file_name.find(".bin") != len(file_name) - 4:
        raise CueError(f"{name}: FILE name must end in a single .bin: {file_name!r}")
    title = file_name[:-4]
    if not title or len(title.encode("utf-8")) > 0xFFFF:
        raise CueError(f"{name}: bad title")
    m = LEADOUT_RE.fullmatch(lines[-1])
    if not m:
        raise CueError(f"{name}: last line must be REM LEADOUT, got {lines[-1]!r}")
    leadout = frames(*m.groups(), name)

    tracks = []
    cur = None
    for line in lines[2:-1]:
        m = TRACK_RE.fullmatch(line)
        if m:
            number = int(m.group(1))
            if number != len(tracks) + 1 or number > 99:
                raise CueError(f"{name}: track numbering broken at {line!r}")
            if number == 1 and m.group(2) != "MODE2/2352":
                raise CueError(f"{name}: track 01 must be MODE2/2352")
            cur = {"number": number, "audio": m.group(2) == "AUDIO",
                   "index00": None, "index01": None, "flags": False}
            tracks.append(cur)
            continue
        if cur is None:
            raise CueError(f"{name}: unexpected line before first TRACK: {line!r}")
        if line == "    FLAGS DCP":
            if cur["flags"] or cur["index00"] is not None or cur["index01"] is not None:
                raise CueError(f"{name}: misplaced FLAGS in track {cur['number']}")
            cur["flags"] = True
            continue
        m = INDEX_RE.fullmatch(line)
        if not m:
            raise CueError(f"{name}: unparseable line {line!r}")
        value = frames(m.group(2), m.group(3), m.group(4), name)
        if cur["index01"] is not None:
            raise CueError(f"{name}: INDEX after INDEX 01 in track {cur['number']}")
        if m.group(1) == "00":
            if cur["index00"] is not None:
                raise CueError(f"{name}: duplicate INDEX 00 in track {cur['number']}")
            cur["index00"] = value
        else:
            if cur["index00"] is not None and cur["index00"] > value:
                raise CueError(f"{name}: INDEX 00 after INDEX 01 in track {cur['number']}")
            cur["index01"] = value
    if not tracks:
        raise CueError(f"{name}: no tracks")
    previous = -1
    for t in tracks:
        if t["index01"] is None:
            raise CueError(f"{name}: track {t['number']} has no INDEX 01")
        first = t["index00"] if t["index00"] is not None else t["index01"]
        if first <= previous:
            raise CueError(f"{name}: track {t['number']} not after previous track")
        previous = t["index01"]
    if leadout <= previous:
        raise CueError(f"{name}: LEADOUT not after last track")
    return {"md5": md5, "title": title, "leadout": leadout, "tracks": tracks}


# --- PSXtract derived values -------------------------------------------------

def overrides_from_model(rec):
    """Track-model algorithm (what cue.zig implements): [(pregap, length)] per audio
    track with number > 1, in file order.  Requires INDEX 01 on every track (enforced
    by parse_strict), so PSXtract's num_track_starts == number of tracks."""
    tracks = rec["tracks"]
    n = len(tracks)
    start00 = [t["index00"] if t["index00"] is not None else t["index01"] for t in tracks]
    out = []
    for t in tracks:
        tn = t["number"]
        if tn <= 1 or not t["audio"]:
            continue
        if t["index00"] is not None:
            pregap = t["index01"] - t["index00"]
            current = start00[tn - 1]
        else:
            pregap = GAP_FRAMES
            current = t["index01"] - GAP_FRAMES
        if tn < n:
            length = start00[tn] - current
        elif rec["leadout"] > 0:
            length = rec["leadout"] - current
        else:
            length = 0
        out.append((pregap, length))
    return out


def overrides_from_text(text):
    """Faithful line-by-line port of psxtract.cpp parse_prebaked_cue_pregaps
    (two passes over the raw text; sscanf replaced by regexes on exact prefixes)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    lines = [l[:-1] if l.endswith("\r") else l for l in lines]

    def msf(s):
        m = re.match(r"\s*(-?\d+):(-?\d+):(-?\d+)", s)
        return int(m[1]) * 4500 + int(m[2]) * 75 + int(m[3]) if m else None

    leadout = -1
    starts00, starts01 = [], []
    pos = 0
    while pos < len(lines):
        line = lines[pos]
        pos += 1
        if line.startswith("REM LEADOUT "):
            v = msf(line[len("REM LEADOUT "):])
            if v is not None:
                leadout = v
        elif line.startswith("  TRACK "):
            if not re.match(r"  TRACK \d+ \S+", line):
                continue
            i0 = i1 = -1
            while pos < len(lines):
                l2 = lines[pos]
                pos += 1
                if l2.startswith("    INDEX 00 "):
                    v = msf(l2[len("    INDEX 00 "):])
                    if v is not None:
                        i0 = v
                elif l2.startswith("    INDEX 01 "):
                    v = msf(l2[len("    INDEX 01 "):])
                    if v is not None:
                        i1 = v
                    break
                elif l2.startswith("  TRACK "):
                    break
            if i1 >= 0:
                starts01.append(i1)
                starts00.append(i0 if i0 >= 0 else i1)
    nstarts = len(starts00)

    out = []
    pos = 0
    while pos < len(lines):
        line = lines[pos]
        pos += 1
        if not line.startswith("  TRACK "):
            continue
        m = re.match(r"  TRACK (\d+) (\S+)", line)
        if not m:
            continue
        tn, ttype = int(m[1]), m[2]
        if not (tn > 1 and ttype == "AUDIO"):
            continue
        i0 = i1 = None
        while pos < len(lines):
            l2 = lines[pos]
            pos += 1
            if l2.startswith("    INDEX 00 "):
                i0 = msf(l2[len("    INDEX 00 "):])
            elif l2.startswith("    INDEX 01 "):
                i1 = msf(l2[len("    INDEX 01 "):])
                break
            elif l2.startswith("  TRACK "):
                pos -= 1
                break
        if i0 is not None and i1 is not None:
            pregap = i1 - i0
            length = 0
            if tn - 1 < nstarts and tn < nstarts:
                length = starts00[tn] - starts00[tn - 1]
            elif tn - 1 < nstarts and leadout > 0:
                length = leadout - starts00[tn - 1]
            out.append((pregap, length))
        else:
            pregap = GAP_FRAMES
            length = 0
            if tn - 1 < nstarts and tn < nstarts:
                length = starts00[tn] - (starts01[tn - 1] - GAP_FRAMES)
            elif tn - 1 < nstarts and leadout > 0:
                length = leadout - (starts01[tn - 1] - GAP_FRAMES)
            out.append((pregap, length))
    return out


# --- encode / decode -----------------------------------------------------------

def encode_record(key, rec):
    kb = key.encode("ascii")
    tb = rec["title"].encode("utf-8")
    out = bytearray()
    out += struct.pack("<B", len(kb)) + kb
    out += struct.pack("<H", len(tb)) + tb
    out += rec["md5"]
    out += struct.pack("<IB", rec["leadout"], len(rec["tracks"]))
    for t in rec["tracks"]:
        flags = (1 if t["audio"] else 0) | (2 if t["index00"] is not None else 0)
        out += struct.pack("<BBII", t["number"], flags, t["index01"], t["index00"] or 0)
    return bytes(out)


def build_blob(records):
    keys = sorted(records, key=lambda k: k.encode("ascii"))
    encoded = [encode_record(k, records[k]) for k in keys]
    base = 16 + 4 * len(keys)
    offsets = []
    pos = base
    for e in encoded:
        offsets.append(pos)
        pos += len(e)
    total = pos + 4
    blob = bytearray(MAGIC + struct.pack("<III", VERSION, len(keys), total))
    for o in offsets:
        blob += struct.pack("<I", o)
    for e in encoded:
        blob += e
    blob += struct.pack("<I", zlib.crc32(bytes(blob)) & 0xFFFFFFFF)
    assert len(blob) == total
    return bytes(blob)


def decode_blob(blob):
    """Independent decoder; returns {key: rec} and raises CueError on any damage."""
    if blob[:4] != MAGIC:
        raise CueError("bad magic")
    version, count, total = struct.unpack_from("<III", blob, 4)
    if version != VERSION or total != len(blob):
        raise CueError("bad header")
    if struct.unpack_from("<I", blob, total - 4)[0] != zlib.crc32(blob[:-4]) & 0xFFFFFFFF:
        raise CueError("bad crc")
    out = {}
    previous = None
    pos = 16 + 4 * count
    for i in range(count):
        off = struct.unpack_from("<I", blob, 16 + 4 * i)[0]
        if off != pos:
            raise CueError("record offset mismatch")
        klen = blob[pos]
        key = blob[pos + 1:pos + 1 + klen]
        pos += 1 + klen
        if previous is not None and key <= previous:
            raise CueError("keys not strictly ascending")
        previous = key
        (tlen,) = struct.unpack_from("<H", blob, pos)
        title = blob[pos + 2:pos + 2 + tlen].decode("utf-8")
        pos += 2 + tlen
        md5 = bytes(blob[pos:pos + 16])
        leadout, ntracks = struct.unpack_from("<IB", blob, pos + 16)
        pos += 21
        tracks = []
        for _ in range(ntracks):
            number, flags, i01, i00 = struct.unpack_from("<BBII", blob, pos)
            pos += 10
            tracks.append({"number": number, "audio": bool(flags & 1),
                           "index00": i00 if flags & 2 else None, "index01": i01})
        out[key.decode("ascii")] = {"md5": md5, "title": title, "leadout": leadout,
                                    "tracks": tracks}
    if pos != total - 4:
        raise CueError("trailing garbage")
    return out


def strip_flags(rec):
    return {"md5": rec["md5"], "title": rec["title"], "leadout": rec["leadout"],
            "tracks": [{k: t[k] for k in ("number", "audio", "index00", "index01")}
                       for t in rec["tracks"]]}


# --- main ------------------------------------------------------------------------

def verify_checkout(cue_dir):
    root = cue_dir.resolve().parent
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    head = git("rev-parse", "HEAD")
    if head != PINNED_COMMIT:
        raise CueError(f"PSXtract-2 checkout is at {head}, expected {PINNED_COMMIT}")
    if git("status", "--porcelain", "--", cue_dir.name):
        raise CueError(f"{cue_dir} has uncommitted changes")


def load_all(cue_dir):
    records, texts = {}, {}
    files = sorted(cue_dir.iterdir())
    for path in files:
        if path.suffix != ".cue" or not path.is_file():
            raise CueError(f"unexpected entry {path.name}")
        key = path.stem
        if not KEY_RE.fullmatch(key):
            raise CueError(f"unsupported key {key!r}")
        if len(key) > 255:
            raise CueError(f"key too long {key!r}")
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as e:
            raise CueError(f"{path.name}: not UTF-8: {e}")
        records[key] = parse_strict(text, path.name)
        texts[key] = text
    if not records:
        raise CueError("no CUE files")
    return records, texts


def self_check(blob, records, texts):
    decoded = decode_blob(blob)
    if set(decoded) != set(records):
        raise CueError("round trip: key sets differ")
    for key, rec in records.items():
        if decoded[key] != strip_flags(rec):
            raise CueError(f"round trip: semantic fields differ for {key}")
        ref = overrides_from_text(texts[key])
        got = overrides_from_model(decoded[key])
        if ref != got:
            raise CueError(f"round trip: pregap/length arrays differ for {key}: {ref} != {got}")
    return len(decoded)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cue-dir", type=Path, default=DEFAULT_CUE_DIR)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="fail if --out is not up to date")
    args = ap.parse_args()
    try:
        verify_checkout(args.cue_dir)
        records, texts = load_all(args.cue_dir)
        blob = build_blob(records)
        n = self_check(blob, records, texts)
    except (CueError, subprocess.CalledProcessError, OSError) as e:
        print(f"psx_cue_db: {e}", file=sys.stderr)
        return 1
    print(f"self-check ok: {n} CUE files, {len(blob)} bytes")
    if args.check:
        if not args.out.is_file() or args.out.read_bytes() != blob:
            print(f"psx_cue_db: {args.out} is stale", file=sys.stderr)
            return 1
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(blob)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
