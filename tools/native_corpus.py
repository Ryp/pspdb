#!/usr/bin/env python3
"""Build the TSV corpus consumed by ingest/src/native_diff.zig.

Read-only walk of a PSPDB catalog (<kind>/v<N>/<sha256>-tree.json; the newest
version per kind+sha256 wins) against the content-addressed store
(<store>/sha256/<aa>/<bb>/<sha256>). Writes only --output.

Rows (tab separated, sorted, store paths absolute):
  <kind>  <sha256>  <store_path>          kind in prx, kl3e, kl4e, pgd, psar
  pops    <DATA.PSP sha>  <psp path>  <DATA.BIN sha>  <bin path>
          sibling DATA.PSP + DATA.BIN (same directory, case-insensitive) in a
          `pbp` tree; both objects must be in the store.
  npdrm   <pbp sha>  <store path>         every `pbp` object present; the
          harness slices DATA.PSAR out of the PBP header.
  psx_pgd <pbp sha>  <store path>         `pbp` objects whose tree lists the
          PS1 decrypt outputs (ISO_HEADER*.BIN, ISO_MAP.BIN, SPECIAL_DATA.BIN,
          UNKNOWN_DATA.BIN). The PGDs are not standalone store objects: they
          live inside DATA.PSAR, so the harness walks the PSAR to find them.
"""

import argparse
import json
import os
import re
import sys

INPUT_KINDS = ("prx", "kl3e", "kl4e", "pgd", "psar")
PSX_OUTPUT = re.compile(
    r"^(ISO_HEADER(_\d+)?|ISO_MAP|SPECIAL_DATA|UNKNOWN_DATA)\.BIN$", re.IGNORECASE
)
TREE = re.compile(r"^([0-9a-f]{64})-tree\.json$")
VERSION = re.compile(r"^v(\d+)$")


def newest_trees(catalog, kind):
    """Return {sha256: tree.json path}, newest version wins."""
    found = {}
    kind_dir = os.path.join(catalog, kind)
    if not os.path.isdir(kind_dir):
        return {}
    for name in os.listdir(kind_dir):
        m = VERSION.match(name)
        if not m:
            continue
        version = int(m.group(1))
        vdir = os.path.join(kind_dir, name)
        for entry in os.listdir(vdir):
            t = TREE.match(entry)
            if not t:
                continue
            sha = t.group(1)
            if sha not in found or found[sha][0] < version:
                found[sha] = (version, os.path.join(vdir, entry))
    return {sha: path for sha, (_, path) in found.items()}


def store_path(store, sha):
    path = os.path.join(store, "sha256", sha[:2], sha[2:4], sha)
    return path if os.path.isfile(path) else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--catalog", default="/home/ryp/dev/psp/pspdb-data/catalog")
    ap.add_argument("--store", default="/mnt/extra/psp/store")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    rows = []
    for kind in INPUT_KINDS:
        for sha in newest_trees(args.catalog, kind):
            path = store_path(args.store, sha)
            if path:
                rows.append((kind, sha, path))

    for sha, tree_path in newest_trees(args.catalog, "pbp").items():
        pbp = store_path(args.store, sha)
        if not pbp:
            continue
        rows.append(("npdrm", sha, pbp))
        with open(tree_path, encoding="utf-8") as f:
            entries = json.load(f).get("entries", [])
        files = [e for e in entries if e.get("type") == "file"]
        if any(PSX_OUTPUT.match(os.path.basename(e["path"])) for e in files):
            rows.append(("psx_pgd", sha, pbp))
        psp, binf = {}, {}
        for e in files:
            d, base = os.path.split(e["path"])
            if base.upper() == "DATA.PSP":
                psp[d] = e["sha256"]
            elif base.upper() == "DATA.BIN":
                binf[d] = e["sha256"]
        for d in psp.keys() & binf.keys():
            pp, bp = store_path(args.store, psp[d]), store_path(args.store, binf[d])
            if pp and bp:
                rows.append(("pops", psp[d], pp, binf[d], bp))

    rows.sort()
    with open(args.output, "w", encoding="utf-8") as out:
        for row in rows:
            out.write("\t".join(row) + "\n")
    counts = {}
    for row in rows:
        counts[row[0]] = counts.get(row[0], 0) + 1
    print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())), file=sys.stderr)


if __name__ == "__main__":
    main()
