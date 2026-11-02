#!/usr/bin/env python3
"""Emit a JSONL corpus of recorded DOCUMENT extractions for ingest/src/document_diff.zig.

Read-only and single-threaded. One row per distinct (source, docinfo) pair:
  {"source", "source_path", "docinfo", "docinfo_path", "expect_error", "entries"}
entries = sorted [path, type, sha256|null, size|null]. Rows whose store objects are
missing are skipped (counted on stderr).
"""

import argparse
import glob
import json
import os
import re
import sys

HELPER = "PSP-DOCUMENT.DAT"
SHA = re.compile(r"^[0-9a-f]{64}$")


def store_path(store, sha):
    return os.path.join(store, "sha256", sha[:2], sha[2:4], sha)


def entry_rows(extraction):
    rows = []
    for e in extraction.get("entries", []):
        if e.get("type") == "directory":
            rows.append([e["path"], "directory", None, None])
        else:
            rows.append([e["path"], e["type"], e.get("sha256"), e.get("size_bytes")])
    rows.sort(key=lambda r: r[0])
    return rows


def newest_global_trees(catalog):
    best = {}
    for path in glob.glob(os.path.join(catalog, "document", "v*", "*-tree.json")):
        version = int(os.path.basename(os.path.dirname(path))[1:])
        sha = os.path.basename(path)[: -len("-tree.json")]
        if sha not in best or version > best[sha][0]:
            best[sha] = (version, path)
    for sha in sorted(best):
        with open(best[sha][1]) as f:
            yield json.load(f)


def inline_extractions(node):
    if isinstance(node, dict):
        extraction = node.get("extraction")
        if (
            isinstance(extraction, dict)
            and str(node.get("path", "")).rsplit("/", 1)[-1] == "DOCUMENT.DAT"
            and (extraction.get("extractor", {}).get("name") == HELPER or "error" in extraction)
        ):
            yield extraction
        for value in node.values():
            yield from inline_extractions(value)
    elif isinstance(node, list):
        for value in node:
            yield from inline_extractions(value)


def candidates(catalog):
    for tree in newest_global_trees(catalog):
        yield tree
    for path in sorted(glob.glob(os.path.join(catalog, "*", "v*", "*-tree.json"))):
        if os.path.basename(os.path.dirname(os.path.dirname(path))) == "document":
            continue
        with open(path) as f:
            tree = json.load(f)
        # Only the extraction objects of DOCUMENT.DAT entries.
        yield from inline_extractions(tree)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--store", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    seen = {}
    skipped = conflicts = 0
    rows = []
    for ex in candidates(args.catalog):
        source = ex.get("sha256")
        if not isinstance(source, str) or not SHA.match(source):
            skipped += 1
            continue
        docinfo = None
        for dep in ex.get("dependencies", []):
            if str(dep.get("path", "")).rsplit("/", 1)[-1] == "DOCINFO.EDAT":
                docinfo = dep.get("sha256")
        source_file = store_path(args.store, source)
        docinfo_file = store_path(args.store, docinfo) if docinfo else None
        if not os.path.isfile(source_file) or (docinfo_file and not os.path.isfile(docinfo_file)):
            skipped += 1
            continue
        row = {
            "source": source,
            "source_path": source_file,
            "docinfo": docinfo,
            "docinfo_path": docinfo_file,
            "expect_error": "error" in ex,
            "entries": entry_rows(ex),
        }
        # Newest extractor version wins; same-version disagreements keep the first.
        version = int(ex.get("extractor", {}).get("version", 0))
        key = (source, docinfo)
        if key in seen:
            old_version, old_row = seen[key]
            if version > old_version:
                rows[rows.index(old_row)] = row
                seen[key] = (version, row)
            elif version == old_version and old_row != row:
                conflicts += 1
            continue
        seen[key] = (version, row)
        rows.append(row)

    with open(args.output, "w") as out:
        for row in rows:
            out.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(
        f"document_corpus: {len(rows)} rows, {skipped} skipped (missing objects), "
        f"{conflicts} same-version duplicate pairs with differing records (first kept)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
