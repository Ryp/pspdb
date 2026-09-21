"""Serve or export the read-only catalog website."""
import argparse
import sys


def main():
    exporting = sys.argv[1:2] == ['export']
    parser = argparse.ArgumentParser(
        prog="pspdb-web export" if exporting else None,
        description="Export the PSPDB catalog" if exporting else "Serve the PSPDB catalog",
        epilog="Static hosting: pspdb-web export --catalog catalog --output dist/site" if not exporting else None)
    parser.add_argument("--catalog", default="catalog")
    if exporting:
        parser.add_argument("--output", required=True, help="Empty destination directory for the static site")
    else:
        parser.add_argument("--port", type=int, default=8000)
        parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1; use your LAN IP for network access)")
        parser.add_argument("--store", help="Optional object store to serve file downloads from (read-only)")
    parser.add_argument("--redump", help="Optional Redump DAT XML or ZIP for exact ISO matches")
    parser.add_argument("--umdatabase", help="Folder of saved UMDatabase ID.html entry pages for exact SHA-1 matches")
    parser.add_argument("--nopaystation", help="Folder of NoPayStation TSV snapshots (or one .tsv) for PSN coverage totals")
    args = parser.parse_args(sys.argv[2:] if exporting else None)
    try:
        if exporting:
            from .export import export_site
            output = export_site(args.catalog, args.output, redump=args.redump, umdatabase=args.umdatabase,
                                 nopaystation=args.nopaystation)
            print(f"Exported PSPDB to {output}")
        else:
            from .server import serve
            serve(args.catalog, args.port, host=args.host, store=args.store, redump=args.redump,
                  umdatabase=args.umdatabase, nopaystation=args.nopaystation)
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"pspdb-web: {exc}", file=sys.stderr)
        return 1
    return 0
