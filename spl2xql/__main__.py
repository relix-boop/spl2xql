import argparse
import json
import sys

from .translator import translate


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="spl2xql",
        description="Translate a subset of Splunk SPL into a Cortex XQL draft.")
    p.add_argument("query", nargs="?", help="SPL query (or use -f / stdin)")
    p.add_argument("-f", "--file", help="read the SPL query from a file")
    p.add_argument("--mode", choices=["datamodel", "dataset"], default="datamodel",
                   help="datamodel maps CIM fields to XDM (default); dataset keeps field names")
    p.add_argument("--map", help="JSON file with fields/values/datasets overrides")
    p.add_argument("--double-backslashes", action="store_true",
                   help="double regex backslashes, for rule content deployed outside XQL Search")
    p.add_argument("--json", action="store_true", help="print {xql, warnings} as JSON")
    args = p.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            spl = fh.read()
    elif args.query:
        spl = args.query
    else:
        spl = sys.stdin.read()
    mapping = None
    if args.map:
        with open(args.map, encoding="utf-8") as fh:
            mapping = json.load(fh)

    result = translate(spl, mode=args.mode, mapping=mapping,
                       double_backslashes=args.double_backslashes)
    if args.json:
        print(json.dumps({"xql": result.xql, "warnings": result.warnings}, indent=2))
    else:
        print(result.xql)
        for w in result.warnings:
            print(f"warning: {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
