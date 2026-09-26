"""PostureHound CLI: `python -m posturehound.cli scan <file>`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import ingest
from .engine import assess_file, assess_many
from .report import render_html


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="posturehound", description="Read-only Azure identity posture audit from AzureHound data.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Assess a collection and print/emit findings.")
    s.add_argument("file", nargs="+", help="One or more collection files (e.g. ad.json rm.json) or a .zip.")
    s.add_argument("--format", choices=["json", "html"], default="json")
    s.add_argument("--out", help="Write output to file instead of stdout.")
    s.add_argument("--min-severity", choices=["Critical", "High", "Medium", "Low", "Info"])

    v = sub.add_parser("validate", help="Lint a collection without assessing.")
    v.add_argument("file", nargs="+")

    args = p.parse_args(argv)

    if args.cmd == "validate":
        blobs = [(Path(f).read_bytes(), f) for f in args.file]
        print(json.dumps({"valid": True, **{"summary": ingest.parse_many(blobs).summary}}, indent=2))
        return 0

    if len(args.file) == 1:
        result = assess_file(args.file[0])
    else:
        result = assess_many([(Path(f).read_bytes(), f) for f in args.file])
    if args.min_severity:
        rank = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}[args.min_severity]
        result["findings"] = [f for f in result["findings"]
                              if {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}[f["severity"]] >= rank]

    out = render_html(result) if args.format == "html" else json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(out)

    # CI gating: non-zero exit if any Critical finding exists.
    return 2 if result["score"]["severity_counts"]["Critical"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
