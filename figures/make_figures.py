#!/usr/bin/env python3
"""Regenerate the figures from a `tools/reproduce.py --json` run.

    python tools/reproduce.py --json figures/reproduce.json
    python figures/make_figures.py --rows figures/reproduce.json

Three figures, each of which says something the table cannot:

`ladder.pdf`      bytes recovered against trace count, one line per cell that
                  recovered. The shape of a ladder is the argument that a
                  trace count is a threshold and not a knob: most cells go from
                  nothing to sixteen bytes inside one doubling.
`coverage.pdf`    the 294 cells by verdict, grouped by part. This is the figure
                  that should get smaller over time, and the honest one to
                  publish: it shows what the artifact does NOT back.
`provenance.pdf`  the trace files by ciphertext provenance. It is mostly one
                  colour and that is the point - see the README.

The figures are derived, so they are not committed. The script is.

WHAT THIS DOES NOT DO: it does not compute anything. Every number in it comes
out of the JSON a reproduce run wrote, so a figure cannot disagree with the
table rows it was drawn from. If a figure looks wrong, the run is wrong.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rows", default=os.path.join(HERE, "reproduce.json"))
    ap.add_argument("--format", default="pdf", choices=("pdf", "png"))
    args = ap.parse_args(argv)

    if not os.path.exists(args.rows):
        raise SystemExit(
            "no %s. Make one first:\n"
            "    python tools/reproduce.py --json %s"
            % (args.rows, os.path.relpath(args.rows, ROOT)))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit("matplotlib is not installed, so no figure was "
                         "drawn. The numbers are all in %s and the tables in\n"
                         "tools/reproduce.py print without it.\n"
                         "    pip install matplotlib" % args.rows)

    run = load(args.rows)
    rows = run["rows"]

    # ---- the ladders
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    drawn = 0
    for row in rows:
        rungs = [r for r in row.get("rungs") or [] if r.get("bytes")
                 is not None]
        if len(rungs) < 2:
            continue
        ax.plot([r["n"] for r in rungs], [r["bytes"] for r in rungs],
                marker=".", linewidth=0.8, alpha=0.65)
        drawn += 1
    ax.set_xscale("log")
    ax.set_xlabel("traces (cumulative prefix of one capture)")
    ax.set_ylabel("round-10 key bytes recovered, of 16")
    ax.set_ylim(-0.5, 16.5)
    ax.set_title("%d recovery ladders" % drawn)
    ax.grid(alpha=0.25)
    out = os.path.join(HERE, "ladder." + args.format)
    fig.tight_layout()
    fig.savefig(out)
    print("wrote %s  (%d ladders)" % (out, drawn))

    # ---- coverage by verdict
    with open(os.path.join(ROOT, "cells", "cells.json"),
              encoding="utf-8") as fh:
        cells = json.load(fh)["cells"]
    by_part = collections.defaultdict(collections.Counter)
    for cell in cells:
        by_part[cell["part_short"] or cell["part"]][cell["verdict"]] += 1
    order = sorted(by_part, key=lambda p: -sum(by_part[p].values()))
    verdicts = ["block", "flat", "recapture", "drop"]
    fig, ax = plt.subplots(figsize=(6.4, 7.0))
    bottom = [0] * len(order)
    for verdict in verdicts:
        values = [by_part[p][verdict] for p in order]
        ax.barh(order, values, left=bottom, label=verdict)
        bottom = [b + v for b, v in zip(bottom, values)]
    ax.invert_yaxis()
    ax.set_xlabel("one-page result cells")
    ax.legend(loc="lower right")
    ax.set_title("%d cells by verdict" % len(cells))
    out = os.path.join(HERE, "coverage." + args.format)
    fig.tight_layout()
    fig.savefig(out)
    print("wrote %s" % out)

    # ---- ciphertext provenance
    tally = collections.Counter()
    manifest = os.path.join(ROOT, "traces", "MANIFEST.tsv")
    with open(manifest, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            bits = line.rstrip("\n").split("\t")
            if len(bits) >= 5 and bits[4] != "n/a":
                tally[bits[4]] += 1
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    names = sorted(tally)
    ax.bar(names, [tally[n] for n in names])
    ax.set_ylabel("trace files")
    ax.set_title("where the recorded ciphertext column came from")
    out = os.path.join(HERE, "provenance." + args.format)
    fig.tight_layout()
    fig.savefig(out)
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
