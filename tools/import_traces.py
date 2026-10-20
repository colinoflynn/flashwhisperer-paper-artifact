#!/usr/bin/env python3
"""Fill `traces/` from the research tree, and write the manifest.

Three steps, and the middle one is the reason this is a script rather than a
line in the README:

1. `tools/artifact_reduce.py --out traces` in the research tree. That is where
   the reduction lives and it is not copied here: it drops each capture's
   ciphertext column for a SHA-256 of it, and replaces a plaintext column with
   a 4-byte PRNG seed wherever all n plaintexts can be shown to be exactly
   what the seed generates. It writes `traces/REDUCTION.json`, which is the
   manifest of record for everything it touched.

2. The captures it could not reduce, copied across byte for byte. There are two
   kinds and neither is a defect: a file whose timing column is a named
   per-cell array rather than `cyc` (the matrix captures, which is most of what
   backs a `flat` claim), and a `.json` capture (the MPC5606B, the MSP430, the
   L475's surface file). The reducer skips both and says so; a cell whose only
   capture was skipped would otherwise have no data in the artifact at all,
   which is a worse outcome than 6 MB.

3. `traces/MANIFEST.tsv`, a size and SHA-256 per file, in the shape the
   research tree's `results/MANIFEST.tsv` uses, plus the two columns that shape
   does not have: whether the file was reduced or copied, and its
   `ct_provenance`.

WHY `ct_provenance` IS ON EVERY ROW. A reduced capture's ciphertext column is
recomputed from the plaintexts and the key at replay time, and the stored
SHA-256 is what makes that sound. What the hash proves is that the recorded
column equalled AES of the recorded plaintexts - and whether that says anything
about the SILICON depends entirely on where the recorded column came from,
which the file cannot tell you, because a host-computed column and a correct
device-reported column are bit-identical by construction. So the field carries
`device`, `host` or `unknown`, and `unknown` prints as `unknown`. Most of these
are `unknown`; see the README.

WHAT THIS DOES NOT DO:

* It does not reduce the pass-through files. They keep every array they had.
* It does not verify the reduction. `python tools/artifact_reduce.py --out
  traces --verify` in the research tree does that, against the originals, and
  it needs the research tree - a verify that could run here would be checking
  the reduction against itself.
* It does not know which capture backs which cell. `cells/cells.json` does.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRACES = os.path.join(ROOT, "traces")

HEADER = [
    "# Reduced captures under traces/, one row per file.",
    "# Regenerate: python tools/import_traces.py --research <tree>",
    "# Verify:     python tools/verify.py",
    "#",
    "# ct_provenance is where the RECORDED ciphertext column came from. A hash",
    "# match proves the column equalled AES_k(pt); whether that is evidence",
    "# about the silicon depends on this field, and `unknown` means nothing on",
    "# disk settles it. It is not rounded up.",
    "#",
    "# path\tbytes\tsha256\tkind\tct_provenance",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def wanted_captures():
    """Every capture path any cell's `repro` block names, expanded."""
    with open(os.path.join(ROOT, "cells", "cells.json"),
              encoding="utf-8") as fh:
        cells = json.load(fh)["cells"]
    out = {}
    for cell in cells:
        repro = cell.get("repro")
        if not repro:
            continue
        form = repro["capture_form"]
        for path in form["paths"]:
            out.setdefault(path, []).append(cell["id"])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--research", default=os.environ.get(
        "FLASHWHISPERER_RESEARCH",
        os.path.join(ROOT, "..", "..", "flash-accelerator-tests")))
    ap.add_argument("--reduce", action="store_true",
                    help="run the research tree's artifact_reduce.py first")
    ap.add_argument("--manifest-only", action="store_true",
                    help="rewrite MANIFEST.tsv over what is already here")
    args = ap.parse_args(argv)
    research = os.path.abspath(args.research)

    if args.reduce:
        script = os.path.join(research, "tools", "artifact_reduce.py")
        print("running %s" % script)
        subprocess.run([sys.executable, script, "--out", TRACES], check=True,
                       cwd=research)

    reduction = os.path.join(TRACES, "REDUCTION.json")
    if not os.path.exists(reduction):
        raise SystemExit("no traces/REDUCTION.json; run with --reduce")
    with open(reduction, encoding="utf-8") as fh:
        rows = json.load(fh)["rows"]
    reduced = {r["path"]: r for r in rows}

    passthrough_path = os.path.join(TRACES, "PASSTHROUGH.json")
    passthrough = {}
    if not args.manifest_only:
        prov = load_module(os.path.join(research, "tools",
                                        "artifact_reduce.py"),
                           "_research_artifact_reduce").provenance
        for path, cell_ids in sorted(wanted_captures().items()):
            if path in reduced:
                continue
            source = os.path.join(research, path)
            if not os.path.exists(source):
                print("MISSING in the research tree: %s" % path)
                continue
            dest = os.path.join(TRACES, path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(source, dest)
            passthrough[path] = {
                "path": path,
                "source": path,
                "kind": "verbatim",
                "ct_provenance": prov(read_meta(source)),
                "bytes": os.path.getsize(dest),
                "cells": cell_ids,
                "why": "the reducer skipped it: %s" % skip_reason(source),
            }
            print("copied %-62s %7.1f KB  ct=%s"
                  % (path, os.path.getsize(dest) / 1024.0,
                     passthrough[path]["ct_provenance"]))
        with open(passthrough_path, "wb") as fh:
            fh.write((json.dumps({"files": passthrough}, indent=1,
                                 ensure_ascii=False) + "\n").encode("utf-8"))
    elif os.path.exists(passthrough_path):
        with open(passthrough_path, encoding="utf-8") as fh:
            passthrough = json.load(fh)["files"]

    lines = list(HEADER)
    total = 0
    for root, _dirs, files in os.walk(TRACES):
        for name in sorted(files):
            if name in ("MANIFEST.tsv",):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, TRACES).replace(os.sep, "/")
            size = os.path.getsize(full)
            total += size
            if rel in reduced:
                kind, prov_s = "reduced", reduced[rel]["ct_provenance"]
            elif rel in passthrough:
                kind, prov_s = "verbatim", passthrough[rel]["ct_provenance"]
            else:
                kind, prov_s = "meta", "n/a"
            lines.append("%s\t%d\t%s\t%s\t%s"
                         % (rel, size, sha256_file(full), kind, prov_s))
    with open(os.path.join(TRACES, "MANIFEST.tsv"), "wb") as fh:
        fh.write(("\n".join(lines) + "\n").encode("utf-8"))
    print("traces/MANIFEST.tsv: %d files, %.1f MB"
          % (len(lines) - len(HEADER), total / 1e6))
    return 0


def read_meta(path):
    """A capture's free-prose `meta` string, or None. Used only to classify
    ciphertext provenance, through the research tree's own `provenance()`."""
    if path.lower().endswith(".json"):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            return doc.get("meta") if isinstance(doc, dict) else None
        except Exception:
            return None
    try:
        import numpy as np
        with np.load(path, allow_pickle=True) as z:
            if "meta" in z:
                return str(np.asarray(z["meta"]).reshape(-1)[0])
    except Exception:
        return None
    return None


def skip_reason(path):
    """Why the reducer left this file alone, in its own words where we can tell.

    Deliberately coarse: the reducer prints the exact reason and this is a
    label for the manifest, not a second implementation of its test.
    """
    if path.lower().endswith(".json"):
        return "not an npz"
    try:
        import numpy as np
        with np.load(path, allow_pickle=True) as z:
            have = set(z.keys())
    except Exception:
        return "unreadable as an npz"
    if not have & {"cyc", "cyc_cycles", "cycles", "timing"}:
        return "no per-trace timing column; the cells it holds are named arrays"
    if not have & {"pt", "pts", "plaintext", "plaintexts", "seed"}:
        return "no plaintexts; the ciphertext column cannot be dropped"
    return "see the reducer's output"


if __name__ == "__main__":
    sys.exit(main())
