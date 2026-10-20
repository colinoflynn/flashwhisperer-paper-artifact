#!/usr/bin/env python3
"""Check this checkout before trusting anything it prints.

    python tools/verify.py            everything
    python tools/verify.py --traces   just the manifest
    python tools/verify.py --pins     just the submodules

Four questions, and each one has cost somebody a day somewhere:

1. Are the submodules at their pins? `deps/PINS`, the gitlink the parent
   records, and the submodule's own HEAD must all be the same commit. A
   `git submodule update --remote` advances one silently, and for a scorer that
   means a different measurement under the same name.

2. Is any of them modified? These three are upstream's own bytes. An edit in a
   submodule is the one way this repository could be measuring something other
   than what it says, and `git status` in the parent does not show it as a
   content change.

3. Is the checkout complete? On Windows a clone into a deep directory exceeds
   MAX_PATH and ABORTS PART WAY THROUGH THE CHECKOUT, leaving a tree that looks
   complete. One sentinel file per dependency catches exactly that.

4. Do the traces match `traces/MANIFEST.tsv`? Three different answers and they
   are not the same thing: MISSING (listed, not here - restore it), CHANGED
   (here with a different hash - whatever used it is not reproducible from what
   is here now), and UNLISTED (here, not listed - a new capture; rerun
   `tools/import_traces.py`). `git status` answers none of these, which is why
   the file exists.

WHAT THIS DOES NOT COVER, and the list matters as much as the checks:

* It does not verify the REDUCTION. Checking that a reduced capture still
  equals what it was reduced from needs the original, which is not in this
  repository; the research tree's `artifact_reduce.py --verify` is what does
  that, against the originals. What is checked here is that the files have not
  changed since they were brought in.
* A hash match on a trace file says nothing about where that capture's
  ciphertext column came from. See the README on `ct_provenance`: a
  host-computed column and a correct device-reported column are bit-identical
  by construction, so no check in this repository can tell them apart.
* It does not run a recovery. A clean verify and a cell that reproduces are
  different claims; `tools/reproduce.py` is the second one.
* It does not check `cells.json` against the research tree. That needs the
  research tree: `python tools/make_cells.py --check --research <tree>`.
* It does not look at `images/`. Nothing has been built here yet, so there is
  no row to check; `tools/build.py` writes them and `tools/record.py` is what
  refuses an unlisted one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRACES = os.path.join(ROOT, "traces")

#: one file per dependency that must exist for the checkout to be complete.
#: Chosen deep rather than at the root: a MAX_PATH abort leaves the top of a
#: tree in place and loses the bottom, so a sentinel at the root passes on a
#: checkout that is half there.
SENTINELS = {
    "flashwhisperer": "flashattack/archive.py",
    "crypto-eval": "instrumentation/victim/include/ss_board.h",
    "demos": "tools/replay.py",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args, cwd=ROOT):
    out = subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True,
                         text=True)
    return out.returncode, out.stdout.strip(), out.stderr.strip()


def read_pins():
    pins = {}
    with open(os.path.join(ROOT, "deps", "PINS"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 3:
                pins[parts[0]] = {"url": parts[1], "commit": parts[2],
                                  "kind": parts[3] if len(parts) > 3 else ""}
    return pins


def gitlinks():
    """What the PARENT records for each submodule path, which is what a fresh
    clone would check out - not what this working tree happens to have."""
    code, out, _ = git("ls-tree", "-r", "HEAD", "deps")
    if code:
        return {}
    links = {}
    for line in out.splitlines():
        meta, _, path = line.partition("\t")
        bits = meta.split()
        if len(bits) >= 3 and bits[1] == "commit":
            links[os.path.basename(path)] = bits[2]
    return links


def check_pins(verbose=True):
    pins, links, bad = read_pins(), gitlinks(), 0
    for name, pin in sorted(pins.items()):
        path = os.path.join(ROOT, "deps", name)
        notes = []
        if not os.path.isdir(path):
            print("MISSING  deps/%s is not checked out. Run "
                  "`git submodule update --init`." % name)
            bad += 1
            continue
        code, head, _ = git("rev-parse", "HEAD", cwd=path)
        if code:
            print("MISSING  deps/%s is not a git checkout" % name)
            bad += 1
            continue
        if head != pin["commit"]:
            notes.append("HEAD %s is not the pin %s"
                         % (head[:12], pin["commit"][:12]))
        recorded = links.get(name)
        if recorded and recorded != pin["commit"]:
            notes.append("the parent records %s, PINS says %s"
                         % (recorded[:12], pin["commit"][:12]))
        _, dirty, _ = git("status", "--porcelain", cwd=path)
        if dirty:
            notes.append("MODIFIED: %d path(s) differ from upstream"
                         % len(dirty.splitlines()))
        sentinel = SENTINELS.get(name)
        if sentinel and not os.path.exists(os.path.join(path, sentinel)):
            notes.append("incomplete checkout: no %s" % sentinel)
        if notes:
            bad += 1
            print("BAD      deps/%-16s %s" % (name, "; ".join(notes)))
        elif verbose:
            print("ok       deps/%-16s %s" % (name, pin["commit"][:12]))
    return bad


def check_traces(verbose=False):
    path = os.path.join(TRACES, "MANIFEST.tsv")
    if not os.path.exists(path):
        print("MISSING  traces/MANIFEST.tsv; run tools/import_traces.py")
        return 1
    listed = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            bits = line.rstrip("\n").split("\t")
            if len(bits) >= 3:
                listed[bits[0]] = (int(bits[1]), bits[2],
                                   bits[3] if len(bits) > 3 else "",
                                   bits[4] if len(bits) > 4 else "")
    here = set()
    for root, _dirs, files in os.walk(TRACES):
        for name in files:
            if name == "MANIFEST.tsv":
                continue
            rel = os.path.relpath(os.path.join(root, name),
                                  TRACES).replace(os.sep, "/")
            here.add(rel)
    bad = 0
    for rel, (size, digest, _kind, _prov) in sorted(listed.items()):
        full = os.path.join(TRACES, rel.replace("/", os.sep))
        if rel not in here:
            print("MISSING  %s" % rel)
            bad += 1
            continue
        if os.path.getsize(full) != size or sha256_file(full) != digest:
            print("CHANGED  %s" % rel)
            bad += 1
        elif verbose:
            print("ok       %s" % rel)
    for rel in sorted(here - set(listed)):
        print("UNLISTED %s" % rel)
        bad += 1
    print("traces:  %d listed, %d on disk, %d problem(s)"
          % (len(listed), len(here), bad))
    provenance = {}
    for _rel, (_s, _d, _k, prov) in listed.items():
        provenance[prov or "n/a"] = provenance.get(prov or "n/a", 0) + 1
    print("         ciphertext provenance: %s"
          % "  ".join("%s=%d" % kv for kv in sorted(provenance.items())))
    return bad


def check_cells():
    path = os.path.join(ROOT, "cells", "cells.json")
    if not os.path.exists(path):
        print("MISSING  cells/cells.json; run tools/make_cells.py")
        return 1
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    missing, concat, prose = [], 0, 0
    for cell in doc["cells"]:
        repro = cell.get("repro")
        if not repro:
            continue
        form = repro["capture_form"]
        if form["kind"] == "prose":
            prose += 1
            continue
        if form["kind"] == "concat":
            concat += 1
        for capture in form["paths"]:
            if not os.path.exists(os.path.join(
                    TRACES, capture.replace("/", os.sep))):
                missing.append((cell["id"], capture))
    print("cells:   %d, verdicts %s"
          % (doc["meta"]["cells"],
             "  ".join("%s=%d" % kv
                       for kv in sorted(doc["meta"]["verdicts"].items()))))
    print("         %d cell(s) name a capture that is not in traces/"
          % len(missing))
    for cell_id, capture in missing[:10]:
        print("           %-52s %s" % (cell_id, capture))
    if concat:
        print("         %d cell(s) name several files summed together"
              % concat)
    if prose:
        print("         %d cell(s) name their capture in prose and cannot be "
              "resolved to a path" % prose)
    return len(missing)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pins", action="store_true")
    ap.add_argument("--traces", action="store_true")
    ap.add_argument("--cells", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    everything = not (args.pins or args.traces or args.cells)
    bad = 0
    if everything or args.pins:
        bad += check_pins(verbose=True)
    if everything or args.cells:
        bad += check_cells()
    if everything or args.traces:
        bad += check_traces(verbose=args.verbose)
    print("\n%s" % ("verify: clean" if not bad
                    else "verify: %d problem(s) - read them before trusting a "
                         "number out of tools/reproduce.py" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
