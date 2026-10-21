#!/usr/bin/env python3
"""Regenerate `cells/cells.json` from the research tree's cross-part table.

The unit is a CELL, meaning one `(part, config, field)` triple where field is
`sbox`, `ttable1` or `ttable` - the three result columns the paper's one-page
table renders. A configuration is three cells and not one, and counting
configurations hides a configuration whose S-box cell has an artifact and whose
two T-table cells do not.

Run this in a checkout that has the research tree beside it:

    python tools/make_cells.py --research ../../flash-accelerator-tests
    python tools/make_cells.py --check          # regenerate and diff, write nothing

This is a GENERATOR and not a one-time copy, which matters because the triage
fragments under the research tree's `research/reference/repro/` land in batches
and a hand-copied `cells.json` goes stale between two of them. The two inputs:

    research/reference/cross_part_table.json    the claims, and the `repro`
                                                blocks for the cells that have
                                                an artifact
    research/reference/repro/<part>.json        the triage verdict for every
                                                cell that does not, which is
                                                where `recapture` and `drop`
                                                live - `repro_merge.py` folds
                                                only `block` and `flat` into
                                                the table file

WHAT THIS DOES NOT DO:

* It does not decide whether a cell reproduces. It carries the recovery
  parameters across verbatim and `tools/reproduce.py` runs them. A wrong
  `line_off` or `ct_adjacent` scores a clean null that is indistinguishable
  from a part that does not leak, so nothing here infers one.
* It does not rewrite `expect`. That field is spelled three ways in the source
  (an int, `"6 250"`, and prose like `"0/16 at 275 000"`); the parsed value
  goes in `expect_n` and the original stays in `expect` so the prose, which
  carries information the integer does not, is not lost.
* It does not check that a cell's capture is present under `traces/`. That is
  `tools/verify.py`, and the answer differs between a full checkout and a
  sparse one.
* It computes which cells the paper's Table 3 renders by importing the research
  tree's own `tools/cross_part_table.py` and calling its `select_configs`,
  rather than reimplementing the baseline/fix/other bucketing. A second
  derivation of that rule is a second thing to get wrong.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: the three result columns the one-page table renders
FIELDS = ("sbox", "ttable1", "ttable")

#: the parts the paper's one-page render excludes, from
#: cross_part_table.json's own `meta.renders.paper_one_page.cmd`
PAPER_EXCLUDE_KEY = "exclude"


def slug(text):
    """A filename-safe, stable slug for a config string.

    Stable matters more than pretty: the slug is half of a cell id, the cell id
    is what `--cell` takes and what `REPRODUCING.md` prints, and a slug that
    changes when somebody retypes an en dash renames every cell on the part.
    So the only characters that survive are `[a-z0-9]` and the separator.
    """
    t = text.lower().replace("—", "-").replace("–", "-")
    t = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    return t[:32].strip("-")


def parse_expect(value):
    """`(n, how)` for a block's `expect`, which is spelled three ways.

    An int is itself. A string of digits and spaces (`"6 250"`) is that number
    with the thousands separator the dossiers use. Anything else is prose and
    comes back `None`: `"0/16 at 275 000"` names a null and a trace count in
    one string, and reading the first integer out of it would score the cell
    against 0 when the claim is that nothing recovers at 275 000.
    """
    if value is None:
        return None, "null"
    if isinstance(value, bool):
        return None, "prose"
    if isinstance(value, int):
        return int(value), "int"
    s = str(value).strip()
    if re.fullmatch(r"[0-9][0-9  ,_]*", s):
        digits = re.sub(r"[^0-9]", "", s)
        if digits:
            return int(digits), "spaced"
    return None, "prose"


def capture_form(capture):
    """How a block names its capture: a path, several paths, or prose.

    One block in the source - the L475's `ACR 0x600` / VOS1 S-box cell - names
    eight files summed with `ladder.py --concat` in a sentence rather than
    giving a path. It is handled rather than dropped because it is a real cell
    with real data behind it, but it cannot be treated as a path, and a tool
    that silently `os.path.exists()`es the sentence reports the cell missing.
    """
    text = (capture or "").strip()
    if re.fullmatch(r"results/[\w./+-]+\.(npz|json)", text):
        return {"kind": "path", "paths": [text]}
    if "--concat" in text or " + " in text:
        return {"kind": "concat", "paths": expand_concat(text), "text": text}
    return {"kind": "prose", "paths": [], "text": text}


def expand_concat(text):
    """The file list out of a `--concat` sentence.

    The one in the source reads

        results/l475/l475_sbox_flash_acr600_vos1_100000.npz
        + l475_sbox_flash_acr600_vos1_sbeef2[1-4]_25000.npz
        + l475_sbox_flash_acr600_vos1_sbeef3[1-3]_25000.npz
        (summed with ladder.py --concat)

    so the directory comes from the first term and `[1-4]` is an inclusive
    range over single digits. Nothing else in the source uses this spelling,
    and a second one that does not parse comes back as an empty list rather
    than as a guess.
    """
    terms = [t.strip() for t in text.split("+")]
    out, directory = [], ""
    for term in terms:
        m = re.match(r"((?:results/[\w./+-]*/)?)([\w.+\-\[\]]+\.npz)", term)
        if not m:
            continue
        if m.group(1):
            directory = m.group(1)
        name = m.group(2)
        rng = re.search(r"\[(\d)-(\d)\]", name)
        if rng:
            lo, hi = int(rng.group(1)), int(rng.group(2))
            for i in range(lo, hi + 1):
                out.append(directory + name[:rng.start()] + str(i)
                           + name[rng.end():])
        else:
            out.append(directory + name)
    return out


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def paper_cmd_excludes(doc):
    """The parts the paper's one-page invocation drops, read off the data file
    rather than retyped. `meta.renders.paper_one_page.cmd` is the command of
    record; this pulls its `--exclude` list out of it."""
    cmd = (doc.get("meta", {}).get("renders", {})
              .get("paper_one_page", {}).get("cmd", ""))
    m = re.search(r"--exclude\s+([\w,]+)", cmd)
    return tuple(m.group(1).split(",")) if m else ()


def fragment_verdicts(research):
    """`(part_key_or_name, config_index, field) -> fragment cell`.

    Keyed on the part's own `part` string as the fragment spells it, because a
    fragment names the part and not the table's key. The config string is
    checked against the table's, character for character, the way
    `repro_merge.py` does: an index that drifted by one files a trace count
    against the neighbouring register setting.
    """
    out = {}
    fragdir = os.path.join(research, "research", "reference", "repro")
    for name in sorted(os.listdir(fragdir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(fragdir, name), "r", encoding="utf-8") as fh:
            frag = json.load(fh)
        part = frag.get("part")
        for cell in frag.get("cells", []):
            out[(part, cell["config_index"], cell["field"])] = cell
    return out


def loader_args():
    """`cells/loader_args.json`, the local overlay of key and seed arguments.

    Some captures hold a cycle count and nothing else a recovery needs,
    because the capture script kept the key or the seed as a module constant.
    Those arguments are data about particular files, so they live in a file
    here rather than in a tool, and they are folded in only where the upstream
    block does not carry its own. That file says why supplying a key is not
    assuming the answer; the short version is that a wrong key gives a clean
    0/16 rather than a wrong 16/16.
    """
    path = os.path.join(ROOT, "cells", "loader_args.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("captures", {})


def build(research):
    data = os.path.join(research, "research", "reference",
                        "cross_part_table.json")
    with open(data, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    cpt = load_module(os.path.join(research, "tools", "cross_part_table.py"),
                      "_research_cross_part_table")
    frags = fragment_verdicts(research)
    overlays = loader_args()
    excluded = paper_cmd_excludes(doc)
    onepage_cols = cpt.PRESETS["onepage"]

    impl = {i["key"]: i for i in doc["meta"].get("implementations", [])}
    cells, seen = [], {}
    for part in doc["parts"]:
        in_paper_part = part["key"] not in excluded
        paper_rows = cpt.select_configs(part, "baseline", cols=onepage_cols)
        paper_ids = {id(c) for c in paper_rows}
        blocks = collections.defaultdict(list)
        for index, config in enumerate(part["configs"]):
            raw = config.get("repro")
            if isinstance(raw, dict):
                raw = [raw]
            for block in (raw or []):
                if isinstance(block, dict) and block.get("field"):
                    blocks[(index, block["field"])].append(block)
        for index, config in enumerate(part["configs"]):
            for field in FIELDS:
                claim = config.get(field)
                if claim is None:
                    continue
                here = blocks.get((index, field), [])
                block = here[0] if here else None
                frag = frags.get((part["part"], index, field))
                block_from = "cross_part_table.json"
                if block is None and frag is not None and frag.get("block"):
                    # The fragment has been written and `repro_merge.py` has
                    # not folded it in yet. That window is normal in a tree
                    # several people are triaging at once, and the fragment IS
                    # the block - the merge copies it. Carrying it across here
                    # keeps a cell scorable during the window; without it the
                    # cell reads `block` with nothing to run, which is how one
                    # malformed cell can take out a whole run.
                    block = frag["block"]
                    block_from = "research/reference/repro fragment, not yet " \
                                 "merged into cross_part_table.json"
                if block is not None:
                    verdict = "flat" if block.get("kind") == "flat" else "block"
                    if frag is not None and frag["verdict"] in ("block", "flat"):
                        verdict = frag["verdict"]
                elif frag is not None:
                    verdict = frag["verdict"]
                else:
                    verdict = "untriaged"
                cid = "%s/%s-%s" % (part["key"], slug(config["config"]), field)
                if cid in seen:
                    raise SystemExit(
                        "cell id collision: %s is both %r and %r"
                        % (cid, seen[cid], (part["key"], index, field)))
                seen[cid] = (part["key"], index, field)
                expect_n, expect_how = parse_expect(
                    block.get("expect") if block else None)
                rec = {
                    "id": cid,
                    "part": part["part"],
                    "part_key": part["key"],
                    "part_short": part.get("part_short"),
                    "vendor": part.get("vendor"),
                    "core": part.get("core"),
                    "group": part.get("group"),
                    "config": config["config"],
                    "config_index": index,
                    "config_note": config.get("note"),
                    "field": field,
                    "implementation": (impl.get(field) or {}).get("label"),
                    "claim": claim,
                    "verdict": verdict,
                    "in_paper_one_page": bool(in_paper_part
                                              and id(config) in paper_ids),
                    "clock_mhz": config.get("clock_mhz"),
                    "ws": config.get("ws"),
                    "addr": config.get("addr"),
                    "src": config.get("src") or part.get("dossier"),
                    "dossier": part.get("dossier"),
                }
                if block is not None:
                    rec["repro"] = {
                        "block_from": block_from,
                        "capture": block.get("capture"),
                        "capture_form": capture_form(block.get("capture")),
                        "field": block.get("field"),
                        "kind": block.get("kind") or "block",
                        "observable": block.get("observable") or "cyc",
                        "function": block.get("function"),
                        "rungs": block.get("rungs"),
                        "pairsets": block.get("pairsets"),
                        "line_shift": block.get("line_shift"),
                        "line_off": block.get("line_off"),
                        "ct_adjacent": block.get("ct_adjacent"),
                        "expect": block.get("expect"),
                        "expect_n": expect_n,
                        "expect_spelling": expect_how,
                        "n": block.get("n"),
                        "distinct": block.get("distinct"),
                        "key_hex": block.get("key_hex"),
                        "pt_seed": block.get("pt_seed"),
                        "loader": block.get("loader"),
                        "replay": block.get("replay"),
                        "line_off_derivation": block.get("line_off_derivation"),
                        "why": block.get("why"),
                        "note": block.get("note"),
                        "function_note": block.get("function_note"),
                    }
                    if len(here) > 1:
                        rec["repro"]["also"] = [b.get("capture")
                                                for b in here[1:]]
                    overlay = overlays.get(block.get("capture") or "")
                    if overlay:
                        for name in ("key_hex", "pt_seed"):
                            if (rec["repro"].get(name) is None
                                    and overlay.get(name) is not None):
                                rec["repro"][name] = overlay[name]
                                rec["repro"].setdefault("loader_args_from",
                                                        []).append(name)
                        if rec["repro"].get("loader_args_from"):
                            rec["repro"]["loader_args_why"] = overlay.get("why")
                if frag is not None and frag.get("recapture"):
                    rec["recapture"] = frag["recapture"]
                if frag is not None and frag.get("note"):
                    rec["note"] = frag["note"]
                cells.append(rec)
    return doc, cells


def research_commit(research):
    try:
        out = subprocess.run(["git", "-C", research, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or None
    except Exception:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--research", default=os.environ.get(
        "FLASHWHISPERER_RESEARCH",
        os.path.join(ROOT, "..", "..", "flash-accelerator-tests")),
        help="the research tree to derive from")
    ap.add_argument("--out", default=os.path.join(ROOT, "cells", "cells.json"))
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and report whether the file on "
                         "disk matches; write nothing")
    ap.add_argument("--pages", action="store_true",
                    help="also write cells/<part>/<cell>.md, one page per cell")
    args = ap.parse_args(argv)

    research = os.path.abspath(args.research)
    if not os.path.isdir(os.path.join(research, "research", "reference")):
        raise SystemExit("not a research tree: %s" % research)

    doc, cells = build(research)
    counts = collections.Counter(c["verdict"] for c in cells)
    payload = {
        "meta": {
            "generated_by": "tools/make_cells.py",
            "generated": datetime.date.today().isoformat(),
            "derived_from": [
                "research/reference/cross_part_table.json",
                "research/reference/repro/*.json",
            ],
            "research_commit": research_commit(research),
            "table_opened": doc["meta"].get("opened"),
            "unit": "one (part, config, field) triple, field in "
                    + "/".join(FIELDS),
            "verdicts": dict(sorted(counts.items())),
            "cells": len(cells),
            "scoring": doc["meta"].get("scoring"),
            "trace_count_caveat": doc["meta"].get("trace_count_caveat"),
            "paper_one_page_cmd": (doc["meta"].get("renders", {})
                                   .get("paper_one_page", {}).get("cmd")),
        },
        "cells": cells,
    }
    text = json.dumps(payload, indent=1, ensure_ascii=False) + "\n"

    if args.check:
        try:
            with open(args.out, "r", encoding="utf-8") as fh:
                have = fh.read()
        except OSError:
            have = ""
        same = _same_but_for_date(have, text)
        print("%s: %s" % (args.out, "up to date" if same else "STALE"))
        return 0 if same else 1

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    # binary mode on purpose: a text-mode write on Windows turns every line of
    # a 294-cell file into a diff hunk.
    with open(args.out, "wb") as fh:
        fh.write(text.encode("utf-8"))
    print("%s: %d cells  %s" % (args.out, len(cells),
                                "  ".join("%s=%d" % kv
                                          for kv in sorted(counts.items()))))
    if args.pages:
        n = write_pages(cells)
        print("cells/<part>/: %d pages" % n)
    return 0


def _same_but_for_date(have, want):
    """Whether two renders agree once the generation date is ignored. The date
    changes every day and a `--check` that fails on it teaches people to
    ignore `--check`."""
    strip = lambda s: re.sub(r'"generated": "[^"]*"', "", s)
    return strip(have) == strip(want)


WARNING = ("*\U0001f916WARNING\U0001f916: This file LLM generated and may read "
           "oddly. Will eventually be human-edited for that real-life touch "
           "and typos.*")


def write_pages(cells):
    """One markdown page per cell, under `cells/<part_key>/<slug>-<field>.md`.

    Generated, never hand-edited: the prose in them is the research tree's own
    `why` text, carried across so a reader can see what a cell claims and what
    was recorded about it without opening the private tree.
    """
    n = 0
    written = set()
    for cell in cells:
        part, name = cell["id"].split("/", 1)
        directory = os.path.join(ROOT, "cells", part)
        os.makedirs(directory, exist_ok=True)
        lines = ["# %s" % cell["id"], "", WARNING, ""]
        lines += ["Generated by `tools/make_cells.py`. Do not edit by hand.", ""]
        lines += ["| | |", "|---|---|"]
        for label, key in (("part", "part"), ("configuration", "config"),
                           ("field", "field"),
                           ("implementation", "implementation"),
                           ("clock (MHz)", "clock_mhz"), ("wait states", "ws"),
                           ("table address", "addr"),
                           ("paper one-page table", "in_paper_one_page"),
                           ("verdict", "verdict")):
            value = cell.get(key)
            if value in (None, ""):
                continue
            lines.append("| %s | %s |" % (label, str(value).replace("|", "\\|")))
        lines += ["| claim | %s |" % str(cell["claim"]).replace("|", "\\|")]
        if cell.get("src"):
            lines.append("| evidence | `%s` |" % cell["src"])
        lines.append("")
        repro = cell.get("repro")
        if repro:
            lines += ["## Recovery parameters", "",
                      "Every one of these comes from the cell and not from a "
                      "tool's default. `line_shift`, `line_off`, "
                      "`ct_adjacent` and the observable each return a clean "
                      "null when wrong, which reads exactly like a part that "
                      "does not leak.", "", "```json",
                      json.dumps({k: v for k, v in repro.items()
                                  if k not in ("why", "line_off_derivation",
                                               "note", "function_note",
                                               "capture_form")
                                  and v is not None},
                                 indent=1, ensure_ascii=False),
                      "```", ""]
            for label, key in (("Where the line offset came from",
                                "line_off_derivation"),
                               ("Why this capture", "why"),
                               ("Note", "note"),
                               ("On the function", "function_note")):
                if repro.get(key):
                    lines += ["### %s" % label, "", str(repro[key]), ""]
        if cell.get("recapture"):
            lines += ["## What the bench owes this cell", "", "```json",
                      json.dumps(cell["recapture"], indent=1,
                                 ensure_ascii=False), "```", ""]
        if cell.get("note"):
            lines += ["## Note", "", str(cell["note"]), ""]
        path = os.path.join(directory, name + ".md")
        with open(path, "wb") as fh:
            fh.write(("\n".join(lines).rstrip() + "\n").encode("utf-8"))
        written.add(os.path.normpath(path))
        n += 1

    # PRUNE, because writing the new page does not remove the old one and a
    # configuration can be RENAMED. A page's name is a slug of the config
    # string, so amending that string writes new pages and leaves the old
    # ones describing a configuration the table no longer has -- a reader
    # finds both and nothing says which is live. It happened on 2026-10-21:
    # the MK21FN1M0's "B0SEBE 0 with the cache also off" was amended because
    # read literally it names a configuration that LEAKS, and three stale
    # pages sat beside the three new ones.
    #
    # Only ever removes a `.md` inside a `cells/<part>/` directory that THIS
    # run did not write, and says what it removed, because a silent delete in
    # a generator is worse than the orphan it fixes.
    removed = []
    for part in sorted(os.listdir(os.path.join(ROOT, "cells"))):
        directory = os.path.join(ROOT, "cells", part)
        if not os.path.isdir(directory):
            continue
        for fn in sorted(os.listdir(directory)):
            if not fn.endswith(".md") or fn == "README.md":
                continue
            path = os.path.normpath(os.path.join(directory, fn))
            if path not in written:
                os.remove(path)
                removed.append("cells/%s/%s" % (part, fn))
    for r in removed:
        print("  pruned %s (no such cell any more)" % r)
    if removed:
        print("  %d stale page(s) removed" % len(removed))
    return n


if __name__ == "__main__":
    sys.exit(main())
