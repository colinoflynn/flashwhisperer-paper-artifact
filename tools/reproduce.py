#!/usr/bin/env python3
"""Stage 3: turn the shipped traces back into the paper's table cells.

    python tools/reproduce.py                      every cell with a block
    python tools/reproduce.py --cell stm32g474/dcen-1-latency-1-sbox
    python tools/reproduce.py --part STM32L475VG
    python tools/reproduce.py --table 3            just the paper's Table 3
    python tools/reproduce.py --json out.json      the rows, machine readable

One row per cell: what the paper claims, what the recovery gave, and whether
those agree. No hardware, no serial port, no toolchain.

EVERY RECOVERY PARAMETER COMES FROM THE CELL. `line_shift`, `line_off`,
`ct_adjacent`, the rungs, the pair sets and the observable are read out of
`cells/cells.json` and this file has no defaults to fall back on. That is not
tidiness: each of those silently returns a clean null when wrong, and a clean
null is indistinguishable from a part that does not leak. A run that guessed
one would report the part safe.

Three details that are easy to get wrong and expensive to notice:

* `ct_adjacent` is spelled `"both"` on 85 cells, meaning both adjacencies were
  swept when the cell was triaged. `archive.ladder` takes a BOOLEAN and every
  non-empty string is truthy, so handing `"both"` straight through scores
  ciphertext adjacency alone - which on a byte-S-box final round is a clean
  0/16. Both are run here and the row says which won.
* `expect` is spelled three ways: an int, a string like `"6 250"`, and prose
  like `"0/16 at 275 000"`. The first two are compared; prose is reported as
  NOT SCORED rather than having an integer dug out of it, because the prose
  carries a claim ("nothing at 275 000") that the integer would invert.
* The shipped captures have no ciphertext column. It was replaced by a
  SHA-256, and the column is recomputed here from the plaintexts and the key
  before anything is scored. The hash is checked first, and what a match does
  and does not prove is in the README under `ct_provenance`.

CONTROLS SCORE NOTHING, THROUGH THE IDENTICAL CALL. A control cell is one
whose configuration is the RAM-table twin, or whose own note says `control`.
It goes through the same `archive.ladder` with the same parameters as the row
beside it, and it is a failure of this whole run if one recovers a key. That is
what makes the other rows quotable, so the rows are marked and counted and the
exit status reflects them.

WHAT THIS DOES NOT DO:

* It does not score a `recapture` or `drop` cell. Those have no block: the data
  on disk cannot support the claim, or the cell should not be in the table.
  `--show-gaps` lists them with the reason, which is the honest version of a
  row that would otherwise read as a failure.
* It does not re-derive a geometry. If the cell's geometry does not recover,
  that is the answer; `flashattack.archive.screen` is the tool for asking which
  geometry does, and the research tree's `repro_triage.py screen` drives it.
* It does not measure anything. Everything that scores is
  `deps/flashwhisperer`, at the commit this repository pins.
* A `flat` cell has no recovery to replay, so it is checked a different way:
  the observable's distinct count is recounted and compared to the claim. Where
  the capture is summary-only - several campaigns recorded aggregates per cell
  and no per-trace data - there is nothing to recount and the row says so
  rather than agreeing with itself.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEPS = os.path.join(ROOT, "deps", "flashwhisperer")

# the toolkit is not importable from its own repository root either; the five
# packages sit one level down, which is what the pin buys.
for candidate in (DEPS, os.path.join(DEPS, "flashwhisperer")):
    if os.path.isdir(os.path.join(candidate, "flashattack")):
        sys.path.insert(0, candidate)
        break
else:
    raise SystemExit(
        "deps/flashwhisperer has no flashattack package. Run\n"
        "    git submodule update --init\n"
        "and see deps/README.md. Nothing that scores is vendored here.")

import numpy as np                                            # noqa: E402

from flashattack import archive                               # noqa: E402
from flashattack.transport import gen_pts                     # noqa: E402
from flashsim import aes as refaes                            # noqa: E402

TRACES = os.path.join(ROOT, "traces")
CELLS = os.path.join(ROOT, "cells", "cells.json")

#: the configurations that are a control rather than a measurement. Two tests,
#: both read off the cell: the triage's own `control` note, and a configuration
#: whose tables were moved to RAM by the linker, which is the mandatory twin -
#: same code, same instruction stream, same indices, no flash read on the table.
CONTROL_NOTE = re.compile(r"^control\b", re.I)
CONTROL_CONFIG = re.compile(r"\b(?:in|to)\s+(?:axi\s+)?s?ram\b|ram\s+twin",
                            re.I)


def sha256_array(a):
    return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()


#: a table cell that opens with a plain trace count. `16/16 @ 100 000` and
#: `0/8 @ 400 000` deliberately do not match: those open with a byte count, and
#: reading 16 out of the first as a trace count would score the strongest cell
#: in the table as the cheapest.
CLAIM_COUNT = re.compile(r"^([0-9][0-9  ]*)(?![0-9/])")


def claim_count(claim):
    """The trace count the table's own cell text prints, where it prints one.

    This is a SECOND comparison and not the same as the block's `expect`. The
    table quotes the cheapest known break and several cells are one rung
    conservative on purpose - the L152RE's 20 000 against a scorer of record
    that gets all sixteen bytes at 10 000, for instance - so a row can
    reproduce its block exactly and still be cheaper than the number in print.
    Both are reported; neither is silently preferred.
    """
    text = str(claim or "").strip()
    if re.match(r"^\d+\s*/\s*\d+", text):
        return None
    m = CLAIM_COUNT.match(text)
    if not m:
        return None
    digits = re.sub(r"[^0-9]", "", m.group(1))
    return int(digits) if digits else None


def thousands(n):
    return "{:,}".format(int(n)).replace(",", " ")


def is_control(cell):
    return bool(CONTROL_NOTE.match(cell.get("config_note") or "")
                or CONTROL_CONFIG.search(cell.get("config") or ""))


class Loader:
    """Resolves a cell's capture into an `archive.Archived`.

    Three paths, because the shipped tree has three kinds of file in it:

    `reduced`    written by the research tree's `artifact_reduce.py`: `cyc`,
                 `key`, and either `pt` or a `pt_seed` the plaintexts
                 regenerate from. No ciphertext column - it is recomputed here
                 and checked against `REDUCTION.json`'s hash before use.
    `verbatim`   copied across unchanged, because the reducer could not reduce
                 it: a matrix capture whose timing lives in named per-cell
                 arrays, or a `.json` capture. `archive.load` reads these.
    `concat`     one cell names eight files summed with `ladder.py --concat`.
                 They are loaded individually and the arrays joined, in the
                 order the block writes them, because a ladder's rungs are
                 cumulative prefixes and the order is part of the claim.
    """

    def __init__(self):
        with open(os.path.join(TRACES, "REDUCTION.json"),
                  encoding="utf-8") as fh:
            self.reduced = {r["path"]: r for r in json.load(fh)["rows"]}
        path = os.path.join(TRACES, "PASSTHROUGH.json")
        self.verbatim = {}
        self._project_key = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self.verbatim = json.load(fh)["files"]

    def local(self, capture):
        return os.path.join(TRACES, capture.replace("/", os.sep))

    def provenance(self, capture):
        row = self.reduced.get(capture) or self.verbatim.get(capture)
        return (row or {}).get("ct_provenance", "unknown")

    def load(self, cell):
        repro = cell["repro"]
        form = repro["capture_form"]
        observable = repro.get("observable") or "cyc"
        key = (bytes.fromhex(repro["key_hex"]) if repro.get("key_hex")
               else None)
        seed = repro.get("pt_seed")
        if form["kind"] == "prose":
            raise Unscorable("the block's `capture` is prose, not a path: %r"
                             % form.get("text"))
        if not form["paths"]:
            raise Unscorable("the block names no capture file")
        caps = [self.one(p, observable, key, seed) for p in form["paths"]]
        if len(caps) == 1:
            return caps[0]
        return self.join(caps, form)

    def one(self, capture, observable, key, seed):
        path = self.local(capture)
        if not os.path.exists(path):
            raise Unscorable("not in traces/: %s  (see traces/MANIFEST.tsv)"
                             % capture)
        if capture in self.reduced:
            return self.reduced_capture(capture, path, observable, key)
        if path.lower().endswith(".json"):
            return self.json_capture(path, observable, key)
        return self.npz_capture(path, observable, key, seed)

    def npz_capture(self, path, observable, key_arg, seed_arg):
        """A verbatim capture, through `archive.load` where that can read it.

        `archive.load` at the pinned commit takes `(path, observable)` only and
        REQUIRES a ciphertext column, which three of the capture classes here
        do not have: a seed-only capture (the ADuCM3029, the L152RE), one whose
        key or seed is a constant in the capture script rather than a field
        (the G474's byte-S-box files), and a capture whose plaintexts are
        stored but whose ciphertexts never were. Where the pin can read the
        file it reads it; where it cannot, the columns are resolved here
        against `archive.ALIASES` and the missing ones are regenerated with
        `flashattack.transport.gen_pts` and `flashsim.aes`. Nothing that SCORES
        is reimplemented - `archive.ladder` does that either way - and this
        collapses to one `archive.load` call the day the loader is published.
        """
        try:
            return archive.load(path, observable=observable)
        except (KeyError, ValueError):
            pass
        with np.load(path, allow_pickle=True) as z:
            have = list(z.keys())

            def pick(which):
                for name in archive.ALIASES[which]:
                    if name in have:
                        return np.asarray(z[name])
                return None

            if observable != "cyc":
                if observable not in have:
                    raise Unscorable("carries no %r; it has %s"
                                     % (observable, have))
                cyc = np.asarray(z[observable])
            else:
                cyc = pick("cyc")
            if cyc is None:
                raise Unscorable("no timing column; it has %s" % have)
            cyc = np.asarray(cyc, dtype=np.float64).reshape(-1)
            ct, pt = pick("ct"), pick("pt")
            seed = (int(np.asarray(z["seed"]).reshape(-1)[0])
                    if "seed" in have else seed_arg)
            key = (np.asarray(z["key"]).reshape(-1)[:16] if "key" in have
                   else (np.frombuffer(key_arg, np.uint8) if key_arg
                         else None))
            extra = {k: np.asarray(z[k]) for k in have
                     if k not in sum(archive.ALIASES.values(), ())
                     and k != observable}
        if key is None:
            raise Unscorable("no key in the file and the cell gives no "
                             "key_hex; a recovery scored against nothing "
                             "returns a clean null")
        n = int(cyc.shape[0])
        if pt is None:
            if seed is None:
                raise Unscorable("neither plaintexts nor a seed")
            pt = np.asarray(gen_pts(int(seed), n), np.uint8).reshape(n, 16)
            extra["pt_form"] = "regenerated from the capture's seed"
        else:
            pt = np.asarray(pt, np.uint8).reshape(-1, 16)[:n]
            extra["pt_form"] = "stored"
        if ct is None:
            ct = np.asarray(refaes.encrypt_trace(
                pt, refaes.key_expansion(bytes(key.tolist())))[0],
                np.uint8).reshape(n, 16)
            extra["ct_provenance"] = "synthesised from (plaintexts, key)"
        else:
            ct = np.asarray(ct, np.uint8).reshape(-1, 16)[:n]
        return archive.Archived(path, ct, pt, cyc, key, extra, tuple())

    def json_capture(self, path, observable, key_arg):
        """A `.json` capture, which is the MPC5606B campaign and two matrix
        files. The schema is in the cell's own `loader` block; three of its
        traps are handled here because each produces a plausible wrong answer:

        `config['pfcr0']` is the value the host REQUESTED and reads 0 on every
        reset-configuration capture, so the live readback in the header line is
        what gets reported. Two files hold `n = 0` - failed first attempts -
        and an empty trace list has one distinct value, which a careless reader
        records as a bit-exactly constant cell. And the file carries no key, so
        the one used is checked against the device's own self-test ciphertext
        for the all-zero block before anything is scored: a wrong key returns a
        clean 0/16 and not an error.
        """
        if observable != "cyc":
            raise Unscorable("a JSON capture carries only a tick count; it "
                             "has no %r" % observable)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        cyc = np.asarray(doc.get("traces") or [], dtype=np.float64)
        if cyc.size == 0:
            raise Unscorable("holds n=0 traces - a failed collection, not a "
                             "constant cell; do not read its single distinct "
                             "value as flat")
        cfg = doc.get("config") or {}
        header = " ".join(doc.get("header") or [])
        extra = {"label": doc.get("label"), "stats": doc.get("stats"),
                 "impl": cfg.get("impl"), "ram": cfg.get("ram"),
                 "pfcr0_requested": cfg.get("pfcr0")}
        for name in ("sbox", "pfcr0", "impl", "ram", "n", "seed", "clk_hz"):
            m = re.search(r"\b%s=((?:0x)?[0-9a-fA-F]+)\b" % name, header)
            if m:
                text = m.group(1)
                extra["readback_" + name] = (int(text, 16)
                                             if text.startswith("0x")
                                             else int(text, 10))
        key = bytes(key_arg) if key_arg else self.project_key()
        want = re.search(r"selftest\s+ok\s+ct=([0-9a-fA-F]{32})", header)
        if want:
            got = np.asarray(refaes.encrypt_trace(
                np.zeros((1, 16), np.uint8), refaes.key_expansion(key))[0],
                np.uint8).reshape(-1)[:16].tobytes().hex()
            if got != want.group(1).lower():
                raise Unscorable(
                    "the key does not match the device's own self-test vector "
                    "(the header says ct=%s for the all-zero block); scoring "
                    "against the wrong key returns a clean null"
                    % want.group(1))
            extra["selftest_checked"] = True
        n = int(cyc.size)
        seed = int(cfg.get("seed", extra.get("readback_seed", 0)))
        pt = np.asarray(gen_pts(seed, n), np.uint8).reshape(n, 16)
        ct = np.asarray(refaes.encrypt_trace(
            pt, refaes.key_expansion(key))[0], np.uint8).reshape(n, 16)
        extra["pt_seed"] = seed
        extra["ct_provenance"] = "host (the device's self-test vector checked)"
        return archive.Archived(path, ct, pt, cyc,
                                np.frombuffer(key, np.uint8), extra, tuple())

    def project_key(self):
        """The key the cells that name one all name.

        Read out of `cells/cells.json` rather than written here, so there is
        one place it lives; the JSON captures carry no key field and the
        self-test check above is what makes using it safe.
        """
        if self._project_key is None:
            with open(CELLS, encoding="utf-8") as fh:
                keys = {c["repro"]["key_hex"] for c in json.load(fh)["cells"]
                        if (c.get("repro") or {}).get("key_hex")}
            if len(keys) != 1:
                raise Unscorable("the cells name %d different keys; a JSON "
                                 "capture carries none and there is no one "
                                 "key to check" % len(keys))
            self._project_key = bytes.fromhex(keys.pop())
        return self._project_key

    def reduced_capture(self, capture, path, observable, key_arg):
        """Rebuild a reduced capture, ciphertext column and all.

        The order here is the order the checks are worth anything in: the
        plaintexts are regenerated and hashed BEFORE the ciphertexts are
        computed from them, so a bad seed is reported as a bad seed rather than
        as a ciphertext mismatch twenty seconds later.
        """
        row = self.reduced[capture]
        with np.load(path, allow_pickle=False) as z:
            have = list(z.keys())
            if observable != "cyc" and observable not in have:
                raise Unscorable("the reduced %s carries no %r; it has %s"
                                 % (os.path.basename(capture), observable,
                                    have))
            cyc = np.asarray(z[observable if observable != "cyc" else "cyc"],
                             dtype=np.float64)
            n = int(np.asarray(z["n"])) if "n" in have else int(cyc.shape[0])
            key = (np.asarray(z["key"]).reshape(-1)[:16] if "key" in have
                   else (np.frombuffer(key_arg, np.uint8) if key_arg else None))
            if key is None:
                raise Unscorable("no key in the reduced file and the cell "
                                 "gives no key_hex; a recovery cannot be "
                                 "scored against nothing")
            if "pt" in have:
                pt = np.asarray(z["pt"], np.uint8).reshape(n, 16)
                pt_form = "stored"
            elif "pt_seed" in have:
                pt = np.asarray(gen_pts(int(np.asarray(z["pt_seed"])), n),
                                np.uint8).reshape(n, 16)
                pt_form = "regenerated from seed"
            else:
                raise Unscorable("the reduced file has neither plaintexts nor "
                                 "a seed")
        if row.get("pt_sha256") and sha256_array(pt) != row["pt_sha256"]:
            raise Unscorable("the plaintexts do not match REDUCTION.json's "
                             "hash; this file is not what was reduced")
        ct = np.asarray(refaes.encrypt_trace(
            pt, refaes.key_expansion(bytes(key.tolist())))[0],
            np.uint8).reshape(n, 16)
        ct_checked = None
        if row.get("ct_sha256"):
            ct_checked = sha256_array(ct) == row["ct_sha256"]
            if not ct_checked:
                raise Unscorable("the recomputed ciphertext column does not "
                                 "match the hash the reduction recorded")
        extra = {
            "ct_provenance": row.get("ct_provenance", "unknown"),
            "ct_source": "recomputed as AES_k(pt) at replay time",
            "ct_hash_checked": ct_checked,
            "pt_form": pt_form,
        }
        return archive.Archived(path, ct, pt, cyc, key, extra, tuple(have))

    def join(self, caps, form):
        ct = np.concatenate([c.ct for c in caps], axis=0)
        pt = (np.concatenate([c.pt for c in caps], axis=0)
              if all(c.pt is not None for c in caps) else None)
        cyc = np.concatenate([c.cyc for c in caps], axis=0)
        keys = {bytes(np.asarray(c.key).reshape(-1)[:16].tolist())
                for c in caps if c.key is not None}
        if len(keys) != 1:
            raise Unscorable("the concatenated captures do not share one key; "
                             "summing them would score against the wrong one")
        extra = dict(caps[0].extra)
        extra["concat_of"] = form["paths"]
        extra["concat_text"] = form.get("text")
        return archive.Archived("+".join(form["paths"]), ct, pt, cyc,
                                np.frombuffer(keys.pop(), np.uint8), extra,
                                caps[0].raw_keys)


class Unscorable(Exception):
    """This cell cannot be scored from what is here, and why. Distinct from a
    cell that was scored and did not reproduce, which is a result."""


def first_full(rungs):
    """The cheapest rung at which all sixteen bytes land. That is what a trace
    count in the table means: the table quotes the cheapest known break."""
    for row in rungs:
        if row.get("bytes") == 16 and row.get("positions") == 16:
            return int(row["n"])
    return None


def best(rungs):
    out = (None, -1)
    for row in rungs:
        if row.get("bytes") is not None and row["bytes"] > out[1]:
            out = (int(row["n"]), int(row["bytes"]))
    return out


def run_ladder(cap, repro):
    """`archive.ladder` at the cell's geometry, both adjacencies where the cell
    says `both`. Returns `(rungs, adjacency_used, all_results)`."""
    adjacency = repro.get("ct_adjacent")
    if isinstance(adjacency, str) and adjacency.strip().lower() == "both":
        wanted = [False, True]
    elif isinstance(adjacency, str):
        raise Unscorable("ct_adjacent is the string %r and archive.ladder "
                         "takes a boolean; every non-empty string is truthy, "
                         "so passing it through would score one adjacency and "
                         "call it both" % adjacency)
    else:
        wanted = [bool(adjacency)]
    results = {}
    for adj in wanted:
        results[adj] = archive.ladder(
            cap, repro["rungs"], tuple(repro["pairsets"]),
            line_shift=repro["line_shift"], line_off=repro["line_off"],
            ct_adjacent=adj, verify=True)
    if len(results) == 1:
        adj = wanted[0]
        return results[adj], adj, results

    def rank(adj):
        full = first_full(results[adj])
        return (0 if full is None else 1, -(full or 0), best(results[adj])[1])

    won = max(results, key=rank)
    return results[won], won, results


def score_block(cell, cap, repro):
    rungs, adjacency, every = run_ladder(cap, repro)
    full = first_full(rungs)
    at, bytes_ = best(rungs)
    verified = any(r.get("verified") for r in rungs)
    got = ("%s, 16/16 verified" % thousands(full) if full and verified
           else "%s, 16/16" % thousands(full) if full
           else "nothing: best %d/16 at %s" % (bytes_, thousands(at))
           if at is not None else "nothing scored")
    want = repro.get("expect_n")
    spelling = repro.get("expect_spelling")
    if spelling == "prose":
        agree = "not scored"
    elif want is None:
        agree = "agrees" if full is None else "DISAGREES"
    elif full is None:
        agree = "DISAGREES"
    else:
        agree = "agrees" if full == want else "DISAGREES"
    return {
        "got": got,
        "agree": agree,
        "vs_paper": vs_paper(cell["claim"], full),
        "recovered_at": full,
        "best_bytes": bytes_,
        "best_at": at,
        "verified": bool(verified),
        "adjacency_used": adjacency,
        "adjacency_swept": len(every) > 1,
        "adjacency_detail": {str(k): first_full(v) for k, v in every.items()},
        "n_available": len(cap),
        "distinct": cap.distinct,
        "sd": round(cap.sd, 4),
        "rungs": [{"n": r["n"], "bytes": r.get("bytes"),
                   "skipped": r.get("skipped")} for r in rungs],
    }


def vs_paper(claim, recovered_at):
    """How the recovery stands against the TABLE'S OWN printed cell.

    Five answers, and the middle one is the interesting one. `cheaper` means
    the recovery got all sixteen bytes at fewer traces than the table prints,
    which is not a disagreement about whether the part leaks - it is the table
    being conservative, which several cells are on purpose - but it is a number
    in print that the artifact does not land on, and it is counted as its own
    thing rather than folded into either pile.
    """
    want = claim_count(claim)
    if want is None:
        return "prose"
    if recovered_at is None:
        return "NOTHING WHERE THE TABLE PRINTS A COUNT"
    if recovered_at == want:
        return "same"
    return "cheaper" if recovered_at < want else "DEARER"


def score_flat(cell, loader, repro):
    """A flat cell's artifact is the capture plus its distinct count.

    No recovery: the claim is that the observable takes one value, so the check
    is to recount it. A summary-only capture has no per-trace column to
    recount, and that is reported rather than passed.
    """
    form = repro["capture_form"]
    if form["kind"] != "path":
        raise Unscorable("a flat cell whose capture is not a path")
    path = loader.local(form["paths"][0])
    if not os.path.exists(path):
        raise Unscorable("not in traces/: %s" % form["paths"][0])
    observable = repro.get("observable") or "cyc"
    if path.lower().endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        traces = doc.get("traces") if isinstance(doc, dict) else None
        if not traces:
            raise Unscorable("summary-only JSON capture: it holds aggregates "
                             "per cell and no per-trace column, so the "
                             "block's own distinct count is the claim and "
                             "there is nothing here to recount")
        col = np.asarray(traces)
        name = "traces"
        return _flat_row(col, name, repro)
    with np.load(path, allow_pickle=True) as z:
        have = list(z.keys())
        name = observable if observable in have else None
        if name is None:
            for alias in ("cyc", "cyc_cycles", "cycles", "timing"):
                if alias in have:
                    name = alias
                    break
        if name is None:
            raise Unscorable("no per-trace column named %r; the file holds "
                             "aggregates only" % observable)
        col = np.asarray(z[name]).reshape(-1)
    return _flat_row(col, name, repro)


def _flat_row(col, name, repro):
    """The distinct count, and whether it is the one the cell claims.

    `n` goes with `distinct` and is checked alongside it: one distinct cycle
    count in 2 000 traces is a much weaker claim than one in 400 000, and the
    table quotes the latter in several places.
    """
    col = np.asarray(col).reshape(-1)
    if col.dtype.kind not in "iuf":
        raise Unscorable("%r is not a numeric per-trace column" % name)
    distinct = int(np.unique(col).size)
    want_d, want_n = repro.get("distinct"), repro.get("n")
    got = "%d distinct in %s" % (distinct,
                                 "{:,}".format(col.size).replace(",", " "))
    if want_d is None:
        agree = "not scored"
    elif distinct != want_d:
        agree = "DISAGREES"
    elif want_n is not None and int(col.size) < int(want_n):
        agree = "DISAGREES"
    else:
        agree = "agrees"
    return {"got": got, "agree": agree, "distinct": distinct,
            "n_available": int(col.size), "observable": name,
            "sd": round(float(np.std(col)), 4)}


def score_one(cell):
    """One cell, start to finish. Top level and taking only the cell, so it can
    be handed to a worker process: `--jobs` is worth having here because a full
    run is a ladder per cell and a ladder is six pair sets at every rung, which
    on the large captures is minutes rather than seconds."""
    loader = _worker_loader()
    repro = cell["repro"]
    control = is_control(cell)
    row = {"id": cell["id"], "part": cell["part"], "field": cell["field"],
           "config": cell["config"], "verdict": cell["verdict"],
           "claim": cell["claim"], "expect": repro.get("expect"),
           "control": control, "in_paper_one_page": cell["in_paper_one_page"],
           "capture": repro.get("capture"),
           "ct_provenance": loader.provenance(repro.get("capture") or ""),
           "src": cell.get("src")}
    t0 = time.time()
    try:
        if cell["verdict"] == "flat":
            row.update(score_flat(cell, loader, repro))
        else:
            row.update(score_block(cell, loader.load(cell), repro))
    except Unscorable as exc:
        row.update({"got": "unscorable: %s" % exc, "agree": "not scored",
                    "unscorable": str(exc)})
    except Exception as exc:                              # noqa: BLE001
        row.update({"got": "%s: %s" % (type(exc).__name__, exc),
                    "agree": "ERROR", "error": str(exc)})
    row["seconds"] = round(time.time() - t0, 2)
    row["claim_count"] = claim_count(cell["claim"])
    row.setdefault("vs_paper", "n/a (flat cell)"
                   if cell["verdict"] == "flat" else "not scored")
    if control and row.get("recovered_at"):
        row["agree"] = "CONTROL LEAKED"
    return row


_LOADER = None


def _worker_loader():
    global _LOADER
    if _LOADER is None:
        _LOADER = Loader()
    return _LOADER


def print_row(cell, row):
    in_print = (thousands(row["claim_count"]) if row["claim_count"]
                else str(cell["claim"])[:9])
    repro = cell["repro"]
    want = repro.get("expect_n")
    if cell["verdict"] == "flat":
        expect = "%d dist" % (repro.get("distinct") or 0)
    elif want is not None:
        expect = thousands(want)
    elif repro.get("expect_spelling") == "null":
        expect = "nothing"
    else:
        expect = "prose"
    print("%-58s %-5s %-9s %-8s %-28s %-11s %s%s"
          % (cell["id"][:58], cell["verdict"][:5], in_print[:9], expect[:8],
             str(row["got"])[:28], row["agree"][:11], row["vs_paper"],
             "   [control, scores nothing]" if row["control"] else ""))
    sys.stdout.flush()


def pick(cells, args):
    out = []
    for cell in cells:
        if args.cell and cell["id"] != args.cell:
            continue
        if args.part and args.part.lower() not in (
                cell["part"].lower(), (cell["part_key"] or "").lower(),
                (cell["part_short"] or "").lower()):
            continue
        if args.table == 3 and not cell["in_paper_one_page"]:
            continue
        if args.field and cell["field"] != args.field:
            continue
        out.append(cell)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cell", help="one cell id, as cells/cells.json spells it")
    ap.add_argument("--part", help="part number, key or short name")
    ap.add_argument("--field", choices=("sbox", "ttable1", "ttable"))
    ap.add_argument("--table", type=int, choices=(3,),
                    help="only the cells the paper's one-page table renders")
    ap.add_argument("--json", help="write the rows here as well")
    ap.add_argument("--show-gaps", action="store_true",
                    help="also list the cells with no block, and why")
    ap.add_argument("--jobs", "-j", type=int, default=1,
                    help="score this many cells at once, in separate "
                         "processes. The rows still print in cell order, so "
                         "two runs of one selection give the same output")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    with open(CELLS, encoding="utf-8") as fh:
        doc = json.load(fh)
    chosen = pick(doc["cells"], args)
    if not chosen:
        raise SystemExit("no cell matched")
    scorable = [c for c in chosen if c["verdict"] in ("block", "flat")]
    gaps = [c for c in chosen if c["verdict"] not in ("block", "flat")]

    rows, started = [], time.time()
    print("%-58s %-5s %-9s %-8s %-28s %-11s %s"
          % ("cell", "kind", "in print", "expect", "the recovery gives",
             "vs block", "vs the table"))
    print("-" * 136)
    ordered = sorted(scorable, key=lambda c: c["id"])
    if args.jobs > 1 and len(ordered) > 1:
        import concurrent.futures
        # one BLAS thread per worker: the recovery is index arithmetic rather
        # than linear algebra, so numpy's own threads buy nothing here and
        # oversubscribing 32 cores with 32 processes each spawning 32 threads
        # is slower than running it serially.
        for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                     "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
            os.environ.setdefault(name, "1")
        done = {}
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=args.jobs) as pool:
            futures = {pool.submit(score_one, c): c for c in ordered}
            for future in concurrent.futures.as_completed(futures):
                done[futures[future]["id"]] = future.result()
                # progress on stderr, because the rows themselves wait for the
                # whole selection so they can print in cell order, and a run
                # that prints nothing for twenty minutes looks hung
                sys.stderr.write("\r%d/%d scored, %.0f s elapsed   "
                                 % (len(done), len(ordered),
                                    time.time() - started))
                sys.stderr.flush()
            sys.stderr.write("\n")
        # printed in cell order rather than completion order, so two runs of
        # the same selection produce the same output
        rows = [done[c["id"]] for c in ordered]
        if not args.quiet:
            for cell, row in zip(ordered, rows):
                print_row(cell, row)
    else:
        for cell in ordered:
            row = score_one(cell)
            rows.append(row)
            if not args.quiet:
                print_row(cell, row)

    tally, paper = {}, {}
    for row in rows:
        tally[row["agree"]] = tally.get(row["agree"], 0) + 1
        paper[row["vs_paper"]] = paper.get(row["vs_paper"], 0) + 1
    controls = [r for r in rows if r["control"]]
    print("-" * 136)
    print("%d cells scored in %.0f s"
          % (len(rows), time.time() - started))
    print("against the cell's own recorded expectation:  %s"
          % "  ".join("%s=%d" % kv for kv in sorted(tally.items())))
    print("against the number the table prints:          %s"
          % "  ".join("%s=%d" % kv for kv in sorted(paper.items())))
    print("%d of them are controls, run through the identical call; %d "
          "recovered a key (any number above zero invalidates the run)"
          % (len(controls),
             sum(1 for r in controls if r.get("recovered_at"))))
    if gaps:
        print("%d cell(s) in this selection have no block: %s"
              % (len(gaps), "  ".join("%s=%d" % (v, sum(
                  1 for c in gaps if c["verdict"] == v))
                  for v in sorted({c["verdict"] for c in gaps}))))
        if args.show_gaps:
            for cell in sorted(gaps, key=lambda c: c["id"]):
                reason = ((cell.get("recapture") or {}).get("reason")
                          or cell.get("note") or "")
                print("   %-58s %-9s %s"
                      % (cell["id"][:58], cell["verdict"],
                         re.sub(r"\s+", " ", reason)[:60]))

    if args.json:
        payload = {"meta": {"run": datetime.datetime.now().isoformat(
            timespec="seconds"), "selection": vars(args),
            "cells_json": doc["meta"], "tally": tally},
            "rows": rows}
        with open(args.json, "wb") as fh:
            fh.write((json.dumps(payload, indent=1, ensure_ascii=False)
                      + "\n").encode("utf-8"))
        print("wrote %s" % args.json)
    leaked = sum(1 for r in controls if r.get("recovered_at"))
    return 1 if (leaked or tally.get("ERROR")) else 0


if __name__ == "__main__":
    sys.exit(main())
