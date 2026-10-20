#!/usr/bin/env python3
"""Stage 1: build the image a cell was measured on, through crypto-eval.

    python tools/build.py --cell stm32g474/art-off-dcen-0-latency-0-ttable1
    python tools/build.py --cell ... --lib mbedtls
    python tools/build.py --list                    what can be built here

The build itself is `deps/crypto-eval/tools/build.sh`, which is the submodule's
own make wrapper. Nothing is compiled by this file: it works out
`(MCU, LIB, LAYOUT, RAMTAB, ...)` from the cell, calls that, hashes what came
out, and writes a row in `images/IMAGES.tsv` with the toolchain version that
produced it.

WHY THE HASH IS THE POINT. `IMAGES.tsv` holds the hash of the image the paper
used beside the hash of the image you just built. Equal means you rebuilt the
measurement. Different is NOT a failure - a different GCC emits a different
instruction stream, and the instruction stream is part of what is being
measured - but you get told, instead of finding out through a trace count that
does not match and spending a day on the capture.

HOW THIS REFUSES, WHICH IS MOST OF WHAT IT DOES.

* No `arm-none-eabi-gcc` on PATH: refused, naming the toolchain.
* A part crypto-eval has not got a `mcufw/<part>/` directory for: refused,
  listing what it does have. Most of the roster is in that position today and
  pretending otherwise would produce an image for the wrong part.
* A cell whose library is not one crypto-eval builds: refused.
* A tier-3 part, whose toolchain is a registered download and can never be in
  CI: refused with the installer named, and the archived binary under `images/`
  pointed at, so stages 2 and 3 are still open to a reader with the board.

WHAT THIS DOES NOT DO:

* It does not flash anything and it does not touch a board. That is
  `tools/record.py`.
* It does not choose the accelerator word. The cell's configuration string
  names a register value and `record.py` writes it at capture time, after
  reading it back off the device; a build-time guess at it would be a
  configuration nobody checked.
* IT HAS NOT BEEN RUN. There is no toolchain on the machine this was written
  on and no row in `images/IMAGES.tsv` was produced by it. The refusals were
  exercised; the build path was not.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EVAL = os.path.join(ROOT, "deps", "crypto-eval")
IMAGES = os.path.join(ROOT, "images")
CELLS = os.path.join(ROOT, "cells", "cells.json")

#: a cell's result field -> crypto-eval's `LAYOUT` for the refsbox provider.
#: Written out rather than derived, because the names differ on purpose: the
#: table's `ttable1` is the ONE rotated table (1.25 KB with its byte S-box
#: final round) and crypto-eval calls that `compact`, while the table's
#: `ttable` is the four-word-table build. Getting these two the wrong way round
#: builds a different cipher with a different flash footprint and measures it
#: under the other one's name.
LAYOUT = {"sbox": "sbox", "ttable1": "compact", "ttable": "ttable"}

#: tier 3 - a toolchain you have to register for, so CI can never build it and
#: the artifact ships the binary. part key -> what you would have to install.
TIER3 = {
    "mpc5606b": "NXP CodeWarrior for MPC55xx/56xx (`mwcceppc`), Windows only",
    "tc234lp": "Infineon AURIX Studio (`tricore-gcc11`)",
    "c2000_f28004x": "TI C2000 CGT (`cl2000`), and the part needs its own "
                     "aes_c28.c because a C28x byte is 16 bits",
    "pic32mz2048efh144": "Microchip XC32",
    "msp430f5529": "TI MSP430 CGT",
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cells():
    with open(CELLS, encoding="utf-8") as fh:
        return json.load(fh)["cells"]


def ported():
    """The parts crypto-eval can build, read off the submodule rather than
    listed here: `mcufw/*/board.mk` is what `build.mk` itself globs."""
    base = os.path.join(EVAL, "mcufw")
    if not os.path.isdir(base):
        return []
    return sorted(name for name in os.listdir(base)
                  if os.path.isfile(os.path.join(base, name, "board.mk")))


def mcu_for(cell):
    """crypto-eval's directory name for a cell's part.

    Matched on the part number with the punctuation and the board parenthetical
    taken out, which is how the six landed directories are named
    (`stm32l152re` for STM32L152RE). A part that does not match is refused and
    not guessed at: an image built for the neighbouring part flashes, boots and
    measures something else.
    """
    want = "".join(ch for ch in cell["part"].split("(")[0].lower()
                   if ch.isalnum())
    for name in ported():
        if name == want:
            return name
    return None


def toolchain_version(cc="arm-none-eabi-gcc"):
    if not shutil.which(cc):
        return None
    out = subprocess.run([cc, "--version"], capture_output=True, text=True)
    return (out.stdout or "").splitlines()[0].strip() or None


def images_rows():
    path = os.path.join(IMAGES, "IMAGES.tsv")
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                rows.append(line.rstrip("\n").split("\t"))
    return rows


HEADER = [
    "# One row per archived or rebuilt image.",
    "# Written by tools/build.py; tools/record.py refuses an image that is",
    "# not listed here.",
    "#",
    "# An image whose sha256 differs from the paper_sha256 of the same cell is",
    "# not a failure. A different compiler emits a different instruction",
    "# stream and the instruction stream is part of what is measured - but it",
    "# is a different image, so the trace count it needs may differ, and this",
    "# file is where that is visible rather than being a surprise in stage 3.",
    "#",
    "# cell\tpath\tsha256\tpaper_sha256\tbuild\ttoolchain\twhen",
]


def record_image(cell_id, path, digest, build_cmd, toolchain):
    rows = [r for r in images_rows() if not (r and r[0] == cell_id
                                             and r[1] == path)]
    paper = ""
    for row in images_rows():
        if row and row[0] == cell_id and len(row) > 3 and row[3]:
            paper = row[3]
            break
    rows.append([cell_id, path, digest, paper, build_cmd, toolchain or "",
                 datetime.date.today().isoformat()])
    os.makedirs(IMAGES, exist_ok=True)
    with open(os.path.join(IMAGES, "IMAGES.tsv"), "wb") as fh:
        text = "\n".join(HEADER + ["\t".join(r) for r in sorted(rows)]) + "\n"
        fh.write(text.encode("utf-8"))
    if paper and paper != digest:
        print("NOTE: this is not the image the paper used.\n"
              "  built %s\n  paper %s\n"
              "Read the header of images/IMAGES.tsv before comparing a trace "
              "count against the table." % (digest, paper))
    elif paper:
        print("the image matches the one the paper used, byte for byte")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cell", help="cell id, as cells/cells.json spells it")
    ap.add_argument("--lib", default="refsbox",
                    help="crypto-eval library: refsbox, mbedtls, wolfssl, "
                         "libtomcrypt")
    ap.add_argument("--ramtab", type=int, choices=(0, 1), default=0,
                    help="1 builds the RAM-table twin, which is the mandatory "
                         "control: same code, same indices, no flash read on "
                         "the table")
    ap.add_argument("--extra", nargs="*", default=[],
                    help="further VAR=value pairs passed to build.sh")
    ap.add_argument("--list", action="store_true",
                    help="the parts crypto-eval can build in this checkout")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the build command and stop")
    args = ap.parse_args(argv)

    if args.list:
        have = ported()
        print("crypto-eval builds %d part(s) in this checkout:" % len(have))
        for name in have:
            print("   %s" % name)
        covered = {mcu_for(c) for c in cells()}
        covered.discard(None)
        missing = sorted({c["part"] for c in cells() if mcu_for(c) is None})
        print("\ncells.json names %d part(s) with no mcufw/ directory:"
              % len(missing))
        for name in missing:
            tier3 = TIER3.get(
                next((c["part_key"] for c in cells()
                      if c["part"] == name), ""), "")
            print("   %-38s %s" % (name, "tier 3: " + tier3 if tier3 else ""))
        return 0

    if not args.cell:
        ap.error("--cell is required unless --list")
    cell = next((c for c in cells() if c["id"] == args.cell), None)
    if cell is None:
        raise SystemExit("no such cell: %s\nTry: python tools/reproduce.py "
                         "--part <name>" % args.cell)

    if not os.path.isdir(os.path.join(EVAL, "mcufw")):
        raise SystemExit("deps/crypto-eval is empty. Run\n"
                         "    git submodule update --init\n"
                         "and see deps/README.md.")

    mcu = mcu_for(cell)
    if mcu is None:
        tier3 = TIER3.get(cell["part_key"])
        message = ["crypto-eval has no port for %s, so this image cannot be "
                   "built here." % cell["part"],
                   "Ported parts: %s" % ", ".join(ported())]
        if tier3:
            message += [
                "",
                "It is a tier-3 part in any case: it needs %s, which is a "
                "registered download, so no CI can build it." % tier3,
                "The archived binary is under images/ and stages 2 and 3 are "
                "still open to you with the board.",
            ]
        raise SystemExit("\n".join(message))

    libdir = os.path.join(EVAL, "eval", "lib", args.lib, "lib.mk")
    if not os.path.isfile(libdir):
        have = sorted(os.listdir(os.path.join(EVAL, "eval", "lib")))
        raise SystemExit("crypto-eval has no library %r; it has %s"
                         % (args.lib, ", ".join(have)))

    layout = LAYOUT[cell["field"]]
    build_args = ["MCU=%s" % mcu, "LIB=%s" % args.lib,
                  "RAMTAB=%d" % args.ramtab]
    if args.lib == "refsbox":
        build_args.append("LAYOUT=%s" % layout)
    build_args += list(args.extra)
    script = os.path.join(EVAL, "tools", "build.sh")
    command = "./tools/build.sh " + " ".join(build_args)
    print("cell  %s" % cell["id"])
    print("part  %s   field %s -> LAYOUT=%s" % (cell["part"], cell["field"],
                                                layout))
    print("build %s   (in deps/crypto-eval)" % command)

    toolchain = toolchain_version()
    if toolchain is None:
        raise SystemExit(
            "\narm-none-eabi-gcc is not on PATH, so nothing was built.\n"
            "Install it and run this again, or skip to stage 2 with one of\n"
            "the archived images under images/ - `python tools/record.py\n"
            "--cell %s --image <path>` takes one." % cell["id"])
    print("gcc   %s" % toolchain)
    if args.dry_run:
        return 0

    bash = shutil.which("bash")
    if bash is None:
        raise SystemExit("no bash on PATH; build.sh is a shell script and "
                         "says so in its own first comment. Under Windows "
                         "run it from WSL or Git Bash.")
    out = subprocess.run([bash, script] + build_args, cwd=EVAL)
    if out.returncode:
        raise SystemExit("build failed (%d); nothing written to IMAGES.tsv"
                         % out.returncode)

    variant = subprocess.run([bash, script] + build_args + ["variant"],
                             cwd=EVAL, capture_output=True, text=True)
    name = (variant.stdout or "").strip().splitlines()[-1:] or [""]
    built = os.path.join(EVAL, "build", mcu, name[0], "fw.bin")
    if not os.path.isfile(built):
        raise SystemExit("the build reported success and %s is not there; "
                         "nothing written to IMAGES.tsv" % built)
    dest_dir = os.path.join(IMAGES, mcu)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, "%s.bin" % name[0])
    shutil.copyfile(built, dest)
    digest = sha256_file(dest)
    rel = os.path.relpath(dest, ROOT).replace(os.sep, "/")
    print("image %s\nsha256 %s" % (rel, digest))
    record_image(cell["id"], rel, digest, command, toolchain)
    return 0


if __name__ == "__main__":
    sys.exit(main())
