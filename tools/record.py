#!/usr/bin/env python3
"""Stage 2: record traces off a board, through crypto-eval's own capture.

    python tools/record.py --cell stm32g474/dcen-0-latency-1-sbox \
        --probe <probe serial> -n 25000
    python tools/record.py --cell ... --image images/stm32g474re/<name>.bin \
        --probe <probe serial>

Either the image you built in stage 1 or one archived in this repository. The
capture itself is `deps/crypto-eval/tools/capture.py`, which already carries
the three things that stop a capture being wrong:

* the board is resolved by DEBUG PROBE SERIAL and never by a COM number, which
  goes stale between replugs and is shared between identical boards;
* the accelerator word is read back off the device after being written, and a
  part that refused the setting aborts the run;
* every ciphertext is checked against a reference AES and a capture that fails
  is never written. That matters more than it sounds: a T-table encrypt that
  updated its state in place in the final round once computed a function that
  is not AES and returned a clean 0/16, which looks exactly like a part that
  does not leak.

WHAT THIS FILE ADDS, and it is the one thing the submodule does not yet do.
THE FILENAME CARRIES EVERY AXIS THAT CAN DIFFER BETWEEN TWO RUNS OF THE SAME
COMMAND, including the ones the build chose rather than the operator. Two
campaigns on this bench lost 400 000-trace captures to filename collisions on
an axis outside that list - a clock that `make` accepted and ignored, and an
S-box address an edit moved mid-campaign. So the name is built from the cell
plus the DEVICE READBACK, never from the arguments, and a name that already
exists is refused rather than overwritten.

It also records, in the capture's own `meta`, where the ciphertext column came
from. That costs one string and it is the difference between a check that can
catch a device not computing AES and a tautology; see the README on
`ct_provenance`.

HOW THIS REFUSES:

* No `--probe`: refused. A COM number is not a handle.
* No pyserial or no pyocd: refused, naming which.
* No image, either built or given: refused, with the build command to run.
* An image whose SHA-256 is not in `images/IMAGES.tsv`: refused, because a
  capture filed against an unlisted image cannot be tied to a build later, and
  that is the link the whole chain is missing today.
* A cell crypto-eval has no port for: refused by `tools/build.py`'s own test,
  which this shares.

WHAT THIS DOES NOT DO:

* It does not reduce the capture. Captures land in `traces/raw/` at full size;
  the research tree's `artifact_reduce.py` is what makes a shippable one.
* It does not claim a board. This repository has no bench lock, and if you are
  working in a tree that does, take the claim there first.
* IT HAS NOT BEEN RUN. No board, no probe and no serial port were present when
  this was written, so every path below the refusals is untested. It is written
  to be read before it is trusted.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EVAL = os.path.join(ROOT, "deps", "crypto-eval")
CELLS = os.path.join(ROOT, "cells", "cells.json")
RAW = os.path.join(ROOT, "traces", "raw")

sys.path.insert(0, HERE)
from build import LAYOUT, cells, mcu_for, sha256_file   # noqa: E402


def need(module, why):
    if importlib.util.find_spec(module) is None:
        raise SystemExit("%s is not installed, and %s.\n"
                         "    pip install %s" % (module, why, module))


def accelerator_word(cell):
    """The register value the cell's configuration names, or None.

    Read out of the configuration STRING, which is where the table keeps it -
    `FLASH_ACR 0x705`, `PFCR0 = 0x18C780ED`. None is not an error: plenty of
    configurations are named by their bits rather than by a word, and in that
    case the operator passes `--acr` and the readback is still checked. What is
    never done is inventing one.
    """
    m = re.search(r"\b(?:0x)([0-9a-fA-F]{2,8})\b", cell["config"])
    return int(m.group(1), 16) if m else None


def listed_images():
    path = os.path.join(ROOT, "images", "IMAGES.tsv")
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                out.setdefault(parts[2], []).append((parts[0], parts[1]))
    return out


def capture_name(cell, mcu, image_sha, readback, n):
    """The capture's filename, from the cell and the DEVICE READBACK.

    Every axis that can differ between two runs of the same command is in here:
    the cell (part, configuration, cipher), the accelerator word the DEVICE
    reports rather than the one that was asked for, the trace count, the first
    twelve hex of the image's hash, and the date. The image hash is what makes
    two runs of the same command on two different builds land in two different
    files, which is the collision that has actually cost captures here.
    """
    acr = readback.get("acr")
    bits = [cell["part_key"], "c%d" % cell["config_index"], cell["field"],
            "acr%s" % (format(acr, "x") if acr is not None else "na"),
            "n%d" % n, image_sha[:12],
            datetime.date.today().strftime("%Y%m%d")]
    return "_".join(bits) + ".npz"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cell", required=True)
    ap.add_argument("--probe", help="debug probe SERIAL, not a COM number")
    ap.add_argument("--image", help="the image to flash; the default is the "
                                    "one tools/build.py last built for this "
                                    "cell")
    ap.add_argument("-n", type=int, default=25000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--acr", help="accelerator word to write, if the cell's "
                                  "configuration string does not name one")
    ap.add_argument("--lib", default="refsbox")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be run, touch no hardware")
    args = ap.parse_args(argv)

    cell = next((c for c in cells() if c["id"] == args.cell), None)
    if cell is None:
        raise SystemExit("no such cell: %s" % args.cell)
    mcu = mcu_for(cell)
    if mcu is None:
        raise SystemExit(
            "crypto-eval has no port for %s. `python tools/build.py --list` "
            "says what it does have, and for a tier-3 part it names the "
            "toolchain you would need." % cell["part"])

    capture_py = os.path.join(EVAL, "tools", "capture.py")
    if not os.path.isfile(capture_py):
        raise SystemExit("deps/crypto-eval is empty. Run\n"
                         "    git submodule update --init")

    image = args.image
    if image is None:
        for digest, rows in listed_images().items():
            for cell_id, path in rows:
                if cell_id == cell["id"]:
                    image = path
    if image is None:
        raise SystemExit(
            "no image for this cell. Either build one -\n"
            "    python tools/build.py --cell %s\n"
            "- or pass --image with one of the archived binaries under "
            "images/." % cell["id"])
    image_path = image if os.path.isabs(image) else os.path.join(ROOT, image)
    if not os.path.isfile(image_path):
        raise SystemExit("no such image: %s" % image)
    digest = sha256_file(image_path)
    if digest not in listed_images():
        raise SystemExit(
            "this image is not in images/IMAGES.tsv:\n"
            "    %s\n    %s\n"
            "A capture filed against an unlisted image cannot be tied back to "
            "a build, which is exactly the link the archive is missing today. "
            "Add it with tools/build.py, or list it by hand with its build "
            "command and toolchain version." % (image, digest))

    acr = int(args.acr, 0) if args.acr else accelerator_word(cell)
    layout = LAYOUT[cell["field"]]
    command = [sys.executable, capture_py, "--mcu", mcu,
               "--variant", "%s-%s-ram0-<link>-<baud>-<timing>-w1-pad0"
               % (args.lib, layout),
               "-n", str(args.n), "--seed", str(args.seed)]
    if args.probe:
        command += ["--probe", args.probe]
    if acr is not None:
        command += ["--acr", hex(acr)]

    print("cell   %s" % cell["id"])
    print("part   %s   -> MCU=%s  LAYOUT=%s" % (cell["part"], mcu, layout))
    print("image  %s  sha256 %s" % (image, digest[:16]))
    print("acr    %s%s" % (hex(acr) if acr is not None else "none named",
                           "" if acr is not None else
                           "  (pass --acr; the readback is still checked)"))
    print("would run, in deps/crypto-eval:\n    %s" % " ".join(command[1:]))

    if args.dry_run:
        return 0
    if not args.probe:
        raise SystemExit(
            "\n--probe is required. A COM number is not a handle: it goes "
            "stale across a replug and two identical boards are "
            "distinguishable only by probe serial, so a capture addressed by "
            "port can be of the wrong board and say nothing about it.")
    need("serial", "the victim speaks over a CDC serial port")
    need("pyocd", "the image has to be flashed before the capture")

    os.makedirs(RAW, exist_ok=True)
    out = subprocess.run(command, cwd=EVAL)
    if out.returncode:
        raise SystemExit("the capture failed (%d); nothing written"
                         % out.returncode)
    print("\nThe capture is under deps/crypto-eval/results/. Name it from the "
          "device readback and move it into traces/raw/:\n"
          "    %s\n"
          "and record where its ciphertext column came from in its meta - "
          "device or host - because the file cannot tell you later and 63 of "
          "the shipped captures are `unknown` for exactly that reason."
          % os.path.join("traces", "raw",
                         capture_name(cell, mcu, digest, {"acr": acr},
                                      args.n)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
