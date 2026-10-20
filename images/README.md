# images/

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Archived binaries, and `IMAGES.tsv` with a hash, a cell, a build command and a
toolchain version per row.

**This directory is empty of binaries today and `IMAGES.tsv` has no rows.** No
image was archived when the artifact was assembled, and the honest statement of
why is that the chain image to capture to table cell is not machine-checkable
at its first link yet: no capture in the corpus records a hash of the image
that produced it, and the free-prose `meta` several of them carry is not that
hash. Filling this directory is the piece of work that closes it.

## Why the file exists before the binaries do

`tools/build.py` writes a row when it builds, with the image's SHA-256 and the
compiler version beside the hash of the image the paper used.
`tools/record.py` refuses an image whose hash is not in this file, because a
capture filed against an unlisted image cannot be tied back to a build later,
and that is exactly the link that is missing.

Equal hashes mean the measurement was rebuilt. Different hashes are not a
failure: a different GCC emits a different instruction stream and the
instruction stream is part of what is being measured. It does mean the trace
count may differ, and this file is where that is visible rather than being a
surprise at the end of a capture.

## Why a binary has to be shipped for some parts at all

Five parts on the roster need a toolchain you have to register for, so no CI
can ever build them and a reader with the board but not the installer can
otherwise do nothing. `python tools/build.py --list` names the toolchain for
each. Shipping the binary leaves stages 2 and 3 open to them, and it is a
partial mitigation rather than a fix: a reader still cannot change the image.

## The axes a filename has to carry

A build's own axes change the link-time layout, and two builds that differ only
in a define are not interchangeable images. The variant string crypto-eval
composes is the record of that, and it is also what the capture gets filed
under. Two campaigns on this bench lost 400 000-trace captures to a filename
collision on an axis outside that list: once a clock that `make` accepted and
silently ignored, and once an S-box address that an edit moved mid-campaign.
Both times the collision was found hours later rather than at the moment of the
overwrite.
