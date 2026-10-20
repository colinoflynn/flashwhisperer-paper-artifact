# Reproducing the table, in order, and the ways it fails quietly

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Four steps. The order is chosen so the failures stay distinguishable rather
than so you get to a board quickly, because most of what goes wrong here goes
wrong silently and ends in the same clean null.

## 1. No hardware

```bash
git submodule update --init
pip install numpy
python tools/verify.py
python tools/reproduce.py
```

If keys come out, the analysis half is right and the traces are intact. If they
do not, nothing later is worth trying, because every stage ends in the same
recovery.

`verify.py` answers four questions and they are not the same question. The
submodules at their pins, none of them modified, the checkout complete (a
MAX_PATH abort leaves a tree that looks finished), and the traces matching
`traces/MANIFEST.tsv`. That last one has three separate answers: MISSING means
listed and not here, CHANGED means here with a different hash and whatever used
it is not reproducible from what is on disk now, and UNLISTED means a new file
nobody recorded. `git status` answers none of them.

`reproduce.py` prints one row per cell, and two verdict columns rather than
one:

```
cell                              kind   in print  expect   the recovery gives       vs block  vs the table
stm32l152/flash-acr-0x07-1-ws-sbox block  20 000   10 000   10 000, 16/16 verified   agrees    cheaper
```

`vs block` is the reproduction check: did the recovery give the number this
cell records? `vs the table` is the paper check: did it give the number printed
in the table? Those differ on purpose on several cells. The table quotes the
cheapest known break and is one rung conservative in places, so a cell can
reproduce exactly and still be `cheaper` than what is in print. Neither column
is preferred over the other and the summary tallies both.

### Narrowing it

```bash
python tools/reproduce.py --cell stm32g474/art-off-dcen-0-latency-0-ttable1
python tools/reproduce.py --part STM32L475VG
python tools/reproduce.py --field sbox
python tools/reproduce.py --table 3            # the cells the paper renders
python tools/reproduce.py --show-gaps          # the cells with no artifact
python tools/reproduce.py --json out.json      # every rung of every ladder
```

A full run is slow, in minutes rather than seconds per cell on the large
captures: a ladder is six pair sets at every rung, the rungs are cumulative
prefixes of one capture, and the cells that swept both last-round adjacencies
run twice. `-j <n>` scores that many cells at once in separate processes and is
how a whole run gets done in under an hour; the rows still print in cell order
so two runs of one selection give the same output. `--part` is the way to work
while you are looking at one part.

## 2. The toolchain, before the board

```bash
python tools/build.py --list
python tools/build.py --cell stm32g474/dcen-0-latency-1-sbox
```

`--list` prints the parts crypto-eval can build in this checkout and the parts
from `cells.json` it cannot, with the tier-3 toolchain named where that is the
reason. Most of the roster is in the second list today. A build writes a row in
`images/IMAGES.tsv` with the image's SHA-256 and the compiler version that
produced it, beside the hash of the image the paper used.

Equal hashes mean you rebuilt the measurement. Different hashes are not a
failure: a different GCC emits a different instruction stream and the
instruction stream is part of what is being measured. It does mean the trace
count may differ, which is why it is in a file you read before stage 3 rather
than a surprise at the end of it.

## 3. The victim, and the address

Build it, flash it, and then read the table's runtime address off the ELF
before capturing anything:

```python
>>> from flashleak import placement
>>> placement.row_offset_from_image("deps/crypto-eval/build/<mcu>/<variant>/fw.elf")
(12, 134287884, 'AES S-box sbox @ 0x0801120c (.rodata, EXPOSED)')
```

That number is `line_off`, and it belongs to the image rather than to the
attack. A rebuild moves it, a toolchain change moves it, and an attack scored
at the wrong offset is a complete null on a victim that leaks. It goes in the
cell, and `reproduce.py` refuses to supply one of its own.

## 4. The capture, and then the key

```bash
python tools/record.py --cell <id> --probe <probe serial> -n 25000
```

Three things `record.py` carries over from crypto-eval, each of which has
stopped a wrong capture here: the board is resolved by debug probe serial and
never by a COM number, the accelerator word is read back off the device and a
part that refused the setting aborts the run, and every ciphertext is checked
against a reference AES so a capture that failed is never written.

One thing it adds. The filename is built from the cell plus the device
readback, never from the arguments, and it carries every axis that can differ
between two runs of the same command. Two campaigns on this bench lost
400 000-trace captures to a filename collision on an axis outside that list,
once a clock that `make` accepted and ignored and once an S-box address an edit
moved mid-campaign.

Then record where the ciphertext column came from, in the capture's own `meta`.
It costs one string and it is the difference between a check that can catch a
device not computing AES and a tautology. Most of the shipped captures are
`unknown` for want of that string.

## The ways this fails without telling you

* A clone that exceeded MAX_PATH. On Windows a deep clone aborts part way
  through the checkout and leaves a tree that looks complete. Clone somewhere
  short with `core.longpaths=true` and run `tools/verify.py`.
* A submodule at the wrong commit. `git submodule update --init --depth 1`
  clones the default branch and can land on something that is not the pin;
  `verify.py` compares `deps/PINS`, the gitlink the parent records, and the
  submodule's own HEAD, because those three can disagree in two directions.
* The row offset. See step 3. This is the one that has cost a result rather
  than an afternoon.
* `ct_adjacent` as a string. It is spelled `"both"` on many cells, meaning both
  adjacencies were swept at triage. `archive.ladder` takes a boolean and every
  non-empty string is truthy, so passing `"both"` through scores ciphertext
  adjacency alone, which on a byte-S-box final round is a clean 0/16 that reads
  as a cell that does not reproduce. `reproduce.py` runs both and reports which
  won.
* A second observable scored as a cycle count. One part's captures carry
  `cyc_dhits`, a hardware cache hit count. Scoring a cell on hit counts and
  re-scoring it on cycles are different measurements under one name, so the
  observable is in the cell and is never substituted.
* A statistic instead of a channel. A pooled z of -21 that yields no key bytes
  is not a channel. Run the recovery, and run the control.
* A control that scores. If one does, the run is void and `reproduce.py` exits
  non-zero. Do not read the rows above it.
