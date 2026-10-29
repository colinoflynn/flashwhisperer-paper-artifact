# FlashWhisperer ("Beyond the Scope of This Paper") Artifacts

*🤖🥩: This document is partially human-written, partially LLM. This repo flags
LLM-written docs as I find they can be more annoying to read as a human bag of 🥩*

The reproduction artifact for the flash-accelerator timing paper. A
microcontroller's flash accelerator (the read latch, the prefetch buffer, the
little data cache) makes an AES lookup table's access time depend on which
flash row the last lookup touched, and that is enough to recover the key off
the part's own cycle counter.

The paper is available at: (see latest papers on E-Print)

This paper has not yet been peer reviewed. It is currently a draft and will
have further updates.

Sections 3 to 6 of the paper land here: the mechanism, the method, the
cross-part survey, and what turns the channel up or down. It lets you build the
image a result was measured on, record traces off a dev board, and turn traces
back into the numbers printed in the table. The delivered attacks over real
protocol stacks are section 7, and they live in
[flashwhisperer-demos](https://github.com/colinoflynn/flashwhisperer-demos),
pinned here at [`deps/demos`](deps).

```bash
git clone -c core.longpaths=true <this repo> && cd flashwhisperer-paper-artifact
git submodule update --init          # the three pinned upstreams
pip install numpy
python tools/verify.py               # pins intact, traces unchanged
python tools/reproduce.py            # every cell with an artifact. No board.
```

**Clone somewhere short, and on Windows with `core.longpaths=true`.** A clone
into a deep directory exceeds MAX_PATH and aborts part way through the
checkout, leaving a tree that looks complete. `tools/verify.py` checks one
sentinel file per dependency for exactly that.

## Three stages

| stage | command | what it needs |
|---|---|---|
| 1, build | `python tools/build.py --cell <id>` | `arm-none-eabi-gcc`, and a part crypto-eval has a port for |
| 2, record | `python tools/record.py --cell <id> --probe <serial>` | the board, a debug probe, pyocd and pyserial |
| 3, reproduce | `python tools/reproduce.py` | numpy. Nothing else |

Stage 3 is the one that runs anywhere, and it is the one the numbers come out
of. Stages 1 and 2 exist so the chain from a build to a printed trace count is
walkable rather than asserted, and both refuse clearly when the toolchain or
the board is absent. Neither has been run on this machine: there is no
toolchain and no board here, so `images/IMAGES.tsv` carries no row either of
those two wrote.

## What a cell is, and why not a configuration

The paper's cross-part table renders three result fields per configuration:
the byte S-box, the compact T-table, and the four-table build. So the unit of
work is a **cell**, one `(part, configuration, field)` triple, and not a
configuration. A configuration whose S-box cell has an artifact and whose two
T-table cells do not is two thirds uncovered, and counting configurations hides
that.

[`cells/cells.json`](cells) is the register, derived from the research tree by
[`tools/make_cells.py`](tools/make_cells.py) rather than copied, and it carries
one of four verdicts per cell:

| verdict | what it means |
|---|---|
| `block` | there is a capture with per-trace data and a geometry that recovers. `reproduce.py` replays it |
| `flat` | the claim is that the cell is constant, so there is no recovery to replay. The artifact is the capture and its distinct count |
| `recapture` | the data on disk cannot support the claim and the bench owes this cell a new capture. The cell says what is missing |
| `drop` | the cell should not be in the table, with a reason that stands on its own |

`cells.json` and the generated tables are the only places that count. Run
`python tools/verify.py` for the tally, and `python tools/reproduce.py
--show-gaps` for the cells with no artifact and the reason each one has none.

## Every recovery parameter comes from the cell

`line_shift`, `line_off`, `ct_adjacent`, the rungs, the pair sets and the
observable are read out of the cell. `reproduce.py` has no defaults to fall
back on, and that is not tidiness: each of those silently returns a clean null
when wrong, and a clean null is indistinguishable from a part that does not
leak. A run that guessed one would report the part safe.

A trace count without the table's **address** is under-specified for the same
reason. The row a lookup hits is `(index + line_off) >> line_shift`, `line_off`
is where the table happened to land inside its flash row, and it is a property
of the image rather than a constant of the attack. The same firmware at three
link-time accidents has needed 6 250, 12 500 and 25 000 traces for the same
recovery, so every cell records the address its count belongs to, or says that
it cannot.

## Controls run through the identical call and score nothing

A control cell is the RAM-table twin (same code, same instruction stream, same
indices, tables moved out of flash by the linker) or a cell whose own note says
`control`. It goes through the same `archive.ladder` with the same parameters
as the row beside it, and `reproduce.py` marks it, counts it, and exits
non-zero if one recovers a key. That is what makes the other rows quotable: a
statistic is not a channel, and a pooled z of -21 that yields no key bytes is
not a channel whatever its size.

## What the ciphertext hash does and does not prove

The shipped captures carry their cycle counts and their plaintexts as recorded,
and their ciphertext column was replaced by a SHA-256 of it. `reproduce.py`
recomputes the column from the plaintexts and the key, checks the hash, and
then scores. So the attack's input is recomputed rather than recorded, and the
hash is what makes that sound.

Here is the part that is less than it looks. A hash match proves the recorded
ciphertext column equalled AES of the recorded plaintexts under the recorded
key. Whether that is evidence about the silicon depends entirely on where the
recorded column came from, and the file cannot tell you, because a
host-computed column and a correct device-reported column are bit-identical by
construction. Where the device reported them, the check catches a device that
is not computing AES, which is a real failure and not a hypothetical one: a
T-table encrypt that updated its state in place in its final round once
computed a function that is not AES and returned a clean 0/16 that looks
exactly like a part with no channel. Where the host computed them, the same
check compares one reference AES against another and is a tautology about the
device. It still catches a corrupted or mislabelled file, which is worth
having, and it is not evidence the silicon did anything.

So every trace file carries a `ct_provenance` of `device`, `host` or `unknown`,
in [`traces/MANIFEST.tsv`](traces) and in each reduced file's own `info` field.
Most of them are `unknown`: nothing on disk settles it, and it has to come from
the producing script, which only a minority of these captures name.
`unknown` prints as `unknown` and is never rounded up to `device` because a
dossier's prose sounds confident. `python tools/verify.py --traces` tallies it.

## Layout

| | |
|---|---|
| [`cells/`](cells) | `cells.json`, the register of result cells, and one generated page per cell |
| [`traces/`](traces) | the reduced captures, `REDUCTION.json` as written by the reducer, and `MANIFEST.tsv` with a size, a SHA-256 and a provenance per file |
| [`images/`](images) | archived binaries and `IMAGES.tsv`: hash, cell, build command, toolchain version |
| [`tools/`](tools) | the three stages, plus `verify.py`, and the two generators that fill `cells/` and `traces/` |
| [`figures/`](figures) | the regeneration scripts. The figures themselves are derived and are not committed |
| [`deps/`](deps) | the three pinned submodules, and `PINS` as the register. Everything that measures or scores is behind one of them |

## Related

| | |
|---|---|
| [flashwhisperer](https://github.com/colinoflynn/flashwhisperer) | the toolkit: the simulator, the attack engine, the scoring rule, the row geometry. Every recovery here goes through it |
| [flashwhisperer-crypto-eval](https://github.com/colinoflynn/flashwhisperer-crypto-eval) | the instrument stages 1 and 2 run on: one part, one library, the victim's own cycle counter |
| [flashwhisperer-demos](https://github.com/colinoflynn/flashwhisperer-demos) | the paper's section 7, end to end against stock protocol stacks, each with its vectors |
