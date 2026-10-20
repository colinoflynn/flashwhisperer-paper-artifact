# tools/

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Six scripts. Three are the stages, one checks the checkout, and two fill the
data directories from the research tree.

| | |
|---|---|
| `build.py` | stage 1. Works out `(MCU, LIB, LAYOUT, RAMTAB)` from a cell, calls crypto-eval's own `tools/build.sh`, and writes a row in `images/IMAGES.tsv` |
| `record.py` | stage 2. crypto-eval's `tools/capture.py` with a cell name instead of a variant string, plus a filename built from the device readback |
| `reproduce.py` | stage 3. Every cell with an artifact, one row each, no hardware |
| `verify.py` | pins intact, nothing upstream modified, checkout complete, traces unchanged |
| `make_cells.py` | regenerates `cells/cells.json` from the research tree |
| `import_traces.py` | fills `traces/` from the research tree's reducer and writes the manifest |

Nothing here measures or scores. The recovery is
`flashattack.archive.ladder` in `deps/flashwhisperer` at its pin, the row
geometry is `flashattack.lastround`, the reference cipher is `flashsim.aes`,
and the build and the capture are crypto-eval's. What is written here is the
mapping from a cell to those calls, and the refusals.

## Each one says what it does not cover

That is a convention worth stating, because all three of the checks this
repository inherited from the research tree were green for days while being
blind to half of the thing they were named after. A link checker validated
every link's target and ignored its label, so hundreds of links resolved
correctly and sent the reader to a document that does not exist. So each script
here carries a "what this does not do" block in its docstring, and a check that
grows a new blind spot is supposed to grow a line in that block with it.

The short version of each:

`reproduce.py` does not score a `recapture` or a `drop` cell, does not
re-derive a geometry when the cell's one fails, and cannot tell a
device-reported ciphertext column from a host-computed one.

`verify.py` does not verify the reduction (that needs the originals, which are
not in this repository), does not run a recovery, and does not check
`cells.json` against the research tree.

`make_cells.py` does not decide whether a cell reproduces, does not rewrite
`expect`, and does not check that a capture is present.

`build.py` does not flash anything and does not choose the accelerator word.

`record.py` does not reduce the capture it takes and does not claim a board.

## Two of these have never been run

`build.py` and `record.py` need a toolchain and a board, and there was neither
on the machine the artifact was assembled on. Their refusal paths were
exercised; the paths past the refusals were not, and `images/IMAGES.tsv` has no
row either of them wrote. They are written to be read before they are trusted.
