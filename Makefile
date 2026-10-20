# The artifact, in the order the three stages run.
#
#   make deps        check out the submodules and verify their pins
#   make verify      pins intact, traces unchanged, cells resolvable
#   make reproduce   stage 3: every cell with a block, no hardware
#   make table3      stage 3, narrowed to the cells the paper's Table 3 renders
#   make cells       regenerate cells/cells.json (needs the research tree)
#   make figures     regenerate the figures from the last reproduce run
#
# Stages 1 and 2 are not targets. They need a toolchain and a board and they
# take a cell name, so they are run by hand:
#
#   python tools/build.py  --cell <id>
#   python tools/record.py --cell <id> --probe <probe serial>
#
# PYTHON is whatever you have; numpy is the only requirement for stage 3.
# JOBS is how many cells stage 3 scores at once. A full serial run is hours:
# a ladder is six pair sets at every rung and the rungs go to 400 000 traces.

PYTHON ?= python
RESEARCH ?= ../../flash-accelerator-tests
REPRO_JSON ?= figures/reproduce.json
JOBS ?= 8

.PHONY: all deps verify reproduce table3 cells traces figures clean-figures

all: verify reproduce

deps:
	git submodule update --init
	$(PYTHON) tools/verify.py --pins

verify:
	$(PYTHON) tools/verify.py

reproduce:
	$(PYTHON) tools/reproduce.py -j $(JOBS) --json $(REPRO_JSON)

table3:
	$(PYTHON) tools/reproduce.py -j $(JOBS) --table 3

# Needs the private research tree beside this one. Regenerating rather than
# hand-editing is the point: the triage fragments land in batches and a copied
# cells.json goes stale between two of them.
cells:
	$(PYTHON) tools/make_cells.py --research $(RESEARCH)
	$(PYTHON) tools/make_cells.py --research $(RESEARCH) --check

traces:
	$(PYTHON) tools/import_traces.py --research $(RESEARCH) --reduce

figures:
	$(PYTHON) figures/make_figures.py --rows $(REPRO_JSON)

clean-figures:
	rm -f figures/*.pdf figures/*.png
