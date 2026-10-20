# figures/

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

The regeneration script, not the figures. A committed PDF is a claim nobody can
check; a script that draws it from a reproduce run is one anybody can.

```bash
python tools/reproduce.py --json figures/reproduce.json
python figures/make_figures.py --rows figures/reproduce.json
```

Three figures:

`ladder` is bytes recovered against trace count, one line per cell that
recovered anything. The shape is the argument that a trace count is a threshold
and not a knob, since most cells go from nothing to all sixteen bytes inside
one doubling.

`coverage` is the result cells by verdict, grouped by part. It is the figure
that should shrink over time and the honest one to publish, because it shows
what the artifact does not back.

`provenance` is the trace files by where their recorded ciphertext column came
from. It is mostly one colour, and that is the point: see the README on
`ct_provenance`.

`make_figures.py` computes nothing. Every number in it comes out of the JSON a
reproduce run wrote, so a figure cannot disagree with the rows it was drawn
from. A figure that looks wrong means the run is wrong.

matplotlib is the only extra requirement and it is not needed for anything
else here, so the script says so and stops rather than failing on an import.
