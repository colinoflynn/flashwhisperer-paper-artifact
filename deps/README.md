# Dependencies: three submodules, pinned by commit

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

```bash
git submodule update --init
python tools/verify.py --pins
```

[`PINS`](PINS) is the register: name, URL, commit, kind, and the reason each
commit is the one it is. Each entry is also a real submodule, so the parent
repository records a gitlink and `verify.py` checks that the gitlink, `PINS`
and the submodule's own HEAD all agree. Those three can disagree in two
different directions and only one of them shows up in `git status`.

Nothing here is vendored and nothing here is patched. Everything that measures
or scores lives behind one of the three lines in `PINS`; this repository writes
the Makefile, the stage tools, the docs and the data, and nothing else. That
constraint is the only thing that makes the pinned-version claim mean anything:
a copy of a scorer is a scorer nobody can check the provenance of.

| | what it is for |
|---|---|
| `flashwhisperer` | the analysis half. `flashattack.archive.ladder` is the scorer of record, `flashattack.lastround` the row geometry, `flashsim.aes` the reference cipher |
| `crypto-eval` | the instrument stages 1 and 2 run on. One part, one library, the victim's own cycle counter, and the accelerator word read back off the device |
| `demos` | the paper's section 7, the delivered attacks over stock protocol stacks. Pinned and pointed at, never duplicated |

## One thing the pin does not have yet

`archive.load` at the pinned flashwhisperer commit takes `(path, observable)`
and requires a ciphertext column. Three of the capture classes here do not have
one:

* a seed-only capture, which stores a PRNG seed and the cycle counts and
  regenerates the material. That is the right format and it is also the
  smallest: twenty thousand traces across three ciphers in tens of kilobytes
  against megabytes stored as plaintexts and ciphertexts
* a capture whose key or whose seed was a constant in the capture script rather
  than a field in the file, which is the case on one part's byte-S-box files
* every reduced file under [`../traces`](../traces), whose ciphertext column
  was replaced by a SHA-256 on purpose

So `tools/reproduce.py` resolves those columns itself, with
`flashattack.transport.gen_pts` and `flashsim.aes`, and hands the result to the
pinned `archive.ladder`. The scorer is upstream's at the pinned commit; only
the loading is local, and it collapses to one `archive.load` call on the day a
loader that takes `key=` and `seed=` and reads a JSON capture is published.
`tools/reproduce.py`'s `Loader` docstring says which path each capture takes.

## If a submodule will not clone

Record the intended commit in `PINS` and carry on. Do not vendor the code: a
copy under `deps/` builds, runs, and silently stops being the thing the paper
was measured with, and nothing in this repository could tell. `verify.py`
reports an absent submodule as MISSING rather than as a pass, and
`reproduce.py` refuses to start without `flashattack`.
