# traces/

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

The captures behind the table's result cells, reduced. Paths mirror the
research tree's own `results/<campaign>/` layout so a file here can be matched
to the campaign that took it without a lookup table.

```bash
python tools/verify.py --traces                    # size and hash per file
python tools/import_traces.py --research <tree>    # refill this directory
```

## What is in a file

Three manifests, and they answer different things.

`REDUCTION.json` is the reducer's own output, carried across unchanged. One row
per reduced capture: the source path, the number of traces, the cycle count's
dtype, the SHA-256 of the ciphertext column that was dropped, the SHA-256 of
the plaintexts, the seed where the plaintexts were replaced by one, and which
cells the capture backs.

`PASSTHROUGH.json` lists the captures that were copied byte for byte because
the reducer could not reduce them, with the reason. Two kinds, neither a
defect: a matrix capture whose timing lives in named per-cell arrays rather
than in a `cyc` column (which is most of what backs a `flat` claim), and a
`.json` capture from a campaign that predates the npz schema.

`MANIFEST.tsv` is a size, a SHA-256, a kind and a `ct_provenance` per file, in
the shape the research tree's `results/MANIFEST.tsv` uses. It is what tells
MISSING from CHANGED from UNLISTED, which `git status` cannot.

## The reduction

The cycle counts and the plaintexts are as recorded. `cyc` is the only column
that could not be derived from anything else. The ciphertext column was
replaced by a SHA-256 of its bytes, and `reproduce.py` recomputes it from the
plaintexts and the key, checks the hash, and then scores.

The plaintext column went the same way wherever that could be proved lossless.
Several campaigns store a seed rather than the material; the ones that store
plaintexts record no seed, but the firmware's xorshift32 is invertible, so the
seed can be recovered from the first output word and then checked against all n
recorded plaintexts. Where every one matches, storing the four-byte seed is
lossless and the check is the proof. That is not guessing a seed, it is
demonstrating that the column is exactly what the seed generates. Where the
plaintexts came from some other generator the column stays.

## ct_provenance, which is the thing to read before quoting a hash

A hash match proves the recorded ciphertext column equalled AES of the recorded
plaintexts under the recorded key. Whether that says anything about the silicon
depends on where the recorded column came from, and the file cannot tell you: a
host-computed column and a correct device-reported column are bit-identical by
construction.

| value | what the check then catches |
|---|---|
| `device` | a device that is not computing AES. A real failure mode: a T-table encrypt that updated its state in place in its final round computed a function that is not AES and returned a clean 0/16, indistinguishable from a part with no channel |
| `host` | a corrupted or mislabelled file, and nothing about the device. The comparison is one reference AES against another |
| `unknown` | the same as `host` for safety's sake. Nothing on disk settles it |

Most of these files are `unknown`. It has to come from the producing script and
only a minority of these captures name theirs, so the field is left as
`unknown` rather than rounded up because a dossier's prose sounds confident.
`python tools/verify.py --traces` prints the tally.

The research tree's reducer is also where the reduction gets checked, with
`python tools/artifact_reduce.py --out <dir> --verify`, against the originals.
Nothing in this repository can do that, because the originals are not here;
what `verify.py` checks is that these files have not changed since they came
in.

## One known false alarm in that check

Four captures come back `DIFFERS` from `--verify` and in every one of them the
cause is that the source capture never had a ciphertext column at all, so
`ct_sha256` is null and the verifier compares a freshly computed hash against
nothing. The data is fine and the reduction is lossless for them; a null
recorded hash means there was nothing to compare, which is not the same as a
comparison that failed. They are the four files under the LPC2124's `traces/`
subdirectory and `REDUCTION.json` shows the null.
