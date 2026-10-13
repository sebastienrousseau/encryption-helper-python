# Fuzzing

Fuzz targets for the parsers that accept untrusted input.

Two things here consume bytes an attacker may control: the envelope container
passed to `decrypt()`, and the key material passed to the loaders. Both must
fail *closed* — a typed `DecryptionError` or `KeyReadError` — for every
possible input. A `struct.error`, `IndexError`, `MemoryError` or segfault is a
bug, and returning plaintext for a container the owner did not produce would
be a vulnerability.

## Running

No fuzzing engine required:

```bash
python fuzz/run_fuzz.py --iterations 20000
python fuzz/run_fuzz.py --target decrypt --seed 42     # reproducible
```

With [Atheris](https://github.com/google/atheris), if installed:

```bash
pip install atheris
python fuzz/fuzz_decrypt.py -atheris_runs=100000
python fuzz/fuzz_load_key.py corpus/
```

The targets are written so the same functions serve both runners. `run_fuzz.py`
is what CI executes, because it needs no engine and no compiler.

## What counts as a finding

| Outcome | Verdict |
| ------- | ------- |
| `DecryptionError` / `KeyReadError` | Correct. Fail closed. |
| Correct plaintext for a valid container | Correct. |
| Any other exception | **Bug.** The parser leaked an implementation error. |
| Plaintext returned for a corrupted container | **Vulnerability.** |
| Hang, or memory growth unbounded in input size | **Bug.** |

Reproduce a crash with the printed seed and iteration:

```bash
python fuzz/run_fuzz.py --target decrypt --seed <seed> --iterations <n>
```
