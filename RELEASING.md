<!-- SPDX-License-Identifier: Apache-2.0 -->

# Releasing

Maintainers only.

## Checklist

1. `CHANGELOG.md` — move `Unreleased` to the new version, with the date.
2. `pyproject.toml` — bump `version`. **The only place a version is written.**
   `__version__` reads it via `importlib.metadata`.
3. `CITATION.cff` — bump `version`.
4. `make check` locally.
5. `./scripts/verify-release-candidate.sh` — clean-environment gate.
6. Merge to `main`, wait for CI to pass on the merge commit.
7. Tag the exact green commit with a signed tag:

```bash
git tag -s v0.0.2 -m "v0.0.2"
git push --tags
```

The release workflow then builds, generates an SBOM, attests provenance, and
publishes to PyPI via Trusted Publishing. No human handles a token.

## Provenance

A merge commit is **not** the commit you tested. If `main` is merged rather
than fast-forwarded, re-run the gate against the merge commit before tagging:

```bash
./scripts/compare_wheel_payload.py <tested-sha> <merge-sha>   # must be identical
./scripts/verify-release-candidate.sh --expect <merge-sha>
```

`--expect` refuses to produce a provenance record for a commit it was not
given, so a record cannot silently describe the wrong one.

## If CI fails after merge

Do not tag. Do not publish. Diagnose on the merged commit, and treat any
change as a **new candidate**: new SHA, new gate run, new artefact hashes.

Never re-point an existing tag. A tag records what was verified.

## If publishing fails after a green tag

Leave the tag alone and republish from it. No code change means no new
candidate. If a code change *is* required, it is a new version.

## Rollback

There is none for a published artefact. That is why the gate runs before the
tag, and the tag before publication.
