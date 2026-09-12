# Contributing

## Releasing

Maturity lives in **the git tag and the GitHub Release**, nowhere else. The
README badge reads the latest Release directly, so promoting alpha → beta is a
tag, not a documentation edit. It used to be a twelve-file edit, which is how
stale labels got in.

```bash
./dev-scripts/set-version.sh 0.3.0-beta.1   # CHANGELOG heading + app.conf only
./tests/run-checks.sh
git commit -am "Release v0.3.0-beta.1"
git tag -a v0.3.0-beta.1 -m "v0.3.0-beta.1"
git push origin main --follow-tags
```

Then create the GitHub Release from the tag, ticking **"set as a pre-release"**
for anything with an `-alpha` / `-beta` / `-rc` suffix. That flag is what keeps
it out of "Latest release".

**Prereleases all target one version.** `0.3.0-alpha.1` → `0.3.0-beta.1` →
`0.3.0-rc.1` → `0.3.0` are steps toward the *same* release, and SemVer sorts
them in that order. Going `0.1.0-alpha` → `0.2.0-beta` is not a promotion: those
are prereleases of two different versions, and it means 0.1.0 was abandoned
unreleased. This project did exactly that once — hence the note.

Only one thing carries a literal version: `CHANGELOG.md`, whose job that is.
The checks enforce that no status line creeps back into the README — the badge
reads the latest Release directly.

## Contributing

Contributions are welcome. This is a beta-stage personal project, so expect
loose process and slow responses.

## Before you start

Read the [pipeline task board](/project-progress.md) and its
[Known Limitations](/project-progress.md#-known-limitations). A lot of what
looks broken is known to be broken, and some of it is deliberately deferred.

The most useful contributions right now, roughly in order:

1. **Tests.** There are none. Anything that makes a "✅" on the task board
   checkable rather than a claim is the highest-value change available.
2. **Verify the MITRE CAR mapping.** The engine's artefact maps are proven on
   the author's corpus and by the smoke test's Sysmon fixtures; confirming
   which fields actually populate for the other lanes — and which are
   silently null — is worth more than adding more mappings. `dxdfir
   verify-car` is the gate; the ranked checklist is issue #14.
3. **EVTX ingest.** Built via EvtxECmd, never run against a real event log.

## Ground rules

**Never commit evidence.** `data_store/` is gitignored deny-by-default, but it
is a safety net, not a guarantee. Check `git status` before every commit, and
never use `git add -f` inside `data_store/`.

**Don't add third-party code without recording it.** If you vendor anything —
a script, a library, a data file — add it to
[THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) with its upstream and licence.
The project is Apache-2.0 and that only stays true if attribution keeps up. See
[why](/THIRD_PARTY_NOTICES.md#why-apache-20).

**Be honest in the task board.** `project-progress.md` uses ✅ for
"ran end-to-end and produced correct output", ⚠️ for "runs but incomplete or
unverified", ❌ for "doesn't work". Over-claiming is how the board got into the
state that prompted the beta rewrite. If you haven't run it, it isn't ✅.

## Scripts

Use `scripts/`. A check asserts every script resolves the repo root correctly,
whatever depth it lives at.

`scripts/v2/` was deleted in `v0.2.0-beta` — a divergent duplicate carrying
none of that release's fixes, so running it got the old broken behaviour.
`scripts/deprecated/` was retired with the Splunk stack; git history keeps
both.

## Checks

Run this before submitting anything:

```bash
./tests/run-checks.sh          # static checks; -v to see each one
```

It covers shell syntax, shellcheck, the collection's pinned requirements,
ansible-lint (production profile), repo-root path resolution, the Python
package's unit tests (when pytest is installed), version and documentation
consistency, evidence-gitignore coverage, secret patterns, and documentation
links. It exits non-zero on failure.

It does **not** test the pipeline — nothing does yet. That is the single most
valuable contribution available (see above), and it runs in CI on every push via
`.github/workflows/checks.yml`.

## Documentation

Docs drift badly in this repo — the rewrite fixed a batch of links pointing at
renamed or nonexistent files. If you rename a script or move a directory, grep
for it:

```bash
grep -rn "old-name" --include="*.md" .
```

Internal links are checked relative to the repo root; a link like
`/docs/Dir-Structure.md` must match the file's real case, or it breaks on
GitHub and on any case-sensitive filesystem.

## Commits and PRs

- Describe *why*, not just what. The reasoning is the part that isn't in the diff.
- Keep unrelated changes in separate commits.
- If something is too involved to finish, say so in the PR and add it to
  `project-progress.md` rather than leaving it undocumented.

## Licensing of contributions

By contributing you agree your work is licensed under the licence of the subtree
you touch: **MIT** for the `python/` package and the `get_sybers.dxdfir` collection
(`ansible/collections/`), and **Apache-2.0** — the repository default — everywhere
else. See the [Licence](/README.md#licence) section.
