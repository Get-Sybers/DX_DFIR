# Linting, conformance and the merge gate (GitHub CI/CD)
 
**Premise:** every public repository in `get-sybers` — Go module, shell scripts,
Ansible collection, container image — runs the same three gates: the commit
hook, the pull-request check, and the merge rule. The checks are native tools
run through their own hooks and actions; the only moving parts a repository
owns are a handful of **mandatory files** that drive them. This standard sits
beside 00–04 and the Go and Ansible standards: 02 defines *what* content must
satisfy, 03/04 the Ansible workflows, this one the whole pipeline and how it
stays current.
 
One sentence governs the rest: **a pull request is green when `make conform`
is green, a branch moves only through a reviewed and signed pull request, and
every version pin lives in exactly one file that a scheduled job can raise.**
 
Status: verified against upstream on 2026-10-09. Versions in [§9](#9-pinned-versions-in-this-release-of-the-standard).
 
## 1. The three gates
 
| Gate | Where | Runs | Blocks |
| --- | --- | --- | --- |
| **Local** | developer machine | `prek` hooks on `git commit` and `commit-msg`; `make conform` on demand | the commit (cheap lint, secrets, commit message) |
| **Pull request** | GitHub Actions, `CI` workflow | the common lint gate + the technology gate, both reusable workflows in `get-sybers/.github` | the status check `all_green` |
| **Merge** | repository ruleset `main` | pull request required, 1 approval from a **code owner**, last push approved, threads resolved, `all_green` passing, signed commits, linear history, squash only | the merge button |
 
After merge, four scheduled workflows keep the repository from going stale
([§6](#6-staleness-what-moves-versions-forward)): nightly external link check,
weekly pin refresh, weekly OpenSSF Scorecard, weekly container rebuild.
 
### What runs before a pull request
 
`prek install` once per clone. From then on every commit runs the hooks in
`.pre-commit-config.yaml` on the staged files, and the `commit-msg` hook rejects
a message that is not a Conventional Commit. `make conform` runs the full
technology gate locally — the same commands CI runs, with the same config
files — so a developer can see the PR result before opening it.
 
### What runs on the pull request
 
The repository's `.github/workflows/ci.yml` is a thin caller (installed from the
organisation's workflow templates). It calls two reusable workflows and defines
one job of its own:
 
```text
lint      (get-sybers/.github reusable-lint)      prek --all-files, offline links, gitleaks history, must-have files, PR title
<tech>    (get-sybers/.github reusable-go|shell|ansible|container)   make conform and the heavy tests
all_green needs: [lint, <tech>]  if: always()   fails when any required job failed or was cancelled
```
 
`all_green` is the one status check the ruleset requires. Adding or removing a
job changes `needs:` in the caller, never the ruleset.
 
### What the repository owner approves
 
- **Code review.** `CODEOWNERS` routes every file to `@get-sybers/maintainers`
  and the pipeline/pin files to `@get-sybers/owners`. The ruleset requires a
  code-owner approval and dismisses it when new commits arrive
  (`require_last_push_approval`), so the owner always approves the exact
  commits that merge.
- **Workflow runs from forks.** Public repositories run `pull_request` workflows
  from forks with a read-only token and no secrets. Set *Settings → Actions →
  General → "Require approval for all external contributors"*: the owner
  approves the run, then approves the code. `pull_request_target` is never used
  (GitHub blocks it by default in public repositories from 2026-11-02).
- **Version pins.** Dependabot and the weekly `Update pins` workflow open pull
  requests; nothing lands unless the owner approves and `all_green` passes.
## 2. Mandatory files
 
The workflow templates contain no configuration of their own. Everything they
do is driven by the files below, which is why a change to a linter, a pin or a
platform is a reviewed diff in the repository, not an edit to CI.
 
### 2.1 Every repository (git level)
 
| File | Read by | Drives |
| --- | --- | --- |
| `.pre-commit-config.yaml` | prek (local), `reusable-lint` (CI), `lint-versions` action | **the single source of linter versions**; the hook set; CI reads `rev:` pins for golangci-lint, ansible-lint, hadolint, gitleaks, actionlint, pinact |
| `.editorconfig` | editors, editorconfig-checker, **shfmt** (`[[shell]]` section) | indentation, newlines, charset; every shfmt formatting flag |
| `.gitattributes` | git | LF normalisation, binary marks, `export-ignore` for CI scaffolding, linguist hints |
| `.gitignore` | git | secrets never staged (`.env`, keys, vault passwords), tool caches, build output |
| `.yamllint` | yamllint hook, ansible-lint's `yaml` rule | YAML style (ansible-standards §16); `truthy.check-keys: false` keeps GitHub's `on:` legal |
| `.markdownlint-cli2.yaml` | markdownlint-cli2 hook | Markdown style: ATX headings, dash lists, fenced code with a language, no bare URLs |
| `lychee.toml` + `.lycheeignore` | lychee (PR offline, nightly online) | link-check inputs, retries, accepted codes, per-host rate limits, justified exclusions |
| `.gitleaks.toml` + `.gitleaksignore` | gitleaks hook and CI | secret-scanning rules (default set extended, never replaced), fixture allowlists |
| `.shellcheckrc` | shellcheck hook, `make conform` | `enable=all` minus three documented noise checks, `source-path` for sourced helpers |
| `.pinact.yaml` | pinact hook and CI | every `uses:` is a full SHA with a version comment; the two documented `@main` exceptions |
| `.github/zizmor.yml` | zizmor hook | workflow security policy; hash-pin everything except the same two exceptions |
| `.github/CODEOWNERS` | GitHub | who must approve what |
| `.github/dependabot.yml` | Dependabot | weekly updates for actions, Go modules, pip, Docker base images, 7-day cooldown, grouped PRs |
| `.github/rulesets/main.json`, `tags.json` | `scripts/apply-rulesets.sh` → GitHub API | the merge rule and immutable `v*` tags (importable in the UI too) |
| `.github/pull_request_template.md` | GitHub | the checklist a PR author ticks |
| `.github/workflows/ci.yml`, `links.yml`, `update.yml`, `scorecard.yml` | GitHub Actions | thin callers of the reusable workflows |
| `LICENSE`, `README.md`, `CHANGELOG.md` (Keep a Changelog), `SECURITY.md` | humans, the `structure` job | repository hygiene (Go §13, Ansible §14) |
 
### 2.2 Go module (go-standards)
 
| File | Read by | Drives |
| --- | --- | --- |
| `go.mod` (+ `go.work` for co-developed modules) | `actions/setup-go` (`go-version-file`), Dependabot `gomod`, structlint | the Go version, dependencies, module path `github.com/get-sybers/<repo>` |
| `.golangci.yml` (v2) | golangci-lint hook, action and `make lint`; `golangci-lint config verify` | linters, formatters (gofmt + goimports), depguard (no assertion libraries, §11), gochecknoglobals (§5), errorlint (§10) |
| `Makefile` | `make conform` locally and in CI | the uniform targets `build test vet fmt fmt-check tidy generate conform upgrade` plus `lint structlint vuln` |
| `scripts/structlint.sh` | `make structlint` | §1 module path, §2 no sibling `replace`, §3 `cmd/` thin and `internal/` present, §6 no `Get*`, §7 no copied files, §11 no vendored assertion helpers |
| `.goreleaser.yaml` | `goreleaser check` and the release workflow | binaries per OS/arch, checksums, attested release assets |
 
### 2.3 Shell repository
 
| File | Read by | Drives |
| --- | --- | --- |
| `.shellcheckrc` | shellcheck | all optional checks on; see 2.1 |
| `.editorconfig` `[[shell]]` and `[*.bats]` | shfmt | 2-space indent, bash dialect, `binary_next_line`, `switch_case_indent`, `simplify`; bats dialect for tests |
| `Makefile` | `make conform` | `shfmt -d`, `shellcheck`, `bats` over every tracked script (`shfmt -f` finds them by extension or shebang) |
| `test/*.bats`, `test/test_helper.bash` | bats-core (+ bats-support, bats-assert) | behavioural tests of `bin/` scripts |
 
### 2.4 Ansible collection (ansible-standards)
 
| File | Read by | Drives |
| --- | --- | --- |
| `galaxy.yml` | ansible-galaxy, galaxy-importer, `check_pins.py` | identity, `dependencies` bounded `>=x.y.z,<next-major` (§2), `build_ignore` so CI scaffolding never ships |
| `requirements.yml` | ansible-lint action (`requirements_file`), molecule `dependency`, `check_pins.py`, `upgrade_pins.py` | **the pin file**: exact `X.Y.Z` per collection; git sources at a tag or commit |
| `meta/runtime.yml` | ansible-core, `check_pins.py` | `requires_ansible` floor; every role's `min_ansible_version` must equal it |
| `.ansible-lint` | ansible-lint (hook, action, `make lint`) | `profile: production`, `strict: true`, var-naming pattern (§18/§28), `name[prefix]` enabled, no skip list |
| `tox.ini` | `tox -e lint` (standard 02) | lint env = `prek run --all-files` |
| `tox-ansible.ini` | tox-ansible via ansible-content-actions and the molecule job | the sanity/unit/integration/molecule matrix (skip everything below `requires_ansible`) |
| `requirements.txt`, `test-requirements.txt` | galaxy-importer, ansible-builder, tox-ansible | runtime Python deps of plugins; test tooling pins (tox-ansible, molecule, molecule-plugins, pytest-ansible, antsibull-changelog) |
| `changelogs/config.yaml`, `changelogs/fragments/` | antsibull-changelog, content-actions `changelog` job | a fragment per change to plugins; `CHANGELOG.rst` generated at release |
| `extensions/molecule/<scenario>/` | molecule (podman) | converge, idempotence, verify, plus the mandatory negative scenario (§12) |
| `scripts/check_pins.py`, `scripts/upgrade_pins.py` | hook, CI `pins` job, `Update pins` workflow | the §13 pin gate and the §13 `upgrade` |
| `Makefile` | `make conform` / `make upgrade` | lint, pins, one sanity env, molecule, changelog lint, artifact build |
 
### 2.5 Container image repository
 
| File | Read by | Drives |
| --- | --- | --- |
| `Dockerfile` / `Containerfile` | hadolint, buildx | multi-stage, cross-compiled (`--platform=$BUILDPLATFORM`), distroless non-root runtime, base images by tag + digest |
| `docker-bake.hcl` | `docker/bake-action`, `docker buildx bake` locally | targets, platforms, build args, GHA cache; `docker-metadata-action` target receives tags/labels |
| `.hadolint.yaml` | hadolint hook and CI | failure threshold, trusted registries, no ignored rules by default |
| `.dockerignore` | buildx | the build context: no `.git`, no CI files, no secrets |
| `execution-environment.yml` + `bindep.txt` (optional) | ansible-builder in CI (`ee-file` input) | an Ansible execution environment built from `requirements.yml` / `requirements.txt` on a free base image |
 
## 3. The checks, one by one
 
Every row names the tool, where its configuration lives, where it runs, and
how a legitimate exception is recorded. "Hook" = `.pre-commit-config.yaml`
(local and the CI `prek` job); "CI" = a dedicated job in a reusable workflow.
 
### 3.1 Common gate (`reusable-lint`)
 
| Check | Tool / config | Hook | CI | Catches | Exception |
| --- | --- | --- | --- | --- | --- |
| git hygiene | `pre-commit-hooks`: large files, case conflicts, merge markers, symlinks, shebang/executable agreement, private keys, EOF/EOL, no commits to `main` | yes | prek job | the classic accidents | hook `exclude:` with a comment |
| **permalinks** | `check-vcs-permalinks` | yes | prek job | a GitHub file link with a `#L123` anchor that points at a branch instead of a commit — the link rots on the next edit | none; use the `y` key on GitHub to get the permalink |
| editorconfig | editorconfig-checker / `.editorconfig` | yes | prek job | indentation, trailing whitespace, missing final newline | `[path]` section with `unset` |
| YAML | yamllint `--strict` / `.yamllint` | yes | prek job | §16 style, octal values, truthy spellings | `# yamllint disable-line rule:<id>` |
| Markdown | markdownlint-cli2 / `.markdownlint-cli2.yaml` | yes | prek job | heading/list style, fences without a language, bare URLs | `<!-- markdownlint-disable-next-line MDxxx -->` |
| shell | shellcheck / `.shellcheckrc`; shfmt / `.editorconfig` | yes | prek job, `make conform` | every script by extension or shebang | `# shellcheck disable=SCxxxx # reason` inline only |
| **secrets** | gitleaks / `.gitleaks.toml` | staged diff | full history (`gitleaks git`) | committed credentials; the CI run walks every commit of the branch | `.gitleaksignore` fingerprint or `gitleaks:allow` with a reason |
| workflow syntax | actionlint | yes | prek job; templates job in the `.github` repo | invalid keys, bad expressions, shellcheck of `run:` scripts | `actionlint -ignore` is not used |
| workflow security | zizmor / `.github/zizmor.yml` | yes | prek job | script injection, excessive permissions, unpinned actions, cache poisoning, dangerous triggers | `rules.<audit>.ignore` with a comment |
| action pinning | pinact / `.pinact.yaml` | yes | prek job | any `uses:` that is not `owner/repo@<40-hex> # vX.Y.Z` | `ignore_actions` (only the two documented) |
| schemas | check-jsonschema | yes | prek job | `dependabot.yml` and workflow files against GitHub's schemas | none |
| **links (offline)** | lychee `--offline --include-fragments` / `lychee.toml` | no | `links` job | relative links, file paths, `#anchors` inside the repo; deterministic, so it is a required check | `.lycheeignore` |
| structure | shell step | no | `structure` job | a missing must-have file; `CHANGELOG.md` without an `## [Unreleased]` section | add the file |
| PR title | regex on `github.event.pull_request.title` | `commit-msg` hook locally | `pr-title` job | a title that is not `type(scope): summary`; squash merges use it as the commit message | none |
 
### 3.2 Go gate (`reusable-go`, `make conform`)
 
| Check | Catches | Standard |
| --- | --- | --- |
| `gofmt -l`, `golangci-lint fmt --diff` (gofmt + goimports, local prefix `github.com/get-sybers`) | unformatted or mis-grouped imports | §12 |
| `go vet ./...` (all analysers incl. shadow) | suspicious constructs | §12 |
| `go build ./...`, `go test -count=1 -shuffle=on -cover ./...`, plus `-race` where cgo exists | broken build, failing or order-dependent tests | §11, §12 |
| `go mod tidy -diff` | go.mod/go.sum drift | §4 |
| `go generate ./...` then `git diff --exit-code` | stale generated artifacts (the data-file drift check of §5) | §5, §12 |
| golangci-lint (`.golangci.yml`, `config verify`) | standard set + depguard, errorlint, gochecknoglobals, gocritic, gosec, revive, misspell(UK), nolintlint (every `//nolint` needs a reason) | §5, §10, §11 |
| `scripts/structlint.sh` | module path and casing, local `replace`, `package main` outside `cmd/`, no `internal/`, `Get*` names, byte-identical files in two places, vendored assertion helpers | §1, §2, §3, §6, §7, §11 |
| `GOWORK=off go build && go test` on `ubuntu-24.04` and `ubuntu-24.04-arm` | a module that only builds inside the workspace; an arch-specific break | §2 |
| govulncheck (official action) | known vulnerabilities reachable from the module | §12 |
 
### 3.3 Shell gate (`reusable-shell`, `make conform`)
 
`shfmt -d` (flags from `.editorconfig`), `shellcheck` with `enable=all`
(`.shellcheckrc`), `bats --recursive test`. The pinned shellcheck is
installed from its release tarball because the runner image ships 0.9.
 
### 3.4 Ansible gate (`reusable-ansible`, `make conform`)
 
| Check | Tool | Catches | Standard |
| --- | --- | --- | --- |
| ansible-lint | official `ansible/ansible-lint` action, version from the hook `rev:`, `requirements_file: requirements.yml` | everything in the `production` profile, strictly: FQCN, naming, `no-changed-when`, `no-log`, `risky-file-permissions`, deprecated syntax, YAML style | §16–§18, §2 |
| pins | `scripts/check_pins.py --resolve-git` | a `galaxy.yml` dependency without an exact `requirements.yml` pin, a pin outside its bound, an unbounded `*`, a git ref that is a branch or does not resolve, a role whose `min_ansible_version` disagrees with `requires_ansible`, a role dependency carrying a version | §2, §3, §13, §25 |
| changelog | content-actions `changelog.yaml` | a plugin change without a `changelogs/fragments/*.yml` | §2 |
| build + import | content-actions `build_import.yaml` (galaxy-importer) | an artifact Galaxy would reject | 04 |
| sanity / unit / integration | content-actions `sanity.yaml`, `unit.yaml`, `integration.yaml`; matrix from `tox-ansible.ini` | `ansible-test sanity`, pytest units, integration targets across the supported core × Python versions | 02, 03 |
| molecule | tox-ansible `--matrix-scope molecule`, podman driver | converge, **idempotence** (second run reports zero changed), verify assertions, the **negative** scenario | §7, §12 |
 
### 3.5 Container gate (`reusable-container`)
 
Pull request: hadolint → `bake` for one platform, loaded locally → trivy
(`CRITICAL,HIGH`, unfixed ignored) must pass. Default branch, tags and the
weekly rebuild: hadolint → multi-platform `bake` pushed to
`ghcr.io/get-sybers/<repo>` with buildx provenance (`mode=max`) → trivy table
gate + SARIF to code scanning → syft SBOM (SPDX JSON, uploaded as artifact and
release asset) → `cosign sign` and `cosign attest --type spdxjson` on the digest
→ GitHub build-provenance and SBOM attestations pushed to the registry.
(ansible-standards §32.) Verification:
 
```sh
gh attestation verify oci://ghcr.io/get-sybers/<repo>@sha256:<digest> -R get-sybers/<repo>
cosign verify ghcr.io/get-sybers/<repo>@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/get-sybers/\.github/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
 
The signing identity is the *reusable workflow* in `get-sybers/.github`, which
is why the regexp names that repository.
 
Tags: `vX.Y.Z`, `X.Y`, `X` on release tags; `main` and `latest` follow the
default branch; `sha-<full commit>` on every push; `pr-<n>` is built but never
pushed. Consumers pin a digest or a `vX.Y.Z` tag, never `latest`.
 
## 4. The merge rule (owner approval)
 
`.github/rulesets/main.json`, applied with `scripts/apply-rulesets.sh
get-sybers/<repo>` (or imported in *Settings → Rules → New ruleset → Import*):
 
- target `~DEFAULT_BRANCH`; no bypass actors;
- `deletion`, `non_fast_forward`, `required_linear_history`, `required_signatures`;
- `pull_request`: 1 approval, code-owner review, dismiss stale reviews, last
  push approved, review threads resolved, **squash only** (GitHub signs the
  squash commit, so `required_signatures` holds without every contributor
  signing; squash keeps the Conventional-Commit PR title as the commit);
- `required_status_checks`: `all_green` from GitHub Actions
  (`integration_id` 15368 so an app cannot impersonate it), strict (the branch
  must be up to date).
`.github/rulesets/tags.json` makes `v*` tags immutable (no update, no
deletion). Turn on **release immutability** in repository settings as well; it
locks assets and adds a release attestation.
 
**Plan limits.** Organisation-level rulesets and "require workflows to pass"
need GitHub Team/Enterprise; on the Free plan, rulesets exist per repository.
The organisation therefore enforces the standard through three things it does
control: the `.github` repository (templates + reusable workflows), the
`structure` job (which fails a PR when a must-have file is missing), and
`scripts/apply-rulesets.sh` run at bootstrap. OpenSSF Scorecard reports a
repository that drifts from this.
 
## 5. Project structure standards followed
 
- **Organisation `.github` repository** — GitHub's community-health
  convention: `workflow-templates/<name>.yml` + `<name>.properties.json`
  (shown under *Actions → New workflow* for every repository),
  `.github/workflows/reusable-*.yml`, `.github/actions/<name>/action.yml`,
  default `CODEOWNERS`, `SECURITY.md`.
- **Go** — the official module layout (`cmd/<name>/main.go`, `internal/<pkg>/`,
  `testdata/` goldens) as fixed by go-standards §3; `.golangci.yml` v2.
- **Ansible** — the `ansible-creator` collection layout: `plugins/`, `roles/`,
  `meta/runtime.yml`, `tests/{unit,integration}`, `extensions/molecule/`,
  `changelogs/`, `tox-ansible.ini`, `test-requirements.txt`.
- **Shell** — `bin/` (executables, no extension), `lib/*.sh` (sourced
  helpers), `test/*.bats` with `test_helper.bash` (bats-core convention).
- **Containers** — `Dockerfile` at the root, `docker-bake.hcl` beside it,
  OCI labels from `docker/metadata-action`.
- **Cross-cutting** — EditorConfig, Keep a Changelog, Semantic Versioning,
  Conventional Commits, SPDX licence identifiers.
## 6. Staleness: what moves versions forward
 
| Pin | Lives in | Raised by | Cadence | Gate |
| --- | --- | --- | --- | --- |
| GitHub Actions (SHA + `# vX.Y.Z`) | the reusable workflows in `get-sybers/.github` (once for every repo) and each repo's thin callers | Dependabot `github-actions`, 7-day cooldown, grouped | weekly | PR + `all_green`; pinact refuses an unpinned ref |
| Linters and hooks | `.pre-commit-config.yaml` `rev:` | `prek update --cooldown-days 7` in the `Update pins` workflow | weekly | the same PR runs the hooks it just bumped |
| Go directive and modules | `go.mod` / `go.sum` | Dependabot `gomod` (minor/patch grouped) and `make upgrade` (`go get go@latest`, `go get -u -t ./...`) | weekly | `make conform` |
| Python test tooling | `test-requirements.txt`, `requirements.txt` | Dependabot `pip` | weekly | sanity/unit/molecule |
| Collections | `requirements.yml` | `scripts/upgrade_pins.py` (highest release inside the `galaxy.yml` bound; newest tag for git sources) | weekly | `check_pins.py`, sanity, molecule |
| Base images | `Dockerfile`, `execution-environment.yml` | Dependabot `docker` (tag and digest) | weekly | hadolint, build, trivy |
| Published image contents | the registry | the `CI` workflow's weekly schedule rebuilds `main` so base-image patches land without a code change | weekly | trivy gate |
| Vulnerability databases | — | govulncheck and trivy always run against the current database; the nightly/weekly schedules surface new CVEs on an unchanged tree | nightly (Ansible, Go weekday) | the scheduled run fails visibly |
| External links | docs | nightly lychee; one "Link checker report" issue updated in place | nightly | issue + failed scheduled run |
| Posture | — | OpenSSF Scorecard | weekly | Security tab |
 
Rules that keep this honest: a version literal lives in one file (never in a
workflow, a Makefile or a README); every raise is a pull request that the
normal gate judges; every raise waits seven days after the upstream release
(Dependabot `cooldown`, `prek update --cooldown-days`, pinact `min_age`).
 
## 7. Broken git links, specifically
 
- Links to a file *and line* on GitHub must be permalinks (commit SHA):
  `check-vcs-permalinks`, on every commit.
- Links inside the repository (relative paths, anchors) are checked offline on
  every pull request and are a required check.
- Links to anything external — upstream repos, tags, Galaxy pages, docs — are
  checked nightly with a GitHub token (no anonymous rate limit), cached for a
  day, and reported in one issue.
- Git references in `requirements.yml` must be a tag or a 40-character commit
  SHA, and `check_pins.py --resolve-git` proves the tag exists (`git ls-remote`)
  or the commit is fetchable.
- References to our own reusable workflows and to `ansible-content-actions` are
  `@main` by policy (recorded in `.pinact.yaml` and `.github/zizmor.yml`); every
  other `uses:` is a SHA, so a deleted or moved tag upstream cannot break a
  build silently.
## 8. Decisions and tensions (read before changing anything)
 
1. **Task names.** ansible-lint's production profile requires names to start
   with an upper-case letter (`name[casing]`), and only recognises a prefix in
   a role's *stage* files (`tasks/<stage>.yml`, never `tasks/main.yml` or a
   playbook). The sanctioned shape is therefore `<stage> | Description` in
   stage files and `Description` elsewhere, with `name[prefix]` enabled.
   ansible-standards §11 says "lowercase description"; §16 says the lint
   profile is the law. **Amend §11 to the capitalised form** rather than
   skipping the rule.
2. **Molecule location.** Inside a collection the scenarios live at
   `extensions/molecule/<scenario>/` (ansible-creator layout; tox-ansible and
   `molecule test --all` find them there). §3's `molecule/default/` per role
   applies to a standalone role repository.
3. **`@main` references.** `get-sybers/.github` reusable workflows and composite
   actions are referenced by branch so one fix propagates to every repository
   without a fan-out of Dependabot PRs; the SHA pins of all third-party actions
   live inside those reusable workflows and are bumped there, once.
   `ansible/ansible-content-actions` is supported upstream at `@main` only.
   Both exceptions are declared in `.pinact.yaml` and `.github/zizmor.yml`.
4. **gitleaks.** The `gitleaks-action` requires a licence key for organisation
   repositories; the MIT binary does not, so CI runs the binary. gitleaks is
   feature-complete upstream (successor: betterleaks); revisit when the
   pre-commit hook moves.
5. **`latest` tag** follows the default branch, not the newest release.
   Consumers pin `vX.Y.Z` or a digest.
6. **govulncheck at `@latest`** is deliberate: a vulnerability checker's value
   is the freshness of its database. Pin it as a `tool` directive in `go.mod`
   if reproducibility matters more.
7. **tox-ansible.ini** is kept (standard 02/03 and content-actions default)
   although `pyproject.toml [tool.tox-ansible]` is now upstream's recommended
   home; if both exist the TOML wins, so do not add both.
8. **Container PR builds** are single-platform and loaded locally because the
   docker exporter cannot load a manifest list; the push builds are
   multi-platform under QEMU. For Python/dnf-heavy execution environments add
   `linux/arm64` only when the build time is acceptable, or move to native
   `ubuntu-24.04-arm` runners (free for public repositories).
9. **`$/` self-repository syntax.** GitHub's new form for in-repo references
   (July 2026) is not yet accepted by actionlint; the `.github` repository
   keeps `./` and ignores zizmor's `self-repository` hint until it is.
10. **Update PRs and CI.** A pull request opened with `GITHUB_TOKEN` does not
    trigger `pull_request` workflows. Configure a GitHub App
    (`BOT_APP_ID`/`BOT_APP_PRIVATE_KEY` secrets) so the weekly PR runs CI;
    otherwise close and reopen it once.
## 9. Pinned versions in this release of the standard
 
Resolved on 2026-10-09; Dependabot and `prek update` move them from here.
 
| Component | Version |
| --- | --- |
| actions/checkout · setup-go · setup-python · cache · upload-artifact · download-artifact · attest | v7.0.1 · v7.0.0 · v7.0.0 · v6.1.0 · v7.0.2 · v8.0.2 · v4.2.2 |
| golangci-lint / golangci-lint-action / govulncheck-action / goreleaser-action | v2.14.0 / v9.3.0 / v1.1.0 / v7.2.3 |
| shellcheck / shfmt / bats-core / bats-action | v0.11.0 / v3.14.1 / 1.14.0 / 4.0.0 |
| ansible-lint (action + hook) / ansible-core / tox-ansible / molecule / molecule-plugins / antsibull-changelog | v26.9.0 / 2.21.5 / 26.9.0 / 26.9.0 / 26.9.28 / 0.35.1 |
| docker setup-qemu · setup-buildx · login · metadata · bake | v4.4.0 · v4.4.1 · v4.6.0 · v6.2.0 · v7.4.0 |
| hadolint / trivy-action / anchore sbom-action / cosign-installer (cosign 3.x) | v2.15.1 / v0.36.0 / v0.24.3 / v4.1.2 |
| lychee / lychee-action / markdownlint-cli2 / yamllint / editorconfig-checker.python | v0.24.2 / v2.9.0 / v0.23.3 / v1.38.0 / 3.11.1 |
| actionlint / zizmor / pinact / gitleaks / check-jsonschema / conventional-pre-commit | v1.7.12 / v1.30.1 / v4.1.1 / v8.30.1 / 0.38.2 / v4.4.0 |
| prek / prek-action / pre-commit-hooks | 0.5.5 / v3.0.1 / v6.0.0 |
| ossf/scorecard-action / codeql-action (upload-sarif) / create-pull-request / create-issue-from-file / create-github-app-token | v2.4.4 / v4.38.3 / v8.1.1 / v5.0.1 / v3.2.0 |
| Runners | `ubuntu-24.04`, `ubuntu-24.04-arm` (free for public repositories) |
 
## 10. Bootstrapping
 
**Organisation, once.** Create the public `get-sybers/.github` repository from
`dot-github-repo/`, create the teams `owners` and `maintainers`, and run
`scripts/apply-rulesets.sh get-sybers/.github`. Optionally create a GitHub App
for the update PRs and add its id/key as organisation secrets.
 
**Each repository.**
 
```sh
scripts/apply-template.sh <go|shell|ansible|container> <path-to-repo>
cd <path-to-repo>
# edit: REPO placeholders, team slugs, go.mod / galaxy.yml names, LICENSE
prek install && prek run --all-files
make conform
scripts/apply-rulesets.sh get-sybers/<repo>
```
 
Then in the repository settings: *Actions → Require approval for all external
contributors*; *Releases → Enable release immutability*; *Code security →
secret scanning + push protection, Dependabot alerts*. For a collection,
create the `release` environment with `ANSIBLE_GALAXY_API_KEY` (standard 04).
 
## Appendix A — sources
 
- GitHub Docs: workflow templates, reusing workflows, rulesets (available rules,
  REST import), managing Actions settings for a repository (fork approvals),
  secure use of Actions, artifact attestations, immutable releases, GitHub
  Packages container registry, Dependabot options reference.
- GitHub Blog changelog: `pull_request_target` default-branch behaviour
  (2025-11), safer checkout defaults (2026-06), self-repository `uses` syntax
  (2026-07).
- `actions/runner-images` Ubuntu 24.04 README (preinstalled tool versions).
- ansible/ansible-lint (`action.yml`, `.pre-commit-hooks.yaml`, `rules/name.py`,
  `profiles.yml`), ansible/ansible-content-actions (workflows, README),
  ansible/tox-ansible docs, ansible/molecule docs, ansible/ansible-creator
  collection template, ansible-documentation (requirements.yml, galaxy.yml,
  `ansible-test sanity`), ansible/ansible-builder docs.
- golangci-lint configuration and migration guides, golangci-lint-action,
  golang/govulncheck-action, Go module reference (`go get -tool`, `tidy -diff`).
- koalaman/shellcheck wiki (Directive, Optional), mvdan/sh man page
  (EditorConfig support), scop/pre-commit-shfmt, shellcheck-py, bats-core.
- docker/metadata-action, docker/bake-action, docker/build-push-action READMEs;
  Docker docs on multi-platform CI and attestations; hadolint; aquasecurity
  trivy-action; anchore sbom-action; sigstore cosign README.
- lycheeverse/lychee (`lychee.example.toml`), DavidAnson/markdownlint-cli2,
  rhysd/actionlint usage, zizmorcore/zizmor configuration and audits,
  suzuki-shunsuke/pinact config, gitleaks README and licence, j178/prek CLI
  reference, python-jsonschema/check-jsonschema, compilerla/conventional-pre-commit,
  pre-commit/pre-commit-hooks (`check_vcs_permalinks.py`).