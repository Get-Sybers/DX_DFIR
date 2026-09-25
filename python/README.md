# get_sybers_dxdfir

The host-side Python of the DX_DFIR pipeline as an importable, unit-tested
package. It runs **no container**: every tool lane is an Ansible role of the
`get_sybers.dxdfir` collection that builds its `docker run` from the tool's
GoDFIR-toolz `contract.yml`. What lives here is what the pipeline still needs on
the host:

| Module | Role |
|---|---|
| `get_sybers_dxdfir.images` | the tool-image supply-chain guard (`--require IMAGE` at every lane preflight, `--audit` for `dxdfir verify-images`), fed by the GoDFIR-toolz submodule's `images.yml` inventory |
| `get_sybers_dxdfir.signatures.detectraptor` / `.suricata_rules` | pinned, checksum-verified ruleset fetchers (DetectRaptor YARA, ET Open Suricata) that land operator rulesets for the `dxdfir_signatures` role to mount |
| `get_sybers_dxdfir.detect` | the Elastic detection rules-as-code (`detect/rules/`, ES|QL/EQL) and their loader/validator |
| `get_sybers_dxdfir.stix` | the STIX 2.1 / OpenCTI exchange verbs (`python -m get_sybers_dxdfir.stix`, driven by `dxdfir stix`) |

The user-facing **`dxdfir`** front-end is the Go binary built from `go/`.

## The `dxdfir` front-end (Go)
The verbs live in the Go binary (`go/` — see [its README](../go/README.md)); it
drives the collection with `ansible-playbook` and shells out to this package only
for the guard and the STIX verbs:
```bash
dxdfir process zeek                     # drive the dxdfir_zeek role (build → preflight → process → verify)
dxdfir process signatures -e '{"dxdfir_signatures_lanes":["yara"]}'
dxdfir build-car                        # normalise every processed source into per-source CAR stores
dxdfir verify-car                       # the CAR correctness gate over the materialised CAR
dxdfir build-docker                     # build (and hardening-verify) every get-sybers/* tool image
dxdfir validate                         # run the check harness
dxdfir list                             # list processable sources
man dxdfir                              # the manual (go/man/dxdfir.1)
```
`validate` runs the repo's check harness (`.github/tests/run-checks.sh`). The repo is
auto-detected (or pass `--repo-root` / `$DFIR_REPO_ROOT`).

## Install
```bash
pip install ./python          # the package (+ ansible-core, so ansible-playbook comes with it)
install -Dm644 go/man/dxdfir.1 ~/.local/share/man/man1/dxdfir.1   # optional: man page
```
The package installs no console script — the `dxdfir` command is the Go binary
(`scripts/setup-environment.sh` builds and installs it). In-repo runs need no
install — set `PYTHONPATH=python` (the roles do this via
`dxdfir_<source>_python_path`). Without installing the man page, read it directly with
`man ./go/man/dxdfir.1`.

## Test
```bash
cd python && PYTHONPATH=. python -m pytest        # unit tests (pure logic; no docker)
```
