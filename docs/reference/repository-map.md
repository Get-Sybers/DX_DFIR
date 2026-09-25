# Repository map

DX_DFIR sits at the centre of a small family of [Get-Sybers](https://github.com/Get-Sybers)
repositories. This is what depends on what, and where each piece lives.

## The Get-Sybers ecosystem

```mermaid
flowchart TD
    DX["<b>DX_DFIR</b><br/>the pipeline"]
    BYA["byakugan<br/>CAR / STIX engine"]
    TOOLZ["GoDFIR-toolz<br/>the Go tool family + goevtx"]
    MEM["anamnesis<br/>MemProcFS (get-sybers/anamnesis)"]
    DX -->|"drives (get-sybers/byakugan image)"| BYA
    DX -->|"submodule docker/GoDFIR-toolz"| TOOLZ
    DX -->|"clone-at-build (Dockerfile ANAMNESIS_REF -> get-sybers/anamnesis)"| MEM
```

| Repository | Link | How DX_DFIR uses it |
|---|---|---|
| **byakugan** | [Get-Sybers/byakugan](https://github.com/Get-Sybers/byakugan) | The external CAR / STIX engine the [`dxdfir_byakugan` lane](../architecture/car-pipeline.md) drives. **Not vendored, not a host checkout** — it is cloned + built into the hardened `get-sybers/byakugan` image (`docker/GoDFIR-toolz/byakugan/Dockerfile`) at the exact sha pinned by `sources.yml`, by `dxdfir build-docker` (the [image build](../architecture/setup-flow.md)) alongside the other tool images. The lane only shells that image. |
| **GoDFIR-toolz** | [Get-Sybers/GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz) | Git submodule at `docker/GoDFIR-toolz`. The source for the static-Go tool family (gore, gomft, goese, goprefetch…), **goevtx** (the `.evtx` parser the [evtx lane](../architecture/processing-lanes.md) runs) and **godaemonhunter** (the Linux daemon-parser matrix — journal, auditd, logins, syslog, units, cron, shells — in one stream-called binary), plus the canonical hardening playbook. |
| **anamnesis** | [Get-Sybers/Anamnesis](https://github.com/Get-Sybers/Anamnesis) | Pure-Go memory-forensics tool (MemProcFS). No longer vendored — cloned + built into the hardened `get-sybers/anamnesis` image (`docker/GoDFIR-toolz/anamnesis/Dockerfile`) at the `sources.yml` pin; the [memory lane](../architecture/processing-lanes.md) docker-runs it. |

## In-repo layout

The full directory map is [Dir-Structure.md](../Dir-Structure.md). The pieces that matter:

| Path | What it is |
|---|---|
| `go/` | The [`dxdfir` Go front-end](go-standards.md) — CLI + TUI. |
| `python/get_sybers_dxdfir/` | The Python processing package (one module per lane) + `detect/` + `stix/`. |
| `ansible/collections/get_sybers.dxdfir/` | The [Ansible collection](ansible-standards.md) — roles + playbooks. |
| `docker/` | The GoDFIR-toolz submodule (every hardened tool-image build context, [Containers.md](../Containers.md)) + the `elastic/` compose stack ([the stack](../architecture/the-stack.md)). |
| `data_store/` | Evidence lifecycle: `raw/ → processed/ → processed/byakugan/` (git-ignored). |
| `scripts/` | Host provisioning + offline packaging ([overview](../scripts/Scripts-Overview.md)). |
| `.github/tests/` | The [check + smoke harnesses](build-and-test.md). |
| `images.yml` | The `get-sybers/*` tool-image inventory (names + build context/dockerfile/args) — the single source of truth both the Python guard (`get_sybers_dxdfir.images`) and the `dxdfir_images` role read. |
