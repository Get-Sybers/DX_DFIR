# EvtxECmd

> **You usually don't need this directory.** The `dxdfir_evtx` role defaults to the
> **bundled** [`get-sybers/evtxecmd`](/third_party/EZTools-Docker/evtxecmd) image, which bakes `EvtxECmd.dll`
> + `Maps/` for you — `docker build -t get-sybers/evtxecmd:latest -f third_party/EZTools-Docker/evtxecmd/Dockerfile third_party/EZTools-Docker`. This
> dir is the **operator-supplied** fallback, used only when you run with
> `dxdfir_evtx_use_bundled_image=false`.

Extract the published EvtxECmd release here for the operator-supplied path. The
`get_sybers_dxdfir.evtx` processor mounts it read-only into a stock .NET runtime
container to turn raw `.evtx` into normalised JSON.

## Get it

- <https://github.com/EricZimmerman/evtx/releases>
- or <https://ericzimmerman.github.io/>

Take the **.NET** build — it runs on Linux inside a
`mcr.microsoft.com/dotnet/runtime:9.0` container (EvtxECmd's current build targets
net9.0), so `EvtxECmd.dll` is what's needed, not `EvtxECmd.exe`.

Expected layout (either works):

```
data_store/dependencies/evtxecmd/
├── EvtxECmd.dll
├── EvtxECmd.deps.json
├── EvtxECmd.runtimeconfig.json
└── Maps/
    └── *.map
```

## Include `Maps/`

Without the `Maps/` folder EvtxECmd still parses, but `MapDescription` comes out
empty — and that field is what `EvtxECmd_App` uses to populate CIM's
`signature`. You lose the human-readable "what this event means" summary.

Update the maps with `EvtxECmd.dll --sync` (needs network).

## Licence

**MIT** — Copyright (c) 2019 Eric Zimmerman.

Worth noting explicitly: EvtxECmd carries **no restriction on commercial
use** — one reason this project standardises on the EZ Tools (here directly,
and via the planned Velociraptor offline collectors) rather than KAPE, whose
Solo Edition EULA forbids business use. See
[THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

It is not vendored here for the same reason nothing else is: this project does
not redistribute other people's builds.

Binaries in this directory are gitignored. Only this README is tracked.
