# EvtxECmd — no longer needed (replaced by goevtx)

> **This directory is obsolete.** The `dxdfir_evtx` lane no longer runs EvtxECmd
> (.NET). Windows Event Logs are parsed by **goevtx** — a static-Go EvtxECmd
> substitute on Velociraptor's go-evtx, built `FROM scratch` as
> [`get-sybers/goevtx`](https://github.com/Get-Sybers/GoDFIR-toolz/tree/main/goevtx).
> There is no `EvtxECmd.dll` to download and nothing to place here.

Build the image once (the `dxdfir_images` role does this for you):

```bash
docker build -t get-sybers/goevtx:latest \
  -f third_party/GoDFIR-toolz/goevtx/Dockerfile third_party/GoDFIR-toolz/goevtx
```

goevtx emits the same `*_EvtxECmd_Output.json` shape the CAR lane consumes
(EventId, Provider, Channel, Computer, EventRecordId, TimeCreated, and the raw
EventData in Payload). It does not reproduce EvtxECmd's Maps layer
(`MapDescription` / `PayloadData1-6`) — byakugan reads the raw EventData, not
those derived columns.

The directory is kept only so existing references resolve; it holds no binaries.
