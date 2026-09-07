# Step 04 — Preserving REG_BINARY bytes in the plaso lane (B4)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (PR #153)

## The gap

The plaso lane was silently discarding raw registry bytes. Plaso renders
Windows registry **`REG_BINARY`** values as a size summary — a literal string
like `(N bytes)` — instead of the bytes themselves. Crucially, this happens at
**`log2timeline` extraction time**, in
`plaso/parsers/winreg_plugins/interface.py`, *before* any normalization in our
pipeline can see the value. By the time a record reaches CAR mapping, the bytes
are already gone.

This is not a rendering choice we could undo downstream: re-running `psort`
cannot bring the bytes back, because the loss is at **extraction**, not at
output formatting. Whatever `log2timeline` did not store, `psort` has nothing to
render.

## What we found

The dropped `REG_BINARY` values are exactly the ones that carry hardware and
device identity — some of the most decisive evidence for tying a volume, a drive
letter, and a physical device together:

- **`MountedDevices`** blobs — the binding between a volume, its drive letter,
  and the USB serial of the device that mounted there.
- **`Tcpip`** device values.
- **`DefaultGatewayMac`** — a 6-byte gateway MAC address. (NetworkList decodes
  its own copy, but the `Tcpip`-side value was being lost.)

Each of these arrived as `(N bytes)` — a count, not content — leaving nothing
to normalize.

## The fix

**PR #153** added the `--extract_winreg_binary` flag to the `log2timeline`
invocation in `run_plaso` (`python/get_sybers_dxdfir/plaso.py`). With the flag
set, `log2timeline` retains the raw bytes, and because the JSON output module
already base64url-encodes `bytes` values, the bytes now survive intact through
to the JSON we ingest.

Concretely, `HKLM\System\MountedDevices` value `\DosDevices\C:` went from the
useless `"(12 bytes)"` to bytes that decode to:

```
c4 81 c4 81 00 7e 00 00 00 00 00 00
```

which is disk signature `0x81C481C4` followed by partition offset `32256` —
the actual volume-to-device binding, now recoverable.

## What it enables

The device-identity bytes now survive extraction and reach the pipeline as
base64url in the JSON output, so downstream normalization finally has something
to work with. The volume↔drive-letter↔USB-serial binding, the `Tcpip` device
values, and the gateway MAC are present rather than summarized away.

## Follow-ups

B4 only guarantees the bytes **survive extraction**. Decoding those raw bytes
into normalized CAR fields — a MAC field, a device-serial field, a disk
signature — is a separate downstream step still to be done. This step secures
the raw material; it does not yet model it.
