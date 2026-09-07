# B4 — plaso drops REG_BINARY values before the pipeline can normalise them

**Status:** fixed at extraction time (see the fix below). Downstream decoding of the
recovered bytes into serial/MAC/disk-signature fields is still open (out of B4's scope).

The cross-source value hunt (`ports_serials.md`, `guids.md`) flagged that plaso renders
Windows registry **REG_BINARY** values as a size summary (`(6 bytes)`, `(224 bytes)`)
instead of the actual bytes, dropping forensically decisive device-identity values —
`MountedDevices` drive-letter → device bindings, disk signatures, USB/volume serials —
*before* the pipeline could normalise them. This documents exactly where that loss
happens, why it is an extraction-time (not output-time) loss, and the fix.

## Where the loss happens (exact, not inferred)

`log2timeline` (extraction), **not** psort (rendering). In the plaso image
(`plaso==20260720`), `plaso/parsers/winreg_plugins/interface.py`, method
`_GetValuesFromKey`:

```python
elif registry_value.DataIsInteger() or registry_value.DataIsString():
    value_string = str(value_object)
elif parser_mediator.extract_winreg_binary_values:
    value_string = registry_value.data            # raw bytes preserved
else:
    # Add a place holder for remaining types such as REG_BINARY and
    # REG_RESOURCE_REQUIREMENT_LIST.
    value_data_size = len(value_object)
    value_string = f"({value_data_size:d} bytes)"  # <-- the loss
```

`parser_mediator.extract_winreg_binary_values` is fed by the log2timeline CLI option
`--extract_winreg_binary` (`plaso/cli/helpers/extraction.py`), which **defaults to
False**. So by default REG_BINARY becomes the string `"(N bytes)"` and the raw bytes are
never written to the `.plaso` storage db. Because the loss is at parse time, **re-running
psort cannot recover the bytes** — they are not in the `.plaso` db. It has to be fixed on
the `log2timeline` step.

This path is taken by the **default** registry plugin (`winreg_default`), which is what
handles `HKLM\System\MountedDevices` and generic `Tcpip`/device REG_BINARY values (no
dedicated plugin claims those keys). Note the `NetworkList` plugin (`networks.py`) already
decodes its own `DefaultGatewayMac` Signatures value to a hex MAC — that specific value is
not lost; the generic-binary loss is the MountedDevices / default-plugin surface.

The JSON output module was **already** capable of emitting the bytes: for
`windows:registry:key_value` (and `:service`), `plaso/output/shared_json.py`
`_FormatValues` base64url-encodes any value whose `data` is `bytes`. So no output-module
change is needed — the only thing missing was the extraction flag that puts real `bytes`
(instead of the `"(N bytes)"` string) into `event_data.values`.

## Real, reproduced example (before/after)

Source: `jo-2009-11-20-newComputer.E01` (the M57-JO image behind
`data_store/processed/log2timeline/jsonl/M57-JO.jsonl`). Extracted its
`\WINDOWS\system32\config\system` hive with `image_export.py` and parsed it twice.

Key `HKEY_LOCAL_MACHINE\System\MountedDevices`, value `\DosDevices\C:`:

**Before (default — matches the shipped M57-JO.jsonl):**
```json
{"data": "(12 bytes)", "data_type": "REG_BINARY", "name": "\\DosDevices\\C:"}
```

**After (`log2timeline.py --extract_winreg_binary`):**
```json
{"data": {"__encoding__": "base64url", "__type__": "bytes",
          "stream": "xIHEgQB-AAAAAAAA"}, "data_type": "REG_BINARY",
 "name": "\\DosDevices\\C:"}
```

`base64url("xIHEgQB-AAAAAAAA")` = `c4 81 c4 81 00 7e 00 00 00 00 00 00` — the 12 bytes are
the NTFS **disk signature `0x81C481C4`** (LE u32) + **partition offset `32256`** (LE u64),
which is exactly the `start_offset: 32256` in the event's own path spec. That is the value
that binds drive letter `C:` to the physical disk — previously thrown away as `(12 bytes)`.
The USB/removable entries in the same key (`\??\Volume{...}`, `\DosDevices\D:`) likewise
come back as their full byte streams (device-instance / volume-serial bytes), which is the
`MountedDevices` USB-serial binding the hunt called out.

## The fix

`python/get_sybers_dxdfir/plaso.py` — add `--extract_winreg_binary` to the `log2timeline`
argv in `run_plaso`. One option, no new dependency, no plaso patch. Covered by
`python/tests/test_plaso.py::test_run_plaso_log2timeline_extracts_winreg_binary`.

**Cost:** plaso warns `--extract_winreg_binary` "can make processing significantly slower".
That is the correct trade for a pipeline whose stated value is device crosslinking — the
alternative is permanent loss of the serial/MAC/disk-signature at extraction.

## Options evaluated

| option | verdict |
|---|---|
| psort output-format change / re-render existing `.plaso` | **No** — bytes aren't in the db when parsed without the flag; loss is upstream of psort. |
| A different psort output module | **No** — same reason; and `shared_json._FormatValues` already handles bytes. |
| Post-extraction re-read of specific keys via dfVFS/dfwinreg | Works but is a second bespoke pass; unnecessary given a first-class extraction flag exists. |
| **`log2timeline --extract_winreg_binary`** | **Chosen** — first-class, comprehensive over all default-plugin REG_BINARY, proven above. |

## Still open (downstream, not B4)

The recovered value is **base64url-encoded raw bytes**, not a decoded serial/MAC/disk
signature. Turning those bytes into normalised CAR fields (drive-letter→disk-signature,
`MountedDevices`→USB volume serial, gateway/creator MAC) is a normalisation step for the
CAR-crosslink epic — B4 only guarantees the bytes now survive extraction so that step is
possible at all.
