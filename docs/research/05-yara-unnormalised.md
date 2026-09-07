# Step 05 — A YARA ruleset for unnormalised values (B5)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (PR #152, Copilot fixes in PR #154)

## The gap

The cross-source value hunt ([Step 04](04-plaso-binary-value-loss.md) and the
`docs/car-provenance/crosslink/*.md` notes) kept surfacing the same shape of
problem: a distinctive value is present in the raw/native artefact but is never
lifted into a CAR field, so it cannot be used as a cross-source join key.

The hunt had already produced roughly **30 YARA rule stubs**, but they were
scattered one-by-one across the crosslink notes (`cmdlines.md`, `guids.md`,
`host_ip.md`, `identity.md`, `ports_serials.md`). They were illustrative, not
runnable — you could not point them at a processed dataset and get a report of
what the pipeline had failed to normalise.

## What we found

The stubs fell into a small number of recurring value classes, each keyed to a
CAR field that *should* have received the value:

- **Host-identity GUIDs** — `MachineGuid`, interface GUIDs, Sysmon
  `ProcessGuid` lineage, scheduled-task GUIDs, imaging-tool GUIDs.
- **Volume / mount** identifiers.
- **MAC-bearing v1 GUIDs** — the node field of a time-based UUID is a real MAC.
- **Network 5-tuple** — IPv4, IPv6, MAC, hostname, ports.
- **Device serials** — e.g. `USBSTOR`.
- **Account / SID identity** — including usernames mined from `\Users\<name>\`.
- **Command-line** obfuscation, C2, and LOLBin indicators.

We also found a large volume of GUID-shaped noise that is *not* worth a rule:
COM CLSID / interface / TypeLib / AppID GUIDs, the OLE `c000-…-46` family, and
the `806e6f6e6963` synthetic-MAC placeholder. These are host-invariant or
constant, so they carry no linkage value.

## The fix

**PR #152** consolidated the scattered stubs into one reusable ruleset,
`docs/car-provenance/crosslink/unnormalised-values.yar` — **33 rules**: 23
general `Gap_*` rules plus 10 case-specific `HUNT_Case_*` rules across the
categories above. Every rule's `meta` block carries a **`car_gap`** tag naming
the CAR field or object the value should feed — so a hit reads as
"this value exists and belongs in *that* CAR field, but isn't there."

The suppressed-as-noise classes are documented explicitly with **no rules**
(COM CLSID/interface/TypeLib/AppID GUIDs, the OLE `c000-…-46` family, the
`806e6f6e6963` synthetic-MAC placeholder), so the omission is a decision on the
record rather than an oversight.

The ruleset compiles clean against **YARA 4.5.2** (the `dxdfir/yara` image).

**Copilot fixes (PR #154):**

- The SSH-port detector used a bare `":22"` string, which matched IPv6
  substrings and timestamps. It was replaced with an octet-validated IPv4
  endpoint regex that reuses `Gap_Net_IPv4_Address`, so a "port 22" hit is now
  anchored to a real IPv4 address.
- Multiple string declarations were split one-per-line for readability and to
  avoid ambiguous grouping.

## What it enables

Run the ruleset over any future processed dataset and it flags the distinctive
values the pipeline has *not* normalised — directly operationalising the user's
ask to "use YARA to limit missing non-normalised data." It turns the value hunt
from a manual reading exercise into a repeatable coverage check, and each hit's
`car_gap` tag points straight at the CAR field that needs a mapping.

## Follow-ups

- Feed confirmed `car_gap` hits back into the CAR mappers so recurring classes
  stop being gaps.
- Fold the ruleset into the detection lane once that lane is wired and carries
  real rulesets — see [Step 07](07-detection-lane-wiring.md).
