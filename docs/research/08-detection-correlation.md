# Step 08 — Detection ↔ CAR correlation

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** demonstrated end-to-end on `ls24-sample` (rests on [Step 03](03-network-identity.md) and [Step 07](07-detection-lane-wiring.md), both merged).

## The gap

The north star is not *"run MITRE's CAR analytics"* — it is to let **threat
detections light up behaviour over the cascaded, cross-source-resolved data**. A
hayabusa alert is one evtx record; a suricata alert is one IP 5-tuple. On their
own they say *what* fired, not *which entity* it belongs to across the rest of
the evidence. The point of CAR is to **expand a detection beyond its own source**
— to name the entity the alert touches, using everything the cascade resolved.

Until [Step 07](07-detection-lane-wiring.md), this couldn't even be attempted: the
detection lane was hollow (no wiring, no rulesets). With that fixed, the lane
produces real alerts, and Steps 1–3 give CAR the resolved identities to join them to.

## What we found

Running the detection lane on the `ls24-sample` collection with `--fetch`
(the wiring of [Step 07](07-detection-lane-wiring.md)):

- **ET Open provisioned** — `suricata.rules` = **144,271 rules** fetched (the
  Step 07 `--fetch` provisioning, live for the first time).
- **suricata: 14 alerts on the DFIRdump capture — every one on the C2 IP
  `100.101.0.42`:**
  - 10 × `ET INFO SSH-2.0-Go version string Observed in Network Traffic` (the Go SSH C2 client)
  - 2 × `ET SCAN NETWORK Outgoing Masscan detected`
  - 2 × `ET SCAN NETWORK Incoming Masscan detected`

  Suricata auto-derived the capture's tuning too: `HOME_NET`,
  `HTTP_SERVERS=[100.101.0.42]`, `DNS_SERVERS=[100.95.95.4]`.
- **hayabusa: 86 alerts on `DESKTOP-M913391`** — 46 × Sysmon EID 1 (process
  create) + 40 × EID 5 (terminate); the one high-severity alert is the
  DOSfuscated `"cmd /c"` execution (RecordID **5261**, ATT&CK **T1059**).

## The correlation

### Network — suricata ↔ CAR

| suricata (independent IDS) | CAR (from the same Zeek capture) |
|---|---|
| 14 alerts to/from **`100.101.0.42`** — masscan recon + a Go SSH C2 client | the flow to `100.101.0.42` resolves to **`dest_fqdn = scoring-c2.berylia.org`** (DNS + SNI, [Step 03](03-network-identity.md)) and carries the **`berylia.org`** certificate (x509) |

Suricata flags *"masscan + SSH C2 to an IP"*; CAR **names that IP as the C2
domain and its certificate**. The IDS supplies the verdict, the cascade supplies
the identity — the exact C2 chain the value hunt first spotted
(`scoring-c2.berylia.org → 100.101.0.42`), now corroborated by an independent
detector and joined to a named entity.

### Host — hayabusa ↔ CAR

Hayabusa's 86 **record-level** alerts normalize, through the evtx→CAR maps, into
**85 `process` objects** (a process's create + terminate fold into one identity
by ProcessGuid). The high T1059 alert (RecordID 5261) is a CAR `process` row
carrying its command line and — via `enrich` — its parent (`parent_guid`) and
any spoke events (files/registry/network) the same ProcessGuid touched. That is
the "expand beyond evtx": one alerted record becomes the process and its
behaviour graph.

## What it enables

This is the north star, realised on real data: **threat detections joined to the
cascaded, cross-source-resolved CAR entities.** A network alert on a bare IP
reads as a named C2 domain + cert; a host alert on one evtx record reads as a
process and its lineage. The same join keys generalise — a detection can be
pivoted to memory, disk, and registry evidence of the same entity wherever the
cascade resolved it.

It also sets up the *generative* half of the project: the behaviours these
detections light up over the cascade are exactly the shapes to **generate new CAR
analytics into** — codified against the broader set of mapped data sources, not
just the ones MITRE's stock analytics assume.

## Follow-ups

- **Same-host disk line-up on `lonewolf`.** `ls24-sample` is the network + evtx
  collection; the `lonewolf` disk (`DESKTOP-PM6C56D`) is disk-only, so its
  detections (hayabusa on image-extracted evtx + yara on the mounted disk) line
  up against the `lonewolf` CAR `car.db` ([Step 06](06-behaviour-timeline.md)) —
  a single-host correlation where cross-source convergence is fully in play.
- **yara/memory detections** (Volatility `vadyarascan` over `memdump.mem` with the
  DetectRaptor ruleset) — the memory-side detections, not yet run.
- **Sightings projection** — emit the detection↔entity joins as STIX Sightings of
  ATT&CK attack-patterns over the spindle-identified observed-data (the behaviour
  timeline as the primary axis).
