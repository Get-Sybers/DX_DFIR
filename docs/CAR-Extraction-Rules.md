# CAR extraction rules

The MITRE CAR data model is DX_DFIR's extraction target. The CAR objects, their
fields and their canonical actions are reconstructed from the pinned `car`
submodule (the forked MITRE model we own), and the engine ([byakugan](https://github.com/Get-Sybers/byakugan), formerly PIIAT-MitreCar)
normalises every artefact into finished CAR events against it. These four
principles govern how each CAR object is built.

## 1. CAR is the extraction goal — exhaustively, per artefact

For every artefact, for every CAR object it can represent, extract **every
canonical CAR field the artefact is capable of supplying** — whatever the
artefact calls it natively. Completeness is measured **per artefact against the
model** ("which of this object's fields does this artefact fill?"), not "does the
object have any rows?". Sysmon's `Hashes` → `md5_hash`/`sha1_hash`/`sha256_hash`;
Security 4688's `SubjectUserSid` → `sid`. A canonical field is never left null
when the artefact carries the data.

## 2. Fill the CAR object — additive, never faked

Filling the canonical fields is the goal, not a rule that strips the row. Each
event carries its canonical CAR fields **plus** its native evidence — the latter
in the `native` object, never lost. Data an artefact has but CAR has no field for
stays in `native`; it is never dressed up as a canonical-looking column. Use the
exact canonical names (`tgt_pid`, not `target_pid`; `image_path`, not
`module_path` on service/driver), and `car_action` must be one of the object's
canonical actions.

## 3. One artefact per object, tied to identity

Each object is sourced from a **single authoritative artefact** that natively
provides the whole object with its identity fields — never assembled from
fragments of many artefacts. Populate every identity field the artefact provides;
where it genuinely lacks one, it stays null (an honest gap), never faked.

| Object | Canonical identity fields |
| --- | --- |
| process, flow, file, registry, service | `fqdn`, `hostname`, `user` |
| thread | `hostname`, `user` |
| module, driver | `hostname`, `fqdn` |
| user_session | `hostname`, `user`, `login_id` |

## 4. Combine downstream, only if joinable

Bringing observations together — across artefacts (same object) or across objects
(correlation) — is a **separate downstream stage**, done only where a shared
identity key (`hostname`/`user`/`login_id`/`guid`/`pid`/time) actually allows the
join. It is never baked into the base object. The within-source enrichment cascade
is described in [CAR-Relations.md](CAR-Relations.md); the optional cross-source
aggregate stage in [CAR-CrossSource.md](CAR-CrossSource.md).

## Where this lives

Extraction runs in the engine, one map per artefact family, producing per-source
CAR stores and the materialised `car_<object>.jsonl` every sink reads (see
[CAR-Pipeline.md](CAR-Pipeline.md)). The four principles hold regardless of
backend, so the per-artefact mapping work is portable if the backend ever changes
— as it did when the Kusto emulator gave way to the Elastic-native stack.
