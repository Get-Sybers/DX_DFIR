# Cross-source CAR correlation — the aggregate stage (deferred)

The optional, much-later stage that correlates memory + disk + network **across**
the per-source databases. It is deferred by design: nothing here runs until the
per-source model is complete and an explicit investigation-scope grouping exists.
It is documented so the analysis is not lost.

Per-source enrichment is self-contained (one source → one `car.db`, see
[CAR-Pipeline.md](CAR-Pipeline.md)) and its within-source inference cascade (see
[CAR-Relations.md](CAR-Relations.md)) stays entirely inside that one database.
This stage is the optional final correlation **across** those databases; it never
mixes into the per-source products.

## The sources may be completely unrelated origins (read first)

The processed tree is **not** one investigation by default — it is whatever
evidence was dropped in. The real batch corpus mixes genuinely unrelated
origins: LoneWolf (one Windows host), **M57** (a different case entirely —
2009 Jean laptop), **sysmon-attack-samples** (three more hosts: DC1 / IEWIN7 /
MSEDGEWIN10), the **2012 NGDC** network captures, and the pfsense / dualserver /
internaldns **appliances**. These belong to different machines, cases, and
years.

Consequence — the correctness risk that dominates every join below:

- A **well-known SID is machine-agnostic**. `S-1-5-18` (SYSTEM), `S-1-5-19/20`
  (LOCAL/NETWORK SERVICE), the RID-`500` Administrator, RID-`501` Guest, the
  BUILTIN aliases — all byte-identical on every Windows install ever made.
  Joining two sources on such a SID **fabricates** a relationship between
  unrelated evidence. (These are exactly the SIDs `relationships.yml`
  canonicalises *within* a source — within-source they dedupe an account;
  cross-source they are poison.)
- **Empty host collides.** The Linux/appliance sources all carry
  `source_host == ""`; a naive host-scoped join would fuse them into one
  phantom host.
- A **coincidental hostname or pid** proves nothing across origins.

So the cross-source stage must **never infer that two sources belong together**
from coincidental key overlap. Shared scope has to be asserted (an explicit
case/investigation grouping input), or positively derived and agreed
(matching machine GUID / domain SID / image identity) — never assumed. The safe
default is **no cross-source join** until scope is established. Every "possible"
verdict below is conditional on that.

## Data assessment (measured on the real per-source stores)

Nine real `car.db` sources from the batch run, plus the memory and godfir-toolz
stores. Key facts, measured:

**1. Host identity is fragmented across lanes — the master blocker.**
The SAME physical host (LoneWolf) renders differently per lane, and many
sources carry no host at all:

| source (LoneWolf host) | `source_host` values |
|---|---|
| event logs (goevtx) | `WIN-1M3263ACE5D`, `DESKTOP-PM6C56D` |
| godfir-toolz (SRUM/gore) | `LONEWOLF` (the `--host` arg), `desktop-pm6c56d` (from hive paths) |
| memory | its own image hostname |
| l2t dualserver / exfat / internaldns / pfsense | **empty** (Linux/appliance — no image_hostname) |
| zeek captures | the capture-dir label (`ngdc-exterior-…`), not a host |

So even for one host, no `source_host` value is shared across lanes. A
**host-identity reconciliation** (casefold + alias table + derive from the
image/`ComputerName` hive value, not an arbitrary `--host`) is prerequisite #1
for any host-scoped cross-source join.

**2. Process-instance identity does NOT share a namespace across lanes.**
Measured `guid` forms for a process create:

- event logs: `process-DESKTOP-PM6C56D-Security-2623` (audit-record identity)
- Sysmon: `dfae8213-70eb-5cdd-0000-0010f66d0a00` (the real ProcessGuid)
- memory: `proc-<_EPROCESS offset>`
- SRUM (godfir-toolz): **None** — SRUM has no process-instance identity at all

⇒ **No definitive cross-lane process-instance join exists.** A process seen in
two lanes cannot be proven the same instance by identity — only heuristically
(host + pid + create-time window), and only where BOTH lanes carry pid+time.

**3. SID is the one strong cross-lane key — fully populated.**

| | with SID/uid |
|---|---|
| event-log process | 40/40 |
| SRUM process | 15055/15055 |
| SRUM flow (uid) | 2358/2471 |
| event-log user_session (uid) | 875/880 |

A SID is a stable principal, so **(canonical host, SID) is a definitive
cross-lane USER-CONTEXT key** — it attributes events to the same account, not
to the same process instance.

**4. The strong within-source keys do not bridge lanes.** The LUID auth↔session
join is real (827 event-log auths carry `TargetLogonId`; owning_guid 692/880 on
sessions) but the LUID appears in **zero** SRUM/registry rows. Sysmon
ProcessGuid links are definitive but exist only inside the Sysmon source.

## Capability determination (per candidate join)

| # | cross-source join | possible? | tier | blocker / basis |
|---|---|---|---|---|
| A | **scope + host disambiguation** | prerequisite | — | NOT mere canonicalisation — must establish which sources share an origin and refuse to fuse unrelated ones (empty host, coincidental hostname); no positive match ⇒ no join |
| B | event ↔ **user context** by (scope, host, SID) | **yes, conditional** | **definitive within an established scope** | requires A AND excludes well-known/machine-agnostic SIDs (SYSTEM, LOCAL/NETWORK SERVICE, RID-500/501, BUILTIN); links account, not instance |
| C | process ↔ process across lanes by (host, pid, create-time window) | yes, narrow | **heuristic** | PID reuse; needs pid+time in BOTH lanes → only memory↔Sysmon↔event-log-4688; **SRUM excluded** (no pid) |
| D | process-instance join by shared **guid** across lanes | **no** | — | guids are per-lane namespaces (measured); no shared instance identity survives cross-lane |
| E | SRUM execution/flow ↔ host process instance | **no (instance)** / yes (user via B) | — | SRUM has no pid/guid and hourly-aggregate times; only user-context (B) is defensible |
| F | zeek flow ↔ host (5-tuple + time) | not in this corpus | heuristic | needs a host with network CAR in the same timeframe; the 2012 NGDC captures have no matching host source |
| G | file/registry/module ↔ its process across lanes | **no** | — | spokes carry no cross-lane process key; owning_guid is in-source only |

### Verdict
Cross-source enrichment is **fundamentally heuristic** between lanes, and only
*within an established shared scope* at all — the sources may be completely
unrelated origins, so the stage's first job is to refuse false joins. The only
*definitive* cross-lane relationship is **user-context by (scope, host, SID)**
(join B), and even that holds only once scope is established and machine-agnostic
SIDs are excluded. Everything process-instance-level is either heuristic and
narrow (C) or impossible (D, E-instance, G). Definitive linkage is a
WITHIN-source property (guid) and must stay there.

## Recommended scope for the enrichment stage (when built)

1. **Establish scope + host disambiguation first** (join A) — take an explicit
   case/investigation grouping (which sources belong together) rather than
   inferring it; canonicalise host only within a group; treat empty/ambiguous
   host as un-joinable, never as a match; also fixes the arbitrary `--host`.
2. **Implement join B** (user-context by scope + host + SID) — the one
   high-value definitive cross-lane enrichment — with a **well-known-SID
   deny-list** (reuse `relationships.yml` `well_known_sids`) so machine-agnostic
   principals never bridge sources.
3. **Implement join C** narrowly (heuristic, confidence-tagged, only within a
   scope and only pid+time-bearing lanes).
4. **Do NOT** attempt D/E-instance/G — they cannot be done honestly; leave the
   raw cross-lane evidence for analyst query instead.
5. **Fail safe**: with no scope input, the stage does nothing rather than guess.
6. Keep it an **opt-in end stage over the aggregate**; never mixed into a
   per-source `car.db`.

## Still to measure (Phase E field-coverage audit)
A per-(artefact × object) fill-rate audit across the full real corpus — pairs
with this assessment; not required to scope the joins above.
