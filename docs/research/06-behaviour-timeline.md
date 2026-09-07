# Step 06 — The behaviour timeline (and psort vs CAR)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (timeline crash fix staged in the engine batch)

## The gap

The north star for this arc is **a timeline based on behaviour rather than
artefacts**. `piiat_mitrecar/timeline.py` builds it from `car.db` (with
`superset.db`): it walks the normalized CAR objects and the relationship edges
between them and emits them time-ordered — a behaviour view, not a per-parser
event dump.

Two things were unresolved: the timeline builder had never been run end-to-end
at scale, and there was an open question about how it relates to plaso's
`psort` super-timeline — whether the two are the same thing.

## What we found

**The first end-to-end run crashed.** `build_timeline` iterated over *every*
table in the database and assumed each carried the CAR header, so it died with
`no such column: timestamp` on PIIAT-Mem's auxiliary `image_context` table —
a table that legitimately has no timestamp column.

**psort and the CAR timeliner are different layers — not substitutes.** The
question got a concrete answer: plaso's `.plaso` storage file *is* itself a
SQLite database, and `psort` runs on it to produce the **artefact
super-timeline** — one row per parser event. The DX_DFIR plaso lane already
produces this. The CAR timeliner operates on a *different* schema: normalized,
cross-source CAR objects plus behaviour, stored in `car.db`. `psort` cannot
read `car.db` (wrong schema) and cannot read a memory image at all. The two are
**complementary**: artefact super-timeline underneath, behaviour timeline on
top.

## The fix

The crash fix (staged in the engine batch) makes `build_timeline`:

- **skip any table without a `timestamp` column**, so auxiliary tables like
  `image_context` no longer abort the run; and
- **escape the table identifier** before interpolating it into the query.

## What it enables

With the fix in place, the full **LoneWolf disk image** ran end to end:

- **4,169,774** plaso rows → **2,773,205** CAR events, in ~8 minutes, into a
  4.3 GB `car.db`.
- CAR event breakdown: registry **1,511,021** · file **1,253,881** · process
  **3,738** · http **2,012** · authentication **1,616** · user_session **880** ·
  service **57**, plus **4,723** relationships.
- Behaviour timeline: **2,701,408** time-ordered entries.

The user-from-path enrichment (A1) proved out at scale: it mined **`jcloudy` on
28,946 rows** where plaso's native username was `-` on essentially everything —
the enrichment paying for itself across the whole image.

## Follow-ups

- A handful of artefacts carry epoch-zero / far-future timestamps that widen
  the raw span (**1970 → 2105**). A cheap sanity-clamp on out-of-range
  timestamps is worth adding so the span reflects real activity.
- The behaviour timeline is the substrate the detection work reads from — see
  [Step 07](07-detection-lane-wiring.md).
