# Step 03 — Network identity: DNS/SSL/x509 → resolved flows (B2)

> Part of the CAR cross-source linkage & detection research arc — see [README](README.md) for the full map.

**Status:** merged (PR #61, PR #65, PR #66)

## The gap

Zeek's network logs are the richest single source of flow evidence in the
pipeline, but a triage of the processed tree showed the Zeek family looking
"entirely raw" — no CAR objects where we expected flows. The instinct was that
the mappings were missing. They were not: `conn → flow`, `http → http`,
`smtp → email`, and `files → file` were already in place, roughly ~80% of the
family mapped. The blank tree was a **lane-execution gap** — the maps existed
but were not being run — not a modelling gap.

Once the lane ran, the *real* remaining gap surfaced: three logs carried no CAR
mapping at all — **`dns`, `ssl`, and `x509`**. These are exactly the logs that
carry network *identity*. Without them, an encrypted connection to a bare IP
address stayed a bare IP: no domain, no certificate, nothing to correlate the
value hunt's C2 chain against.

## What we found

Each of the three logs identifies its records differently, and getting the
identity form right was the crux of each fix:

- **`dns`** — one UDP:53 connection carries *many* queries, so `uid` alone is
  not unique. Records are keyed by `uid` + `trans_id`. This needed a new spindle
  form, `zeek_uid_trans_id`.
- **`ssl`** — `ssl.log` is **1:1 with the connection**, unlike dns and http, so
  `uid` alone is a stable identity (`guid = uid`).
- **`x509`** — the Zeek `fingerprint` field *is* a SHA-256 of the DER
  certificate. That means it maps straight onto `sha256_hash` — a free
  content-hash convergence with the file model, no re-hashing.

## The fix

**DNS (PR #61).** `zeek_dns → flow` (message), the queried name in `fqdn`, raw
answers kept in native. `enrich._dns_resolution` builds a **host-scoped
`ip → resolved domain` map** from each (query, answer-IPs) pair, and
`_stamp_resolved_fqdn` fills `dest_fqdn` / `src_fqdn` on any flow to or from a
resolved IP. So a bare connection to **`100.101.0.42`** now reads as
**`scoring-c2.berylia.org`** — the C2 chain the value hunt found, now queryable.
Only IP answers resolve; CNAMEs are skipped. Resolution is gated on
`source_artefact == "zeek_dns"`, because a conn flow with `service:dns` is
DNS *traffic*, not DNS *resolution evidence*.

**SSL/SNI (staged in PR #65).** `zeek_ssl → flow` (message); `server_name`
(the SNI) → `dest_fqdn`; `guid = uid`. enrich propagates the SNI onto the conn
flow of the same `uid`, so the domain lands **directly on the encrypted flow**
even when DNS never resolved it.

**x509 (PR #66).** `zeek_x509 → file` (create); `fingerprint → sha256_hash`;
subject / issuer / SAN / validity kept in native. `enrich._cert_by_fingerprint`
and `_stamp_flow_cert` walk `ssl.cert_chain_fps → x509.fingerprint` and surface
the **leaf cert subject** on the TLS flow that presented it. The C2 flow now
reads **`CN=berylia.org`** alongside its SNI, and `sni_matches_cert` is the
mismatch tell when the two disagree.

## What it enables

An encrypted flow to a bare IP now carries its C2 domain — from DNS resolution
*and* from the SNI on the flow itself — plus the certificate identity of the
endpoint it handshook with. That is the network-identity substrate the
detection-correlation work ([Step 08](08-detection-correlation.md)) joins
against: domains, certs, and IPs are now first-class, cross-referenceable
fields rather than opaque addresses.

## Follow-ups

None major. `ssl` and `x509` close out the Zeek family — every Zeek log the
pipeline ingests now has a CAR mapping.
