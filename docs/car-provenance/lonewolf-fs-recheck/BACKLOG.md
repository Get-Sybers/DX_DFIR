# Unmined filesystem-artefact backlog — all 13 CAR objects (LoneWolf-grounded)

A "find once, done" sweep of every CAR object for Windows filesystem/disk artefacts
the pipeline does NOT yet turn into the right CAR row — grounded in the real
LoneWolf Win10 image (`DESKTOP-PM6C56D`, plaso 4.17M events, VSS included).
Per-object detail: one `<object>.md` per CAR object in this dir. The first-round
property-provenance catalogues in the parent directory are the priors this builds on.

## The five recurring patterns (this is the real finding)
Almost every gap is one of five shapes — and most are **cheap re-emits of data plaso
already parsed**, not new tooling:

1. **Right data, WRONG object.** Disk evidence is parsed but emitted as `registry`/`file`
   and the CAR identity is parked in `_native`:
   - `Services` key → `registry`, not **`service`** (1,796 rows / 618 services; a dead disk yields **0 service objects** today).
   - amcache `InventoryDriverBinary` + SYSTEM `Services` Type 1/2 → `registry`/`file`, not **`driver`** (352 unique .sys, 6/11 fields fillable).
   - `pe_coff` DLL/.sys (150k / 4,643) → `file`, not hydrated onto **`module`/`driver`**.
   - RecentApps / AppCompatFlags\Store / `.job` (winjob, *entirely raw*) → not **`process`** (and `.job` carries a real user).
   - Save/Open MRU (RecentDocs/OpenSave/LastVisited) → `registry`, not **`file`/read** (the actual accessed files).
   - SAM `Last Login` + ProfileList → `registry`, not **`user_session`/login** or **`authentication`/success**.
   - Firewall rules → `registry`, not **`socket`/bind** (895 inbound-port rules / 40 apps).
2. **`user` is in the path, never mined.** Across process/file/registry/user_session/service,
   `user`/`uid` is null because maps read a native `username` that is `"-"`, while the account is
   right there — `\Users\<name>\` paths, hive `display_name`, SIDs (RID + the machine SID
   `S-1-5-21-2734969515-1644526556-1039763013` from ProfileList), service `object_name`.
   **`recmd.py` already does it** (`regex1(HivePath, …Users\<name>…)`); nothing else does. #1 win.
3. **Over-narrow data_type predicate.** A working map rejects real rows: `l2t_firefox_places`
   gates Firefox-only so **all Chrome/Edge history** (2,293 visits + 42 downloads) is rejected;
   IE `WebCache` is routed to the SRUM-only predicate and dropped.
4. **Value trapped in an unindexable LIST.** 1.35M registry rows carry `value`/`data`/`type` in a
   `values` list the marker set can't index; same shape hides service `ImagePath`/`ObjectName`
   and every firewall-rule string. RECmd flattens these; plaso_registry doesn't.
5. **Parser output produced then binned.** The Zimmerman lane RUNS SBECmd / AmcacheParser /
   AppCompatCacheParser, but `pipeline.py` ROUTES consumes **none** of them (only RECmd) —
   shellbags/amcache/shimcache EZ output is written and silently dropped. Chrome cache
   (`.L2tChromeCache`) has no route; `.job` (winjob), olecf doc-summary, openxml metadata unrouted.

## Cheap code fixes (data already in-store — routing/derivation only)
- **A1 · user-from-path** in `plaso_registry`, `plaso_exec` (userassist), `plaso_shellitem`,
  `l2t_lnk`, `l2t_recyclebin` (+ resolve BAM/recycle/ProfileList SID→name via SAM). Names 100%
  of userassist/shellbag/registry activity. Retire the dead `hive_user_sid` regex (matches 0%).
- **A2 · Services key → `service/create`** (re-emit; `object_name`→user, `ServiceDll`→real binary
  for svchost hosts; expand `%SystemRoot%`; dedupe the 3× VSS inflation).
- **A3 · amcache SHA-1 bug** — every amcache map reads `sha1`/`Record.sha1` but the SHA-1 lives in
  `file_identifier`/`DriverId` (`0000`+40hex); amcache's hash reaches **no** object today. Plus
  amcache `company_name`→`file.company` dropped. One-liners.
- **A4 · amcache `InventoryDriverBinary` + Services Type 1/2 → `driver`**; **prefetch `mapped_files`
  → `module/load`**; **`pe_coff` → `module`/`driver` hash** via a `crosssource.py` fix (add
  module/driver to the content-hash collapse — today the bucket is object-scoped so only process
  collapses into file; add a `module_path`↔`file_path` key).
- **A5 · LNK "Not a time" drop** — `l2t_lnk` sends non-time variants to `default: None`, dropping
  931/1,639 shortcuts incl. their `link_target`/`command_line_arguments`/`working_directory` (the
  case-defining Desktop `.lnk`s). Emit a `file`/access row regardless.
- **A6 · flatten the registry `values` list** → `value`/`data`/`type` (1.35M rows); surface the
  dropped `network` fields (ssid/gateway MAC/dns_suffix).
- **A7 · Chrome/Edge history** — widen `l2t_firefox_places`'s predicate (it already derives the
  exact fields incl. `from_visit`→referrer) → `http`; route `.L2tChromeCache`; webmail address
  (`jimcloudy1@gmail.com`) → could seed `email.src_address`.
- **A8 · route the Zimmerman EZ output** (SBECmd/amcache/appcompatcache) in `pipeline.py` ROUTES —
  compute already spent.
- **A9 · winjob `.job` → `process`** (uniquely carries a real native user); RecentApps + AppCompatFlags\Store → `process`.
- **A10 · Firewall rules → `socket/bind`** (config confidence, `success` null); `Svc=`→service join.
- **A11 · WebCache `response_headers` → `http`** (the ONLY on-disk source of `response_status_code`/`http_version`).

## Collection-lane / new-parser gaps (epic #134 — not map defects)
- **$MFT absent** (`fs:ntfs:mft`=0): blocks `timestomp`, `previous_creation_time`, resident `$DATA` content, `$I30` deleted names, and NTFS `$Secure` owner/ACL — 5 `file` fields at once. The `l2t_mft` map is already well-formed; the disk lane just isn't extracting `$MFT`.
- **SRUM empty** (`windows:srum:*`=0): SRUDB.dat is a dirty ESE db libesedb skips + the Zimmerman SRUM step is unwired → the only disk source of `flow` in/out bytes yields nothing.
- **New parsers, artefacts present but unread:** ActivitiesCache.db / Win10 Timeline (richest process source: exe+cmdline+user+title+duration; `windows_timeline` fired 0), mail stores (`store.vol`+`HxStore.hxd` present; also PST/OST via `pff`) → the whole `email` object (0/21 today), minidumps/`.dmp` (the only disk `thread` stack/start source), WMI `OBJECTS.DATA`, WER, ADS/Zone.Identifier (download provenance), `.cat` CatRoot (true `signature_valid`).

## Honest no-sources (document, never fake)
- **thread**: near-total — a runtime/ETW object; only minidump bodies (+ the `<image>.<pid>.dmp` filename PID) offer anything from disk.
- **socket**: mostly runtime — only firewall *config* (a policy, not an observed bind).
- **flow**: the wire 5-tuple / `content` / `packet_count` / `tcp_flags` / `proto_info` / L7 — a dead disk can't hold them.
- Per-field structural nulls: `base_address`/`pid`/`tid` (module/driver/thread), `env_vars`/`parent_*`/`integrity_level`/`command_line`(mostly) (process), `login_id`/`login_type`/`src_*` (user_session), `response_time`/`method`/`decision_reason` (authentication), the delivery-verdict actions + wire ports (email), `md5` (disk gives SHA-1/256), `signer`/`signature_valid` (need Authenticode/.cat verification, no parser).

## Bottom line
On a Windows dead-box image *full* of user-attributable execution, access, service, driver, and
web evidence, the pipeline today emits CAR rows with null `user` and misses whole objects
(`service`/`driver`/`email` = 0 from disk). The bulk of the fix is **re-emitting data plaso already
parsed to the correct object + deriving `user` from the path** — cheap, and it lights up the whole
image. The rest is collection-lane extraction ($MFT, SRUM, mail stores, ActivitiesCache) tracked
under epic #134.
