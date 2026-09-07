# CAR completeness backlog — ranked

The concrete "squeeze more from every artefact" work items the 13 per-object
provenance audits surfaced, ranked by value/effort. Each is a source that
genuinely exists but the pipeline doesn't (yet) turn into the CAR field. Honest
no-source fields are listed last — document them as permanent nulls, never fake.

## The biggest lever — promote the quarantined audit family
`to-be-validated/evtx_audit.yml` holds schema-grounded, INERT maps for the
Windows object-access audit family. It needs one audit-enabled capture to
validate, then promotion into `mappings/`. It alone unlocks:
- **file** `write`/`read` actions (4663/4660/4670/5140/5145/5058) — today file has **no `write` source at all**.
- **registry** live writes (4657) — the only non-Sysmon source of a registry write with the true writer `pid`/`user`/`image_path`.
- **flow** endpoint identity + **socket** `bind` (5156/5157/5158) — a second, log-native source of `exe`/`pid`/`direction` on a connection (normalize 5158's raw numeric protocol on the way).

## Tier 1 — quick wins (the source is already IN a mapped record)
1. **file.uid** ← Security 4907 `SubjectUserSid` (already in the record; `evtx_more.py:102`).
2. **registry.new_content** ← Sysmon 14 `NewName` (native-only today); and flatten the Plaso `windows:registry:*` `values` list → `value`/`data`/`type`.
3. **thread.uid** — inherit-list asymmetry: the memory lane inherits `uid`, the Sysmon lane inherits `sid` (which thread lacks) not `uid`, so every `remote_create` leaves `thread.uid` null (`relationships.yml`).
4. **email.return_address** ← zeek smtp `reply_to`; **email.server_relay** ← zeek `path` (both already captured, kept native).
5. **socket/flow.family** normalize `ipv4`/`ipv6` → `AF_INET`/`AF_INET6` (memory emits ECS-style; the STIX `socket-ext` gate `startswith("AF_")` silently drops it).
6. **process** — `hostname` null on SRUM app-usage; `image_path` null on prefetch (the `path_hints[]` list is unindexed).
7. **module** — decompose prefetch `mapped_files` into `module/load` rows (path/name).

## Tier 2 — wire an existing but unmapped source
1. **authentication: Kerberos 4768/4769/4771 + NTLM 4776** — EvtxECmd already parses them; the object has **one** mapper (4624/4625/4672) and **zero Kerberos** coverage. Highest-value object gap. (Also: Zeek `ssh.json`/`kerberos`/`ntlm` not even ingested; Linux sshd/sudo/PAM auth routed to user_session, dropping `method`.)
2. **service: the registry `Services` key** — `plaso_registry.py`/`recmd.py` parse it but emit `registry` objects; the full definition (name, ImagePath, ObjectName→`user`, Start/Type) survives only in `native`. **A dead disk yields zero `service` objects today.** Reconstruct `service/create` from it.
3. **file: `timestomp` + `previous_creation_time`** — from the $MFT $SI/$FN birth mismatch (Plaso already emits per-attribute rows via `attribute_name`; `l2t_mft` flattens them) and Sysmon EID 2. Plus NTFS owner/mode from the security descriptor / $Secure (`OldSd`/`NewSd` sit native).
4. **flow: Zeek dns/ssl/http → flow by shared `uid`** (the R3 pattern) — fills `application_protocol`/`proto_info`/`dest_fqdn` from logs already produced but unmapped.
5. **http: UA parsing** → `user_agent_name`/`_version`/`_device` (a pure heuristic post-process; `user_agent_full` is already captured). Plus proxy/IIS logs for decrypted-HTTPS + requester IP.
6. **module/driver: memory `ldrmodules`** (unlinked = injected) and **dumpfiles+hash**; and **cross-object hash hydration** — disk hashes (amcache sha1, PE sha256) reach file/process but never module/driver — a path/hash join propagates them (exactly what `crosssource.py` enables).
7. **user_session: 4800/4801 lock/unlock** (the proper `lock` source; today `lock` never fires) and Linux **btmp/lastlog** (failed logins; `login_successful=false` has no source — 4625 is diverted to `authentication`).
8. **service: svcscan → derive `start`/`stop` from `State`** and propagate its `pid` (today a store-only snapshot).

## Tier 3 — run the plugin / capture the evidence (schema complete, unexercised)
Several objects are wired but empty on LS24 because the plugin wasn't run or the
channel wasn't captured: run **windows.piiat.network** (socket `listen`),
**windows.modules/ldrmodules** (module `base_address` + injection),
**windows.threads** (thread stacks) over the memdump; capture **Sysmon EID
6/7/8**, the **Security** channel, and the **audit subcategories**.

## Honest no-source (document as permanent nulls — never fake)
- authentication `response_time`; file/flow `content`; socket `local_path` (needs Linux auditd `SOCKADDR`), `remote_*`, `close`.
- process `signer`/`signature_valid`/`target_address`; module `tid` + `unload`; thread `src_tid` + `suspend`/`terminate`; driver `unload` + `pid`; service `delete`/`pause`; email `message_body`/`message_links`/`message_type`/`action_reason` (STARTTLS / server-side verdict).

## Recurring themes
- **The quarantined audit family is the #1 lever** (file write/read, registry writes, flow/socket endpoint identity) — promote it once an audit-enabled capture exists.
- **Cross-object hash + identity hydration** (`crosssource.py`) closes many single-source gaps — a hash/path join carries disk hashes onto module/driver and memory-only fields onto their log rows.
- **Trust the maps, not the CAR sensor cards** — upstream `coverage_map`s overclaim; these tables are ground truth.
