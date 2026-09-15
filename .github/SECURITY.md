# Security Policy

## Supported versions

| Version | Supported |
|:---|:---|
| The [latest release](https://github.com/Get-Sybers/DX_DFIR/releases), and `main` | ⚠️ Best effort only |
| Any earlier release | ❌ No. Fixes land on `main` and ship in the next release; there is no backporting |
| The `deprecated` branch | ❌ No. It is the frozen pre-release line and carries known unfixed defects — see [DEPRECATED.md](https://github.com/Get-Sybers/DX_DFIR/blob/deprecated/DEPRECATED.md) |

This project is experimental. Nothing here is hardened beyond the tool
containers; the smoke test exercises one lane, and the rest of the pipeline is
verified by hand on the author's corpus. Do not treat it as a secure system.

## Reporting a vulnerability

Open a [security advisory](https://github.com/Get-Sybers/DX_DFIR/security/advisories/new)
rather than a public issue. If advisories are unavailable, open an issue that
describes the *class* of problem without a working exploit, and say you have
details to share privately.

Expect a slow response — this is a personal project, not a maintained product.

## Known weaknesses

These are already known. You do not need to report them.

- **The analysis backend holds evidence.** The Elastic-native stack
  (`docker/elastic`) runs with security **on** — authentication, RBAC, TLS on
  the Elasticsearch API and transport — but Kibana is served over plain HTTP on
  the loopback interface, Filebeat writes as the `elastic` superuser for now
  (a least-privilege writer role is a follow-up), and every credential lives in
  the gitignored `docker/elastic/.env`. The retiring SOF-ELK stack
  (`docker/sof-elk`) has no security at all — no authentication, no access
  control, plaintext HTTP. Every published port binds `127.0.0.1`; that
  binding is a real control, the rest is best effort.
- **`chmod -R 777`.** The setup and processing scripts widen permissions
  across `data_store/` to work around container UID mismatch. Anyone with
  local access can read or modify evidence and configuration. Do not run this
  on a shared or multi-user host.
- **Evidence lives in the working tree.** `data_store/` is gitignored
  deny-by-default, but a determined `git add -f` defeats it.
- **Egress restriction is best-effort; the localhost binding is not.** The
  stacks publish only on `127.0.0.1`, which is a real control. The tool
  containers run with `--network none` (the Volatility symbol fetch is the one
  explicit opt-in). Note that Docker's published-port rules are inserted ahead
  of the host firewall, so `ufw` will not save you from a wrong bind address —
  check `docker compose ps` / `docker port` after a change to the compose files.
  An `--internal` network was tried once (on the Splunk-era deploy this project
  grew up on) and reverted: it blocks published ports as well, making the
  service unreachable.
- **Pulled images are version-pinned, not digest-pinned.** The Elastic images
  are pinned to `ELASTIC_VERSION`, the .NET runtime to a major version; there is
  no digest pinning and no signature verification. You are trusting the
  registry at pull time. The `dxdfir/*` tool images are built in-repo.

## Handling evidence

This is DFIR tooling — the data it touches is usually sensitive and sometimes
legally significant.

- Work on copies, and verify hashes before and after processing.
- The processing scripts mount evidence directories into containers. The VMware
  path is mounted read-only; treat everything else as potentially mutable.
- The backend holds ingested evidence on localhost (named Docker volumes for the
  Elastic stack), and the delivery role (`dxdfir_ingest_sofelk`) mirrors processed
  output into the watch directory the stack mounts — copies that outlive the
  run; purge them with the case.
- Nothing here is written to preserve chain of custody. If your work needs to
  stand up in a legal context, this project is not sufficient on its own.
