# The `malcolm` space

A Kibana space holding 36 dashboards derived from the
[cisagov/Malcolm](https://github.com/cisagov/Malcolm) project, converted to
the documents the stack's ingest pipelines produce for Zeek
(`logs-dxdfir.zeek-*`) and Suricata (`logs-dxdfir.detections-*`). The stack
deploy imports this directory the way [`../../README.md`](../../README.md)
describes for a space: `space.json` is the space, the `*.ndjson` files are
its saved objects, imported together with overwrite whenever their content
changes. Every dashboard, with its file, data view, the logs it selects and
its panels: [DASHBOARDS.md](DASHBOARDS.md).

```
malcolm/
├── space.json               id malcolm, name Malcolm, initials Ma, colour #54B399, every feature enabled
├── 00-data-views.ndjson     malcolm-zeek on logs-dxdfir.zeek-*, malcolm-suricata on logs-dxdfir.detections-*
├── <name>.ndjson            one file per dashboard: its saved searches, then the dashboard
├── README.md, DASHBOARDS.md this file and the catalogue
└── LICENSE.txt              Malcolm's licence notice (Apache License 2.0)
```

## What the dashboards read

The documents Filebeat ships from the Zeek lane (`processed/zeek/<item>/<log>.json`)
and the signatures lane (`processed/detections/suricata/<item>/eve.json`),
after the stack's ingest pipelines ([`../../pipelines/`](../../pipelines/)):

- the record's own fields, named as the tool wrote them: Zeek's `ts`, `uid`,
  `id.orig_h`, `conn_state`, `query`, …; Suricata's `timestamp`, `event_type`,
  `src_ip`, `alert.signature`, …;
- `@timestamp` from the record's own timestamp, `event.ingested` the ingest
  time, `event.module` the tool (`zeek`, `suricata`), `event.dataset` the
  record type (`zeek.conn`, `zeek.dns`, …; `suricata.alert`, `suricata.flow`,
  …);
- on Zeek `conn` records `network.bytes` (`orig_ip_bytes + resp_ip_bytes`);
  on Zeek `files` and `weird` records the string column `source` under
  `zeek.log_source`.

Every panel query is KQL on the data view: `event.dataset:zeek.<log>` selects
a Zeek log, `event.dataset:suricata.alert` the Suricata alerts. A dashboard
whose panels name no dataset reads every record of its data view.

## What is in a dashboard file

The saved searches the dashboard embeds (Discover tables, referenced by id)
followed by the dashboard itself. Charts are Lens visualisations stored by
value in the dashboard (data table, pie chart, metric, bar and line charts,
tag cloud); the navigation panel at the top of every dashboard is a markdown
visualisation whose links use the dashboards' ids; the HTTP dashboard's
method-to-status sankey is a Vega visualisation. Object ids are fixed, so a
re-import updates the objects in place.

## Field names

Malcolm's dashboards use the ECS names its Logstash pipelines produce; these
use the names above. A Zeek column name applies to the log that carries it.

| Malcolm | Zeek (`logs-dxdfir.zeek-*`) | Suricata (`logs-dxdfir.detections-*`) |
|---|---|---|
| `event.provider` | `event.module` | `event.module` |
| `event.dataset` (`conn`, `dns`, …; `alert`) | `event.dataset` (`zeek.conn`, `zeek.dns`, …) | `event.dataset` (`suricata.alert`) |
| `source.ip`, `source.port` | `id.orig_h`, `id.orig_p` (dhcp: `client_addr`) | `src_ip`, `src_port` |
| `destination.ip`, `destination.port` | `id.resp_h`, `id.resp_p` (dhcp: `server_addr`) | `dest_ip`, `dest_port` |
| `network.transport` | `proto` | `proto` |
| `network.protocol` as a filter | `event.dataset` | `event.dataset` |
| `network.protocol` bucketed over conn | `service` | `app_proto` |
| `network.protocol_version` | `version` | |
| `event.id` | `uid` (pe, ocsp: `id`; x509: `fingerprint`; dhcp: `uids`) | `flow_id` |
| `zeek.<log>.<field>` | `<field>`; renamed columns: `ssl_version` is `version`, `certificate_subject_full` is `certificate.subject`, `certificate_issuer_full` is `certificate.issuer`, kerberos `cname`/`sname` are `client`/`service`, ntlm `user`/`host`/`domain` are `username`/`hostname`/`domainname`, ldap `operation`/`result_code`/`result_message` are `opcode`/`result`/`diagnostic_message`, modbus `trans_id`/`unit_id` are `tid`/`unit`, redis `cmd_name`/`cmd_key`/`cmd_value`/`reply` are `cmd.name`/`cmd.key`/`cmd.value`/`reply.value`, dhcp `assigned_ip`/`requested_ip` are `assigned_addr`/`requested_addr`, conn `conn_state_description` is `conn_state` | |
| `event.action` | the log's own verb: http `method`, dns `opcode_name`, ftp `command`, dce_rpc `operation`, dhcp `msg_types`, dnp3 `fc_request`, irc `command`, kerberos `request_type`, ldap `opcode`, modbus `func`, mqtt_subscribe `action`, mysql `cmd`, ntp `mode`, postgresql `frontend`, redis `cmd.name`, sip `method`, smb_files `action`, tunnel `action` | `alert.action` |
| `event.result` | the log's own outcome: http `status_code`, dns `rcode_name`, ftp `reply_code`, dhcp `server_message`, dnp3 `fc_reply`, kerberos/mysql/postgresql/redis/ntlm `success`, ldap and ldap_search `result`, modbus `exception`, mqtt_connect `connect_status`, mqtt_publish `status`, rdp `result`, sip `status_code`, smtp `last_reply`, ssh `auth_success`, ssl `last_alert` | |
| `rule.name`, `rule.category`, `rule.id` | weird: `name` | `alert.signature`, `alert.category`, `alert.signature_id` |
| `event.severity` | | `alert.severity` |
| `related.user`, `related.password` | `user` (http, ntlm, radius: `username`), `password` | |
| `user_agent.original`, `url.original` | `user_agent`, `uri` | |
| `file.mime_type`, `file.name`, `file.size`, `file.source` | `mime_type` (http: `resp_mime_types`), `filename`, `total_bytes`, `zeek.log_source` | |
| `source.bytes`, `destination.bytes` | `orig_ip_bytes`, `resp_ip_bytes` | |
| `client.bytes`, `server.bytes` | `orig_bytes`, `resp_bytes` | |
| `source.packets`, `destination.packets` | `orig_pkts`, `resp_pkts` | |
| `network.bytes` (conn) | `network.bytes`, set by the Zeek pipeline | |
| `event.duration` | `duration` (seconds) | |
| `quic.host`, `quic.version` | `server_name`, `version` | |
| `@timestamp`, `event.ingested`, `host.name` | the same names, set by the pipelines or by Filebeat | the same names |

## Scope

The space holds the Malcolm dashboards whose panels can be computed from
Zeek's default-script logs and Suricata's EVE records: the general dashboards
(Overview, Connections, Files, Executables, Zeek Weird, Suricata Alerts), one
dashboard per Zeek protocol log, and Modbus and DNP3 from Zeek's base
analyzers. It does not hold:

- panels that need Malcolm's enrichment: GeoIP, MAC and OUI, NetBox inventory,
  severity and risk scores, domain randomness scores, JA4 fingerprints,
  community ids, direction and subnet names, ATT&CK and vulnerability tags,
  file extraction and file scanning;
- dashboards and panels for Zeek logs the default script set does not write
  (notice, intel, signatures, software, known_hosts, known_services,
  known_certs, smb_cmd) or for the Zeek packages Malcolm installs (the ICSNPP
  protocol analyzers and their detailed Modbus and DNP3 logs, JA4, STUN,
  OSPF, TDS, TFTP);
- Malcolm's own host and beats telemetry, the map dashboards (their panel
  types were removed in Kibana 8) and the Security Overview, Severity and
  Actions and Results dashboards, which count Zeek and Suricata records in one
  shared field set.

## Changing a dashboard

Open it in the `malcolm` space, change it, then export it from Stack
Management › Saved Objects with its related objects (or
`POST /s/malcolm/api/saved_objects/_export` with `includeReferencesDeep: true`
and `excludeExportDetails: true`) and replace its `<name>.ndjson` with the
export, minus its `index-pattern` lines, which `00-data-views.ndjson` owns.
The repository check harness (`dx validate`) checks the result's structure;
the next `dx deploy stack` or `dx update stack` imports it. A field a
dashboard needs and a pipeline must add goes into
[`../../pipelines/`](../../pipelines/).

## Source and licence

The dashboards derive from Malcolm v26.09.0 (commit
`7cfac5bc448bd9031a2cbb35bd058d7253c2e2c8`, `dashboards/dashboards/*.json`),
Copyright 2026 Battelle Energy Alliance, LLC, Apache License 2.0;
`LICENSE.txt` is Malcolm's licence notice and
[`.github/THIRD_PARTY_NOTICES.md`](../../../.github/THIRD_PARTY_NOTICES.md)
records the derivation. They differ from the originals in the field names,
queries and data views described above, in the visualisation format (Lens by
value instead of the legacy aggregation-based objects) and in the panels and
dashboards outside the scope above, which are absent.
