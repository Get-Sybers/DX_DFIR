# Kibana spaces

Three spaces, two owners:

| space | colour | holds | comes from | deployed by |
|---|---|---|---|---|
| `default` (**DX DFIR**) | — | the evidence overview, the `logs-dxdfir.*` / `logs-car.*` data views, the per-lane saved searches, the pipeline-errors view; the Security app's home | [`dashboards/*.ndjson`](dashboards/) in this tree | `dx deploy stack` / `dx update stack` (`dxdfir_stack`) |
| `malcolm` (**Malcolm**, navy `#54B399`) | navy | 36 dashboards derived from cisagov/Malcolm over `logs-dxdfir.zeek-*` and `logs-dxdfir.detections-*` | [`dashboards/malcolm/`](dashboards/malcolm/README.md) in this tree | `dx deploy stack` / `dx update stack` |
| `byakugan` (**Byakugan**, steel blue `#4682B4`) | steel blue | the `logs-car.*` data view and the **CAR timeline** dashboard (saved search + histogram by `car.object`) | [the Byakugan engine's own `elastic/dashboards/byakugan/`](https://github.com/Get-Sybers/Byakugan/blob/main/elastic/README.md), rendered from its CAR→ECS contract and baked into the `get-sybers/byakugan` image | `dx byakugan load --kibana` (a `--setup` run; the same run installs the `logs-car.*` templates) |

A space in this tree is a directory `dashboards/<id>/` holding `space.json`
(the space as Kibana's spaces API takes it: id, name, initials, colour,
disabled features) plus its saved objects as `*.ndjson` — see
[README.md](README.md) "A Kibana space". The Byakugan engine's tree carries
its space in exactly that shape, so either deployer can walk either tree; this
repo deliberately does not copy it — the engine owns the `logs-car.*` family
end to end and the image imports it.

Open: the default space should land on the Security app (**DX DFIR**) when
navigating there.
