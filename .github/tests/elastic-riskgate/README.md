# Byakugan Phase-0 risk gate

The proof harness for the two assumptions the Elastic-native detection design
stands on: **manual detection runs over an evidence-time window** and **ES|QL
`LOOKUP JOIN` flagging** against the `car-detections` lookup index, on the
Byakugan stack (Elasticsearch 9.4.3). It stands up nothing — the stack
must already be running — and it cleans up after itself.

```bash
./.github/tests/elastic-riskgate/riskgate.sh            # load fixture, proof 1, proof 2, probe, clean
./.github/tests/elastic-riskgate/riskgate.sh selftest   # offline: fixtures / queries / expected tables agree
```

**The manual is [docs/riskgate.md](../../../docs/riskgate.md)** — run steps, what
each proof demonstrates, the pass/fail bar, and what to do when a check fails.

| path | what |
|---|---|
| `riskgate.sh` | entry point: discovers the password (the deploy's `elastic.env` handoff) and CA (the deploy's certs tree), runs the runner |
| `riskgate.py` | the runner (stdlib only): loads, queries `POST /_query`, compares with `expected/`, cleans |
| `fixtures/logs-car.ndjson` | four synthetic CAR rows dated 2019-04-12 (bulk NDJSON, ECS per the CAR->ECS projection) |
| `fixtures/car-detections.ndjson` | three detection rows for the lookup index (bulk NDJSON, strict to the contract template) |
| `queries/*.esql` | the proofs as plain ES|QL — paste-able into Kibana Dev Tools / Discover |
| `expected/*.json` | the table each gated query must return (order-insensitive) |

Everything it creates is namespaced `riskgate` (`logs-car.*-riskgate`,
`car-detections-riskgate`); the only shared object it writes is the contract's
own `car-detections` index template, PUT verbatim from
[`byakugan/rules/car-detections/`](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/byakugan/rules/car-detections/car-detections.index-template.json) (read from the submodule at its pin)
(idempotent; `clean --drop-template` removes it).
