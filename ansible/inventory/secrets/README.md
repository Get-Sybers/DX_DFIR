# The per-host secret store

`<this dir>/<inventory hostname>/` holds everything `dxdfir deploy stack`
generates for that host — one file per secret (`elastic_password`,
`kibana_system_password`, `byakugan_loader_password`, the three Kibana
encryption keys), the stack's TLS material under `certs/` (CA at
`certs/ca/ca.crt`), and the generated `elastic.env` credential handoff that
tools outside ansible read (the `dxdfir` TUI's Kibana tab, `dxdfir
stamp-detections`, the elastic riskgate).

- **Everything here except this README is gitignored — never commit it.**
- A secret is generated on the first deploy that needs it and reused after
  that; deploys never overwrite one.
- To set your own value, override the matching `dxdfir_elastic_*` variable
  (inventory `host_vars` — `ansible-vault encrypt_string` works — or `-e`);
  an overridden variable never materialises a file here.
- To rotate a generated secret, edit or remove its file and redeploy —
  rotating a password Elasticsearch already knows also needs the matching
  API change, or a destroy with volumes and a fresh deploy.
- `elastic.env` is regenerated every deploy: edit the per-secret files or
  override the variables, never the handoff.

The variables live in
`ansible/collections/get_sybers.dxdfir/playbooks/group_vars/all.yml`
(`dxdfir_elastic_*`); the deploy logic in the `dxdfir_stack` role
(`tasks/secrets.yml`, `tasks/certs.yml`).
