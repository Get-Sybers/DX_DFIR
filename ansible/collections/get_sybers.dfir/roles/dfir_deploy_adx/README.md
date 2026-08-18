# dfir_deploy_adx

Deploy the **ADX (Kusto) emulator** and apply the schema (databases, tables,
ingestion mappings, MITRE CAR functions). The role asserts inputs, runs a preflight
(docker, the schema dir + `00-databases.kql`, the module), pulls + runs the
`kustainer` container (localhost-only, ephemeral by default), waits for the engine,
then creates the databases and applies every `kusto/schema/*.kql`.

The container is stood up with `community.docker`; the schema side is the
`get_sybers_dfir.deploy` helper.

## ⚠️ EULA
The emulator starts with `ACCEPT_EULA=Y` — running this role **accepts Microsoft's
Software License Terms** on your behalf. The emulator is *as-is*, unsupported, has
**no authentication** (hence localhost-only), and is documented as generally
unsuitable for production.

## Role variables
| Variable | Default | Description |
|---|---|---|
| `dfir_deploy_adx_image` | `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest` | Emulator image (multi-GB; first pull is slow). |
| `dfir_deploy_adx_container` | `kusto-emulator` | Container name. |
| `dfir_deploy_adx_host` | `127.0.0.1` | Bind address + schema-client connect host (keep on localhost). |
| `dfir_deploy_adx_port` | `8080` | Host port → emulator 8080. |
| `dfir_deploy_adx_memory` | `4G` | Container memory limit. |
| `dfir_deploy_adx_schema_dir` | `<repo>/kusto/schema` | The `.kql` schema files. |
| `dfir_deploy_adx_persist` | `false` | Persistent (on-disk) databases; needs a `/kustodata` mount. |
| `dfir_deploy_adx_python_path` | `<repo>/python` | PYTHONPATH to `get_sybers_dfir` (in-repo runs). |

## Idempotence
`docker_image`/`docker_container` are idempotent; the readiness wait is
`changed_when: false`; schema apply reports `changed` only when a **new database was
created** (`created_dbs > 0`) — the per-file schema (`.create-merge` /
`.create-or-alter`) re-applies harmlessly. So a first deploy is `changed=true`, a
re-deploy against the same running cluster is `changed=false`.

## Example
```bash
dxdfir deploy                       # drives this role
ansible-playbook playbooks/dfir-deploy-adx.yml
```

## Testing
Python unit tests cover the schema-applier's pure logic (database parsing, `//
Database:` header, dry-run). The **Molecule** scenario deploys a **throwaway**
emulator (`kusto-emulator-moltest` on port 8090 — never a production instance),
converges, converges again asserting zero changes (idempotence), verifies the CAR
databases exist, and tears the test emulator down in `cleanup`.
