# Ansible Standards

**Premise:** These rules govern every collection, role, and playbook in the ecosystem.

One sentence governs the rest: **a role performs actions and a playbook decides which run; every
value arrives through the native variable system; every task is idempotent and honest about
change.**

---

## 1. Layout & Style

### a. Namespace

The galaxy namespace is `get_sybers` (underscore, the one place the organisation cannot take a
hyphen). A collection uses the native `ansible_collections/<namespace>/<name>/` layout, and the
directory name, the declared `name`, and the prefix every role is named with all agree. One
fully-qualified name, no second spelling.

Every module and action reference is its FQCN: `ansible.builtin.copy`, not `copy`;
`ansible.posix.firewalld`, not `firewalld`. Short names still sometimes resolve, which is exactly
the problem: the same short name can resolve to two different modules in two collections, and the
one that wins depends on what is installed. FQCN removes the ambiguity and makes the dependency in
`galaxy.yml`/`requirements.yml` legible at the call site. The `fqcn` lint rule enforces this;
there is no waiver for a builtin.

### b. Naming Convention

**Variables.** A name starts with a letter and contains only lowercase letters, digits, and
underscores. No dots, hyphens, or leading digit (those are not valid identifiers and break
templating). `web_port`, not `web.port` or `1st_port`.

Every variable a role exposes or sets is prefixed with the role name: the `apache` role owns
`apache_listen_port`, not `port`. This is the single most effective guard against collisions,
because a plain `port` set by one role silently reshapes another. The prefix is the namespace that
precedence cannot give you.

**Two prefixes, not one.** User-facing inputs carry the role-name prefix (`foo_packages`). Internal
variables a user should never set, including anything from `register` or `set_fact`, get a
double-underscore `__foo_` prefix, because those persist in the global namespace after the role
ends. Modules shipped inside a role take the role prefix too.

**Tasks.** One naming form everywhere: `<role>-<stage> | lowercase description`, entry files and
shared roles included. Task names are imperative ("Ensure the service is running"). A variable in a
task name goes at the *end* of the string only, so a reader can still grep the static part; play
names take no variable at all, because they do not expand.

**Booleans.** Names are positive: `webserver_enabled: true`, never `webserver_disabled: false`, so
conditions do not become double negatives (`when: not webserver_disabled`).

**Repositories.** `{purpose}-{type}` in lowercase with hyphens. Playbook files are verb-noun
(`deploy-webapp.yml`). Branches are `{type}/{description}` (`fix/inventory-validation`). Commits
follow conventional-commit form (`feat:`, `fix:`, `docs:`, `chore:`, `test:`). Structured commits
and branches are what let changelog and release tooling run themselves.

### c. Repo Layout

A collection uses the native `ansible_collections/<namespace>/<name>/` layout. `molecule/` is
`build_ignore`d from the artifact.

Every role ships this structure without exception:

- `meta/main.yml` (with `galaxy_info` and an explicit `dependencies:` list)
- `meta/argument_specs.yml` (every input typed and described)
- `defaults/main.yml` (a self-contained default for each input)
- `tasks/` (split by stage)
- `molecule/default/` (a scenario with a committed real fixture, plus `converge`/`verify`/`prepare`)
- `README.md`

Repository root carries: `LICENSE` matching `galaxy.yml`, `.ansible-lint`, `README.md`, and
`CHANGELOG.md`.

### d. Fact Prefixes

Read facts through the `ansible_facts.*` namespace (`ansible_facts['default_ipv4']['address']`),
never the legacy injected `ansible_*` variables. Set `inject_facts_as_vars = false` in
`ansible.cfg` so the legacy names are gone, not merely discouraged. The reason is precedence: an
injected fact outranks play and inventory variables, so a stray `ansible_<thing>` is a collision
waiting to fire.

The magic variables (`inventory_hostname`, `hostvars`, `groups`, `group_names`,
`ansible_play_hosts`, `ansible_facts`) are read-only context. Never shadow them with a variable of
your own.

Read dictionary values with bracket notation, `item['name']`, not `item.name`: dot notation breaks
on hyphenated keys and silently collides with Python dict methods (`count`, `copy`, `title`).

---

## 2. When to Galaxy, Playbook, Role, Collection, Task

Four levels, largest to smallest:

- **Landscape**: everything deployed at once (a three-tier app, a cluster). A playbook of imported
  playbooks, one per type. This is the cost-free analog of a Controller workflow.
- **Type**: each managed host has exactly one type, applied by exactly one playbook ("web server",
  "database server"). No numbered playbooks run in sequence by hand.
- **Function**: a role, the reusable unit. A function reused across types is written once.
- **Component**: a `tasks/<component>.yml` file imported from the function role's `tasks/main.yml`.
  A component that outgrows one task file is promoted to its own component role, included by the
  function role.

**The role acts; the playbook decides.** A task performs one action and carries no branching logic.
Which actions run is decided in the playbook, a thin, single-purpose wrapper. Orchestration stays
out of roles; actions stay out of playbooks.

**Don't repeat roles.** A task sequence needed by more than one role is factored into one role the
others delegate to and declare as a dependency. Copying tasks between roles is a defect.
Parameterise the shared role; do not fork it.

**Roles are contracts for outcomes, not wrappers around one tool's commands.** Design for the
outcome, hide the implementation. A "time sync" role decides internally between chronyd and ntpd;
the caller asks for synchronised time, not for a daemon. When implementations diverge too far to
hide honestly (postfix versus sendmail), split into separate roles rather than forcing one.

**Providers.** A role supporting more than one implementation takes a `<role>_provider` input.
Unset, it detects the running provider and keeps it rather than surprising the operator by
switching; with none running it picks by OS. Export `<role>_provider_os_default` so a caller can
pin `<role>_provider: "{{ <role>_provider_os_default }}"` and get a consistent choice across OS
versions without naming the value (lazy evaluation makes this work).

**Collections at type or landscape scope.** Gather roles into a collection at the type or landscape
level, not one collection per role. One cohesive unit distributes more simply, shares plugins
across its roles instead of duplicating them per role `library/`, and gives every role a namespace
that removes collisions. This is the structural reason behind the single namespace.

**Give a collection one entry point.** Present a collection as an automation application: a single
dispatcher role that takes a list of actions and orchestrates the internal roles, so a consumer
never names internal roles or `tasks_from` files and the internals can change without breaking the
caller. This sits in tension with declared role dependencies in `meta/main.yml`. The trade is real:
meta dependencies buy explicit resolution and isolated per-role testing; a dispatcher buys loose
coupling and freedom to refactor internals. Decide per collection, and where you do use meta
dependencies keep them few, because deep dependency trees are exactly what GPA warns against.

The payoff is recombination: a new type is a new playbook that re-shuffles existing function roles,
with no code copied. Functions exist for reuse, components for maintainability. Break the layering
only for a reason stated openly to the team, never by accident.

---

## 3. Use Native Modules Over Shell

Use a module wherever one exists (`ansible.builtin.*` and the collection's declared dependencies).
`command:`/`shell:` is a last resort — a liveness probe, or an operation with no module — always in
argv form, with `changed_when` set and a lint waiver naming the reason. Where a raw invocation is
unavoidable it is confined and identical everywhere it appears, never scattered ad hoc.

---

## 4. Must-Includes

### a. Galaxy (`galaxy.yml`)

| File | Rule |
|---|---|
| `galaxy.yml` | each dependency bounded `>=x.y.z,<next-major`; `license` matches the repo `LICENSE` |
| `meta/runtime.yml` | one `requires_ansible` floor, agreeing with every role's `min_ansible_version` |
| `requirements.yml` | the single source of pinned versions: every dependency an exact `X.Y.Z`, never a range, `:latest`, or a branch |

Every pinned version lives in `requirements.yml` and nowhere else; scripts and bootstrappers read
it rather than carrying their own copy.

### b. Playbook

A playbook is a thin, single-purpose wrapper. It decides which roles run, in what order, on which
hosts. It carries no action logic of its own.

Keep play structure in one order and do not mix idioms. Prefer a `roles:` list, or run roles as
tasks with `import_role`/`include_role`, but not both a `roles:` section and a `tasks:` section in
the same play; the execution order (`pre_tasks` → `roles` → `tasks` → `post_tasks`, with handlers
flushed between stages) is then obvious instead of something a reader has to reconstruct.

Compose the site playbook with `import_playbook`.

### c. Role

Every role, without exception, ships:

- `meta/main.yml` (with `galaxy_info` and an explicit `dependencies:` list)
- `meta/argument_specs.yml` (every input typed and described)
- `defaults/main.yml` (a self-contained default for each input)
- `tasks/` (split by stage)
- `molecule/default/` (a scenario with a committed real fixture, plus `converge`/`verify`/`prepare`)
- `README.md`

A role resolves and tests in isolation from its own metadata. A dependency on another role is
**declared**, never left for `roles_path` to satisfy.

A role never carries a secret or site-specific value in its own `vars`/`defaults`. It declares a
non-sensitive default and expects the play to supply the real value from a vaulted variable. Secrets
are the playbook's job, not the role's.

The role README states the contract: inputs and their argument specs, user-facing capabilities, the
outcome, idempotent yes/no, and any rollback behaviour.

### d. Collection

| File | Rule |
|---|---|
| `galaxy.yml` | each dependency bounded `>=x.y.z,<next-major`; `license` matches the repo `LICENSE` |
| `meta/runtime.yml` | one `requires_ansible` floor, agreeing with every role's `min_ansible_version` |
| `requirements.yml` | the single source of pinned versions |
| `README.md` | how it is consumed |
| `CHANGELOG.md` | Keep a Changelog |
| `.ansible-lint` | `profile: production` |

For a value shared across a collection's roles, define an implicit collection variable and
reference it from each role's `defaults/` (`alpha_db_user: "{{ mycollection_db_user }}"`),
documented in the collection README. Each role keeps its own default, stays reusable outside the
collection, and the shared value is set once.

### e. Task

- One naming form everywhere: `<role>-<stage> | lowercase description`.
- Every play and every task carries a `name:`. An unnamed task is a defect, not a shortcut: the
  name is the line a reader and a failing run both read first.
- `block`/`rescue` around a fallible sequence surfaces one diagnostic; `block`/`always` cleans up
  on every exit path.
- `no_log` on anything secret-bearing.
- Mark a string that must reach the target with literal braces (a regex, a config snippet, a
  Prometheus query) as `!unsafe`, so Jinja2 does not try to evaluate `{{ ... }}` inside it.
- Do not use `meta: end_play`; it aborts the run for every host. Use `meta: end_host` if you must
  stop one.

---

## 5. Variables

Every variable enters through native precedence and nothing else:

- **`defaults/main.yml`** — overridable inputs, each mirrored in `argument_specs.yml`.
- **`vars/main.yml`** — true constants only.
- **`group_vars/`** — shared identities, defined once and referenced by the roles that need them.
- **`host_vars/`** — per-host values.
- **`-e` / vault** — run-time overrides, which win over all of the above.

Two prohibitions make this concrete:

- **No inline `vars:`** on a play, a role invocation, or a task.
- **`set_fact` is only for values genuinely computed from runtime facts** — never to declare,
  default, or assemble configuration the precedence layers should own.

Static reference data is a declaration in these layers, or a data file loaded with `vars_files` /
`include_vars` / a `lookup` — never assembled inside a task.

**`defaults/` is the single list of inputs.** Every input gets an entry in `defaults/main.yml`,
documented in the README. Where there is no safe default, leave the entry present but commented
out and let the role fail fast rather than default to something dangerous, so `defaults/main.yml`
stays the one place a consumer reads to learn the inputs. Required internal data and "magic" lists
live in `vars/main.yml` (high precedence, not meant to be overridden), split as `foo_packages`
(required, in `vars/`) versus `foo_extra_packages` (optional, defaults to `[]`). Do not paper over
a missing default with a `default()` filter at the call site.

**As-Is is a fact; To-Be is a variable.** Discovered state (facts) and desired state (variables)
must never share a name, or a run mistakes "what is" for "what should be" and does nothing where it
should act. Automation is the act of making As-Is match To-Be.

**Restrict variable types.** There are twenty-two precedence levels and no one holds them in their
head. Keep to a small set: role `defaults/` (overridable by anything), inventory group then host
vars (desired state), facts (current state, distinct names per above), role `vars/` (constants),
and scoped block/task vars for loops and runtime temporaries. Avoid play and playbook vars and
play-level `include_vars` for defining desired state, because they blur code and data. Loading
platform or provider data with `include_vars` inside a role is the sanctioned use and is not what
this forbids.

**Inventory vars over extra-vars.** The inventory, tracked in Git, is the non-ambiguous record of
desired state; `-e` is bound to one run and vanishes with it. Reserve extra-vars for
troubleshooting, validation, a guard like `are_you_really_sure: false` on a destructive play, or
forcing a fact value in a test.

**Never hardcode an inventory group name in a role.** A group name inside role code mingles data
with code and limits you to one cluster per inventory. Take the host set as a variable, or make the
group name a documented parameter, and let the inventory supply it; you can then describe many
clusters in one inventory, which a fixed group name forbids.

---

## 6. Constants

Constants live in `vars/main.yml` (high precedence, not meant to be overridden by the caller).

Required internal data and "magic" lists belong here. The split is:
- `foo_packages` (required, in `vars/`) — not overridable.
- `foo_extra_packages` (optional, in `defaults/`, defaults to `[]`) — overridable.

Platform and version data also lives in `vars/`. Do not branch on distribution inside tasks. Put
per-distribution values in `vars/<os>.yml` and load them at the top of `tasks/main.yml` with
`include_vars` over a least-to-most-specific list (`<os_family>.yml` → `<distribution>.yml` →
`<distribution>_<major>.yml` → `<distribution>_<version>.yml`), guarded by `when: <file> is file`.
Always give the include an absolute `{{ role_path }}/vars/...` path so an including role cannot
shadow the file. For a one-time platform task, use `lookup('first_found')` most-specific-first with
a `default.yml` or `skip: true`.

---

## 7. Secrets (Vault)

Secrets are generated once and read back thereafter, overridable, and never committed.

**The split vars/vault pattern.** Split every secret-bearing scope into two files: a plaintext
`vars` and an encrypted `vault`. The `vars` file holds normal variables plus pointers such as
`web_db_password: "{{ vault_web_db_password }}"`. The `vault` file holds only the `vault_`-prefixed
secrets and is encrypted with `ansible-vault`. A reviewer sees which secrets exist and where they
are used without the ciphertext, and a diff on the `vars` file stays meaningful.

**Encryption.** Encrypt with `ansible-vault` and AES256. Prefer encrypting whole files over
scattering `encrypt_string` output through the tree; a file is easier to rotate. Rotate with
`ansible-vault rekey`. `ansible-vault edit` rewrites the file every time, so use `view` to read and
only `edit` to change, or the diff churns for nothing.

**Vault IDs.** Give each vault a `--vault-id` label when more than one password is in play, so the
right password is tried first instead of Ansible trying each in turn. The vault password itself is
supplied at run time by `--vault-id @prompt`, a `--vault-password-file` (itself gitignored and
permission-locked), or `ANSIBLE_VAULT_PASSWORD_FILE`. The password file is never committed.

**Secrets in roles.** A role never carries a secret or site-specific value in its own
`vars`/`defaults`. It declares a non-sensitive default and expects the play to supply the real value
from a vaulted variable. Secrets are the playbook's job, not the role's.

**Secrets never enter Git, and the host enforces it.** Turn on the Git platform's push protection
and secret scanning so a secret is blocked at push, not merely caught later, and run `gitleaks` in
both pre-commit and CI so detection never rests on a single hook.

**No secret ever reaches a command line.** Arguments to `command`/`shell` are visible in the managed
host's process table, so a password passed that way is a disclosure even with `no_log`. Pass
secrets as module parameters from a vaulted variable, and keep the secret-bearing task `no_log`.

**Credentials for a Galaxy/hub source** never sit in `ansible.cfg`, because that file is committed.
Put the token in an environment variable (`ANSIBLE_GALAXY_SERVER_<ID>_TOKEN`) and leave only the
URL in the file.

**Storage.** A gitignored per-host store, every secret-bearing task `no_log`, and the store excluded
from inventory parsing.

**Rotate on a schedule.** Add a rotation cadence and a `rekey` path so a leaked credential has a
short life.

**Least privilege, as objects not literals.** The run holds only the access it needs. Keep
credentials in a secret store (Vault, the CI secret store, or env-var lookups) referenced by name,
never pasted into a playbook. Review access and run a security audit on a cadence.

## Connection and Transport Security

Key-based SSH only; password auth (`ask_pass`) is a fallback for first contact, not a standing
mode. Deploy keys with `ansible.posix.authorized_key` reading the public key through a
`lookup('ansible.builtin.file', ...)`, and manage `known_hosts` rather than disabling host-key
checking. `host_key_checking = false` is a lab-bootstrap exception, named and time-boxed, never a
default.

---

## 8. Become (Privilege Escalation)

Escalate narrowly. `become: true` belongs on the task or block that needs root, not blanket on the
play. A play that installs one package and reads three files should not run every task, including
fact gathering, as root. Set `become_user` when the target is not root. State the privilege a role
needs in its README.

Connection settings (`remote_user`, `become`, `become_method`) live in the project `ansible.cfg`,
which is the nearest config Ansible reads (project `./ansible.cfg` outranks `~/.ansible.cfg` and
`/etc/ansible/ansible.cfg`). `ansible-config dump --only-changed` prints what you have actually
overridden, so the effective config is auditable, not assumed.

---

## 9. Idempotence

Every task is idempotent: re-running a play changes nothing when nothing needs changing. Prefer a
module's own idempotence; otherwise gate with `creates`/`removes` or a `changed_when`/`failed_when`
tied to a real result. A blanket `changed_when: false` used to hide noise is not allowed. Molecule
proves this: a second `converge` reports zero changed.

**Honest status drives everything downstream.** `changed_when` and `failed_when` tie a task's
reported result to a real condition, not to the module's default. A handler fires only on a genuine
`changed`, so a dishonest `changed` silently triggers restarts, and a dishonest `ok` silently
suppresses them. `ansible.builtin.fail` with a `msg`, or `ansible.builtin.assert` with `that` and
`fail_msg`, turns a bad state into a clean, labelled stop.

`state: present` installs and holds a version; `state: latest` changes under you on every run and
makes "changed" non-deterministic. Reserve `latest` for a deliberate, tested upgrade path, not as
the default verb.

### Fact Gathering and Run Efficiency

- Set `gather_facts: false` on a play that uses no facts, and gather a subset
  (`gather_subset: ["!all", "min"]`, or just `hardware`, or `network`) when you need a few. On a
  large fleet, enable fact caching: `gathering = smart` plus a `jsonfile` cache plugin, so facts are
  gathered once and reused across plays rather than re-collected every run. A managed host with
  SELinux enabled needs `python3-libselinux` present before copy/file/template modules work; install
  it first rather than letting the run fail on it.
- Give the whole list to the module in one call; do not `loop` a package module one name at a time.
  `ansible.builtin.dnf: name: "{{ package_list }}"` is one transaction; a loop is one transaction
  per package and far slower. Use `loop` only where the module takes a single item per call (users,
  for instance).
- `forks` in `ansible.cfg` sets how many hosts run in parallel; raise it for a large static
  inventory rather than accepting the default of five.

### Inventory Modelling

**Loop over the inventory; do not build lists of hosts.** A variable holding a list of hosts
duplicates the inventory, forfeits group inheritance, forfeits `--limit`, and forfeits the
parallelism, throttling, and batching Ansible gives you for free across inventory hosts. Put the
hosts in groups and target the groups.

---

## 9. Reuse

### a. Pinning (Version Control and Dependency Tracking)

Every dependency is pinned in `requirements.yml` to an exact version, tag, or commit. A `galaxy.yml`
dependency is bounded `>=x.y.z,<next-major`; the exact pin lives in `requirements.yml` and nowhere
else.

**Immutable tags, promoted unchanged.** Releases are semantic-versioned (`0.y.z` until the
interface is stable, strict `X.Y.Z` for Galaxy), cut as immutable Git tags. Promote the *same* tag
through dev, test, and prod; never rebuild per environment, and never point a production reference
at `latest` or a branch. Synchronise versions across components that ship together, and document
every breaking change prominently where a consumer sees it before upgrading.

**Supply chain.** Install only from sources the project declares: Ansible Galaxy, a named git ref,
or a local/remote tarball. A `galaxy.yml` or `MANIFEST.json` in the source is what makes a git repo
installable as a collection.

**Verify what you installed.** `ansible-galaxy collection verify` checks installed files against
the collection's manifest; where a collection is GPG-signed on Galaxy, verify the signature on
install. A pin fixes the version; verification fixes the bytes.

**Prefer the free upstream** of any "certified" content. The identical upstream of
`redhat.rhel_system_roles` is `fedora.linux_system_roles` on Galaxy, free and pinnable like any
other dependency.

### b. Importing

`import_*` is static (parsed before the run); `include_*` is dynamic (evaluated when reached).
Default to `import_role`/`import_tasks` and `import_playbook`, because static content is visible to
`--list-tasks`, reachable by `--start-at-task`, and can be notified by name. Reach for
`include_role`/`include_tasks` only when the thing you are pulling in is chosen at run time: a loop
over a list, or a path that depends on a fact. The trade is real, so make it on purpose.

A `when:` behaves differently across the two: on an `import_*` the condition is copied onto every
imported task; on an `include_*` it gates the single include. A loop works on `include_*`, not on
`import_*`. These are the usual surprises; knowing which you used tells you which behaviour you get.

Keep shared task files generic by parameterising them (`name: "{{ package }}"`), so one task file
serves many callers. A task file is a flat list of tasks and nothing else.

Tag plays and tasks (`tags:`) so a run can be scoped with `--tags`/`--skip-tags`, and confirm the
map with `--list-tags`. Tags are for selecting work within a correct playbook, never for smuggling
branching logic a role should not contain.

### c. Exporting

Gather roles into a collection at the type or landscape level, not one collection per role. A
collection distributes as a unit, shares plugins across its roles, and gives every role a namespace
that removes collisions.

The `server_list` in `ansible.cfg` sets source order when more than one Galaxy/hub is configured.
Credentials for a Galaxy/hub source go in an environment variable, never in `ansible.cfg`.

---

## 10. Validation & Linting

### Validate Inputs and Contracts

Assert a role's required inputs at its entry with a clear `fail_msg`. Validate external or
structured data against a schema with a native module (`ansible.utils.validate`), not a shelled-out
script. Bad input is a clean diagnostic, never a crash midway through a run.

---

### Testing and Assertions

Every role has a molecule scenario whose `verify.yml` asserts with `ansible.builtin.assert`, each
assertion an explicit `that:` with a `fail_msg`. Every scenario asserts idempotence (a second
`converge` reports zero changed), that the expected outputs exist, and that any produced summary or
interface carries its required keys. Every role has a negative scenario — a missing input or a
failing step resolves to a controlled skip or a clean error, never an uncaught crash. Fixtures are
committed and real.

### Execution Control and Fleet-Level Failure Semantics

**Dry run before apply.** `--check` reports what would change without changing it, and `--diff`
shows the content delta for templated and line-edited files. Treat the pair as a release step. The
caveat: a task with `check_mode: false` runs for real even under `--check`, so never set it on a
task that mutates state, or `--check` stops being trustworthy. The modern spelling is `check_mode`,
not the retired `always_run`.

**Fleet-level failure control.** `serial:` rolls a change through the inventory in batches so a bad
release stops after the first batch instead of taking every host at once. `max_fail_percentage` and
`any_errors_fatal` set the threshold at which the whole play aborts. `run_once: true` runs a
one-time step (a migration, a notification) on a single host.

**Transient failure, not logic failure.** `until:` with `retries:` and `delay:` is for an operation
that is expected to converge (a service coming up, an endpoint answering), checked with a real
condition. A long task gets `async:`/`poll:` so the connection does not block. Neither is a
substitute for fixing a task that fails deterministically.

**Handlers survive a mid-play failure only on purpose.** A handler notified before a later task
fails does not run unless `force_handlers: true` is set on the play, or `meta: flush_handlers` has
already fired it at a chosen point. Decide this deliberately for anything that must restart to leave
the host consistent.

### Linting

The lint profile is the law. `profile: production` in `.ansible-lint`.

**YAML style enforced:**
- Two spaces per level, spaces only, never a tab. A file starts with `---`. The trailing `...` is
  optional and omitted.
- Module arguments are a YAML mapping, one `key: value` per line, never the inline `k=v` form.
- Booleans are `true`/`false`, lower case. Pick one spelling for the repo and let yamllint's
  `truthy` rule hold it; do not mix `yes`/`no` into the same tree.
- Quote any scalar that starts with a character YAML reads as syntax: `{`, `[`, `*`, `!`, `&`, `%`,
  `@`, or a leading `#`, and quote a bare `:` inside a value. A host pattern with `*`, `!`, `&`, or
  `:` is single-quoted for the same reason.
- One blank line separates tasks; arguments stack vertically under the module. Comment the
  non-obvious with `#`. No trailing whitespace, no run of blank lines (both are lint failures and
  both are noise in a diff).
- A line that must run long (a compound `when:`, a templated string) is folded with `>` or split
  across lines, not left to wrap.


---

## 11. Documentation

Every collection ships: `README.md` (how it is consumed) and `CHANGELOG.md` (Keep a Changelog
format).

Every role ships: `README.md` stating the contract (inputs, argument specs, user-facing
capabilities, the outcome, idempotent yes/no, and any rollback behaviour) and
`meta/argument_specs.yml` (every input typed and described).

`LICENSE` in the repository root, matching `galaxy.yml`.

Structured commits (conventional-commit form) and branches are what let changelog tooling
(`antsibull-changelog`) run itself.

---

## 12. CI-Enforced Conformance

**`conform` — the gate.** One command, exit non-zero on any failure, run by CI and locally:
`ansible-lint --profile production`, `molecule test` for every scenario, schema validation of any
data contracts, the structure/naming/must-have checks, and the pin check (every `galaxy.yml`
dependency has an exact `requirements.yml` pin, and no version literal lives outside it).

**`upgrade` — raise to the ceiling.** One command that raises every collection pin to the highest
release within its `galaxy.yml` bound and `ansible-core` to the highest within `requires_ansible`,
then runs `conform`; changes land only if `conform` passes. Those bounds are the only thing that
holds a version back.

`conform` runs in CI on every collection; nothing merges red. A rule `conform` cannot yet check is
a gap to close, not an exemption.

**Trunk-based, short-lived branches.** One long-lived `main`; feature branches live days, not
weeks, and merge behind required review and green CI. Protect `main` with both.

**Separate CI from CD.** CI tests on every push; CD builds and releases, gated separately. Put a
quality gate at each promotion stage, keep a release manifest recording which tag is deployed where,
and write the rollback step down before you need it. `conform` is the CI gate; promotion and
rollback are the CD half.

**Git as the audit trail.** Every configuration change lands through a reviewed, signed commit, so
history is the record of who changed what and when. Segment environments on the network so dev
cannot reach prod.

---

## 13. Template & File (Deployment)

Every file the automation writes declares its identity and its permissions, and a config that can
reject bad input is checked before it lands.

- `copy`, `template`, and `file` always set `owner`, `group`, and `mode` explicitly. An unset mode
  inherits whatever the umask gives, which is not a decision. Write the mode as a quoted string
  (`mode: "0644"`) so YAML does not read it as a surprising integer.
- Prefer `template` over `lineinfile`/`blockinfile` for anything with more than a line of structure.
  A template is the whole desired file, which is idempotent by construction and reviewable as a
  unit; line-editing a file the automation does not own is fragile and order-dependent. Keep
  templates in `templates/` with a `.j2` suffix.
- Template logic (`{% ... %}`, filters, `loop.index`) belongs in the template, never in the
  playbook. Open every generated config with a managed-file banner: `# {{ ansible_managed }}` plus a
  "do not edit by hand" line, and set `ansible_managed` in `ansible.cfg` so the banner is
  meaningful.
- For a config whose own tool can validate syntax, use the module's `validate:` option so a broken
  file is rejected before it replaces the live one: `visudo -cf %s` for sudoers, `sshd -t -f %s` for
  sshd_config, `nginx -t` style checks for nginx. `%s` is the temp file Ansible checks; the file
  only moves into place if validation passes. Set `backup: true` where a rollback copy is worth
  keeping.

---

## 14. Providing `env.templates` for Deployment

Connection settings (`remote_user`, `become`, `become_method`) live in the project `ansible.cfg`,
which is the nearest config Ansible reads. `ansible-config dump --only-changed` prints what you
have actually overridden.

**Inventory is a directory, not a file.** Use `group_vars/` and `host_vars/` as directories of
files, one file per topic, named after the role they steer; reserve `ansible.yml` for connection
variables (user, become). A role's `defaults/main.yml` then drops straight into the structure. The
payoff is fewer merge conflicts across maintainers and a layout that documents itself under `tree`.

**Single Source of Truth.** Each piece of data has one authoritative home. Pull technical data
(addresses, OS) from the system that owns it through a dynamic inventory plugin, pull
organisational data from a CMDB, and keep in the static inventory only what lives nowhere else.
Combine the sources into one inventory rather than maintaining copies.

The controlled host set is static inventory; what varies is discovered at run time, not hard-coded.

Execution environments without a subscription: either run `ansible-playbook` directly (the
controller is the execution environment, no image needed) or build your own EE with
`ansible-builder` on a free base image and run it under `ansible-navigator`/podman. Both paths are
first-class; neither costs anything.

---

## Appendix A: Allowed Mechanisms for Linting

The order below is cheapest-first, which is also roughly most-failures-first. Wire it into
`conform` and `pre-commit`.

| Stage | Command | Catches |
|---|---|---|
| Parse | `ansible-playbook --syntax-check site.yml` | malformed YAML, unknown play keys |
| YAML style | `yamllint .` | indentation, truthy spelling, trailing space, blank-line runs |
| Lint | `ansible-lint --profile production` | FQCN, naming, risky patterns, deprecations |
| Secrets | `gitleaks detect --no-banner` or `detect-secrets scan` | anything secret-bearing committed in the clear |
| Collection sanity | `ansible-test sanity --docker` (or `--venv`) | import, doc, and metadata defects in a collection |
| Role tests | `molecule test` per scenario | converge, idempotence, verify, negative |
| Supply chain | `ansible-galaxy collection verify <ns.coll>` | installed bytes vs manifest / signature |
| Dry run | `ansible-playbook --check --diff site.yml` | what a real run would change, before it does |

**Toolchain (all free):**

| Tool | What it does | Install |
|---|---|---|
| `ansible-core` | the runtime, plus `ansible-playbook`, `ansible-vault`, `ansible-galaxy`, `ansible-doc`, `ansible-config`, `ansible-inventory`, `ansible-test` | `pip install ansible-core` |
| `ansible-lint` | rule-based static analysis at `profile: production` | `pip install ansible-lint` |
| `yamllint` | YAML style | `pip install yamllint` |
| `molecule` + `molecule-plugins[podman]` | per-role test scenarios, run rootless on podman | `pip install molecule molecule-plugins[podman]` |
| `ansible-test` | collection sanity / unit / integration tests | ships in `ansible-core` |
| `ansible-navigator` | run and inspect inside an execution environment | `pip install ansible-navigator` |
| `ansible-builder` | build your own execution-environment image | `pip install ansible-builder` |
| `podman` | rootless engine for EEs and molecule | distro package |
| `pre-commit` | runs lint/yamllint/secret-scan as a git hook | `pip install pre-commit` |
| `gitleaks` or `detect-secrets` | scans the tree and history for committed secrets | gitleaks binary / `pip install detect-secrets` |
| `antsibull-changelog` | changelog fragments assembled into the `CHANGELOG` | `pip install antsibull-changelog` |

**Built-in flags (free):** `--syntax-check`, `--check` and `--diff`, `--list-tasks` /
`--list-hosts` / `--list-tags`, `--step` and `--start-at-task`, `-v` through `-vvvv` for graded
verbosity, and `log_path` in `ansible.cfg` (or `ANSIBLE_LOG_PATH`) to persist run output, with
`logrotate` managing it if it lands under `/var/log`. `ansible-doc <fqcn>` is the authoritative
argument reference for any module, offline.

**Pre-commit config:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/adrienverge/yamllint
    rev: v1.35.1
    hooks:
      - id: yamllint
  - repo: https://github.com/ansible/ansible-lint
    rev: v24.9.2
    hooks:
      - id: ansible-lint
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

Pin each `rev:` like any other dependency, and let `upgrade` raise it.

## Appendix B: Allowed Mechanisms for Importing

**Source types.** Install only from sources the project declares:
- Ansible Galaxy
- A named git ref
- A local/remote tarball

Each pinned in `requirements.yml` to an exact version, tag, or commit. A `galaxy.yml` or
`MANIFEST.json` in the source is what makes a git repo installable as a collection.

**Import vs include.** `import_*` is static (parsed before the run); `include_*` is dynamic
(evaluated when reached). Default to static. Reach for dynamic only when the thing you are pulling
in is chosen at run time. A task file is a flat list of tasks and nothing else.

**Verification.** `ansible-galaxy collection verify` checks installed files against the
collection's manifest. A pin fixes the version; verification fixes the bytes.

**Source order.** The `server_list` in `ansible.cfg` sets source order when more than one
Galaxy/hub is configured.

---

## Sources (all free)

- *Good Practices for Ansible* (GPA), redhat-cop.github.io/automation-good-practices
- Ansible documentation, docs.ansible.com
- `ansible-lint` documentation and rule list, ansible.readthedocs.io/projects/lint
- Molecule documentation, ansible.readthedocs.io/projects/molecule
- `ansible-builder` documentation, ansible.readthedocs.io/projects/builder
- `fedora.linux_system_roles` on Ansible Galaxy
- Pipeline security tools: `trivy`, `grype`, `syft`, `cosign`, `gitleaks`, `detect-secrets`
- Semantic Versioning (semver.org) and Conventional Commits (conventionalcommits.org)
- RH294, *Red Hat Enterprise Linux Automation with Ansible* (RHEL 9.0, Edition 5)


## Red Hat Subscription Features and Their Cost-Free Equivalents

| Red Hat (subscription) | Cost-free equivalent |
|---|---|
| Ansible Automation Platform (AAP) | `ansible-core` plus the toolchain |
| Automation Controller (web UI, RBAC, scheduling) | AWX (free upstream; needs Kubernetes) or CI-driven runs (GitLab CI / GitHub Actions) with cron / systemd timers for scheduling |
| Automation Hub (certified collections) | Ansible Galaxy plus community collections, pinned and verified |
| Private Automation Hub | `galaxy_ng` / `pulp_ansible` self-hosted, or a git + tarball source in `requirements.yml` |
| `redhat.rhel_system_roles` / `rhel-system-roles` RPM | `fedora.linux_system_roles` on Galaxy (same roles, upstream and free) |
| Supported EE images from `registry.redhat.io` | build your own with `ansible-builder` on a free base (CentOS Stream, Fedora, a Quay community image), run under `ansible-navigator`/podman |
| `ansible-navigator` default EE (entitled) | a self-built EE, or `ansible-playbook` with no EE at all |
| Red Hat Insights / `insights_client` | no drop-in; use OpenSCAP (`openscap`/`scap-security-guide`, free) for compliance scanning |
| `subscription-manager` / RHSM tasks | on cost-free hosts, use the distro's native repos (CentOS Stream, Rocky, Alma, Fedora); no RHSM needed |