# Reference — standards and conventions

For contributors: the conventions the code holds to, the harness that enforces them, and
a map of the repositories DX_DFIR is built on. Read [CONTRIBUTING.md](../../.github/CONTRIBUTING.md)
first for the workflow; these pages are the *house style*.

- **[Go standards](go-standards.md)** — the `go-thonic` naming vocabulary, the `internal/`
  package layout, the Sunset TUI theme, and error handling.
- **[Ansible standards](ansible-standards.md)** — *roles group, playbooks decide*;
  one-action tasks; the dynamic walk; pinned dependencies; robustness.
- **[Build and test](build-and-test.md)** — the check harness, the smoke test, the Go
  pins, and the ephemeral build.
- **[Repository map](repository-map.md)** — the Get-Sybers ecosystem and the in-repo layout.

## The one principle behind all of it

The naming and the layering rhyme across languages on purpose: **a name reads as a phrase
at the point it's used, and each layer does one thing.** In Go, `collection.CheckStatus()`
reads as a phrase and never stutters. In Ansible, a task does one action and the playbook
holds the logic. In the pipeline, a processor runs one tool and emits a summary. Same
instinct, three languages — so someone who learns one layer can predict the next.
