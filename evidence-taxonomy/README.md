# Evidence taxonomy

The single source of truth for the `raw/` evidence lanes, consumed by
**both** sides so the directory a processor reads and the directory `sort`
writes never drift:

- the dxdfir Go front-end (`go/internal/identify`) — the sort classifier
  that types each file **by content** and files it into a canonical lane,
  and the collection/lanes views that count and scope evidence;
- the `get_sybers.dxdfir` ansible roles — their raw input-dir defaults.

One `<name>.yml` per lane; `_index.yml` lists them. `order` is the
precedence the classifier walks: the first lane whose content signature
matches wins; failing any magic, the first lane whose extension claims the
file wins; failing both, the file goes to `catch_all_subdir` (never
dropped). A file's **identity is its content**, not its path — extensions
are only a fallback.

Per-lane fields: `subdir` (the canonical directory under `raw/`), content
`signatures` (magic), claimed `extensions`, and optional notes the
classifier surfaces.
