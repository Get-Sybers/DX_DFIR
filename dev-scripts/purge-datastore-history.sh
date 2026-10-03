#!/bin/bash
# ==============================================================================
# Purge all data_store/ paths from git history.
#
# ⚠️  THIS REWRITES EVERY COMMIT SHA IN THE REPOSITORY.
#     Everyone with a clone must re-clone. Merged PR references break.
#     It is not reversible once force-pushed.
#
# Run this yourself. It is deliberately not wired into anything.
#
# Context — what this actually removes (audited 2026-08-03):
#   58 data_store paths exist in history. HEAD tracks ZERO non-skeleton files
#   there, so nothing currently in use is lost. The content is:
#     - 24 x *.log:Zone.Identifier   ([ZoneTransfer] / ZoneId=3, no URLs)
#     - data_store/dependencies/SuperMem/   (4 third-party files)
#     - data_store/dependencies/log2timeline/ (3 .py files)
#     - .gitkeep / README.md skeleton
#
#   No credentials, private keys, or tokens were found anywhere in history.
#   The only arguably sensitive artefact is the path name "P2-Network_PCAP".
#
#   If that case name is not sensitive, you probably do not need this script.
#
# Validated on a disposable mirror clone (the real repo was not touched):
#   commits          71 -> 58   (13 data_store-only commits dropped)
#   data_store paths 74 -> 0
#   main sha         45f7b8e2 -> b54d0c61   (every SHA changes)
#   remaining tree   714 files, scripts/ and README.md intact
# ==============================================================================
set -euo pipefail

REPO_URL="${1:-}"
if [[ -z "$REPO_URL" ]]; then
    echo "usage: $0 <clone-url-or-path>"
    echo ""
    echo "Run against a FRESH clone, never your working copy:"
    echo "  git clone --mirror https://github.com/Get-Sybers/DX_DFIR.git purge-work"
    echo "  $0 purge-work"
    exit 1
fi

command -v git-filter-repo >/dev/null 2>&1 || {
    echo "❌ git-filter-repo not installed."
    echo "   pip install git-filter-repo   (or: apt install git-filter-repo)"
    echo "   Do NOT substitute filter-branch — it is slow and error-prone here."
    exit 1
}

cd "$REPO_URL"

echo "── before ──────────────────────────────────────────"
echo "commits:            $(git rev-list --all --count)"
echo "data_store paths:   $(git log --all --pretty=format: --name-only --diff-filter=A | grep -c '^data_store/' || true)"
echo "HEAD sha:           $(git rev-parse HEAD 2>/dev/null || git rev-parse --verify main)"
echo ""

read -r -p "Rewrite history in $(pwd)? [y/N]: " ok
[[ "${ok,,}" == "y" || "${ok,,}" == "yes" ]] || { echo "aborted"; exit 1; }

git filter-repo --path data_store --invert-paths --force

echo ""
echo "── after ───────────────────────────────────────────"
echo "commits:            $(git rev-list --all --count)"
remaining=$(git log --all --pretty=format: --name-only --diff-filter=A | grep -c '^data_store/' || true)
echo "data_store paths:   $remaining"
echo "HEAD sha:           $(git rev-parse HEAD 2>/dev/null || git rev-parse --verify main)"
echo ""

if [[ "$remaining" -eq 0 ]]; then
    echo "✅ data_store fully purged from history."
else
    echo "❌ $remaining data_store paths remain — do not push. Investigate first."
    exit 1
fi

cat <<'EOF'

Not pushed. To publish the rewrite (destructive, coordinate first):

    git push --force --all
    git push --force --tags

Then every collaborator must re-clone. Pulling will not work.

Note: this removes the paths from history, but GitHub keeps unreferenced
objects reachable via the API for a period. For anything genuinely secret,
rotate the secret — purging history is not sufficient on its own.
EOF
