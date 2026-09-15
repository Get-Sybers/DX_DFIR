#!/bin/bash
#
# Set the project version in the few places that genuinely carry it.
#
#   ./dev-scripts/set-version.sh 0.3.0-alpha.1
#
# Why this exists: promoting alpha -> beta once meant hand-editing a dozen
# documents, and a stale string in any of them would have made the release
# contradict itself. Maturity now lives in the git tag and the GitHub Release,
# surfaced by a badge that reads them directly — so prose never needs touching.
#
# What still carries a literal version, and why:
#   CHANGELOG.md    the versioned record; that is its whole job
#
# Everything else reads the release from the badge or the CHANGELOG.
#
# This does NOT tag. Releasing is:
#   ./dev-scripts/set-version.sh X.Y.Z-pre.N
#   git commit -am "Release vX.Y.Z-pre.N"
#   git tag -a vX.Y.Z-pre.N -m "vX.Y.Z-pre.N"
#   git push origin main --follow-tags
# then create the GitHub Release from the tag, ticking "pre-release" for any
# -alpha / -beta / -rc.

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"
cd "$REPO_ROOT_DIR"

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo ""
    echo "  <version> is SemVer without the leading v, e.g."
    echo "    0.3.0             a release"
    echo "    0.3.0-alpha.1     a prerelease of 0.3.0"
    echo "    0.3.0-beta.2      a later prerelease of the SAME 0.3.0"
    echo "    0.3.0-rc.1        release candidate for 0.3.0"
    echo ""
    echo "  Prereleases all target ONE version and sort alpha < beta < rc < release."
    echo "  0.1.0-alpha followed by 0.2.0-beta is not a promotion — it abandons 0.1.0."
    echo ""
    echo "  Current: $(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\]' CHANGELOG.md | tr -d '#[] ')"
    exit 1
fi

# SemVer 2.0.0 §2 (core) and §9 (prerelease).
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ '$VERSION' is not valid SemVer."
    echo "   Expected MAJOR.MINOR.PATCH with an optional -prerelease, and no leading 'v'."
    exit 1
fi

TODAY="$(date -u +%Y-%m-%d)"

echo "Setting version to $VERSION"
echo ""

# CHANGELOG: retitle the topmost release heading, or open a new section under
# Unreleased if the top one is already tagged.
CURRENT=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\]' CHANGELOG.md | tr -d '#[] ' || true)
if [[ -z "$CURRENT" ]]; then
    echo "❌ No release heading found in CHANGELOG.md."
    exit 1
fi

if git rev-parse -q --verify "refs/tags/v$CURRENT" >/dev/null 2>&1; then
    # v$CURRENT is already released, so its notes are a historical record and
    # are never retitled. Open an empty section for the new version above it.
    #
    # Deliberately does NOT move anything out of Unreleased: this project keeps
    # a standing "To be resolved before X" roadmap there, which is not release
    # notes. Writing the notes is a human job; this only does the mechanics.
    python3 - "$VERSION" "$TODAY" <<'PY'
import re, sys
version, today = sys.argv[1], sys.argv[2]
text = open('CHANGELOG.md').read()

new_section = f"## [{version}] - {today}\n\n_Add release notes._\n\n"

# Insert immediately above the topmost existing release heading.
text = re.sub(r'^(## \[[0-9])', new_section + r'\1', text, count=1, flags=re.M)

# Link refs: Unreleased compares against the new tag; define the new tag above
# the previous ones so the list stays newest-first.
text = re.sub(r'^\[Unreleased\]: (\S+)/compare/\S+\.\.\.HEAD',
              rf'[Unreleased]: \1/compare/v{version}...HEAD', text, count=1, flags=re.M)
text = re.sub(r'^(\[Unreleased\]: .*\n)',
              rf'\1[{version}]: https://github.com/Get-Sybers/DX_DFIR/releases/tag/v{version}\n',
              text, count=1, flags=re.M)

open('CHANGELOG.md', 'w').write(text)
PY
    echo "  CHANGELOG.md   new empty section [$VERSION] - $TODAY"
    echo "                 (v$CURRENT is tagged, so its notes were left alone)"
else
    # Not yet tagged — this release is still being assembled, so retitle it.
    sed -i "s|^## \[$CURRENT\].*|## [$VERSION] - $TODAY|" CHANGELOG.md
    sed -i "s|^\[$CURRENT\]:|[$VERSION]:|" CHANGELOG.md
    sed -i "s|v$CURRENT|v$VERSION|g" CHANGELOG.md
    echo "  CHANGELOG.md   [$CURRENT] -> [$VERSION] - $TODAY"
fi

echo ""
echo "✅ Done. Nothing else carries the version — the README badge reads the"
echo "   latest GitHub Release directly."
echo ""
echo "Next:"
echo "  ./.github/tests/run-checks.sh"
echo "  git commit -am 'Release v$VERSION'"
echo "  git tag -a v$VERSION -m 'v$VERSION'"
echo "  git push origin main --follow-tags"
case "$VERSION" in
    *-*) echo "  ...then create the GitHub Release and TICK 'set as a pre-release'." ;;
    *)   echo "  ...then create the GitHub Release." ;;
esac
