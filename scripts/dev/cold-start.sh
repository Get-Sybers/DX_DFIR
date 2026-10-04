#!/usr/bin/env bash
set -euo pipefail

# Cold-start cleanup for this repo. Wipes all Docker images and volumes,
# the generated .ansible and .venv dirs, and every local branch except
# main, so the next run builds from nothing. Add -f/--force to also stop
# and remove containers that are holding images or volumes hostage.

FORCE=0
[[ "${1:-}" == "-f" || "${1:-}" == "--force" ]] && FORCE=1

# Repo root, resolved from git so this works from any subdirectory.
# Falls back to the script's own directory if we're not in a git tree.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
  || REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ "$FORCE" -eq 1 ]]; then
  # Stop and remove all containers first so nothing blocks image or
  # volume removal.
  containers=$(docker ps -aq)
  if [[ -n "$containers" ]]; then
    echo "Stopping and removing containers..."
    docker stop $containers >/dev/null 2>&1 || true
    docker rm   $containers >/dev/null 2>&1 || true
  fi
fi

# Remove volumes. With containers gone (force) every volume is fair game;
# otherwise any still in use get skipped.
volumes=$(docker volume ls -q)
if [[ -n "$volumes" ]]; then
  echo "Removing volumes..."
  docker volume rm $volumes >/dev/null 2>&1 || true
else
  echo "No volumes to remove."
fi

# Remove images.
images=$(docker images -aq | sort -u)
if [[ -n "$images" ]]; then
  if [[ "$FORCE" -eq 1 ]]; then
    echo "Force-removing all images..."
    docker rmi -f $images
  else
    echo "Removing all images..."
    docker rmi $images
  fi
else
  echo "No images to remove."
fi

# Scrub the generated dirs so the next run bootstraps them fresh.
if [[ -n "$REPO_ROOT" ]]; then
  echo "Removing $REPO_ROOT/.ansible and $REPO_ROOT/.venv..."
  rm -rf -- "$REPO_ROOT/.ansible" "$REPO_ROOT/.venv"
fi

# Delete every local branch except main. Anchored to the repo with the same
# rev-parse method as REPO_ROOT, and matched exactly so names like
# "maintenance" aren't caught. Switch to main first so we're not standing on
# a branch we're trying to delete.
if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  switched=1
  if [[ "$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)" != "main" ]]; then
    git -C "$REPO_ROOT" checkout main || switched=0
  fi
  if [[ "$switched" -eq 1 ]]; then
    branches=$(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short)' refs/heads/ \
      | grep -vx main || true)
    if [[ -n "$branches" ]]; then
      echo "Deleting branches: $branches"
      git -C "$REPO_ROOT" branch -D $branches
    else
      echo "No branches to remove."
    fi
  else
    echo "Could not switch to main (uncommitted changes?); skipping branch cleanup." >&2
  fi
fi

echo "Done."
