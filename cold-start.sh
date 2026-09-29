#!/usr/bin/env bash
set -euo pipefail

# Remove all Docker images. Add -f/--force to also stop and remove
# containers that are holding images hostage.

FORCE=0
[[ "${1:-}" == "-f" || "${1:-}" == "--force" ]] && FORCE=1

images=$(docker images -aq | sort -u)

if [[ -z "$images" ]]; then
  echo "No images to remove."
  exit 0
fi

if [[ "$FORCE" -eq 1 ]]; then
  # Stop and remove all containers first so nothing blocks image removal
  containers=$(docker ps -aq)
  if [[ -n "$containers" ]]; then
    echo "Stopping and removing containers..."
    docker stop $containers >/dev/null 2>&1 || true
    docker rm $containers   >/dev/null 2>&1 || true
  fi
  echo "Force-removing all images..."
  docker rmi -f $images
else
  echo "Removing all images..."
  docker rmi $images
fi

echo "Done."
