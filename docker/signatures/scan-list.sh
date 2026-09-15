#!/bin/sh
# The ONLY script the signatures image runs for YARA (baked, allow-listed): a
# per-file scan over the mounted list with the mounted include index. No
# arguments accepted. (Carried over verbatim from the former get-sybers/yara
# image; sh remains in the consolidated image only for this loop.)
set -eu
while IFS= read -r f; do
    [ -n "$f" ] && yara -w -s -N /index.yar "$f" || true
done < /list.txt
