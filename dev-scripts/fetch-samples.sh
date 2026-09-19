#!/bin/bash
#
# Fetch DFIR test samples and land them where the processing scripts read.
#
#   ./dev-scripts/fetch-samples.sh --list              # every group and where it routes
#   ./dev-scripts/fetch-samples.sh --list <group>      # the files in one group + routing
#   ./dev-scripts/fetch-samples.sh --route             # show the routing map for every file
#   ./dev-scripts/fetch-samples.sh --fetch <group>     # fetch one group into data_store/raw/
#   ./dev-scripts/fetch-samples.sh --file <name>       # fetch individual files by name
#                                                      # pattern, one at a time
#   ./dev-scripts/fetch-samples.sh --fetch all --yes   # fetch everything (2.8 TB)
#   ./dev-scripts/fetch-samples.sh --verify [<group>]  # re-check what is on disk
#
#   Flags: --keep-archives retains the compressed source under .sources/ after
#          extraction (hash-re-verifiable, but doubles disk). The DEFAULT prunes
#          each source once its artifact is extracted, so nothing is stored
#          twice. Uncompressed artifacts (.E01, .dd, …) are never staged — they
#          download straight into the type directory.
#
# WHERE THINGS LAND: routed by FILE TYPE, then isolated in a per-group folder:
#
#     data_store/raw/disk_images/<group>/   the plaso lane
#     data_store/raw/memory/<group>/        the memory lane
#     data_store/raw/pcaps/<group>/         the zeek lane
#     data_store/raw/logs/winevt/<group>/  the evtx lane
#     data_store/raw/other_raw_data/<group>/         no processor yet (mobile, apk, …)
#
#   Type is decided per file by its content/name (a single scenario group can
#   hold a disk image AND a pcap AND a memory dump, each routed separately). The
#   final <group>/ folder gives every download its own space, so files from
#   different corpora that share a basename cannot overwrite or silently
#   deduplicate one another — 172 basenames collide across the manifest, at
#   least one (terry-2009-12-11-001.E01) with genuinely different content. A
#   multi-segment set stays whole because all its parts share one group folder.
#
#   NOTE: the processing scripts currently glob their type directory at depth 1,
#   so they will need to descend into <group>/ subfolders (or be pointed at one)
#   to see these files — a deliberate follow-up, not an oversight.
#
# DECOMPRESSION and DEDUPLICATION:
#   Uncompressed artifacts (.E01 and its .E02…E0x continuation segments, .dd,
#   .vmdk, …) are downloaded straight into the type directory and verified in
#   place — there is only ever one copy. Every segment of a multi-volume EWF set
#   is its own manifest row and lands flat in the same directory, which is
#   exactly what libewf/plaso needs: the plaso lane processes
#   the .E01 and libewf pulls in the rest.
#
#   Compressed samples (.pcap.gz, .dmp.gz, *.mddramimage.zip) can't be consumed
#   as-is — zeek wants .pcap, memory wants the raw dump — so they are staged
#   under data_store/raw/.sources/<group>/, verified, extracted into the type
#   directory, and then the staged source is DELETED so the data is not stored
#   twice (use --keep-archives to retain it). A .<name>.done marker records a
#   completed extraction so re-runs skip the work even after the source is gone.
#
# TWO LEVELS OF VERIFICATION, and the difference matters:
#
#   sha256 present  — pinned to a hash computed by streaming the object through
#                     sha256sum. A mismatch means the upstream object changed or
#                     the download was tampered with.
#   sha256 is "-"   — size-verified only. The manifest carries S3's own
#                     Content-Length, so a truncated or wrong-file download is
#                     still caught, but a same-size substitution is not.
#
# Everything fetched lands under data_store/raw/, which is deny-by-default
# gitignored. Nothing here is case evidence; the sources are public corpora.
# No samples are committed to the repo; every file is fetched here on demand.

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
REPO_ROOT_DIR="$(realpath "$SCRIPT_DIR/..")"
cd "$REPO_ROOT_DIR"

RAW="data_store/raw"
SRC_DIR="$RAW/.sources"                       # staged compressed originals
BASE="https://digitalcorpora.s3.amazonaws.com/corpora"
S3_BASE="s3://digitalcorpora/corpora"         # same objects over the S3 API
MANIFEST_FILE="dev-scripts/samples-manifest.tsv"
KEEP_ARCHIVES=false
EXCLUDE=""                                    # --exclude <regex>: skip matching groups

# Prefer the AWS CLI when present: `aws s3 cp` does parallel multipart with
# automatic part-level retries (more robust on the 80 GB objects than a single
# curl stream) and handles keys with spaces/parentheses natively. Fall back to
# curl (with a percent-encoded URL) when the CLI is not installed.
DL_TOOL="curl"; command -v aws >/dev/null 2>&1 && DL_TOOL="aws"

[[ -f "$MANIFEST_FILE" ]] || { echo "missing $MANIFEST_FILE" >&2; exit 1; }

human() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "$1 bytes"; }

# Percent-encode a URL path. Many manifest paths contain spaces and parentheses
# (e.g. "2022 CTF - Windows.zip", "3_Samsung GSM_SM-G973F_DS Galaxy S10.zip");
# curl rejects those raw ("Malformed input to a URL function"). Encode every
# byte except the RFC 3986 unreserved set and "/", which must stay a separator.
urlencode_path() {
    local s="$1" out= c i
    for (( i=0; i<${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9._~/-]) out+="$c" ;;
            *) printf -v c '%%%02X' "'$c"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

# curl shows a progress bar interactively but falls back to a noisy transfer
# table when piped, so stay quiet when stdout is not a terminal.
if [[ -t 1 ]]; then CURL_PROGRESS=(--progress-bar); else CURL_PROGRESS=(--no-progress-meter); fi

# Download one object (path relative to the corpora/ root) to a local path.
# aws s3 cp when available (parallel multipart, part-level retries, native
# handling of keys with spaces); otherwise curl with a percent-encoded URL.
download() { # rel dest
    local rel="$1" dest="$2"
    # A path column that is itself a full URL (http/https) is fetched directly —
    # for samples hosted outside Digital Corpora (e.g. GitHub). It is stored
    # already percent-encoded in the manifest, so curl gets it verbatim; aws and
    # the corpora base are bypassed.
    case "$rel" in
        http://*|https://*)
            curl -fSL "${CURL_PROGRESS[@]}" --retry 3 --retry-delay 5 -C - -o "$dest" "$rel"
            return ;;
    esac
    if [[ "$DL_TOOL" == aws ]]; then
        aws s3 cp "$S3_BASE/$rel" "$dest" --no-sign-request --only-show-errors
    else
        curl -fSL "${CURL_PROGRESS[@]}" --retry 3 --retry-delay 5 -C - -o "$dest" "$BASE/$(urlencode_path "$rel")"
    fi
}

manifest_rows() { grep -v '^#' "$MANIFEST_FILE" | grep -v '^[[:space:]]*$'; }

rows_for() { # group, where "all" matches everything; honours $EXCLUDE (group regex)
    { if [[ "$1" == "all" ]]; then manifest_rows
      else manifest_rows | awk -F'\t' -v g="$1" '$1==g'
      fi
    } | awk -F'\t' -v ex="$EXCLUDE" 'ex=="" || $1 !~ ex'
}

# ------------------------------------------------------------------------------
# Routing: (group, name) -> directory under data_store/raw where the artifact
# must land so the matching processor's depth-1 glob finds it.
#
# Order matters. Memory markers are checked before the disk rule because a bare
# ".raw" is globbed by BOTH memory and log2timeline; a memory-image name
# (*.dmp.gz, *dramimage, *.mem, *.lime) must win. Everything with no processor
# falls through to other_raw_data.
classify_dir() { # group name  ->  path under $RAW
    local group="$1" ln; ln="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"

    case "$ln" in
        *.evtx)                       echo "$RAW/logs/winevt"; return ;;
    esac
    # memory: explicit dump markers (checked before the disk .raw rule)
    case "$ln" in
        *dramimage|*dramimage.zip|*.dmp|*.dmp.gz|*.mem|*.lime|*.vmem|*.dump)
                                      echo "$RAW/memory"; return ;;
    esac
    # network captures
    case "$ln" in
        *.pcap|*.pcap.gz|*.pcapng|*.cap)
                                      echo "$RAW/pcaps"; return ;;
    esac
    # disk / media images by extension
    case "$ln" in
        *.e[0-9][0-9]|*.l[0-9][0-9]|*.aff|*.vmdk|*.vhd|*.dd|*.img|*.raw|*.001|*.[0-9][0-9][0-9])
                                      echo "$RAW/disk_images"; return ;;
    esac
    # bare archives with no type marker: fall back on the corpus. Drive and
    # scenario corpora are disk/media images; everything else is unmapped.
    case "$ln" in
        *.zip|*.7z|*.tar|*.tgz|*.tar.gz|*.gz)
            case "$group" in
                drives-*|scenarios-*|dfrws-*) echo "$RAW/disk_images"; return ;;
            esac
            ;;
    esac
    # mobile extractions, apk, and anything else: no processor consumes these.
    echo "$RAW/other_raw_data"
}

# ".dmp" is ambiguous: tcpdump writes packet captures as .dmp (the nps-2009
# net-*.dmp.gz files), Windows writes crash dumps. The name-based rule above
# routes .dmp to memory/; once the BYTES exist, a capture magic wins and the
# file is re-routed to pcaps/ so zeek/suricata find it (memory can't parse
# a capture anyway). Same magics as get_sybers_dxdfir.zeek.is_pcap.
is_pcap_magic() { # path
    local h; h="$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    case "$h" in a1b2c3d4|d4c3b2a1|a1b23c4d|4d3cb2a1|0a0d0d0a) return 0 ;; esac
    return 1
}

# Destination directory for a file: its type directory, then a per-group folder.
#
# Every download lands in its own group folder — data_store/raw/<type>/<group>/
# — so files from different corpora that happen to share a basename can never
# overwrite or silently deduplicate each other. (172 basenames collide across
# the manifest, at least one with genuinely different content: see the audit of
# terry-2009-12-11-001.E01.) A multi-segment set stays intact because all its
# segments belong to the same group and therefore the same folder.
group_dir() { # group name -> path under $RAW
    echo "$(classify_dir "$1" "$2")/$1"
}

# The filename a source decompresses to, when that is knowable up front. Used to
# detect "already materialized" without re-extracting. Empty for multi-file
# archives whose contents are not known from the name alone.
expected_output() { # name -> basename or ""
    local n="$1"
    case "$n" in
        *.tar.gz|*.tgz|*.tar|*.zip|*.7z) echo "" ;;   # archive: contents unknown
        *.gz)                            echo "${n%.gz}" ;;
        *)                               echo "$n" ;;  # already an artifact
    esac
}

# True when a source needs decompression/extraction (and therefore staging).
# False for a file that is already the artifact — those download straight into
# the type directory with no second copy.
is_packed() { # name
    case "$1" in
        *.tar.gz|*.tgz|*.tar|*.zip|*.7z|*.gz) return 0 ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------------------
list_groups() {
    printf '%-38s %6s %10s %s\n' GROUP FILES SIZE PINNED
    manifest_rows | awk -F'\t' '
        { n[$1]++; b[$1]+=$3; if ($4!="-") p[$1]++ }
        END { for (g in n) printf "%s\t%d\t%d\t%d\n", g, n[g], b[g], p[g]+0 }' \
    | sort | while IFS=$'\t' read -r g n b p; do
        printf '%-38s %6d %10s %d/%d\n' "$g" "$n" "$(human "$b")" "$p" "$n"
    done
    echo
    manifest_rows | awk -F'\t' '
        { n++; b+=$3; if ($4!="-") p++ }
        END { printf "%d files, %.1f GB total, %d hash-pinned\n", n, b/1024/1024/1024, p+0 }'
}

list_group() { # group
    local rows; rows="$(rows_for "$1")"
    [[ -n "$rows" ]] || { echo "no such group: $1" >&2; echo "try --list" >&2; exit 2; }
    printf '%-40s %10s  %-22s %s\n' NAME SIZE ROUTES-TO SHA256
    local dir
    while IFS=$'\t' read -r group name bytes sha _; do
        dir="$(group_dir "$group" "$name")"
        printf '%-40s %10s  %-34s %s\n' "$name" "$(human "$bytes")" \
            "${dir#"$RAW"/}" \
            "$( [[ "$sha" == "-" ]] && echo 'size only' || echo "${sha:0:16}…" )"
    done <<< "$rows"
}

route_map() { # every file -> its destination
    printf '%-22s %-42s %s\n' GROUP NAME ROUTES-TO
    while IFS=$'\t' read -r group name _ _ _; do
        printf '%-22s %-42s %s\n' "$group" "$name" "$(group_dir "$group" "$name")"
    done <<< "$(manifest_rows)" | sort
}

# 0 when a staged source matches its manifest row: size always, hash when pinned.
verify_source() { # path bytes sha
    local path="$1" bytes="$2" sha="$3" actual
    [[ -f "$path" ]] || return 1
    [[ "$(stat -c%s "$path")" == "$bytes" ]] || return 1
    [[ "$sha" == "-" ]] && return 0
    actual="$(sha256sum "$path" | cut -d' ' -f1)"
    [[ "$actual" == "$sha" ]]
}

# Decompress/extract a verified source into its per-group destination folder.
#
# Because every group has its own folder, archive contents are extracted in
# place with their internal structure preserved — there is no need to flatten or
# namespace anything, and nothing from another group can be there to collide
# with. An archive that wraps its files in a top-level directory therefore lands
# as <group>/<that-dir>/…; one that does not lands its files directly under the
# group folder.
# Sort the files of an already-unpacked archive into per-type directories.
#
# You cannot know what an archive holds from its name — a scenario zip may bundle
# a disk image, a memory dump AND a pcap — so classification happens per
# EXTRACTED FILE, not per archive. Each file is routed by its own type into
# data_store/raw/<type>/<group>/<archive>/, i.e. under a subdirectory named
# after the archive it was pulled from — in EVERY type dir, other_raw_data
# included — so its origin is always traceable and two archives never collide.
# The archive's internal path is preserved beneath that. Recursive processors
# find them at any depth.
sort_extracted() { # extract-root group archive-stem
    local root="$1" group="$2" stem="$3" f rel tdir
    while IFS= read -r -d '' f; do
        rel="${f#"$root"/}"
        tdir="$(classify_dir "$group" "$(basename "$f")")/$group/$stem"
        # content beats name for the ambiguous .dmp case (see is_pcap_magic)
        [[ "$tdir" == "$RAW/memory/"* ]] && is_pcap_magic "$f" && tdir="$RAW/pcaps/$group/$stem"
        mkdir -p "$tdir/$(dirname "$rel")"
        mv -f "$f" "$tdir/$rel"
    done < <(find "$root" -type f -print0)
}

# Unpack a verified source. A single-file .gz is routed by its DECOMPRESSED name
# (its type is known). A multi-file archive is extracted to a scratch tree and
# then sorted per extracted file — because its contents, and therefore their
# types, are only knowable after unzipping.
materialize() { # src group name
    local src="$1" group="$2" name="$3" out dest tmp stem
    case "$name" in
        *.tar.gz|*.tgz|*.tar|*.zip|*.7z)
            stem="${name%.*}"; [[ "$name" == *.tar.gz ]] && stem="${name%.tar.gz}"
            tmp="$(mktemp -d "$SRC_DIR/.extract.XXXXXX")"
            case "$name" in
                *.tar.gz|*.tgz) tar -xzf "$src" -C "$tmp" ;;
                *.tar)          tar -xf  "$src" -C "$tmp" ;;
                *.zip)          unzip -o -q "$src" -d "$tmp" ;;
                *.7z)
                    if command -v 7z >/dev/null 2>&1; then 7z x -y -o"$tmp" "$src" >/dev/null
                    else echo "     ⚠️  7z not installed; leaving archive un-extracted"; rm -rf "$tmp"; return 1; fi ;;
            esac
            sort_extracted "$tmp" "$group" "$stem"
            rm -rf "$tmp" ;;
        *.gz)
            out="${name%.gz}"
            dest="$(group_dir "$group" "$out")"; mkdir -p "$dest"
            gunzip -c "$src" > "$dest/$out"
            # content beats name for the ambiguous .dmp case (see is_pcap_magic);
            # idempotency is carried by the .done marker, not the landing path
            if [[ "$dest" == "$RAW/memory/"* ]] && is_pcap_magic "$dest/$out"; then
                mkdir -p "$RAW/pcaps/$group"
                mv -f "$dest/$out" "$RAW/pcaps/$group/$out"
                rmdir "$dest" 2>/dev/null || true
            fi ;;
        *)
            dest="$(group_dir "$group" "$name")"; mkdir -p "$dest"
            cp -f "$src" "$dest/$name" ;;   # already an artifact (not normally reached)
    esac
}

# ------------------------------------------------------------------------------
verify_all() { # group
    local ok=0 sizeonly=0 bad=0 missing=0 group name bytes sha _ dest out src
    while IFS=$'\t' read -r group name bytes sha _; do
        dest="$(group_dir "$group" "$name")"
        out="$(expected_output "$name")"
        src="$SRC_DIR/$group/$name"
        if ! is_packed "$name"; then
            # Plain artifact: the only copy lives in the type directory and is
            # still checkable against the manifest.
            if verify_source "$dest/$name" "$bytes" "$sha"; then
                printf '  ✅ %-42s -> %s\n' "$name" "${dest#"$RAW"/}/$name"; ok=$(( ok + 1 ))
            elif [[ -f "$dest/$name" ]]; then
                printf '  ❌ %-42s FAILED verification\n' "$name"; bad=$(( bad + 1 ))
            else
                missing=$(( missing + 1 ))
            fi
        elif [[ -n "$out" && -f "$dest/$out" ]] || [[ -f "$SRC_DIR/$group/.$name.done" ]]; then
            printf '  ✅ %-42s -> %s (extracted)\n' "$name" "${dest#"$RAW"/}/"; ok=$(( ok + 1 ))
        elif [[ -f "$src" ]] && verify_source "$src" "$bytes" "$sha"; then
            printf '  ◑ %-42s staged, not yet extracted\n' "$name"; sizeonly=$(( sizeonly + 1 ))
        elif [[ -f "$src" ]]; then
            printf '  ❌ %-42s staged source FAILED verification\n' "$name"; bad=$(( bad + 1 ))
        else
            missing=$(( missing + 1 ))
        fi
    done <<< "$(rows_for "${1:-all}")"
    echo
    echo "materialized: $ok   staged-only: $sizeonly   failed: $bad   not fetched: $missing"
    [[ "$bad" -eq 0 ]]
}

# Refuse up front if the manifest (compressed) size of the selected rows exceeds
# free space — dying halfway through a 400 GB fetch is worse. Extraction
# transiently needs the source plus its expanded contents before the source is
# pruned, so leave headroom on archive-heavy selections.
disk_ok() { # total-bytes
    local total="$1" avail
    avail=$(stat -f --format="%a" .); avail=$(( avail * $(stat -f --format="%S" .) ))
    if (( avail < total )); then
        echo; echo "❌ not enough disk: $(human "$avail") free, $(human "$total") needed" >&2
        return 1
    fi
}

# Download + route one manifest row per line on stdin (g name bytes sha rel).
# Shared by --fetch (a whole group) and --file (individual rows). Increments the
# global FAILED counter; each file resumes independently, so a re-run continues.
FAILED=0
process_rows() {
    local g name bytes sha rel dest out src marker
    while IFS=$'\t' read -r g name bytes sha rel; do
        dest="$(group_dir "$g" "$name")"

        if ! is_packed "$name"; then
            # Plain artifact (E01/E02…/dd/vmdk/…): download straight into the
            # group folder. One copy, verified in place — no staging, no dupe.
            mkdir -p "$dest"
            if verify_source "$dest/$name" "$bytes" "$sha"; then
                printf '  ✅ %-42s already in %s\n' "$name" "${dest#"$RAW"/}/"; continue
            fi
            printf '  ⬇  %-42s %s -> %s\n' "$name" "$(human "$bytes")" "${dest#"$RAW"/}/"
            if ! download "$rel" "$dest/$name"; then
                printf '  ❌ %-42s download failed\n' "$name"; FAILED=$(( FAILED + 1 )); continue
            fi
            if verify_source "$dest/$name" "$bytes" "$sha"; then
                printf '  ✅ %-42s in %s\n' "$name" "${dest#"$RAW"/}/"
            else
                printf '  ❌ %-42s verification FAILED\n' "$name"; FAILED=$(( FAILED + 1 ))
            fi
            continue
        fi

        # Packed source: stage to its own dir, verify, unpack. A .gz is routed by
        # its decompressed name; a multi-file archive is unzipped and its files
        # are then sorted per-type — the contents (and their types) are only
        # knowable after extraction, so we never guess from the archive name.
        out="$(expected_output "$name")"
        src="$SRC_DIR/$g/$name"
        marker="$SRC_DIR/$g/.$name.done"
        if [[ -f "$marker" ]] || { [[ -n "$out" ]] && [[ -f "$(group_dir "$g" "$out")/$out" ]]; }; then
            printf '  ✅ %-42s already unpacked\n' "$name"; continue
        fi

        mkdir -p "$SRC_DIR/$g"
        if ! verify_source "$src" "$bytes" "$sha"; then
            printf '  ⬇  %-42s %s (archive, staged)\n' "$name" "$(human "$bytes")"
            if ! download "$rel" "$src"; then
                printf '  ❌ %-42s download failed\n' "$name"; FAILED=$(( FAILED + 1 )); continue
            fi
            if ! verify_source "$src" "$bytes" "$sha"; then
                printf '  ❌ %-42s verification FAILED\n' "$name"; FAILED=$(( FAILED + 1 )); continue
            fi
        fi

        if materialize "$src" "$g" "$name"; then
            : > "$marker"
            printf '  ✅ %-42s unpacked and sorted by type\n' "$name"
            [[ "$KEEP_ARCHIVES" == true ]] || rm -f "$src"
        else
            printf '  ❌ %-42s unpack failed\n' "$name"; FAILED=$(( FAILED + 1 ))
        fi
    done
}

fetch_group() { # group
    local group="$1" rows total
    rows="$(rows_for "$group")"
    [[ -n "$rows" ]] || { echo "no such group: $group" >&2; echo "try --list" >&2; exit 2; }

    total=$(awk -F'\t' '{b+=$3} END{print b+0}' <<< "$rows")
    echo "Group: $group"
    echo "Size:  $(human "$total") across $(wc -l <<< "$rows") file(s)"
    echo "Source: public DFIR corpora. Nothing here is case evidence."
    disk_ok "$total" || return 1
    echo

    FAILED=0
    process_rows <<< "$rows"

    echo
    if (( FAILED > 0 )); then
        echo "❌ $FAILED file(s) failed. Re-run to resume; downloads continue where they stopped."
        return 1
    fi
    echo "✅ $group fetched and routed into data_store/raw/"
}

# Fetch individual files by name pattern, one row at a time — for pulling a
# single large "everything" archive without its whole group. The pattern is
# matched against the file's basename (substring, case-insensitive).
fetch_file() { # pattern
    local pattern="$1" rows total
    rows="$(manifest_rows | awk -F'\t' -v p="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" 'tolower($2) ~ p')"
    [[ -n "$rows" ]] || { echo "no file matches: $pattern" >&2; echo "try --list <group> or --route" >&2; exit 2; }

    total=$(awk -F'\t' '{b+=$3} END{print b+0}' <<< "$rows")
    echo "Matched $(wc -l <<< "$rows") file(s), $(human "$total"):"
    awk -F'\t' '{printf "   %s / %s\n",$1,$2}' <<< "$rows"
    echo "Source: public DFIR corpora. Nothing here is case evidence."
    disk_ok "$total" || return 1
    echo

    FAILED=0
    process_rows <<< "$rows"

    echo
    if (( FAILED > 0 )); then
        echo "❌ $FAILED file(s) failed. Re-run to resume; downloads continue where they stopped."
        return 1
    fi
    echo "✅ fetched and routed into data_store/raw/"
}

# ------------------------------------------------------------------------------
# Argument parsing: pull optional flags out first, then act on the verb.
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-archives)  KEEP_ARCHIVES=true ;;
        --prune-archives) KEEP_ARCHIVES=false ;;
        --exclude)        EXCLUDE="$2"; shift ;;   # group-name regex to skip
        *)                ARGS+=("$1") ;;
    esac
    shift
done
set -- "${ARGS[@]:-}"

case "${1:---list}" in
    --list)   if [[ -n "${2:-}" ]]; then list_group "$2"; else list_groups; fi ;;
    --route)  route_map ;;
    --verify) verify_all "${2:-all}" ;;
    --fetch)
        group="${2:-}"
        [[ -n "$group" ]] || { echo "usage: $0 --fetch <group|all>" >&2; exit 2; }
        if [[ "$group" == "all" && "${3:-}" != "--yes" ]]; then
            echo "Refusing to fetch all 2.8 TB without --yes." >&2
            echo "Pick a group instead: $0 --list" >&2
            exit 2
        fi
        fetch_group "$group"
        ;;
    --file)
        [[ -n "${2:-}" ]] || { echo "usage: $0 --file <name-pattern>" >&2; exit 2; }
        fetch_file "$2"
        ;;
    -h|--help) sed -n '2,66p' "$0" | sed 's/^# \{0,1\}//' ;;
    *)
        echo "unknown option: $1" >&2
        echo "usage: $0 [--list [group]|--route|--fetch <group|all>|--file <name>|--verify [group]|--help]" >&2
        echo "       [--keep-archives|--prune-archives]" >&2
        exit 2
        ;;
esac
