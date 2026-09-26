#!/bin/bash
# ==============================================================================
# Byakugan Phase-0 RISK GATE — the proof harness for the detection design's
# two load-bearing assumptions (docs/riskgate.md has both, in full). Stands up
# NOTHING: the stack must already be up; this wrapper only discovers how to
# reach it and hands over to riskgate.py (synthetic fixture in, proofs, out).
#
#   ./.github/tests/elastic-riskgate/riskgate.sh               # load, proof 1, proof 2, probe, clean
#   ./.github/tests/elastic-riskgate/riskgate.sh --keep        # ... leave the fixture for inspection
#   ./.github/tests/elastic-riskgate/riskgate.sh clean         # remove the fixture
#   ./.github/tests/elastic-riskgate/riskgate.sh selftest      # offline consistency check (no cluster)
#   ./.github/tests/elastic-riskgate/riskgate.sh load|proof1|proof2|probe
#
# Overrides (all optional): ES_URL (https://127.0.0.1:9200), ES_USER (elastic),
# ES_PASSWORD (else the elastic.env handoff), ES_CA (else the deployed CA),
# RISKGATE_INSECURE=1 (skip TLS verification — last resort, loopback only).
#
# FAILS LOUDLY, never skips: a gate that no-ops when the stack is missing would
# be a green tick that proved nothing. Missing prerequisite -> non-zero + why.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# The deploy's per-host artifacts ("localhost" is the default inventory's
# name for the workstation) and the compose-era fallbacks.
SECRETS_DIR="$REPO_ROOT/ansible/inventory/secrets/localhost"
LEGACY_ELASTIC_DIR="$REPO_ROOT/docker/elastic"
RUNNER="$SCRIPT_DIR/riskgate.py"

die()  { echo "❌ riskgate | $*" >&2; exit 1; }
note() { echo "riskgate | $*"; }

command -v python3 >/dev/null 2>&1 || die "python3 is required (the runner is stdlib-only)"

# The offline self-test and --help need no cluster and no credentials.
case "${1:-}" in
    selftest|-h|--help) exec python3 "$RUNNER" "$@" ;;
esac

ES_URL="${ES_URL:-https://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
RISKGATE_INSECURE="${RISKGATE_INSECURE:-0}"

# --- password: the environment, else the deploy's handoff --------------------
if [[ -z "${ES_PASSWORD:-}" ]]; then
    for _env in "$SECRETS_DIR/elastic.env" "$LEGACY_ELASTIC_DIR/.env"; do
        if [[ -f "$_env" ]]; then
            ES_PASSWORD="$(sed -n 's/^ELASTIC_PASSWORD=//p' "$_env" | tail -n 1 | sed -e "s/^[\"']//" -e "s/[\"']\$//")"
            [[ -n "$ES_PASSWORD" ]] && { note "ELASTIC_PASSWORD read from ${_env#"$REPO_ROOT/"}"; break; }
        fi
    done
fi
[[ -n "${ES_PASSWORD:-}" ]] || die "ES_PASSWORD is not set and no elastic.env handoff carries ELASTIC_PASSWORD — run \`dxdfir deploy stack\` first, or export ES_PASSWORD"
case "$ES_PASSWORD" in
    *change-me*) die "ELASTIC_PASSWORD still holds the .env.example placeholder — the stack would not have started with it" ;;
esac

# --- CA: the environment, else the deploy's host-side certs tree -------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
if [[ -z "${ES_CA:-}" && "$RISKGATE_INSECURE" != "1" && "$ES_URL" == https://* ]]; then
    if [[ -s "$SECRETS_DIR/certs/ca/ca.crt" ]]; then
        ES_CA="$SECRETS_DIR/certs/ca/ca.crt"
        note "CA read from the deploy's certs tree"
    elif command -v docker >/dev/null 2>&1 \
         && docker cp "byakugan-elasticsearch-1:/usr/share/elasticsearch/config/certs/ca/ca.crt" "$TMP_DIR/ca.crt" >/dev/null 2>&1 \
         && [[ -s "$TMP_DIR/ca.crt" ]]; then
        # compose-era fallback: the old stack kept the CA only in its volume.
        ES_CA="$TMP_DIR/ca.crt"
        note "CA fetched from the compose-era elasticsearch container"
    fi
    [[ -n "${ES_CA:-}" ]] || die "no CA for $ES_URL: run \`dxdfir deploy stack\` (writes ansible/inventory/secrets/<host>/certs/ca/ca.crt) — or set ES_CA, or RISKGATE_INSECURE=1"
fi
[[ -z "${ES_CA:-}" || -s "$ES_CA" ]] || die "ES_CA=$ES_CA is not a readable file"

export ES_URL ES_USER ES_PASSWORD RISKGATE_INSECURE
[[ -n "${ES_CA:-}" ]] && export ES_CA

note "target $ES_URL as $ES_USER"
# Not exec: the EXIT trap must still remove the copied CA when the runner returns.
python3 "$RUNNER" "$@"
