#!/usr/bin/env bash
# Byakugan Elastic bootstrap — runs once per `docker compose up` from the
# Elasticsearch image as root (the compose `setup` service).
#   1. generate the CA + node certificates into the shared certs volume (once);
#   2. wait for Elasticsearch to answer over TLS with security on;
#   3. set the kibana_system password (idempotent).
# Elasticsearch waits for step 1 (healthcheck), Kibana/Filebeat for the script
# to complete successfully.
set -euo pipefail

CERTS=/usr/share/elasticsearch/config/certs
ES_URL=https://elasticsearch:9200
# The Elasticsearch image bundles a JDK but not necessarily `unzip`, so ZIP
# output from elasticsearch-certutil is extracted with the JDK `jar` tool
# (a .jar is a .zip) — no dependency on unzip being present in the image.
JAR=/usr/share/elasticsearch/jdk/bin/jar

: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD must be set (docker/elastic/.env)}"
: "${KIBANA_SYSTEM_PASSWORD:?KIBANA_SYSTEM_PASSWORD must be set (docker/elastic/.env)}"
for v in ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD; do
  case "${!v}" in
    *change-me*)
      echo "setup | ${v} still holds the .env.example placeholder — set a real value in docker/elastic/.env" >&2
      exit 1 ;;
  esac
done

if [ ! -f "${CERTS}/ca/ca.crt" ]; then
  echo "setup | generating the CA"
  /usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent --pem --out "${CERTS}/ca.zip"
  ( cd "${CERTS}" && "${JAR}" xf ca.zip )
fi

if [ ! -f "${CERTS}/es01/es01.crt" ]; then
  echo "setup | generating node certificates"
  cat > "${CERTS}/instances.yml" <<'EOF'
instances:
  - name: es01
    dns: [elasticsearch, es01, localhost]
    ip: [127.0.0.1]
  - name: fleet-server
    dns: [fleet-server, localhost]
    ip: [127.0.0.1]
EOF
  /usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent --pem \
    --in "${CERTS}/instances.yml" \
    --ca-cert "${CERTS}/ca/ca.crt" --ca-key "${CERTS}/ca/ca.key" \
    --out "${CERTS}/certs.zip"
  ( cd "${CERTS}" && "${JAR}" xf certs.zip )
fi

# Readable by the stack's service users (uid 1000, group 0), nobody else.
chown -R root:0 "${CERTS}"
find "${CERTS}" -type d -exec chmod 750 {} \;
find "${CERTS}" -type f -exec chmod 640 {} \;
# The CA private key is only needed during bootstrap (cert generation); keep it
# root-only so a group-0 service container cannot read it afterwards.
[ -f "${CERTS}/ca/ca.key" ] && chmod 600 "${CERTS}/ca/ca.key"

echo "setup | waiting for Elasticsearch at ${ES_URL}"
until curl -s --cacert "${CERTS}/ca/ca.crt" "${ES_URL}" | grep -q "missing authentication credentials"; do
  sleep 5
done

echo "setup | setting the kibana_system password"
until curl -s -X POST --cacert "${CERTS}/ca/ca.crt" \
      -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
      "${ES_URL}/_security/user/kibana_system/_password" \
      -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" | grep -q "^{}"; do
  sleep 5
done

echo "setup | done"
