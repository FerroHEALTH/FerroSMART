#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# FerroSMART with ZITADEL upstream, end to end (#523): ZITADEL from the image
# docs/VERSIONS.md pins, bootstrapped by app/ferrosmart/examples/zitadel/
# bootstrap.sh; the example's Actions v2 target (tools/zitadel-fhir-user),
# which writes the user's `fhirUser`; FerroSMART on the configuration the
# bootstrap writes; and a SMART standalone launch through them
# (scripts/idp/standalone-launch.sh) to a token response whose ID Token and
# access token carry the mapped `fhirUser`, with a `user/` scope ZITADEL's
# role claim grants. Every secret is made for the run and never kept. No
# specification governs the check itself: our own design.
#
#   scripts/idp/zitadel-launch.sh
#
# It expects built `target/debug/ferrosmart` and
# `target/debug/zitadel-fhir-user`, PostgreSQL at LANE_PG (a superuser URL
# without a database), docker, openssl, psql, jq and curl, and ports 8080,
# 8280 and 8290 free on the loopback interface. It writes its files and logs
# to LANE_DIR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
example="$root/app/ferrosmart/examples/zitadel"
: "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the run directory}"
mkdir -p "$LANE_DIR/zitadel" "$LANE_DIR/out"

fail() {
  echo "zitadel-launch: $*" >&2
  exit 1
}

image=$(grep -E '^\| ZITADEL image \|' "$root/docs/VERSIONS.md" | grep -oE 'ghcr\.io/zitadel/zitadel:[^`]+@sha256:[0-9a-f]{64}' | head -1)
[ -n "$image" ] || fail "no ZITADEL image pin in docs/VERSIONS.md"

fhir_user="http://localhost:8090/fhir/Practitioner/example"
openssl rand -hex 16 | tr -d '\n' > "$LANE_DIR/zitadel/masterkey"
# NOTE: ZITADEL's cmd/defaults.yaml PasswordComplexityPolicy, an upper case letter, a digit, a symbol.
printf 'A1!%s' "$(openssl rand -hex 12)" > "$LANE_DIR/password"
psql "$LANE_PG/postgres" -qc 'CREATE DATABASE zitadel' -c 'CREATE DATABASE ferrosmart_zitadel'

# NOTE: ZITADEL's cmd/defaults.yaml HTTPClient.DenyList without localhost, 127.0.0.0/8 and ::1/128,
# where the example's target listens.
denylist=0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,198.18.0.0/15,::/128,fc00::/7,fe80::/10
# The example's ZITADEL settings (compose.zitadel.yaml), on the host network.
docker run -d --name ferrosmart-zitadel --network host --user "$(id -u):$(id -g)" \
  -v "$LANE_DIR/zitadel:/zitadel/bootstrap" \
  -e ZITADEL_PORT=8280 -e ZITADEL_EXTERNALDOMAIN=localhost -e ZITADEL_EXTERNALPORT=8280 \
  -e ZITADEL_EXTERNALSECURE=false -e ZITADEL_TLS_ENABLED=false \
  -e "ZITADEL_DATABASE_POSTGRES_DSN=$LANE_PG/zitadel?sslmode=disable" \
  -e "ZITADEL_HTTPCLIENT_DENYLIST=$denylist" \
  -e ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED=false \
  -e ZITADEL_FIRSTINSTANCE_PATPATH=/zitadel/bootstrap/admin.pat \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=admin \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME=Administrator \
  -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=2099-01-01T00:00:00Z \
  -e ZITADEL_FIRSTINSTANCE_LOGINCLIENTPATPATH=/zitadel/bootstrap/login-client.pat \
  -e ZITADEL_FIRSTINSTANCE_ORG_LOGINCLIENT_MACHINE_USERNAME=login-client \
  -e ZITADEL_FIRSTINSTANCE_ORG_LOGINCLIENT_MACHINE_NAME=Login \
  -e ZITADEL_FIRSTINSTANCE_ORG_LOGINCLIENT_PAT_EXPIRATIONDATE=2099-01-01T00:00:00Z \
  -e ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=true \
  -e 'ZITADEL_OIDC_DEFAULTLOGINURLV2=http://localhost:3000/ui/v2/login/login?authRequest=' \
  "$image" start-from-init --masterkeyFile /zitadel/bootstrap/masterkey > /dev/null
for _ in $(seq 1 90); do
  curl -fsS -o /dev/null http://localhost:8280/debug/ready && break
  sleep 2
done

ZITADEL_FHIR_USER_SIGNING_KEY_FILE="$LANE_DIR/out/target-signing-key" \
  "$root/target/debug/zitadel-fhir-user" > "$LANE_DIR/zitadel-fhir-user.log" 2>&1 &
target=$!
trap 'kill "$target" "${smart:-}" 2> /dev/null || true; docker rm -f ferrosmart-zitadel > /dev/null 2>&1 || true' EXIT

ZITADEL_API=http://localhost:8280 ADMIN_PAT_FILE="$LANE_DIR/zitadel/admin.pat" \
  USER_PASSWORD_FILE="$LANE_DIR/password" FERROSMART_ISSUER=http://localhost:8080 \
  FHIR_USER="$fhir_user" TARGET_URL=http://127.0.0.1:8290/ OUT="$LANE_DIR/out" \
  "$example/bootstrap.sh"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/signing.pem" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$LANE_DIR/backend.pem" 2> /dev/null
ferrosmart=("$root/target/debug/ferrosmart" --config "$LANE_DIR/out/ferrosmart.toml"
  --set server.listen=127.0.0.1:8080
  --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem"
  --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
  --set "ferrosmart.database.url=$LANE_PG/ferrosmart_zitadel")
"${ferrosmart[@]}" client apply "$LANE_DIR/out/example-app.json"
"${ferrosmart[@]}" serve > "$LANE_DIR/ferrosmart-zitadel.log" 2>&1 &
smart=$!
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null http://localhost:8080/.well-known/smart-configuration && break
  sleep 1
done

answer=$(ZITADEL_API=http://localhost:8280 ZITADEL_LOGIN_PAT_FILE="$LANE_DIR/zitadel/login-client.pat" \
  LAUNCH_USER=clinician LAUNCH_PASSWORD="$(cat "$LANE_DIR/password")" \
  "$root/scripts/idp/standalone-launch.sh" zitadel http://localhost:8080 example-app \
  http://localhost:9000/callback http://localhost:8090/fhir "openid fhirUser user/Patient.rs")
docker logs ferrosmart-zitadel > "$LANE_DIR/zitadel.log" 2>&1 || true

# The payload of a compact JWS (RFC 7515 §7.1), base64url decoded.
payload() {
  local part
  part=$(cut -d. -f2 <<< "$1" | tr '_-' '/+')
  while [ $((${#part} % 4)) -ne 0 ]; do part="$part="; done
  base64 -d <<< "$part"
}

scope=$(jq -r .scope <<< "$answer")
for wanted in openid fhirUser user/Patient.rs; do
  grep -qw -- "$wanted" <<< "$scope" || fail "the token response does not grant $wanted: $scope"
done
got=$(payload "$(jq -r .id_token <<< "$answer")" | jq -r '.fhirUser // empty')
[ "$got" = "$fhir_user" ] || fail "the ID Token's fhirUser is '$got', the bootstrap set '$fhir_user'"
got=$(payload "$(jq -r .access_token <<< "$answer")" | jq -r '.fhirUser // empty')
[ "$got" = "$fhir_user" ] || fail "the access token's fhirUser is '$got', the bootstrap set '$fhir_user'"
echo "zitadel-launch: a standalone launch through ZITADEL granted '$scope' with fhirUser $fhir_user"
