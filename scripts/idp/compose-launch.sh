#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The quickstart end to end (#519): the FerroSMART image built from a local
# static binary with docker/ferrosmart/Dockerfile, `compose.yaml` with
# `compose.keycloak.yaml` brought up on it exactly as their comments tell an
# operator to, with the secrets made the way those comments make them, and a
# SMART standalone launch through both (scripts/idp/standalone-launch.sh)
# to a token response whose ID Token and access token carry the person's
# mapped `fhirUser`. Every secret is made for the run and removed after it.
# No specification governs the check itself: our own design.
#
#   scripts/idp/compose-launch.sh
#
# It expects FERROSMART_BINARY, a static Linux build of `ferrosmart` for the
# host's architecture, docker with compose, openssl, jq and curl, no
# `secrets/`, `dist/` or `config/` directory in the checkout, and ports 8080 and 8180 free on the
# loopback interface. It writes its logs to LANE_DIR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${FERROSMART_BINARY:?the static ferrosmart binary}" "${LANE_DIR:?the run directory}"
mkdir -p "$LANE_DIR"

fail() {
  echo "compose-launch: $*" >&2
  exit 1
}

for made in secrets dist config; do
  [ -e "$root/$made" ] && fail "a $made/ directory exists in the checkout; this run makes its own"
done
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "no image architecture for $(uname -m)" ;;
esac

tag="compose-launch"
compose=(docker compose -f "$root/compose.yaml" -f "$root/compose.keycloak.yaml")
export FERROSMART_VERSION=$tag

cleanup() {
  "${compose[@]}" logs --no-color > "$LANE_DIR/compose.log" 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans > /dev/null 2>&1 || true
  rm -rf "$root/secrets" "$root/dist" "$root/config"
}
trap cleanup EXIT

# The image as the release lane stages it: the binary under
# dist/<os>_<arch>/, the one path docker/ferrosmart/Dockerfile copies.
mkdir -p "$root/dist/linux_$arch"
install -m 0755 "$FERROSMART_BINARY" "$root/dist/linux_$arch/ferrosmart"
docker build --quiet -f "$root/docker/ferrosmart/Dockerfile" \
  -t "ghcr.io/ferrohealth/ferrosmart:$tag" "$root" > /dev/null

# The secrets, made as the comments of compose.yaml and
# compose.keycloak.yaml make them.
mkdir -p "$root/secrets"
openssl rand -hex 24 > "$root/secrets/postgres_password"
printf 'postgresql://ferrosmart:%s@postgres:5432/ferrosmart?sslmode=disable' \
  "$(cat "$root/secrets/postgres_password")" > "$root/secrets/database_url"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$root/secrets/signing_key.pem" 2> /dev/null
openssl rand -hex 16 | tr -d '\n' > "$root/secrets/keycloak_user_password"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$root/secrets/upstream_assertion_key.pem" 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -out "$root/secrets/backend_assertion_key.pem" 2> /dev/null
chmod 0644 "$root/secrets/database_url" "$root/secrets/signing_key.pem" \
  "$root/secrets/keycloak_user_password" "$root/secrets/upstream_assertion_key.pem" \
  "$root/secrets/backend_assertion_key.pem"

"${compose[@]}" up --detach --pull missing --quiet-pull > "$LANE_DIR/up.log" 2>&1 ||
  fail "the quickstart did not come up ($LANE_DIR/up.log)"
# NOTE: compose.yaml, HEALTH, FerroSMART serves its SMART configuration once
# it has discovered the provider and migrated its store.
ready=false
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null http://localhost:8080/.well-known/smart-configuration; then
    ready=true
    break
  fi
  sleep 2
done
[ "$ready" = true ] || fail "FerroSMART did not serve its SMART configuration ($LANE_DIR/compose.log)"
# NOTE: compose.keycloak.yaml, CLIENTS, the example app is applied once the database is up.
"${compose[@]}" run --rm ferrosmart client apply /etc/ferrosmart-example/example-app.json \
  > "$LANE_DIR/apply.log" 2>&1 || fail "the example app was not applied ($LANE_DIR/apply.log)"

fhir_user="http://localhost:8090/fhir/Practitioner/example"
answer=$(LAUNCH_USER=clinician LAUNCH_PASSWORD=$(cat "$root/secrets/keycloak_user_password") \
  "$root/scripts/idp/standalone-launch.sh" keycloak http://localhost:8080 example-app \
  http://localhost:9000/callback http://localhost:8090/fhir "openid fhirUser user/Patient.rs")

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
id_token=$(jq -r '.id_token // empty' <<< "$answer")
[ -n "$id_token" ] || fail "the token response carries no id_token"
got=$(payload "$id_token" | jq -r '.fhirUser // empty')
[ "$got" = "$fhir_user" ] || fail "the ID Token's fhirUser is '$got', the realm maps '$fhir_user'"
access=$(jq -r .access_token <<< "$answer")
[ "$(payload "$access" | jq -r '.fhirUser // empty')" = "$fhir_user" ] ||
  fail "the access token carries another fhirUser"
[ "$(payload "$access" | jq -r .aud)" = "http://localhost:8090/fhir" ] ||
  fail "the access token names another audience"
echo "compose-launch: the quickstart image granted '$scope' with fhirUser $fhir_user"
