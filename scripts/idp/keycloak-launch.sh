#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# FerroSMART with Keycloak upstream, end to end (#522): Keycloak from the
# image docs/VERSIONS.md pins, importing app/ferrosmart/examples/keycloak/
# ferrosmart-realm.json, FerroSMART on that directory's configuration, and a
# SMART standalone launch through both (scripts/idp/standalone-launch.sh)
# to a token response whose ID Token and access token carry the person's
# mapped `fhirUser`. FerroSMART authenticates to Keycloak with a JWT its
# assertion key signs, which Keycloak verifies against FerroSMART's
# upstream JWK Set URL. Every secret is made for the run and never kept. No
# specification governs the check itself: our own design.
#
#   scripts/idp/keycloak-launch.sh
#
# It expects a built `target/debug/ferrosmart`, PostgreSQL at LANE_PG (a
# superuser URL without a database), docker, openssl, psql, jq and curl, and
# ports 8080 and 8180 free on the loopback interface. It writes its files
# and logs to LANE_DIR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
example="$root/app/ferrosmart/examples/keycloak"
: "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the run directory}"
mkdir -p "$LANE_DIR"

fail() {
  echo "keycloak-launch: $*" >&2
  exit 1
}

fhir_user="http://localhost:8090/fhir/Practitioner/example"
password=$(openssl rand -hex 16)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/signing.pem" 2> /dev/null
rm -f "$LANE_DIR/backend.pem"
"$root/target/debug/ferrosmart" key generate --out "$LANE_DIR/backend.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$LANE_DIR/assertion.pem" 2> /dev/null
psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart_keycloak'

"$root/scripts/idp/keycloak-up.sh" ferrosmart-keycloak "$password" "$fhir_user"

ferrosmart=("$root/target/debug/ferrosmart" --config "$example/ferrosmart.toml"
  --set server.listen=127.0.0.1:8080
  --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem"
  --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
  --set "ferrosmart.upstream.0.oidc.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem"
  --set "ferrosmart.database.url=$LANE_PG/ferrosmart_keycloak")
"${ferrosmart[@]}" client apply "$example/example-app.json"
"${ferrosmart[@]}" serve > "$LANE_DIR/ferrosmart-keycloak.log" 2>&1 &
smart=$!
trap 'kill "$smart" 2> /dev/null || true; docker rm -f ferrosmart-keycloak > /dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null http://localhost:8080/.well-known/smart-configuration && break
  sleep 1
done

answer=$(LAUNCH_USER=clinician LAUNCH_PASSWORD=$password \
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
got=$(payload "$(jq -r .access_token <<< "$answer")" | jq -r '.fhirUser // empty')
[ "$got" = "$fhir_user" ] || fail "the access token's fhirUser is '$got', the realm maps '$fhir_user'"
echo "keycloak-launch: a standalone launch through Keycloak granted '$scope' with fhirUser $fhir_user"
