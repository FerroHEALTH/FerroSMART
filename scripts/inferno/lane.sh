#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The Inferno SMART App Launch lane (#520, docs/architecture.md §13.13):
# FerroSMART with Keycloak upstream, FerroBRIDGE as the FHIR server with
# FerroEHR as its CDR, and the Inferno SMART App Launch test kit on one host
# network, the kit's STU 2.2 suite run by
# `inferno execute_script` over app/ferrosmart/inferno/smart_stu2_2.yaml.
# No specification governs the lane itself: our own design.
#
#   scripts/inferno/lane.sh check     the expected results hold every test to
#                                     `pass` outside exceptions.tsv
#   scripts/inferno/lane.sh run       start everything, run the suite, record
#                                     the results and list the pending groups
#
# `run` expects, as the `nextest (core and axum)` job of ci.yml provides
# them: a built `target/debug/ferrosmart`; the kit checked out at the
# pinned commit in INFERNO_KIT; PostgreSQL at
# LANE_PG (a superuser URL without a database); docker, openssl, psql, jq
# xxd and curl; ports 4567, 6379, 8180, 8443, 9080 and 9443 free on the
# loopback interface; and sudo for the two /etc/hosts names. It writes its files and
# the logs to LANE_DIR.
# shellcheck disable=SC2016 # every backtick in a pattern or a format is a Markdown code span, matched or written literally
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lane="$root/app/ferrosmart/inferno"
versions="$root/docs/VERSIONS.md"

# The image a row of docs/VERSIONS.md pins, by its item name.
pinned_image() {
  local cell image
  cell=$(awk -F'|' -v item="$1" '$2 ~ "^ "item" $" { print $3 }' "$versions")
  image=$(grep -oE '`[^`]+@sha256:[0-9a-f]{64}`' <<< "$cell" | head -1 | tr -d '`' || true)
  # A row may name the tag and the index digest apart.
  [ -n "$image" ] || image=$(sed -nE 's/^ *`([^`]+)`, index digest `(sha256:[0-9a-f]{64})`.*/\1@\2/p' <<< "$cell")
  [ -n "$image" ] || { echo "lane: no image pin for '$1' in docs/VERSIONS.md" >&2; exit 1; }
  printf '%s\n' "$image"
}

# The rows of a table under app/ferrosmart/inferno, without its comments.
rows() {
  grep -vE '^(#|$)' "$lane/$1"
}

# Whether every issue of a comma-separated list is closed; `gh` unreadable
# counts as open.
all_closed() {
  local number
  for number in ${1//,/ }; do
    [ "$(gh issue view "$number" --json state --jq .state 2> /dev/null || true)" = CLOSED ] || return 1
  done
}

check() {
  local expected="$lane/smart_stu2_2_expected.json" failures=0 id result
  while IFS=$'\t' read -r id result; do
    if rows exceptions.tsv | cut -f1 | grep -qxF "$id"; then
      continue
    fi
    if [ "$result" != pass ]; then
      echo "lane: $id is expected to be '$result'; every test outside exceptions.tsv passes" >&2
      failures=$((failures + 1))
    fi
  done < <(jq -r '.[] | select(.test_id) | [.test_id, .result] | @tsv' "$expected")
  while IFS= read -r id; do
    if ! jq -e --arg id "$id" 'any(.[]; .test_id == $id and .result != "pass")' "$expected" > /dev/null; then
      echo "lane: exceptions.tsv lists $id, which the expected results do not hold failing" >&2
      failures=$((failures + 1))
    fi
  done < <(rows exceptions.tsv | cut -f1)
  # An `omitted` row is the kit's own omission: the expected result is
  # `omit`, so a run where the kit ran the test fails the comparison.
  while IFS=$'\t' read -r id kind _; do
    [ "$kind" = omitted ] || continue
    if ! jq -e --arg id "$id" 'any(.[]; .test_id == $id and .result == "omit")' "$expected" > /dev/null; then
      echo "lane: exceptions.tsv marks $id omitted, which the expected results do not hold omitted" >&2
      failures=$((failures + 1))
    fi
  done < <(rows exceptions.tsv)
  [ "$failures" -eq 0 ] || exit 1
  echo "lane: the expected results pass every test outside exceptions.tsv"
}

# Every group not run and every test excepted, in the log and the job
# summary, with a warning once the issues a row waits on are closed.
pending() {
  local short id state issues needs kind reason
  local summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
  printf '### Inferno groups not run\n\n| Group | Waits on | Needs |\n|---|---|---|\n' >> "$summary"
  while IFS=$'\t' read -r short id state issues needs; do
    [ "$state" = pending ] || continue
    echo "lane: group $short ($id) is pending on #${issues//,/, #}: $needs"
    printf '| %s `%s` | #%s | %s |\n' "$short" "$id" "${issues//,/, #}" "$needs" >> "$summary"
    if all_closed "$issues"; then
      echo "::warning title=Inferno group $short can run::the issues group $short waits on are closed; add its step to smart_stu2_2.yaml and mark it run in groups.tsv"
    fi
  done < <(rows groups.tsv)
  printf '\n### Inferno tests excepted\n\n| Test | Kind | Issue | Reason |\n|---|---|---|---|\n' >> "$summary"
  while IFS=$'\t' read -r id kind issues reason; do
    echo "lane: test $id is excepted ($kind${issues:+, #$issues}): $reason"
    printf '| `%s` | %s | %s | %s |\n' "$id" "$kind" "$issues" "$reason" >> "$summary"
    if [ "$kind" = pending ] && all_closed "$issues"; then
      echo "::warning title=Inferno test excepted past its issue::#$issues is closed; record the new result of $id in smart_stu2_2_expected.json and drop its row from exceptions.tsv"
    fi
  done < <(rows exceptions.tsv)
}

# Each result of the session against the SMART App Launch 2.2.0
# requirements the kit's coverage map ties the test to.
record() {
  local results=$1
  local coverage="$root/docs/specs/inferno-smart-test-kit/lib/smart_app_launch/requirements/generated/smart_stu2_2_requirements_coverage.csv"
  {
    echo "### Inferno results against the SMART App Launch 2.2.0 requirements"
    echo
    echo "| Test | Result | Requirements |"
    echo "|---|---|---|"
    jq -r '.[] | select(.test_id) | [.test_id, .result] | @tsv' "$results" |
      while IFS=$'\t' read -r id result; do
        local requirements
        requirements=$(grep -F "$id" "$coverage" | cut -d, -f2 | sort -n | paste -sd, - || true)
        printf '| `%s` | %s | %s |\n' "$id" "$result" "${requirements:--}"
      done
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

wait_for() {
  local what=$1 url=$2
  for _ in $(seq 1 90); do
    if curl -fsS --cacert "$LANE_DIR/ca.crt" -o /dev/null "$url"; then
      return 0
    fi
    sleep 2
  done
  echo "lane: $what did not answer at $url" >&2
  return 1
}

# The development CA, the server certificates of FerroSMART and FerroBRIDGE,
# FerroSMART's signing key and the lane client's key, made for this run and
# never kept, with the JWK Sets FerroSMART registers.
make_keys() {
  local dir=$1 name modulus
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=FerroSMART Inferno lane CA' -keyout "$dir/ca.key" -out "$dir/ca.crt" 2> /dev/null
  for name in smart bridge; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=$name.localhost" -keyout "$dir/$name.key" -out "$dir/$name.csr" 2> /dev/null
    printf 'subjectAltName=DNS:%s.localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$name" > "$dir/$name.ext"
    openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
      -days 1 -extfile "$dir/$name.ext" -out "$dir/$name.crt" 2> /dev/null
  done
  rm -f "$dir/ca.key"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/signing.pem" 2> /dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/assertion.pem" 2> /dev/null
  rm -f "$dir/backend.pem"
  "$root/target/debug/ferrosmart" key generate --out "$dir/backend.pem"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/lane-client.pem" 2> /dev/null
  modulus=$(openssl rsa -in "$dir/lane-client.pem" -noout -modulus | cut -d= -f2 | xxd -r -p |
    openssl base64 -A | tr '+/' '-_' | tr -d '=')
  jq -n --arg n "$modulus" '{keys: [{kty: "RSA", kid: "lane", alg: "RS384", n: $n, e: "AQAB"}]}' \
    > "$dir/lane-client.jwks.json"
  # The public half of the kit's verification keys, its registered JWK Set.
  jq '{keys: [.keys[] | select(.key_ops | index("verify"))
        | {kty, kid, alg, crv, x, y, n, e} | with_entries(select(.value != null))]}' \
    "$INFERNO_KIT/lib/smart_app_launch/smart_jwks.json" > "$dir/inferno-client.jwks.json"
  chmod 0644 "$dir"/*.key "$dir"/*.pem
}

# An access token of the lane's own client for `scope` with the audience
# `resource`, by the client credentials grant with a private_key_jwt
# assertion (RFC 7523 §2.2; SMART App Launch 2.2.0, Client Authentication:
# Asymmetric), signed by scripts/inferno/assertion.sh.
lane_token() {
  local scope=$1 resource=$2 assertion
  assertion=$("$root/scripts/inferno/assertion.sh" "$LANE_DIR/lane-client.pem" https://smart.localhost:8443/token)
  curl -fsS --cacert "$LANE_DIR/ca.crt" https://smart.localhost:8443/token \
    --data-urlencode grant_type=client_credentials --data-urlencode "scope=$scope" \
    --data-urlencode "resource=$resource" \
    --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
    --data-urlencode "client_assertion=$assertion" | jq -r .access_token
}

run() {
  : "${INFERNO_KIT:?the kit checkout}" "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the lane directory}"
  local vendored="$root/docs/specs/ferrobridge-party" cdr=http://127.0.0.1:9080/ferroehr/rest/openehr/v1
  local password person practitioner secret status session
  mkdir -p "$LANE_DIR/mappings"
  check
  make_keys "$LANE_DIR"
  cp "$vendored"/app/ferrobridge-server/tests/it/fixtures_demographic/*.yml "$LANE_DIR/mappings/"
  echo '127.0.0.1 smart.localhost bridge.localhost' | sudo tee -a /etc/hosts > /dev/null
  psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart' -c 'CREATE DATABASE ferroehr'

  # 1. FerroEHR, holding the PERSONs the facade serves as the person's
  #    Practitioner and as the Patient the picker finds.
  docker run -d --name inferno-lane-ferroehr --network host \
    -v "$lane/ferroehr.toml:/etc/ferroehr/ferroehr.toml:ro" \
    -e FERROEHR_CONFIG=/etc/ferroehr/ferroehr.toml \
    -e "FERROEHR__DATABASE__URL=$LANE_PG/ferroehr" \
    -e FERROEHR__USAGE_REPORT__ENABLED=false \
    "$(pinned_image 'FerroEHR resource server image')" > /dev/null
  wait_for FerroEHR "$cdr/definition/template/adl1.4"
  curl -fsS -o /dev/null -X POST -H 'Content-Type: application/xml' \
    --data-binary "@$vendored/tools/ferrobridge-testkit/fixtures/opt/person.opt" "$cdr/definition/template/adl1.4"
  person=$(curl -fsS -D - -o /dev/null -X POST -H 'Content-Type: application/json' -H 'Prefer: return=minimal' \
    --data-binary "@$lane/practitioner-person.json" "$cdr/demographic/person" |
    grep -i '^etag:' | grep -oE '[0-9a-f-]{36}' | head -1)
  [ -n "$person" ] || { echo "lane: FerroEHR stored no PERSON" >&2; return 1; }
  curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' -H 'Prefer: return=minimal' \
    --data-binary "@$lane/patient-person.json" "$cdr/demographic/person"
  practitioner="https://bridge.localhost:9443/fhir/Practitioner/$person"

  # 2. Keycloak, the upstream login, whose person's fhirUser names it. It
  # reads FerroSMART's JWK Set over the lane's TLS, so it trusts the lane CA
  # (Keycloak's server guide, Configuring trusted certificates).
  password=$(openssl rand -hex 16)
  docker run -d --name inferno-lane-keycloak --network host \
    -v "$root/app/ferrosmart/examples/keycloak/ferrosmart-realm.json:/opt/keycloak/data/import/ferrosmart-realm.json:ro" \
    -v "$LANE_DIR/ca.crt:/opt/keycloak/lane-ca.pem:ro" \
    --add-host smart.localhost:127.0.0.1 \
    -e KC_HTTP_PORT=8180 -e KC_HTTP_HOST=127.0.0.1 \
    -e KC_TRUSTSTORE_PATHS=/opt/keycloak/lane-ca.pem \
    -e FERROSMART_KEYCLOAK_JWKS_URL=https://smart.localhost:8443/upstream-jwks \
    -e FERROSMART_KEYCLOAK_REDIRECT_URI=https://smart.localhost:8443/callback \
    -e "FERROSMART_KEYCLOAK_USER_PASSWORD=$password" \
    -e "FERROSMART_KEYCLOAK_FHIR_USER=$practitioner" \
    "$(pinned_image 'Keycloak test image')" start-dev --import-realm > /dev/null
  wait_for Keycloak http://localhost:8180/realms/ferrosmart/.well-known/openid-configuration

  # 3. FerroSMART, trusting the lane's CA beside the system roots for the
  #    picker's search at FerroBRIDGE, with the kit's clients applied first,
  #    each given its keys or secret hash for the run.
  cat /etc/ssl/certs/ca-certificates.crt "$LANE_DIR/ca.crt" > "$LANE_DIR/trust.pem"
  local smart=("$root/target/debug/ferrosmart" --config "$lane/ferrosmart.toml"
    --set "server.tls.certificate_file=$LANE_DIR/smart.crt"
    --set "server.tls.key_file=$LANE_DIR/smart.key"
    --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem"
    --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
    --set "ferrosmart.upstream.0.oidc.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem"
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart")
  mkdir -p "$LANE_DIR/clients"
  jq --slurpfile set "$LANE_DIR/inferno-client.jwks.json" '.jwks = $set[0]' \
    "$lane/clients/inferno-backend-services.json" > "$LANE_DIR/clients/inferno-backend-services.json"
  cp "$lane/clients/inferno-standalone.json" "$LANE_DIR/clients/"
  cp "$lane/clients/inferno-ehr.json" "$LANE_DIR/clients/"
  jq --slurpfile set "$LANE_DIR/lane-client.jwks.json" '.jwks = $set[0]' \
    "$lane/clients/inferno-lane.json" > "$LANE_DIR/clients/inferno-lane.json"
  "${smart[@]}" client apply "$LANE_DIR"/clients/*.json > "$LANE_DIR/apply.log"
  # The secret FerroSMART issued the kit's symmetric client, given to the kit
  # for group 2 (RFC 7591 §3.2.1).
  secret=$(awk '$3 == "\"inferno-ehr\"" && $4 == "client_secret" { print $5 }' "$LANE_DIR/apply.log")
  [ -n "$secret" ] || { echo "lane: FerroSMART issued inferno-ehr no secret" >&2; return 1; }
  sed "s/INFERNO_EHR_SECRET/$secret/" "$lane/smart_stu2_2.yaml" > "$LANE_DIR/smart_stu2_2.yaml"
  # NOTE: inferno execute_script reads the expected results beside the script.
  cp "$lane/smart_stu2_2_expected.json" "$LANE_DIR/"
  SSL_CERT_FILE="$LANE_DIR/trust.pem" "${smart[@]}" serve > "$LANE_DIR/ferrosmart.log" 2>&1 &
  wait_for FerroSMART https://smart.localhost:8443/.well-known/smart-configuration

  # 4. FerroBRIDGE, the FHIR server the kit is pointed at. Its REST routes
  #    answer CORS for the kit's origin, the origin the kit's app runs on
  #    (SMART App Launch 2.2.0, App Launch, CORS support, item 2); the
  #    discovery endpoints answer any origin by themselves (item 1).
  docker run -d --name inferno-lane-ferrobridge --network host \
    -v "$lane/ferrobridge.toml:/etc/ferrobridge/ferrobridge.toml:ro" -v "$LANE_DIR:/lane:ro" \
    -e FERROBRIDGE_CONFIG=/etc/ferrobridge/ferrobridge.toml \
    -e FERROBRIDGE__SERVER__LISTEN=127.0.0.1:9443 \
    -e FERROBRIDGE__SERVER__TLS__CERTIFICATE_FILE=/lane/bridge.crt \
    -e FERROBRIDGE__SERVER__TLS__KEY_FILE=/lane/bridge.key \
    -e FERROBRIDGE__AUTH__TLS__TRUST_ROOTS_FILE=/lane/ca.crt \
    -e FERROBRIDGE__MAPPINGS__DIRECTORY=/lane/mappings \
    -e FERROBRIDGE__FACADE__IDENTITY_STORE=/tmp/identity.redb \
    -e 'FERROBRIDGE__FACADE__CORS__ALLOWED_ORIGINS=["http://localhost:4567"]' \
    --add-host smart.localhost:127.0.0.1 --add-host bridge.localhost:127.0.0.1 \
    "$(pinned_image 'FerroBRIDGE FHIR server image')" > /dev/null
  wait_for FerroBRIDGE https://bridge.localhost:9443/fhir/metadata

  # 5. The kit, in the Ruby image docs/VERSIONS.md pins, on the gems its
  #    Gemfile.lock locks, trusting the lane's CA beside the system roots.
  #    Group 4 introspects with the lane client's token; group 2's EHR
  #    launches as the lane client (scripts/inferno/ehr-launch.sh).
  printf 'Authorization: Bearer %s' "$(lane_token system/introspect https://smart.localhost:8443)" \
    > "$LANE_DIR/introspection-header.txt"
  docker run -d --name inferno-lane-redis --network host "$(pinned_image 'Redis test image')" > /dev/null
  docker run -d --name inferno-lane-kit --network host \
    -v "$INFERNO_KIT:/kit" -v "$lane:/script" -v "$LANE_DIR:/lane:ro" -v "$root/scripts:/repo/scripts:ro" -w /kit \
    -e APP_ENV=development -e SSL_CERT_FILE=/tmp/trust.pem -e CURL_CA_BUNDLE=/tmp/trust.pem \
    -e LAUNCH_USER=clinician -e "LAUNCH_PASSWORD=$password" -e LAUNCH_PATIENT_NAME=Lane \
    -e LANE_KEY=/lane/lane-client.pem -e SMART_ISSUER=https://smart.localhost:8443 -e LAUNCH_APP=inferno-ehr \
    --add-host smart.localhost:127.0.0.1 --add-host bridge.localhost:127.0.0.1 \
    "$(pinned_image 'Inferno runtime')" sh -c '
      cat /etc/ssl/certs/ca-certificates.crt /lane/ca.crt > /tmp/trust.pem &&
      bundle install --quiet && bundle exec inferno migrate &&
      { bundle exec sidekiq -r ./worker.rb > /tmp/worker.log 2>&1 & } &&
      exec bundle exec puma' > /dev/null
  for _ in $(seq 1 150); do
    curl -fsS -o /dev/null http://localhost:4567 && break
    sleep 2
  done
  docker exec inferno-lane-kit bundle exec inferno execute_script --allow-commands /lane/smart_stu2_2.yaml \
    2> "$LANE_DIR/execute.log" && status=0 || status=$?
  cat "$LANE_DIR/execute.log"
  for name in kit ferroehr keycloak ferrobridge; do
    docker logs "inferno-lane-$name" > "$LANE_DIR/$name.log" 2>&1 || true
  done
  session=$(grep -oE 'Session created: [A-Za-z0-9_-]+' "$LANE_DIR/execute.log" | head -1 | cut -d' ' -f3 || true)
  if [ -n "$session" ]; then
    docker exec inferno-lane-kit bundle exec inferno session results "$session" > "$LANE_DIR/results.json"
    record "$LANE_DIR/results.json"
  fi
  pending
  return "$status"
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  *)
    echo "usage: scripts/inferno/lane.sh check|run" >&2
    exit 2
    ;;
esac
