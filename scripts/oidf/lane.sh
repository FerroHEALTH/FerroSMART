#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The OpenID Foundation conformance suite lane (#621, docs/architecture.md
# §13.24): the suite's published image tests FerroSMART in both roles. As
# the relying party FerroSMART logs in at the suite, its upstream provider;
# as the OpenID Provider it answers the suite, with Keycloak upstream. The
# suite's own scripts/run-test-plan.py runs each plan, and
# app/ferrosmart/oidf/expected.tsv holds every module to its result. No
# specification governs the lane itself: our own design.
#
#   scripts/oidf/lane.sh check   expected.tsv is well formed, and every
#                                failure and every login of FerroSMART
#                                that a module does not ask for names its
#                                issue
#   scripts/oidf/lane.sh run     start everything, run the four plans and
#                                compare each module with expected.tsv
#
# `run` expects, as the `nextest (core and axum)` job of ci.yml provides
# them: a built `target/debug/ferrosmart`; PostgreSQL at LANE_PG (a
# superuser URL without a database); OIDF_PYTHON, a Python with the
# packages of app/ferrosmart/oidf/requirements.txt; docker, npm, openssl,
# psql, jq, xxd and curl; ports 8080, 8180, 8443 to 8445, 9443 and 27017
# free on the loopback interface; and sudo for the /etc/hosts name. It
# writes its files and logs to LANE_DIR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lane="$root/app/ferrosmart/oidf"
runner="$root/docs/specs/oidf-conformance-suite"
host=localhost.emobix.co.uk
suite="https://$host:8443"
issuer="https://$host:9443"
containers=(oidf-lane-nginx oidf-lane-suite oidf-lane-mongo oidf-lane-keycloak)

# The four plans, each with the variants its modules leave open and the
# suite configuration it runs with. Both Basic certification plans fix
# `client_secret_basic` themselves.
rp_variants='[client_auth_type=private_key_jwt][response_type=code][response_mode=default][request_type=plain_http_request][client_registration=static_client]'
plans=(
  "oidcc-client-test-plan$rp_variants rp"
  "oidcc-client-basic-certification-test-plan[request_type=plain_http_request][client_registration=static_client] rp"
  "oidcc-config-certification-test-plan op"
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] op"
)

fail() {
  echo "oidf-lane: $*" >&2
  exit 1
}

# The image the row ITEM of docs/VERSIONS.md pins by tag and digest.
pinned_image() {
  local cell image
  cell=$(awk -F'|' -v item="$1" '$2 ~ "^ "item" $" { print $3 }' "$root/docs/VERSIONS.md")
  # shellcheck disable=SC2016 # the backticks are Markdown code spans of docs/VERSIONS.md, matched literally
  image=$(grep -oE '`[^`]+@sha256:[0-9a-f]{64}`' <<< "$cell" | head -1 | tr -d '`' || true)
  # shellcheck disable=SC2016 # as above
  [ -n "$image" ] || image=$(sed -nE 's/^ *`([^`]+)`, index digest `(sha256:[0-9a-f]{64})`.*/\1@\2/p' <<< "$cell")
  [ -n "$image" ] || fail "no image pin for '$1' in docs/VERSIONS.md"
  printf '%s\n' "$image"
}

# The rows of expected.tsv, without its comments.
rows() { grep -vE '^(#|$)' "$lane/expected.tsv"; }

# What a relying party module asks of FerroSMART's login, from the
# module's own summary in the suite: a refusal of the ID Token or the
# metadata it serves, or the login to go on. `any` is a module whose
# verdict is the suite's alone.
wanted_login() {
  case "$1" in
    oidcc-client-test-nonce-invalid | oidcc-client-test-kid-absent-multiple-jwks | \
      oidcc-client-test-missing-iat | oidcc-client-test-missing-aud | oidcc-client-test-invalid-aud | \
      oidcc-client-test-idtoken-sig-none | oidcc-client-test-missing-sub | \
      oidcc-client-test-invalid-sig-rs256 | oidcc-client-test-invalid-sig-es256 | \
      oidcc-client-test-invalid-iss)
      echo refused
      ;;
    oidcc-client-test-discovery-issuer-mismatch) echo no-start ;;
    oidcc-client-test-discovery-openid-config) echo started ;;
    oidcc-client-test-discovery-webfinger-*) echo any ;;
    *) echo accepted ;;
  esac
}

check() {
  local failures=0 plan module result login issue reason wanted named
  while IFS=$'\t' read -r plan module result login issue reason; do
    named=false
    if grep -qE '^[0-9]+(,[0-9]+)*$' <<< "$issue"; then named=true; fi
    case "$result" in
      PASSED | REVIEW | SKIPPED | NOT-RUN) ;;
      FAILED | WARNING)
        $named || {
          echo "oidf-lane: $plan $module is expected $result and names no issue" >&2
          failures=$((failures + 1))
        }
        ;;
      # The driver stops a module once FerroSMART's part is over; any other
      # interruption is a failure.
      INTERRUPTED)
        $named || [ "$login" = accepted ] || {
          echo "oidf-lane: $plan $module is expected $result after a login that was not accepted and names no issue" >&2
          failures=$((failures + 1))
        }
        ;;
      *)
        echo "oidf-lane: $plan $module has the unknown result '$result'" >&2
        failures=$((failures + 1))
        ;;
    esac
    case "$login" in
      accepted | refused | no-start | started)
        wanted=$(wanted_login "$module")
        if [ "$wanted" != any ] && [ "$login" != "$wanted" ] && ! $named; then
          echo "oidf-lane: $plan $module expects FerroSMART's login $wanted, is expected $login and names no issue" >&2
          failures=$((failures + 1))
        fi
        ;;
      none | -) ;;
      *)
        echo "oidf-lane: $plan $module has the unknown login '$login'" >&2
        failures=$((failures + 1))
        ;;
    esac
    if [ "$result" != PASSED ] && [ -z "$reason" ]; then
      echo "oidf-lane: $plan $module is expected $result and gives no reason" >&2
      failures=$((failures + 1))
    fi
  done < <(rows)
  if [ -n "$(rows | cut -f1,2 | sort | uniq -d)" ]; then
    echo "oidf-lane: expected.tsv lists a module of a plan twice" >&2
    failures=$((failures + 1))
  fi
  for plan in "${plans[@]}"; do
    plan=${plan%% *}
    rows | cut -f1 | grep -qxF "${plan%%\[*}" || {
      echo "oidf-lane: expected.tsv has no row of ${plan%%\[*}" >&2
      failures=$((failures + 1))
    }
  done
  [ "$failures" -eq 0 ] || exit 1
  echo "oidf-lane: expected.tsv names an issue for every failure and every login the module does not ask for"
}

get() { curl -sS --cacert "$LANE_DIR/ca.crt" "$@"; }

wait_for() {
  local what=$1 url=$2
  for _ in $(seq 1 90); do
    if get -f -o /dev/null "$url" 2> /dev/null; then
      return 0
    fi
    sleep 2
  done
  fail "$what did not answer at $url"
}

stop() {
  local name
  kill "${smart:-}" 2> /dev/null || true
  for name in "${containers[@]}"; do
    docker logs "$name" > "$LANE_DIR/$name.log" 2>&1 || true
    docker rm -f -v "$name" > /dev/null 2>&1 || true
  done
}

# The development CA and the one server certificate, FerroSMART's signing
# and assertion keys, the relying party's client secret, and the hashes of
# the suite's two client secrets, made for this run and never kept.
make_keys() {
  local dir=$1 modulus name
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj '/CN=FerroSMART OIDF lane CA' -keyout "$dir/ca.key" -out "$dir/ca.crt" 2> /dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$host" -keyout "$dir/host.key" -out "$dir/host.csr" 2> /dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$host" > "$dir/host.ext"
  openssl x509 -req -in "$dir/host.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
    -days 1 -extfile "$dir/host.ext" -out "$dir/host.crt" 2> /dev/null
  rm -f "$dir/ca.key"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/signing.pem" 2> /dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/assertion.pem" 2> /dev/null
  chmod 0644 "$dir/host.key" "$dir"/*.pem
  cat /etc/ssl/certs/ca-certificates.crt "$dir/ca.crt" > "$dir/trust.pem"
  # The suite's configurations: the relying party's registers the assertion
  # key FerroSMART signs with, under the `kid` ferrosmart-rp.toml names.
  modulus=$(openssl rsa -in "$dir/assertion.pem" -noout -modulus | cut -d= -f2 | xxd -r -p |
    openssl base64 -A | tr '+/' '-_' | tr -d '=')
  jq --arg n "$modulus" \
    '.client.jwks.keys = [{kty: "RSA", kid: "oidf-lane", use: "sig", alg: "RS256", n: $n, e: "AQAB"}]' \
    "$lane/rp.json" > "$dir/rp.json"
  jq -j '.client.client_secret' "$lane/rp.json" > "$dir/rp-secret"
  cp "$lane/op.json" "$dir/op.json"
  for name in client client2; do
    jq -j --arg name "$name" '.[$name].client_secret' "$lane/op.json" |
      "$root/target/debug/ferrosmart" client hash-secret > "$dir/$name.phc"
  done
  # NOTE: run-test-plan.py reads the key files of the directory `certs-keys` beside it, which
  # no configuration of this lane names, so it runs from a copy beside an empty one.
  mkdir -p "$dir/runner/certs-keys" "$dir/sample-openid-client-nodejs"
  cp "$runner"/*.py "$dir/runner/"
  # NOTE: run-test-plan.py runs a relying party as `npm run client` in the directory
  # `sample-openid-client-nodejs` of where it is called; this one's client is FerroSMART.
  jq -n --arg client "$root/scripts/oidf/rp-client.sh" '{private: true, scripts: {client: $client}}' \
    > "$dir/sample-openid-client-nodejs/package.json"
}

# The suite: its database, its server and the TLS front its own image is,
# given the lane's certificate.
start_suite() {
  docker run -d --name oidf-lane-mongo --network host "$(pinned_image 'MongoDB test image')" > /dev/null
  docker run -d --name oidf-lane-suite --network host --add-host "$host:127.0.0.1" \
    -e "BASE_URL=$suite" -e "BASE_MTLS_URL=https://$host:8444" -e MONGODB_HOST=localhost \
    -e SPRING_PROFILES_ACTIVE=dev \
    -e OIDC_GOOGLE_CLIENTID=unused -e OIDC_GOOGLE_SECRET=unused \
    -e OIDC_GITLAB_CLIENTID=unused -e OIDC_GITLAB_SECRET=unused \
    "$(pinned_image 'OpenID Foundation conformance suite image')" > /dev/null
  docker run -d --name oidf-lane-nginx --network host --add-host server:127.0.0.1 \
    -v "$LANE_DIR/host.crt:/etc/ssl/certs/nginx-selfsigned.crt:ro" \
    -v "$LANE_DIR/host.key:/etc/ssl/private/nginx-selfsigned.key:ro" \
    "$(pinned_image 'OpenID Foundation conformance suite TLS front image')" > /dev/null
  wait_for "the conformance suite" "$suite/api/runner/available"
}

# FerroSMART as the OpenID Provider, with Keycloak upstream. No module of
# the suite reaches the login today (expected.tsv), so the person's
# password is made and never used.
start_provider() {
  docker run -d --name oidf-lane-keycloak --network host --add-host "$host:127.0.0.1" \
    -v "$root/app/ferrosmart/examples/keycloak/ferrosmart-realm.json:/opt/keycloak/data/import/ferrosmart-realm.json:ro" \
    -v "$LANE_DIR/ca.crt:/opt/keycloak/lane-ca.pem:ro" \
    -e KC_HTTP_PORT=8180 -e KC_HTTP_HOST=127.0.0.1 \
    -e KC_TRUSTSTORE_PATHS=/opt/keycloak/lane-ca.pem \
    -e "FERROSMART_KEYCLOAK_JWKS_URL=$issuer/upstream-jwks" \
    -e "FERROSMART_KEYCLOAK_REDIRECT_URI=$issuer/callback" \
    -e "FERROSMART_KEYCLOAK_USER_PASSWORD=$(openssl rand -hex 16)" \
    -e "FERROSMART_KEYCLOAK_FHIR_USER=$issuer/fhir/Practitioner/example" \
    "$(pinned_image 'Keycloak test image')" start-dev --import-realm > /dev/null
  wait_for Keycloak http://localhost:8180/realms/ferrosmart/.well-known/openid-configuration
  SSL_CERT_FILE="$LANE_DIR/trust.pem" \
    "$root/target/debug/ferrosmart" --config "$lane/ferrosmart-op.toml" \
    --set "server.tls.certificate_file=$LANE_DIR/host.crt" \
    --set "server.tls.key_file=$LANE_DIR/host.key" \
    --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem" \
    --set "ferrosmart.upstream.0.oidc.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem" \
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart_oidf_op" \
    --set "ferrosmart.client[0].secret_hash_file=$LANE_DIR/client.phc" \
    --set "ferrosmart.client[1].secret_hash_file=$LANE_DIR/client2.phc" \
    serve > "$LANE_DIR/ferrosmart-op.log" 2>&1 &
  smart=$!
  wait_for FerroSMART "$issuer/.well-known/openid-configuration"
}

# Runs the plan SPEC with the suite configuration CONFIG and appends each
# module's result, with FerroSMART's login where it is the relying party,
# to actual.tsv.
run_plan() {
  local spec=$1 config=$2 plan=${1%%\[*} id module instance info result login
  export OIDF_PLAN=$plan
  [ "$config" = op ] || spec="$spec{sample-openid-client-nodejs}_"
  # NOTE: run-test-plan.py's own verdict wants the suite's expected-failures file, a row
  # for each failing condition; the lane holds each module's result instead, so it is not read.
  (cd "$LANE_DIR" && "$OIDF_PYTHON" "$LANE_DIR/runner/run-test-plan.py" --no-parallel "$spec" "$config.json") \
    > "$LANE_DIR/run-$plan.log" 2>&1 || true
  id=$(sed -n 's/.*Created test plan, new id: //p' "$LANE_DIR/run-$plan.log" | head -1)
  [ -n "$id" ] || {
    tail -20 "$LANE_DIR/run-$plan.log" >&2
    fail "the suite created no plan $plan"
  }
  get "$suite/api/plan/$id" > "$LANE_DIR/plan-$plan.json"
  while IFS=$'\t' read -r module instance; do
    result=NOT-RUN
    if [ -n "$instance" ]; then
      info=$(get "$suite/api/info/$instance")
      # A module that was stopped has no result, or the suite's UNKNOWN.
      result=$(jq -r 'if (.result // "UNKNOWN") == "UNKNOWN" then .status else .result end' <<< "$info")
    fi
    login=-
    if [ "$config" = rp ]; then
      login=$(awk -F'\t' -v module="$module" '$1 == module { print $2 }' "$LANE_DIR/logins-$plan.tsv" 2> /dev/null | tail -1)
    fi
    printf '%s\t%s\t%s\t%s\n' "$plan" "$module" "$result" "${login:-none}" >> "$LANE_DIR/actual.tsv"
  done < <(jq -r '.modules[] | [.testModule, (.instances[-1] // "")] | @tsv' "$LANE_DIR/plan-$plan.json")
}

# Every module's result against expected.tsv, in the log and the job
# summary; any difference fails the lane.
compare() {
  local summary="${GITHUB_STEP_SUMMARY:-/dev/null}" plan module result login issue reason actual
  {
    echo "### OpenID Foundation conformance suite"
    echo
    echo "| Plan | Module | Result | FerroSMART's login | The module asks | Issue | Reason |"
    echo "|---|---|---|---|---|---|---|"
    while IFS=$'\t' read -r plan module result login; do
      issue=$(awk -F'\t' -v plan="$plan" -v module="$module" '$1 == plan && $2 == module { print $5 }' "$lane/expected.tsv")
      reason=$(awk -F'\t' -v plan="$plan" -v module="$module" '$1 == plan && $2 == module { print $6 }' "$lane/expected.tsv")
      # shellcheck disable=SC2016 # the backticks are Markdown code spans, written literally
      printf '| `%s` | `%s` | %s | %s | %s | %s | %s |\n' "$plan" "$module" "$result" "$login" \
        "$(case "$login" in none | -) echo - ;; *) wanted_login "$module" ;; esac)" \
        "$([ -z "$issue" ] || [ "$issue" = - ] || printf '#%s' "${issue//,/, #}")" "$reason"
    done < "$LANE_DIR/actual.tsv"
  } >> "$summary"
  rows | cut -f1-4 > "$LANE_DIR/expected.tsv"
  if ! actual=$(diff "$LANE_DIR/expected.tsv" "$LANE_DIR/actual.tsv"); then
    echo "oidf-lane: the suite's results differ from app/ferrosmart/oidf/expected.tsv (<) in this run (>):" >&2
    echo "$actual" >&2
    echo "oidf-lane: a module that got worse is a regression to fix; one that got better is recorded in expected.tsv" >&2
    return 1
  fi
  echo "oidf-lane: $(wc -l < "$LANE_DIR/actual.tsv" | tr -d ' ') modules of ${#plans[@]} plans answered as expected.tsv records"
}

run() {
  : "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the lane directory}" "${OIDF_PYTHON:?the Python of the runner}"
  local plan
  export LANE_PG LANE_DIR OIDF_SUITE=$suite
  # NOTE: run-test-plan.py reads the suite's base URL here, and in development mode asks
  # for no token; the suite's own certificate is the lane's, which the runner does not know.
  export CONFORMANCE_SERVER="$suite/" CONFORMANCE_SERVER_MTLS="https://$host:8444/" CONFORMANCE_DEV_MODE=1
  # NOTE: run-test-plan.py gives the run up after three modules in a row that did not finish,
  # which the modules scripts/oidf/rp-client.sh stops are; expected.tsv holds each instead.
  export CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000
  mkdir -p "$LANE_DIR"
  check
  trap stop EXIT
  make_keys "$LANE_DIR"
  grep -qF "$host" /etc/hosts || echo "127.0.0.1 $host" | sudo tee -a /etc/hosts > /dev/null
  psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart_oidf_rp' -c 'CREATE DATABASE ferrosmart_oidf_op'
  : > "$LANE_DIR/actual.tsv"
  start_suite
  for plan in "${plans[@]}"; do
    if [ "${plan##* }" = rp ]; then run_plan "${plan%% *}" rp; fi
  done
  start_provider
  for plan in "${plans[@]}"; do
    if [ "${plan##* }" = op ]; then run_plan "${plan%% *}" op; fi
  done
  compare
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  *)
    echo "usage: scripts/oidf/lane.sh check|run" >&2
    exit 2
    ;;
esac
