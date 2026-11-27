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
#   scripts/oidf/lane.sh run     start everything, run the four OpenID Connect
#                                plans and the FAPI 2.0 Security Profile plan
#                                (#966), and compare each module with
#                                expected.tsv
#   scripts/oidf/lane.sh verifier run the OpenID4VP HAIP verifier plan (#817)
#                                against FerroSMART's EUDI Wallet verifier the
#                                same way, once with the PID as an SD-JWT VC
#                                and once as an mdoc (#793),
#                                scripts/oidf/verifier-client.sh starting each
#                                presentation and uploading the screenshot of
#                                FerroSMART's page each accepted one asks for
#                                (#851)
#   scripts/oidf/lane.sh certify  the verifier plan at the OpenID Foundation's
#                                hosted suite, with CONFORMANCE_TOKEN, and
#                                FerroSMART reached at TUNNEL_URL
#
# `run` expects, as the `nextest (core and axum)` job of ci.yml provides
# them: a built `target/debug/ferrosmart`; PostgreSQL at LANE_PG (a
# superuser URL without a database); OIDF_PYTHON, a Python with the
# packages of app/ferrosmart/oidf/requirements.txt; docker, npm, openssl,
# psql, jq, xxd and curl; ports 8080, 8180, 8443 to 8445, 9443 and 27017
# free on the loopback interface; and sudo for the /etc/hosts name.
# `verifier` and `certify` also need OIDF_CHROMEDRIVER, a chromedriver
# beside its Chrome, and port 9515 free. It writes its files and logs to
# LANE_DIR.
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
  "fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi][authorization_request_type=simple][grant_management=disabled] fapi"
  "oid4vp-1final-verifier-haip-test-plan[credential_format=sd_jwt_vc][response_mode=direct_post.jwt] verifier"
  "oid4vp-1final-verifier-haip-test-plan[credential_format=iso_mdl][response_mode=direct_post.jwt] verifier"
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

# The name expected.tsv gives the plan SPEC: the plan's own, and for the
# verifier plan's mdoc variant, `.iso_mdl` after it.
plan_key() {
  local spec=$1 key=${1%%\[*}
  case "$spec" in *credential_format=iso_mdl*) key="$key.iso_mdl" ;; esac
  printf '%s\n' "$key"
}

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
      oidcc-client-test-invalid-iss | oidcc-client-test-userinfo-invalid-sub)
      echo refused
      ;;
    oidcc-client-test-discovery-issuer-mismatch) echo no-start ;;
    oidcc-client-test-discovery-openid-config) echo started ;;
    oidcc-client-test-discovery-webfinger-*) echo any ;;
    oid4vp-1final-verifier-happy-flow | oid4vp-1final-verifier-minimal-cnf-jwk | \
      oid4vp-1final-verifier-request-uri-method-post | oid4vp-1final-verifier-request-uri-fetched-twice | \
      oid4vp-1final-verifier-present-credential-without-status)
      echo accepted
      ;;
    oid4vp-1final-verifier-*) echo refused ;;
    *) echo accepted ;;
  esac
}

# The failures of one expected outcome RESULT and LOGIN of the module
# MODULE of PLAN, whose row names an issue when NAMED is true and gives
# REASON.
check_outcome() {
  local plan=$1 module=$2 result=$3 login=$4 named=$5 reason=$6 failures=0 wanted
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
  echo "$failures"
}

check() {
  local failures=0 plan module result login issue reason named i
  local -a results logins
  while IFS=$'\t' read -r plan module result login issue reason; do
    named=false
    if grep -qE '^[0-9]+(,[0-9]+)*$' <<< "$issue"; then named=true; fi
    # A module whose outcome races the suite lists each outcome it can end
    # in, `|` between them, the logins paired with the results by position.
    IFS='|' read -ra results <<< "$result"
    IFS='|' read -ra logins <<< "$login"
    if [ "${#results[@]}" -ne "${#logins[@]}" ]; then
      echo "oidf-lane: $plan $module lists ${#results[@]} results and ${#logins[@]} logins" >&2
      failures=$((failures + 1))
      continue
    fi
    if [ "${#results[@]}" -gt 1 ] && { ! $named || [ -z "$reason" ]; }; then
      echo "oidf-lane: $plan $module lists more than one outcome and names no issue and reason" >&2
      failures=$((failures + 1))
    fi
    for i in "${!results[@]}"; do
      failures=$((failures + $(check_outcome "$plan" "$module" "${results[$i]}" "${logins[$i]}" "$named" "$reason")))
    done
  done < <(rows)
  if [ -n "$(rows | cut -f1,2 | sort | uniq -d)" ]; then
    echo "oidf-lane: expected.tsv lists a module of a plan twice" >&2
    failures=$((failures + 1))
  fi
  for plan in "${plans[@]}"; do
    plan=$(plan_key "${plan%% *}")
    rows | cut -f1 | grep -qxF "$plan" || {
      echo "oidf-lane: expected.tsv has no row of $plan" >&2
      failures=$((failures + 1))
    }
  done
  [ "$failures" -eq 0 ] || exit 1
  echo "oidf-lane: expected.tsv names an issue for every failure and every login the module does not ask for"
}

# A request of the lane; one to the suite carries its token, when there is one,
# and no other does.
get() {
  local -a auth=()
  local arg
  for arg in "$@"; do
    case "$arg" in "$suite"/*) [ -z "${CONFORMANCE_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $CONFORMANCE_TOKEN") ;; esac
  done
  curl -sS --cacert "$LANE_DIR/trust.pem" "${auth[@]}" "$@"
}

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
  # The ES256 key the FAPI 2.0 clients' ID Tokens are signed with, and each
  # FAPI 2.0 client's ES256 assertion key (FAPI 2.0 Security Profile §5.4.1).
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/signing-es256.pem" 2> /dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/fapi-1.pem" 2> /dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/fapi-2.pem" 2> /dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/assertion.pem" 2> /dev/null
  rm -f "$dir/backend.pem"
  "$root/target/debug/ferrosmart" key generate --out "$dir/backend.pem"
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

# FerroSMART as the OpenID Provider, with Keycloak upstream. The person's
# password is made for the run and handed to the suite's browser, which logs
# in at Keycloak's form whenever a module's authorization request reaches it.
start_provider() {
  local password
  password=$(openssl rand -hex 16)
  docker run -d --name oidf-lane-keycloak --network host --add-host "$host:127.0.0.1" \
    -v "$root/app/ferrosmart/examples/keycloak/ferrosmart-realm.json:/opt/keycloak/data/import/ferrosmart-realm.json:ro" \
    -v "$LANE_DIR/ca.crt:/opt/keycloak/lane-ca.pem:ro" \
    -e KC_HTTP_PORT=8180 -e KC_HTTP_HOST=127.0.0.1 \
    -e KC_TRUSTSTORE_PATHS=/opt/keycloak/lane-ca.pem \
    -e "FERROSMART_KEYCLOAK_JWKS_URL=$issuer/upstream-jwks" \
    -e "FERROSMART_KEYCLOAK_REDIRECT_URI=$issuer/callback" \
    -e "FERROSMART_KEYCLOAK_USER_PASSWORD=$password" \
    -e "FERROSMART_KEYCLOAK_FHIR_USER=$issuer/fhir/Practitioner/example" \
    "$(pinned_image 'Keycloak test image')" start-dev --import-realm > /dev/null
  wait_for Keycloak http://localhost:8180/realms/ferrosmart/.well-known/openid-configuration
  local op=("$root/target/debug/ferrosmart" --config "$lane/ferrosmart-op.toml"
    --set "server.tls.certificate_file=$LANE_DIR/host.crt"
    --set "server.tls.key_file=$LANE_DIR/host.key"
    --set "ferrosmart.keys.private_key_files=[\"$LANE_DIR/signing.pem\", \"$LANE_DIR/signing-es256.pem\"]"
    --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
    --set "ferrosmart.upstream.0.oidc.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem"
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart_oidf_op")
  fapi_config "$password"
  "${op[@]}" client apply "$lane"/op-clients/*.json "$LANE_DIR"/fapi-client-*.json > "$LANE_DIR/apply.log"
  # The suite's configuration takes the secrets FerroSMART issued its two
  # clients (RFC 7591 §3.2.1).
  local one two
  one=$(awk '$3 == "\"oidf-suite\"" && $4 == "client_secret" { print $5 }' "$LANE_DIR/apply.log")
  two=$(awk '$3 == "\"oidf-suite-2\"" && $4 == "client_secret" { print $5 }' "$LANE_DIR/apply.log")
  [ -n "$one" ] && [ -n "$two" ] || fail "FerroSMART issued the suite's clients no secret"
  jq --arg one "$one" --arg two "$two" --arg password "$password" \
    '.client.client_secret = $one | .client2.client_secret = $two
      | (.browser[].tasks[].commands[] | select(.[2] == "password")) |= (.[3] = $password)' \
    "$lane/op.json" > "$LANE_DIR/op.json"
  SSL_CERT_FILE="$LANE_DIR/trust.pem" "${op[@]}" serve > "$LANE_DIR/ferrosmart-op.log" 2>&1 &
  smart=$!
  wait_for FerroSMART "$issuer/.well-known/openid-configuration"
}

# Runs the plan SPEC with the suite configuration CONFIG and appends each
# module's result, with FerroSMART's login where it is the relying party,
# to actual.tsv.
run_plan() {
  local spec=$1 config=$2 plan id module instance info result login
  plan=$(plan_key "$spec")
  export OIDF_PLAN=$plan
  case "$config" in op | fapi) ;; *) spec="$spec{sample-openid-client-nodejs}_" ;; esac
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
    if [ "$config" != op ] && [ "$config" != fapi ]; then
      login=$(awk -F'\t' -v module="$module" '$1 == module { print $2 }' "$LANE_DIR/logins-$plan.tsv" 2> /dev/null | tail -1)
    fi
    printf '%s\t%s\t%s\t%s\n' "$plan" "$module" "$result" "${login:-none}" >> "$LANE_DIR/actual.tsv"
  done < <(jq -r '.modules[] | [.testModule, (.instances[-1] // "")] | @tsv' "$LANE_DIR/plan-$plan.json")
}

# Every verifier module the suite holds in REVIEW carries the screenshot
# of FerroSMART's page and no placeholder left open; any other fails the lane.
screenshots() {
  local plan=$1 module instance images failures=0
  local -a auth=()
  [ -z "${CONFORMANCE_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $CONFORMANCE_TOKEN")
  while IFS=$'\t' read -r module instance; do
    [ "$(awk -F'\t' -v plan="$plan" -v module="$module" '$1 == plan && $2 == module { print $3 }' "$LANE_DIR/actual.tsv")" = REVIEW ] ||
      continue
    images=$(curl -sS --cacert "$LANE_DIR/trust.pem" "${auth[@]}" "$suite/api/log/$instance/images")
    if ! jq -e 'any(.[]; (.img // "") | startswith("data:image/png;base64,")) and all(.[]; has("upload") | not)' \
      <<< "$images" > /dev/null; then
      echo "oidf-lane: $plan $module is in REVIEW without the screenshot of FerroSMART's page" >&2
      failures=$((failures + 1))
    fi
  done < <(jq -r '.modules[] | [.testModule, (.instances[-1] // "")] | @tsv' "$LANE_DIR/plan-$plan.json")
  [ "$failures" -eq 0 ] || return 1
  echo "oidf-lane: every $plan module in REVIEW carries the screenshot of FerroSMART's page"
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
  # A row listing more than one outcome takes the one this run ended in, when
  # it is among them.
  rows | cut -f1-4 | awk -F'\t' -v OFS='\t' '
    NR == FNR { ran[$1] = 1; got[$1 FS $2] = $3 FS $4; next }
    !($1 in ran) { next }
    $3 ~ /\|/ {
      n = split($3, results, "|"); split($4, logins, "|")
      for (i = 1; i <= n; i++) if (got[$1 FS $2] == results[i] FS logins[i]) { $3 = results[i]; $4 = logins[i] }
    }
    { print }
  ' "$LANE_DIR/actual.tsv" - > "$LANE_DIR/expected.tsv"
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
  for plan in "${plans[@]}"; do
    if [ "${plan##* }" = fapi ]; then run_plan "${plan%% *}" fapi; fi
  done
  compare
}

# The base64url of the hex bytes on standard input.
b64url_hex() { xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# The `count` bytes of the hex scalar `hex`, zero-padded on the left.
fixed_hex() { local hex=$1 count=$2; hex=$(printf '%0*d%s' "$count" 0 "$hex"); printf '%s' "${hex: -$count}"; }

# A P-256 key at DIR/NAME.key and its certificate DIR/NAME.crt for SUBJECT,
# signed by the authority DIR/SIGNER (self-signed when none), a certificate
# authority when CA is `ca`.
certificate() {
  local dir=$1 name=$2 subject=$3 signer=${4:-} ca=${5:-}
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/$name.key" 2> /dev/null
  if [ "$ca" = ca ]; then
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$dir/$name.ext"
  else
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n' > "$dir/$name.ext"
  fi
  if [ -z "$signer" ]; then
    openssl req -x509 -new -key "$dir/$name.key" -days 1 -subj "$subject" -extensions v3 \
      -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat "$dir/$name.ext") -out "$dir/$name.crt" 2> /dev/null
  else
    printf 'authorityKeyIdentifier=keyid\n' >> "$dir/$name.ext"
    openssl req -new -key "$dir/$name.key" -subj "$subject" -out "$dir/$name.csr" 2> /dev/null
    openssl x509 -req -in "$dir/$name.csr" -CA "$dir/$signer.crt" -CAkey "$dir/$signer.key" -CAcreateserial \
      -days 1 -extfile "$dir/$name.ext" -out "$dir/$name.crt" 2> /dev/null
  fi
}

# The verifier's certificates and the suite's credential issuer, made for
# this run: FerroSMART's access certificate under a root the suite trusts,
# and the PID provider's certificate under the anchor FerroSMART trusts,
# whose key, with its certificate as `x5c`, the suite signs credentials with.
make_verifier_keys() {
  local dir=$1
  certificate "$dir" rp-root '/CN=FerroSMART OIDF lane verifier root' '' ca
  certificate "$dir" access '/CN=FerroSMART OIDF lane verifier' rp-root
  certificate "$dir" pid-root '/CN=FerroSMART OIDF lane PID provider root' '' ca
  certificate "$dir" pid-issuer '/CN=OIDF conformance suite PID provider' pid-root
  openssl pkcs8 -topk8 -nocrypt -in "$dir/access.key" -out "$dir/access-pkcs8.pem"
  printf 'eyJhbGciOiJub25lIn0.eyJsYW5lIjoib2lkZiJ9.\n' > "$dir/registration.jwt"
  ec_jwk "$dir/pid-issuer.key" oidf-lane-pid |
    jq --arg c "$(openssl x509 -in "$dir/pid-issuer.crt" -outform der | openssl base64 -A)" '. + {x5c: [$c]}' \
    > "$dir/pid-issuer.jwk"
}

# The private P-256 JWK of the PEM key FILE under the `kid` KID.
ec_jwk() {
  local file=$1 kid=$2 text priv pub
  text=$(openssl ec -in "$file" -noout -text 2> /dev/null)
  priv=$(awk '/^priv:/ { f = 1; next } /^pub:/ { f = 0 } f' <<< "$text" | tr -d ' :\n')
  pub=$(awk '/^pub:/ { f = 1; next } /^ASN1 OID/ { f = 0 } f' <<< "$text" | tr -d ' :\n')
  jq -n --arg x "$(b64url_hex <<< "${pub:2:64}")" --arg y "$(b64url_hex <<< "${pub:66:64}")" \
    --arg d "$(fixed_hex "$priv" 64 | b64url_hex)" --arg kid "$kid" \
    '{kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: $kid, x: $x, y: $y, d: $d}'
}

# The FAPI 2.0 plan's two clients, registered with FerroSMART by the public
# half of each client's key, and the suite's configuration holding the
# private half and the person's PASSWORD.
fapi_config() {
  local password=$1 n jwk
  for n in 1 2; do
    jwk=$(ec_jwk "$LANE_DIR/fapi-$n.pem" "fapi-$n")
    printf '%s\n' "$jwk" > "$LANE_DIR/fapi-$n.jwk"
    jq --argjson key "$jwk" '.jwks.keys = [$key | del(.d)]' \
      "$lane/fapi-clients/fapi-suite$([ "$n" = 1 ] || echo -2).json" > "$LANE_DIR/fapi-client-$n.json"
  done
  jq --slurpfile one "$LANE_DIR/fapi-1.jwk" --slurpfile two "$LANE_DIR/fapi-2.jwk" --arg password "$password" \
    '.client.jwks.keys = $one | .client2.jwks.keys = $two
      | (.browser[].tasks[].commands[] | select(.[2] == "password")) |= (.[3] = $password)' \
    "$lane/fapi.json" > "$LANE_DIR/fapi.json"
}

# The suite's configuration of the verifier plan at the alias ALIAS.
verifier_config() {
  local dir=$1 alias=$2
  jq --arg alias "$alias" --rawfile anchor "$dir/rp-root.crt" --slurpfile jwk "$dir/pid-issuer.jwk" \
    '.alias = $alias | .client.request_object_trust_anchor_pem = $anchor | .credential.signing_jwk = $jwk[0]' \
    "$lane/verifier.json" > "$dir/verifier.json"
}

# FerroSMART as the verifier at ISSUER, its wallet the suite's alias ALIAS at
# SUITE, asking for the PID in the credential format of the plan SPEC;
# served with the lane's certificate unless ISSUER is a tunnel's. In an mdoc
# test the suite signs with its own IACA root, which this run alone trusts.
start_verifier() {
  local issuer=$1 suite_base=$2 alias=$3 spec=$4 tls=${5:-tls} format=dc+sd-jwt anchor=$LANE_DIR/pid-root.crt
  case "$spec" in
    *credential_format=iso_mdl*)
      format=mso_mdoc anchor=$LANE_DIR/mdoc-iaca-root.pem
      get -f -o "$anchor" "${suite_base}mdoc-iaca-root.pem" || fail "the suite served no mdoc IACA root"
      ;;
  esac
  local -a sets=(--set "ferrosmart.issuer=$issuer"
    --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem"
    --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart_oidf_verifier"
    --set "ferrosmart.upstream.0.openid4vp.access_certificate_file=$LANE_DIR/access.crt"
    --set "ferrosmart.upstream.0.openid4vp.access_key_file=$LANE_DIR/access-pkcs8.pem"
    --set "ferrosmart.upstream.0.openid4vp.registration_certificate_file=$LANE_DIR/registration.jwt"
    --set "ferrosmart.upstream.0.openid4vp.issuer_anchor_files=$anchor"
    --set "ferrosmart.upstream.0.openid4vp.credential_formats=$format"
    --set "ferrosmart.upstream.0.openid4vp.wallet_endpoint=${suite_base}test/a/$alias/authorize"
    --set "ferrosmart.resource.0.base=$issuer/fhir")
  if [ "$tls" = tls ]; then
    sets+=(--set "server.tls.certificate_file=$LANE_DIR/host.crt" --set "server.tls.key_file=$LANE_DIR/host.key")
  fi
  local smart_cmd=("$root/target/debug/ferrosmart" --config "$lane/ferrosmart-verifier.toml" "${sets[@]}")
  jq --arg issuer "$issuer" '.redirect_uris = [$issuer + "/app-callback"] | .resources = [$issuer + "/fhir"]' \
    "$lane/verifier-app.json" > "$LANE_DIR/verifier-app.json"
  "${smart_cmd[@]}" client apply "$LANE_DIR/verifier-app.json" > /dev/null
  SSL_CERT_FILE="$LANE_DIR/trust.pem" "${smart_cmd[@]}" serve >> "$LANE_DIR/ferrosmart-verifier.log" 2>&1 &
  smart=$!
}

# Each verifier plan with FerroSMART at ISSUER, its wallet the suite's alias
# ALIAS at SUITE, started afresh for the plan's credential format.
verifier_plans() {
  local issuer=$1 suite_base=$2 alias=$3 tls=${4:-tls} plan
  for plan in "${plans[@]}"; do
    [ "${plan##* }" = verifier ] || continue
    start_verifier "$issuer" "$suite_base" "$alias" "${plan%% *}" "$tls"
    wait_for FerroSMART "$issuer/.well-known/smart-configuration"
    run_plan "${plan%% *}" verifier
    kill "$smart" 2> /dev/null || true
    wait "$smart" 2> /dev/null || true
  done
}

# The verifier plan against the lane's own suite.
verifier() {
  : "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the lane directory}" "${OIDF_PYTHON:?the Python of the runner}"
  local plan
  : "${OIDF_CHROMEDRIVER:?the chromedriver of headless Chrome}"
  export LANE_PG LANE_DIR OIDF_SUITE=$suite OIDF_ISSUER=$issuer OIDF_CHROMEDRIVER
  export CONFORMANCE_SERVER="$suite/" CONFORMANCE_SERVER_MTLS="https://$host:8444/" CONFORMANCE_DEV_MODE=1
  export CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000
  mkdir -p "$LANE_DIR"
  check
  trap stop EXIT
  make_keys "$LANE_DIR"
  make_verifier_keys "$LANE_DIR"
  verifier_driver "$LANE_DIR"
  verifier_config "$LANE_DIR" ferrosmart-verifier
  grep -qF "$host" /etc/hosts || echo "127.0.0.1 $host" | sudo tee -a /etc/hosts > /dev/null
  psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart_oidf_verifier'
  : > "$LANE_DIR/actual.tsv"
  start_suite
  verifier_plans "$issuer" "$suite/" ferrosmart-verifier
  compare
  for plan in "${plans[@]}"; do
    if [ "${plan##* }" = verifier ]; then screenshots "$(plan_key "${plan%% *}")"; fi
  done
}

# The runner calls the verifier's driver, not the relying party's.
verifier_driver() {
  jq -n --arg client "$root/scripts/oidf/verifier-client.sh" '{private: true, scripts: {client: $client}}' \
    > "$1/sample-openid-client-nodejs/package.json"
}

# The verifier plan against the OpenID Foundation's hosted suite, which
# reaches FerroSMART at TUNNEL_URL; the token stays in the environment.
certify() {
  : "${LANE_PG:?the PostgreSQL URL}" "${LANE_DIR:?the lane directory}" "${OIDF_PYTHON:?the Python of the runner}"
  : "${CONFORMANCE_TOKEN:?the token of the hosted suite}" "${TUNNEL_URL:?the public URL of FerroSMART}"
  : "${OIDF_CHROMEDRIVER:?the chromedriver of headless Chrome}"
  export OIDF_CHROMEDRIVER
  local hosted=https://www.certification.openid.net plan
  suite=$hosted
  export LANE_PG LANE_DIR OIDF_SUITE=$hosted OIDF_ISSUER=$TUNNEL_URL CONFORMANCE_SERVER="$hosted/"
  export CONFORMANCE_SERVER_MTLS="$hosted/" CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000
  mkdir -p "$LANE_DIR"
  check
  trap stop EXIT
  make_keys "$LANE_DIR"
  make_verifier_keys "$LANE_DIR"
  verifier_driver "$LANE_DIR"
  verifier_config "$LANE_DIR" ferrosmart-verifier-certification
  psql "$LANE_PG/postgres" -qc 'CREATE DATABASE ferrosmart_oidf_verifier'
  : > "$LANE_DIR/actual.tsv"
  verifier_plans "$TUNNEL_URL" "$hosted/" ferrosmart-verifier-certification plain
  compare
  for plan in "${plans[@]}"; do
    if [ "${plan##* }" = verifier ]; then screenshots "$(plan_key "${plan%% *}")"; fi
  done
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  verifier) verifier ;;
  certify) certify ;;
  *)
    echo "usage: scripts/oidf/lane.sh check|run|verifier|certify" >&2
    exit 2
    ;;
esac
