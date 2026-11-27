#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# FerroSMART's part of one relying party test module of the OpenID
# Foundation conformance suite (#621, scripts/oidf/lane.sh). The suite's
# run-test-plan.py calls it, through `npm run client`, once the module waits
# for its relying party. It starts FerroSMART with the module's provider
# upstream, sends an app's authorization request, follows the browser to the
# provider and back to FerroSMART's callback, and records what FerroSMART
# made of the provider's answer:
#
#   accepted   the login went on to the consent page
#   refused    FerroSMART answered the app with an error (RFC 6749 §4.1.2.1)
#   no-start   FerroSMART refused to start with the provider's metadata
#   started    FerroSMART started, and the module ended on that: it tests
#              the reading of the metadata alone
#
# FerroSMART makes the UserInfo request (OpenID Connect Core 1.0 §5.3) as
# part of the login, so a module of the code flow is over once the callback
# answers. One that still waits once FerroSMART's part is over gets the
# suite's own five seconds and is then stopped, which the suite records as
# INTERRUPTED. No specification governs the driver: our own design.
#
# It reads MODULE_NAME from run-test-plan.py and LANE_DIR, LANE_PG, OIDF_PLAN
# and OIDF_SUITE from the lane, and needs bash, curl, jq and openssl.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${MODULE_NAME:?the test module}" "${LANE_DIR:?the run directory}" "${LANE_PG:?the PostgreSQL URL}"
: "${OIDF_PLAN:?the test plan}" "${OIDF_SUITE:?the base URL of the suite}"

issuer=https://localhost.emobix.co.uk:9443
app=http://localhost:9000/callback
log="$LANE_DIR/ferrosmart-$OIDF_PLAN-$MODULE_NAME.log"
jar="$(mktemp)"
smart=""

stop() {
  if [ -n "$smart" ]; then
    kill "$smart" 2> /dev/null || true
    wait "$smart" 2> /dev/null || true
  fi
  rm -f "$jar"
}
trap stop EXIT

get() { curl -sS --cacert "$LANE_DIR/ca.crt" "$@"; }

# The location a request of the person's browser answers with; empty when
# the answer is no redirect.
redirect() { get -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$1"; }

# The client authentication at the provider's token endpoint the module
# fixes (OpenID Connect Core 1.0 §9): `client_secret_basic` for the plan
# that fixes it and for the module of that name, `private_key_jwt` for every
# other.
authentication() {
  case "$OIDF_PLAN:$MODULE_NAME" in
    oidcc-client-basic-certification-test-plan:* | *:oidcc-client-test-client-secret-basic)
      printf '%s\n' "ferrosmart.upstream.0.oidc.client_secret_basic.secret_file=$LANE_DIR/rp-secret"
      ;;
    *)
      printf '%s\n' "ferrosmart.upstream.0.oidc.private_key_jwt.keys.private_key_file=$LANE_DIR/assertion.pem" \
        "ferrosmart.upstream.0.oidc.private_key_jwt.keys.kid=oidf-lane"
      ;;
  esac
}

# Starts FerroSMART, which reads the provider's metadata as it starts
# (OpenID Connect Discovery 1.0 §4); fails when it refuses them.
start() {
  local setting
  local -a sets=()
  while IFS= read -r setting; do sets+=(--set "$setting"); done < <(authentication)
  local rp=("$root/target/debug/ferrosmart" --config "$root/app/ferrosmart/oidf/ferrosmart-rp.toml"
    --set "server.tls.certificate_file=$LANE_DIR/host.crt"
    --set "server.tls.key_file=$LANE_DIR/host.key"
    --set "ferrosmart.keys.private_key_files=$LANE_DIR/signing.pem"
    --set "ferrosmart.backend.keys.private_key_file=$LANE_DIR/backend.pem"
    "${sets[@]}"
    --set "ferrosmart.database.url=$LANE_PG/ferrosmart_oidf_rp")
  "${rp[@]}" client apply "$root"/app/ferrosmart/oidf/rp-clients/*.json > /dev/null
  SSL_CERT_FILE="$LANE_DIR/trust.pem" "${rp[@]}" serve > "$log" 2>&1 &
  smart=$!
  for _ in $(seq 1 40); do
    if get -f -o /dev/null "$issuer/.well-known/smart-configuration" 2> /dev/null; then
      return 0
    fi
    if ! kill -0 "$smart" 2> /dev/null; then
      smart=""
      return 1
    fi
    sleep 0.5
  done
  return 1
}

# FerroSMART's part of the login: what it made of this module's provider.
login() {
  local verifier challenge location
  verifier=$(openssl rand -hex 32)
  challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  # 1. The app sends the browser to FerroSMART, which sends it on to the
  #    provider (SMART App Launch 2.2.0, Obtain authorization code).
  location=$(redirect "$issuer/authorize?response_type=code&client_id=oidf-app&redirect_uri=$(jq -rn --arg v "$app" '$v | @uri')&scope=openid&state=$(openssl rand -hex 16)&aud=$(jq -rn --arg v "$issuer/fhir" '$v | @uri')&code_challenge=$challenge&code_challenge_method=S256")
  case "$location" in "$OIDF_SUITE"*) ;; *)
    echo "unexpected: FerroSMART did not send the browser to the provider: $location"
    return
    ;;
  esac
  # 2. The provider answers with the redirect back to FerroSMART's callback
  #    (OpenID Connect Core 1.0 §3.1.2.5).
  location=$(redirect "$location")
  case "$location" in "$issuer"/callback*) ;; *)
    echo "unexpected: the provider did not return to FerroSMART: $location"
    return
    ;;
  esac
  # 3. FerroSMART redeems the code, checks the ID Token (§3.1.3.7) and asks
  #    the UserInfo Endpoint for the claims about its subject (§5.3).
  location=$(redirect "$location")
  case "$location" in
    "$issuer"/consent*) echo accepted ;;
    "$app"\?*error=*) echo refused ;;
    *) echo "unexpected: the callback answered $location" ;;
  esac
}

# The id of the module the suite is running, the one this call serves.
running() { get "$OIDF_SUITE/api/runner/running" | jq -r '.[0] // empty'; }

# The status of the module at the suite.
status() { get "$OIDF_SUITE/api/info/$module" | jq -r '.status // empty'; }

module=$(running)
[ -n "$module" ] || {
  echo "rp-client: the suite runs no module" >&2
  exit 1
}
if ! start; then
  outcome=no-start
elif sleep 1 && [ "$(status)" = FINISHED ]; then
  # A module about the provider's metadata is over once they are read.
  outcome=started
else
  outcome=$(login)
fi
printf '%s\t%s\n' "$MODULE_NAME" "$outcome" >> "$LANE_DIR/logins-$OIDF_PLAN.tsv"
echo "rp-client: $OIDF_PLAN $MODULE_NAME: $outcome"

# The module ends by itself when it has what it waits for; one that still
# waits is stopped.
for _ in $(seq 1 12); do
  case "$(status)" in FINISHED | INTERRUPTED) exit 0 ;; *) sleep 1 ;; esac
done
get -o /dev/null -X DELETE "$OIDF_SUITE/api/runner/$module"
