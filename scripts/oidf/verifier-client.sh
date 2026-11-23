#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# FerroSMART's part of one verifier test module of the OpenID Foundation
# conformance suite (#817, scripts/oidf/lane.sh verifier and certify). The
# suite's run-test-plan.py calls it, through `npm run client`, once the
# module waits for the verifier's authorization request. It sends an app's
# authorization request to FerroSMART, whose wallet is the module's
# authorization endpoint, and delivers the invocation to the suite as a
# browser would. The suite then fetches the request object and posts its
# answer to FerroSMART's response URI itself. The script records what
# FerroSMART made of the presentation:
#
#   accepted   the response URI answered with a redirect_uri, which brought
#              the browser on to the consent page
#   refused    the response URI refused the presentation
#
# No specification governs the driver: our own design.
#
# It reads MODULE_NAME from run-test-plan.py and LANE_DIR, OIDF_PLAN,
# OIDF_SUITE and OIDF_ISSUER from the lane, and needs bash, curl, jq and
# openssl.
set -euo pipefail

: "${MODULE_NAME:?the test module}" "${LANE_DIR:?the run directory}" "${OIDF_PLAN:?the test plan}"
: "${OIDF_SUITE:?the base URL of the suite}" "${OIDF_ISSUER:?the issuer of FerroSMART}"

issuer=$OIDF_ISSUER
app="$issuer/app-callback"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

get() {
  local -a auth=()
  local arg
  for arg in "$@"; do
    case "$arg" in "$OIDF_SUITE"/*) [ -z "${CONFORMANCE_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $CONFORMANCE_TOKEN") ;; esac
  done
  curl -sS --cacert "$LANE_DIR/trust.pem" "${auth[@]}" "$@"
}

# The location a request of the person's browser answers with; empty when
# the answer is no redirect.
redirect() { get -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$1"; }

# FerroSMART's part of the presentation: what it made of this module's.
present() {
  local verifier challenge location
  verifier=$(openssl rand -hex 32)
  challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  # 1. The app sends the browser to FerroSMART, which invokes the wallet with
  #    the request URI (OpenID4VP 1.0 §5.10, §9).
  location=$(redirect "$issuer/authorize?response_type=code&client_id=oidf-verifier-app&redirect_uri=$(jq -rn --arg v "$app" '$v | @uri')&scope=openid&state=$(openssl rand -hex 16)&aud=$(jq -rn --arg v "$issuer/fhir" '$v | @uri')&code_challenge=$challenge&code_challenge_method=S256")
  case "$location" in "$OIDF_SUITE"*) ;; *)
    echo "unexpected: FerroSMART did not invoke the suite's wallet: $location"
    return
    ;;
  esac
  # 2. The suite, as the wallet, fetches the request object, posts its answer
  #    to the response URI and follows the redirect_uri FerroSMART answers
  #    with (§8.2), or stops on a refusal.
  location=$(redirect "$location")
  case "$location" in
    "$issuer"/wallet/complete*) ;;
    *)
      echo refused
      return
      ;;
  esac
  # 3. The browser brings the response code back (§14.2).
  location=$(redirect "$location")
  case "$location" in
    "$issuer"/consent*) echo accepted ;;
    *) echo "unexpected: the way back answered $location" ;;
  esac
}

# The id of the module the suite is running, the one this call serves.
running() { get "$OIDF_SUITE/api/runner/running" | jq -r '.[0] // empty'; }

# The status of the module at the suite.
status() { get "$OIDF_SUITE/api/info/$module" | jq -r '.status // empty'; }

module=$(running)
[ -n "$module" ] || {
  echo "verifier-client: the suite runs no module" >&2
  exit 1
}
outcome=$(present)
printf '%s\t%s\n' "$MODULE_NAME" "$outcome" >> "$LANE_DIR/logins-$OIDF_PLAN.tsv"
echo "verifier-client: $OIDF_PLAN $MODULE_NAME: $outcome"
for _ in $(seq 1 20); do
  case "$(status)" in FINISHED | INTERRUPTED) exit 0 ;; *) sleep 1 ;; esac
done
