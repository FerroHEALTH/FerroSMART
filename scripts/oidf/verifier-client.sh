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
# After an acceptance, headless Chrome takes the way back with the
# browser's session, and its screenshot of the page FerroSMART shows fills
# the module's image placeholder. No specification governs the driver: our
# own design.
#
# It reads MODULE_NAME from run-test-plan.py and LANE_DIR, OIDF_PLAN,
# OIDF_SUITE, OIDF_ISSUER and OIDF_CHROMEDRIVER from the lane, and needs
# bash, curl, jq and openssl.
set -euo pipefail

: "${MODULE_NAME:?the test module}" "${LANE_DIR:?the run directory}" "${OIDF_PLAN:?the test plan}"
: "${OIDF_SUITE:?the base URL of the suite}" "${OIDF_ISSUER:?the issuer of FerroSMART}"
: "${OIDF_CHROMEDRIVER:?the chromedriver of headless Chrome}"

issuer=$OIDF_ISSUER
app="$issuer/app-callback"
jar="$(mktemp)"
driver=""
session=""
trap 'finish' EXIT

finish() {
  [ -z "$session" ] || curl -sS -o /dev/null -X DELETE "$webdriver/session/$session" || true
  [ -z "$driver" ] || kill "$driver" 2> /dev/null || true
  rm -f "$jar" "$jar.outcome"
}

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
  # 2. The suite, as the wallet, fetches the request object and posts its answer
  #    to the response URI; the redirect_uri FerroSMART answers with (§8.2) is in
  #    the module's log, and none is there after a refusal.
  redirect "$location" > /dev/null
  location=""
  for _ in $(seq 1 10); do
    location=$(get "$OIDF_SUITE/api/log/$module" | jq -r '[.[] | .redirect_uri? // empty | strings][0] // empty')
    [ -z "$location" ] || break
    sleep 1
  done
  case "$location" in
    "$issuer"/wallet/complete*) ;;
    *)
      echo refused
      return
      ;;
  esac
  # 3. The person's browser brings the response code back (§14.2) and shows
  #    the page FerroSMART answers with.
  browse "$location"
  case "$landed" in
    "$issuer"/consent*) echo accepted ;;
    *) echo "unexpected: the way back answered $landed" ;;
  esac
}

webdriver=http://127.0.0.1:9515

# Calls the WebDriver command PATH of the session with the JSON BODY.
wd() { curl -sS -X POST -H 'Content-Type: application/json' --data-binary "$2" "$webdriver/session/$session/$1"; }

# Opens URL in headless Chrome with the cookies FerroSMART set in the jar,
# and sets `landed` to the location the browser ends at.
browse() {
  local url=$1 host name value path secure
  landed=""
  "$OIDF_CHROMEDRIVER" --port=9515 > "$LANE_DIR/chromedriver-$MODULE_NAME.log" 2>&1 &
  driver=$!
  for _ in $(seq 1 50); do
    curl -sSf -o /dev/null "$webdriver/status" 2> /dev/null && break
    sleep 0.2
  done
  # NOTE: the lane's server certificate is under a CA made for the run, which
  # Chrome's own trust store does not hold.
  session=$(curl -sS -X POST -H 'Content-Type: application/json' "$webdriver/session" --data-binary '{"capabilities":{"alwaysMatch":{"browserName":"chrome","acceptInsecureCerts":true,"goog:chromeOptions":{"args":["--headless=new","--no-sandbox","--disable-gpu","--window-size=1280,960"]}}}}' |
    jq -r '.value.sessionId // empty')
  [ -n "$session" ] || return 1
  wd url "$(jq -n --arg url "$issuer/.well-known/smart-configuration" '{url: $url}')" > /dev/null
  host=$(jq -rn --arg v "$issuer" '$v | sub("^https://"; "") | sub("[:/].*$"; "")')
  while IFS=$'\t' read -r name value path secure; do
    wd cookie "$(jq -n --arg name "$name" --arg value "$value" --arg path "$path" --argjson secure "$secure" \
      '{cookie: {name: $name, value: $value, path: $path, secure: $secure, httpOnly: true}}')" > /dev/null
  done < <(sed 's/^#HttpOnly_//' "$jar" |
    awk -F'\t' -v host="$host" 'NF == 7 && $1 == host { print $6 "\t" $7 "\t" $3 "\t" ($4 == "TRUE" ? "true" : "false") }')
  wd url "$(jq -n --arg url "$url" '{url: $url}')" > /dev/null
  landed=$(curl -sS "$webdriver/session/$session/url" | jq -r '.value // empty')
}

# Uploads the browser's screenshot of FerroSMART's page to the module's image
# placeholder (the suite's ImageAPI, POST /api/log/{id}/images/{placeholder}),
# and keeps a copy beside the lane's logs.
evidence() {
  local placeholder="" shot="$LANE_DIR/evidence-$MODULE_NAME.png" body filled
  for _ in $(seq 1 10); do
    placeholder=$(get "$OIDF_SUITE/api/log/$module" | jq -r '[.[] | .upload? // empty | strings][0] // empty')
    [ -z "$placeholder" ] || break
    sleep 1
  done
  [ -n "$placeholder" ] || {
    echo "verifier-client: $MODULE_NAME has no image placeholder" >&2
    return 1
  }
  body=$(mktemp)
  curl -sS "$webdriver/session/$session/screenshot" | jq -j '"data:image/png;base64," + .value' > "$body"
  sed 's/^data:image\/png;base64,//' "$body" | openssl base64 -d -A > "$shot"
  filled=$(get -X POST -H 'Content-Type: text/plain' --data-binary "@$body" \
    "$OIDF_SUITE/api/log/$module/images/$placeholder" | jq -r '._id? // empty')
  rm -f "$body"
  [ -n "$filled" ] || {
    echo "verifier-client: the suite took no image for $MODULE_NAME" >&2
    return 1
  }
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
present > "$jar.outcome"
outcome=$(cat "$jar.outcome")
printf '%s\t%s\n' "$MODULE_NAME" "$outcome" >> "$LANE_DIR/logins-$OIDF_PLAN.tsv"
echo "verifier-client: $OIDF_PLAN $MODULE_NAME: $outcome"
if [ "$outcome" = accepted ]; then evidence || true; fi
for _ in $(seq 1 20); do
  case "$(status)" in FINISHED | INTERRUPTED) exit 0 ;; *) sleep 1 ;; esac
done
