#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# A person's part of FerroSMART's authorization code flow, as a browser
# without script would take it: from the authorization request an app sent
# the browser to, through the upstream provider's login form, FerroSMART's
# patient picker when the app asks for `launch/patient`, and its consent
# page when it shows one, approving every scope offered, to the redirect
# back to the app (SMART App Launch 2.2.0, Obtain authorization code). It
# prints that redirect and, with --follow, also requests it, which is how
# the Inferno lane hands the code to the kit. No specification governs the
# driver: our own design.
#
#   scripts/idp/authorize.sh LOGIN <authorization_url> [--follow]
#
# LOGIN names how the provider's login is answered: `keycloak` posts the
# username and password to the form `kc-form-login` names; `zitadel` takes
# ZITADEL's custom login flow, a session with a password check and the
# callback of the auth request it finishes, with the login client's token
# in ZITADEL_LOGIN_PAT_FILE at ZITADEL_API. The person is
# read from LAUNCH_USER and LAUNCH_PASSWORD. FerroSMART's issuer is the
# authorization URL up to `/authorize`. It needs bash, curl, grep and sed;
# CURL_CA_BUNDLE names a private root.
set -euo pipefail

[ "$#" -ge 2 ] || {
  echo "usage: scripts/idp/authorize.sh LOGIN <authorization_url> [--follow]" >&2
  exit 2
}
login=$1 url=$2 follow=${3:-}
: "${LAUNCH_USER:?the person to log in as}" "${LAUNCH_PASSWORD:?their password}"
issuer=${url%%/authorize*}

jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

fail() {
  echo "authorize: $*" >&2
  exit 1
}

# The location a request answers with, refusing anything but a redirect.
redirect() {
  local location
  location=$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$@")
  [ -n "$location" ] || fail "expected a redirect from $*"
  printf '%s\n' "$location"
}

# The value of the attribute `$3` in the first tag of `$1` that `$2` matches,
# with the HTML entities of a URL decoded.
attribute() {
  grep -oE "$2" <<< "$1" | head -1 | grep -oE "$3=\"[^\"]*\"" | head -1 |
    sed -E "s/^$3=\"//; s/\"$//; s/&amp;/\\&/g; s/&#x2F;/\\//g; s/&#47;/\\//g; s/&#61;/=/g"
}

# 1. FerroSMART sends the browser to the provider, whose login form the
#    person fills.
location=$(redirect "$url")
case "$login" in
  keycloak)
    page=$(curl -sS -c "$jar" -b "$jar" "$location")
    action=$(attribute "$page" '<form[^>]*id="kc-form-login"[^>]*>' action)
    [ -n "$action" ] || fail "the provider's page has no login form"
    location=$(redirect --data-urlencode "username=$LAUNCH_USER" --data-urlencode "password=$LAUNCH_PASSWORD" "$action")
    ;;
  zitadel)
    # NOTE: ZITADEL's login-ui/oidc-standard.mdx, the custom login flow: a session
    # with a password check, then the callback of the auth request it finishes.
    : "${ZITADEL_API:?the API base of ZITADEL}" "${ZITADEL_LOGIN_PAT_FILE:?the token of the login client}"
    location=$(redirect "$location")
    request=$(sed -nE 's/.*[?&]authRequest=([^&]+).*/\1/p' <<< "$location")
    [ -n "$request" ] || fail "ZITADEL named no auth request: $location"
    zitadel() {
      curl -fsS -X POST -H "Authorization: Bearer $(cat "$ZITADEL_LOGIN_PAT_FILE")" \
        -H 'Content-Type: application/json' "$ZITADEL_API/$1" -d "$2"
    }
    session=$(zitadel zitadel.session.v2.SessionService/CreateSession \
      "{\"checks\":{\"user\":{\"loginName\":\"$LAUNCH_USER\"},\"password\":{\"password\":\"$LAUNCH_PASSWORD\"}}}")
    session_id=$(sed -nE 's/.*"sessionId" *: *"([^"]+)".*/\1/p' <<< "$session")
    session_token=$(sed -nE 's/.*"sessionToken" *: *"([^"]+)".*/\1/p' <<< "$session")
    callback=$(zitadel zitadel.oidc.v2.OIDCService/CreateCallback \
      "{\"authRequestId\":\"$request\",\"session\":{\"sessionId\":\"$session_id\",\"sessionToken\":\"$session_token\"}}")
    location=$(sed -nE 's/.*"callbackUrl" *: *"([^"]+)".*/\1/p' <<< "$callback" | sed 's/\\u0026/\&/g')
    ;;
  *) fail "unknown login '$login'" ;;
esac

# 2. The provider sends it back to FerroSMART's callback. For `launch/patient`
#    FerroSMART shows its patient picker first: the person searches by
#    LAUNCH_PATIENT_NAME and picks the first patient found.
case "$location" in "$issuer"/callback*) ;; *) fail "the login did not return to FerroSMART: $location" ;; esac
location=$(redirect "$location")
if [[ "$location" == "$issuer"/picker* ]]; then
  : "${LAUNCH_PATIENT_NAME:?the name the person searches a patient by}"
  page=$(curl -sS -c "$jar" -b "$jar" -G "$issuer/picker" --data-urlencode "name=$LAUNCH_PATIENT_NAME")
  form_token=$(attribute "$page" '<input[^>]*name="form_token"[^>]*>' value)
  patient=$(attribute "$page" '<input[^>]*name="patient"[^>]*>' value)
  [ -n "$form_token" ] && [ -n "$patient" ] || fail "the picker found no patient named $LAUNCH_PATIENT_NAME"
  location=$(redirect --data-urlencode "form_token=$form_token" --data-urlencode "patient=$patient" "$issuer/picker")
fi

# 3. FerroSMART shows the consent page, unless the client's registration
#    answers for the person (a professional at an administrator-registered
#    app) and the code goes to the app at once; on the page the person
#    approves every scope offered.
case "$location" in
  "$issuer"/consent*)
    page=$(curl -sS -c "$jar" -b "$jar" "$location")
    form_token=$(attribute "$page" '<input[^>]*name="form_token"[^>]*>' value)
    [ -n "$form_token" ] || fail "the consent page has no form token"
    approve=(--data-urlencode "form_token=$form_token" --data-urlencode "decision=approve")
    while IFS= read -r offered; do
      approve+=(--data-urlencode "scope=$offered")
    done < <(grep -oE '<input[^>]*name="scope"[^>]*>' <<< "$page" | grep -oE 'value="[^"]*"' | sed -E 's/^value="//; s/"$//')
    location=$(redirect "${approve[@]}" "$issuer/consent")
    ;;
  "$issuer"*) fail "FerroSMART answered neither the consent page nor the app: $location" ;;
esac
printf '%s\n' "$location"

# 4. The browser follows the redirect to the app.
if [ "$follow" = --follow ]; then
  curl -fsS -o /dev/null "$location" || fail "the app did not take its redirect: $location"
fi
