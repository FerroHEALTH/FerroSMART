#!/bin/sh
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# Bootstraps ZITADEL v4.20.3 as FerroSMART's upstream login (#523), through
# ZITADEL's v2 APIs with the IAM_OWNER token its first instance wrote
# (`cmd/setup/steps.yaml`, FirstInstance). Every id it can choose is fixed:
#
#   project      ferrosmart, with role assertion on, and its role `clinician`
#                (project/v2 CreateProject, AddProjectRole)
#   application  ferrosmart-login: an OIDC web app, the code flow with PKCE,
#                Private Key JWT, the redirect URI FERROSMART_ISSUER/callback,
#                roles and userinfo asserted into the ID Token
#                (application/v2 CreateApplication, OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT),
#                and its key (CreateApplicationKey)
#   user         clinician, with the role and the metadata `fhir_user`
#                (user/v2 AddHumanUser, SetUserMetadata;
#                authorization/v2 CreateAuthorization)
#   target       fhir-user, a REST call to TARGET_URL, run for the
#                `preuserinfo` function (action/v2 CreateTarget, SetExecution)
#
# ZITADEL generates the OIDC client id, the application's private key and
# the target's signing key, so the script writes them to OUT with the
# FerroSMART configuration that names them: `upstream-assertion.pem`,
# `target-signing-key` and `ferrosmart.toml`. FerroSMART signs its client
# assertion with that key under the `kid` ZITADEL gave it (OpenID Connect
# Core 1.0 §9, private_key_jwt). A second run finds `ferrosmart.toml` and does nothing.
# It needs sh, curl, sed and base64, so it runs in the curl image and on a CI host.
#
#   app/ferrosmart/examples/zitadel/bootstrap.sh
#
# Environment: ZITADEL_API (the API base), ADMIN_PAT_FILE, USER_PASSWORD_FILE,
# FERROSMART_ISSUER, FHIR_USER, TARGET_URL, OUT. No specification governs
# the script: our own design.
set -eu

: "${ZITADEL_API:?}" "${ADMIN_PAT_FILE:?}" "${USER_PASSWORD_FILE:?}" "${FERROSMART_ISSUER:?}"
: "${FHIR_USER:?}" "${TARGET_URL:?}" "${OUT:?}"

if [ -f "$OUT/ferrosmart.toml" ]; then
  echo "bootstrap: $OUT/ferrosmart.toml exists; ZITADEL is bootstrapped"
  exit 0
fi

fail() {
  echo "bootstrap: $*" >&2
  exit 1
}

# The string member `$2` of the JSON object `$1`, which holds no escape.
member() {
  printf '%s' "$1" | sed -n "s/.*\"$2\" *: *\"\\([^\"]*\\)\".*/\\1/p"
}

# Calls the v2 API method `$1` with the JSON body `$2` (Connect, unary JSON).
call() {
  answer=$(curl -sS -X POST -H "Authorization: Bearer $(cat "$ADMIN_PAT_FILE")" \
    -H 'Content-Type: application/json' -w '\n%{http_code}' "$ZITADEL_API/$1" -d "$2")
  status=$(printf '%s' "$answer" | tail -n 1)
  body=$(printf '%s' "$answer" | sed '$d')
  [ "$status" = 200 ] || fail "$1 answered $status: $body"
  printf '%s' "$body"
}

i=0
until curl -fsS -o /dev/null "$ZITADEL_API/debug/ready"; do
  i=$((i + 1))
  [ "$i" -lt 90 ] || fail "ZITADEL is not ready at $ZITADEL_API"
  sleep 2
done
i=0
until [ -s "$ADMIN_PAT_FILE" ]; do
  i=$((i + 1))
  [ "$i" -lt 90 ] || fail "no admin token at $ADMIN_PAT_FILE"
  sleep 2
done

org=$(member "$(call zitadel.org.v2.OrganizationService/ListOrganizations '{}')" id)
[ -n "$org" ] || fail "no organization"

call zitadel.project.v2.ProjectService/CreateProject \
  "{\"organizationId\":\"$org\",\"projectId\":\"ferrosmart\",\"name\":\"FerroSMART\",\"projectRoleAssertion\":true}" > /dev/null
call zitadel.project.v2.ProjectService/AddProjectRole \
  '{"projectId":"ferrosmart","roleKey":"clinician","displayName":"Clinician"}' > /dev/null

app=$(call zitadel.application.v2.ApplicationService/CreateApplication "{
  \"projectId\":\"ferrosmart\",\"applicationId\":\"ferrosmart-login\",\"name\":\"FerroSMART\",
  \"oidcConfiguration\":{
    \"redirectUris\":[\"$FERROSMART_ISSUER/callback\"],
    \"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],
    \"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\"],
    \"applicationType\":\"OIDC_APP_TYPE_WEB\",
    \"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT\",
    \"developmentMode\":true,
    \"idTokenRoleAssertion\":true,
    \"idTokenUserinfoAssertion\":true}}")
client_id=$(member "$app" clientId)
[ -n "$client_id" ] || fail "the application has no client id"
# NOTE: application/v2 CreateApplicationKeyResponse.key_details, base64 JSON with `keyId` and the PEM `key`.
key=$(call zitadel.application.v2.ApplicationService/CreateApplicationKey \
  '{"projectId":"ferrosmart","applicationId":"ferrosmart-login","expirationDate":"2099-01-01T00:00:00Z"}')
details=$(printf '%s' "$(member "$key" keyDetails)" | base64 -d)
key_id=$(member "$details" keyId)
pem=$(member "$details" key | sed 's/\\n/\n/g')
[ -n "$key_id" ] && [ -n "$pem" ] || fail "the application key has no id or private key"

password=$(cat "$USER_PASSWORD_FILE")
call zitadel.user.v2.UserService/AddHumanUser "{
  \"userId\":\"clinician\",\"username\":\"clinician\",\"organization\":{\"orgId\":\"$org\"},
  \"profile\":{\"givenName\":\"Example\",\"familyName\":\"Clinician\"},
  \"email\":{\"email\":\"clinician@example.org\",\"isVerified\":true},
  \"password\":{\"password\":\"$password\",\"changeRequired\":false}}" > /dev/null
call zitadel.authorization.v2.AuthorizationService/CreateAuthorization \
  "{\"userId\":\"clinician\",\"projectId\":\"ferrosmart\",\"organizationId\":\"$org\",\"roleKeys\":[\"clinician\"]}" > /dev/null
encoded=$(printf '%s' "$FHIR_USER" | base64 | tr -d '\n')
call zitadel.user.v2.UserService/SetUserMetadata \
  "{\"userId\":\"clinician\",\"metadata\":[{\"key\":\"fhir_user\",\"value\":\"$encoded\"}]}" > /dev/null

target=$(call zitadel.action.v2.ActionService/CreateTarget \
  "{\"name\":\"fhir-user\",\"restCall\":{\"interruptOnError\":true},\"timeout\":\"5s\",\"endpoint\":\"$TARGET_URL\",\"payloadType\":\"PAYLOAD_TYPE_JSON\"}")
target_id=$(member "$target" id)
signing_key=$(member "$target" signingKey)
[ -n "$target_id" ] && [ -n "$signing_key" ] || fail "the target has no id or signing key"
call zitadel.action.v2.ActionService/SetExecution \
  "{\"condition\":{\"function\":{\"name\":\"preuserinfo\"}},\"targets\":[\"$target_id\"]}" > /dev/null

mkdir -p "$OUT"
printf '%s\n' "$pem" > "$OUT/upstream-assertion.pem"
printf '%s' "$signing_key" > "$OUT/target-signing-key"
cat > "$OUT/ferrosmart.toml" << TOML
# Written by app/ferrosmart/examples/zitadel/bootstrap.sh: FerroSMART with
# ZITADEL as its upstream login (#523, docs/architecture.md §13.20).

[ferrosmart]
issuer = "$FERROSMART_ISSUER"
# A workforce login with no eIDAS level of assurance; an EU deployment keeps the
# substantial floor and maps its provider's values under
# [ferrosmart.upstream.assurance] (docs/architecture.md §13.28).
assurance_minimum = "none"

[[ferrosmart.resource]]
base = "http://localhost:8090/fhir"
kind = "fhir"

# The \`zitadel\` preset brings the scopes, the \`fhirUser\` claim the Actions
# v2 target writes from the user's \`fhir_user\` metadata, and RS256; the
# keys below win over it.
[[ferrosmart.upstream]]
name = "zitadel"
preset = "zitadel"

[ferrosmart.upstream.oidc]
issuer = "$ZITADEL_API"
client_id = "$client_id"
# The roles of the project \`ferrosmart\`, which ZITADEL names beside the
# client in every ID Token's aud.
role_claims = ["urn:zitadel:iam:org:project:ferrosmart:roles"]
trusted_audiences = ["ferrosmart"]

# The application's key, which ZITADEL knows by its key id.
[ferrosmart.upstream.oidc.private_key_jwt.keys]
private_key_file = "$OUT/upstream-assertion.pem"
kid = "$key_id"

[[ferrosmart.role]]
name = "clinician"
scopes = ["user/Patient.rs", "user/Observation.rs"]

[[ferrosmart.client]]
client_id = "example-app"
name = "Example SMART app"
kind = "public"
redirect_uris = ["http://localhost:9000/callback"]
scopes = ["openid", "fhirUser", "user/Patient.rs", "user/Observation.rs"]
resources = ["http://localhost:8090/fhir"]
grant_types = ["authorization_code"]
TOML
# NOTE: FerroSMART and the target run as other users, so they read the two files.
chmod 0644 "$OUT/upstream-assertion.pem" "$OUT/target-signing-key"
echo "bootstrap: ZITADEL is bootstrapped; the client id is $client_id"
