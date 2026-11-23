<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Quickstart

The quickstart is one file, `compose.yaml`, which runs the FerroSMART image
beside PostgreSQL. It needs Docker with Compose and no checkout of the
repository. It pulls `ghcr.io/ferrohealth/ferrosmart` at the release the
file shipped with, v{{version:ferrosmart}} ([the image](image.md)).

## Run it

Download `compose.yaml` from the repository or from a release, and create
the three secret files beside it. FerroSMART runs as uid 65532, so the two
files it reads must be readable by that user:

```sh
mkdir -p secrets
openssl rand -hex 24 > secrets/postgres_password
printf 'postgresql://ferrosmart:%s@postgres:5432/ferrosmart?sslmode=disable' \
  "$(cat secrets/postgres_password)" > secrets/database_url
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/signing_key.pem
chmod 0644 secrets/database_url secrets/signing_key.pem
docker compose up
```

FerroSMART migrates its database at start. Read its SMART configuration:

```sh
curl http://localhost:8080/.well-known/smart-configuration
```

With no identity provider configured, this is the Backend Services document:
FerroSMART issues tokens to registered systems and nobody logs in.

## What the file sets

The environment of the `ferrosmart` service sets the issuer, the signing
key, the database URL and one FHIR server. Two variables change the
defaults, in your shell or a `.env` file beside `compose.yaml`:

| Variable | Default | What it is |
|---|---|---|
| `FERROSMART_ISSUER` | `http://localhost:8080` | The URL clients and resource servers reach FerroSMART by: `https`, or `http` on a loopback host |
| `FERROSMART_RESOURCE` | `http://localhost:8090/fhir` | The base URL of the FHIR server the tokens are for, their `aud` |

Everything else goes in a configuration file in the `config` directory,
which `FERROSMART_CONFIG` names (`FERROSMART_CONFIG=/etc/ferrosmart/ferrosmart.toml`).
The environment wins over the file. `docker compose run --rm ferrosmart
config check` prints the configuration as FerroSMART reads it, every secret
masked. [Configuration](../configure/configuration.md) lists every key.

## Add the clients

Clients live in FerroSMART's database. Write each as a JSON client document
in the `config` directory and apply it; the first is the administrator, a
Backend Services client whose `system/admin` scope reaches the
[admin API](../configure/admin-api.md):

```sh
cat > config/admin.json <<'JSON'
{
  "client_id": "admin",
  "name": "Administrator",
  "kind": "confidential_asymmetric",
  "jwks_uri": "https://admin.example.org/jwks.json",
  "scopes": ["system/admin"],
  "grant_types": ["client_credentials"]
}
JSON
docker compose run --rm ferrosmart client apply /etc/ferrosmart/admin.json
```

`client apply` creates the client or replaces the one with its
`client_id`. [Clients, roles and consent](../configure/clients.md) describes
the document.

## Add a login

To have people log in, run an identity provider upstream. The repository
carries two overlays of this file that do it on your machine:

```sh
docker compose -f compose.yaml -f compose.keycloak.yaml up
docker compose -f compose.yaml -f compose.zitadel.yaml up
```

Each needs a few more secret files, listed at the top of the overlay, and a
checkout of the repository for its realm file or bootstrap script.
[Identity providers](upstream.md) describes both, and Entra ID and Okta.

## The hardening the file applies

- **The port binds loopback.** A published port on `0.0.0.0` is reachable
  from the network even when the host firewall says otherwise, so the file
  binds `127.0.0.1`. To serve other machines, put a reverse proxy that
  terminates TLS in front and set `FERROSMART_ISSUER` to its `https` URL.
- **A read-only root.** Every piece of state is in PostgreSQL and every
  secret is read once at start, so the container's filesystem is read-only.
- **No capabilities.** FerroSMART drops every Linux capability and cannot
  gain new privileges. PostgreSQL keeps the five its entrypoint needs to
  hand its data directory to the `postgres` user, and publishes no port.
- **Secrets as files.** The database password, the database URL and the
  signing key are Compose secrets, never environment values.

## The whole file

```yaml
{{#include ../../../../compose.yaml}}
```
