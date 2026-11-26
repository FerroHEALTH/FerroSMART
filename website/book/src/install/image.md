<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Run the image

**For:** operators who deploy the container image.

FerroSMART ships as `ghcr.io/ferrohealth/ferrosmart`, for `linux/amd64` and
`linux/arm64`, from v0.1.0 on. The image is one static
binary on `gcr.io/distroless/static-debian13:nonroot`: no shell, no package
manager, and the user 65532.

| Property | Value |
|---|---|
| Entrypoint | `/usr/local/bin/ferrosmart` |
| Default command | `serve` |
| Listener | `0.0.0.0:8080` (`FERROSMART__SERVER__LISTEN`), plain HTTP |
| User | `65532:65532` |
| Health check | `ferrosmart healthcheck` every 30 seconds, 60 seconds to start |

The listener speaks plain HTTP for a reverse proxy that terminates TLS, or
TLS itself with `[server.tls]`. The issuer is always the `https` URL people
and servers reach FerroSMART by.

## Releases and tags

The release lane tags each image after it is scanned: `<version>`, and for a
release that is no pre-release `<major>.<minor>` and `latest`. Pin the
version or, better, the digest the release notes name. Beside the image,
each release attaches a tarball per target (`x86_64` and `aarch64`, each
for GNU and musl libc), with its checksum, a CycloneDX source SBOM and an
SPDX build SBOM, and `compose.yaml`.

## Verify before you run

Every artefact carries SLSA provenance signed through Sigstore by the lane
that built it. Check the image and a tarball with the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/ferrohealth/ferrosmart:X.Y.Z \
  --repo FerroHEALTH/FerroSMART \
  --signer-workflow FerroHEALTH/FerroSMART/.github/workflows/release-ferrosmart-image.yml
gh attestation verify ferrosmart-X.Y.Z-x86_64-unknown-linux-musl.tar.gz \
  --repo FerroHEALTH/FerroSMART \
  --signer-workflow FerroHEALTH/FerroSMART/.github/workflows/release-ferrosmart-build.yml
```

## Build it from a checkout

To run a change of your own, build the static
binary and stage it where `docker/ferrosmart/Dockerfile` copies it from,
`dist/<os>_<arch>/ferrosmart`. On an x86_64 Linux host with `musl-tools`:

```sh
cargo build --locked --release -p ferrosmart --target x86_64-unknown-linux-musl
mkdir -p dist/linux_amd64
install -m 0755 target/x86_64-unknown-linux-musl/release/ferrosmart dist/linux_amd64/ferrosmart
docker build -f docker/ferrosmart/Dockerfile -t ghcr.io/ferrohealth/ferrosmart:{{version:ferrosmart}} .
```

The Dockerfile compiles nothing, and the tag lets `compose.yaml` use the
image you built. CI builds and runs the image the same way, with the
Keycloak overlay, on every change that reaches it.
