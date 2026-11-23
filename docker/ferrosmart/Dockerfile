# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# The FerroSMART image: one static binary on distroless static, per platform.
# Nothing is compiled here. The release lane builds and attests the musl
# binaries and stages them under dist/<os>_<arch>/ferrosmart before this file
# is built for linux/amd64 and linux/arm64 (docs/release.md). .dockerignore
# holds the build context to that one directory.
#
# Build from a staged dist/ tree, at the repository root:
#   docker buildx build -f docker/ferrosmart/Dockerfile --platform linux/arm64 .

# distroless static: ca-certificates, tzdata, an /etc/passwd carrying the
# nonroot user (uid 65532), a /tmp, no shell and no package manager. Pinned by
# the digest of its image index, which is what Docker resolves for a
# multi-platform build; Dependabot (the docker ecosystem over
# /docker/ferrosmart) proposes the bumps.
# https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

# The platform of the manifest being built, set by buildx per platform.
# https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope
ARG TARGETOS
ARG TARGETARCH

# Root-owned, executable, and not writable by the runtime user.
COPY --chmod=0555 dist/${TARGETOS}_${TARGETARCH}/ferrosmart /usr/local/bin/ferrosmart

# The binary's own default is loopback, which no container can publish, so the
# image default is every interface on the documented port. The configuration
# key is `[server] listen`; every override is FERROSMART__<SECTION>__<KEY>.
ENV FERROSMART__SERVER__LISTEN=0.0.0.0:8080
EXPOSE 8080/tcp

# Numeric on purpose: the kubelet cannot resolve a user name against an image
# it does not read, so `runAsNonRoot: true` refuses a named USER.
USER 65532:65532

# The base has no shell and no HTTP client, so the binary probes itself:
# `ferrosmart healthcheck` reads the same configuration as `serve`, asks the
# running server for /health/readiness on loopback and exits 0 only on 200.
# The start period covers a boot that waits for its database and migrates it.
# Kubernetes ignores the instruction and keeps its own probes.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/ferrosmart", "healthcheck"]

# Exec form: the binary is PID 1 and receives SIGTERM itself, which it drains
# on. CMD is the default job, so `config check` replaces it alone.
ENTRYPOINT ["/usr/local/bin/ferrosmart"]
CMD ["serve"]

# Build-independent labels only. The release lane sets the version, revision
# and created labels at build time and mirrors every label as an index
# annotation, which is what GHCR reads for the package page.
LABEL org.opencontainers.image.title="FerroSMART" \
      org.opencontainers.image.description="The SMART App Launch 2.x authorization server of the FerroHEALTH products, with any OpenID Connect provider upstream for login" \
      org.opencontainers.image.source="https://github.com/FerroHEALTH/FerroSMART" \
      org.opencontainers.image.vendor="Cadasto B.V." \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot"
