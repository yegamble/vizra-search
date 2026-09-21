# vizra-search runtime image.
#
# ADR-009 / Q-027: Ubuntu 24.04 on native amd64 is the only qualified
# acceptance target and runtime images are published linux/amd64 only. A
# developer on Apple Silicon may build this natively for arm64 for local use;
# that build carries no support claim and no arm64 entry is added to a
# multi-arch manifest until a native arm64 runner exists.
#
# This service decodes no pixels and links no C library, so it needs neither
# libvips nor a glibc base: CGO is off and the runtime stage is `scratch` plus
# CA certificates. That is the smallest attack surface available for a process
# that terminates HMAC-authenticated HTTP on a private network.

# Digest-pinned build stage (ADR-001: pin the build, not only the version).
# This is the OCI image index for docker.io/library/golang:1.27.1-bookworm,
# resolved from the registry on 2026-09-20; the index covers linux/amd64 and
# linux/arm64 (among others), so the same digest builds natively on the amd64
# CI runner and on an Apple-Silicon developer machine.
FROM golang@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

ARG VERSION=unknown
ARG COMMIT=unknown
ARG BUILD_TIME=1970-01-01T00:00:00Z

WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# -trimpath and the pinned ldflags keep two builds of one commit identical
# apart from the build time, which is supplied as a build argument.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w \
        -X github.com/yegamble/vizra-search/internal/buildinfo.Version=${VERSION} \
        -X github.com/yegamble/vizra-search/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/yegamble/vizra-search/internal/buildinfo.BuildTime=${BUILD_TIME}" \
      -o /out/vizra-search ./cmd/vizra-search

# `scratch` is Docker's reserved empty base. It is not a pullable image, has no
# manifest and therefore no digest to pin; it contributes no bytes to the final
# image. Every FROM that does resolve to a real image in this file is pinned by
# @sha256 digest above. scripts/ci-required-guard.sh enforces that rule.
FROM scratch

ARG VERSION=unknown
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="vizra-search" \
      org.opencontainers.image.description="Vizra internal search service" \
      org.opencontainers.image.source="https://github.com/yegamble/vizra-search" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/vizra-search /usr/local/bin/vizra-search

# The canonical contract this build implements, so an operator can read the
# served surface out of the image (ADR-002 § Contracts).
COPY api/search-internal.openapi.yaml /usr/share/vizra-search/search-internal.openapi.yaml
COPY api/CONTRACT-SOURCE.json /usr/share/vizra-search/CONTRACT-SOURCE.json

# Never root. 65532 is the conventional "nonroot" uid; scratch has no
# /etc/passwd, so the numeric form is the only correct one.
USER 65532:65532

EXPOSE 8081

# No port is published by the base compose file (ADR-002 / Q-017); this is the
# in-network listen address only.
#
# VIZRA_MODE is the platform-wide runtime mode, the same name vizra-core reads.
# VIZRA_SEARCH_MODE is core's search TOPOLOGY and is never a mode here.
ENV VIZRA_SEARCH_ADDR=:8081 \
    VIZRA_MODE=production

# The runtime stage is `scratch`, so there is no shell and no curl for a
# healthcheck. The binary probes itself instead.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/vizra-search", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/vizra-search"]
