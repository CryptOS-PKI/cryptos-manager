# syntax=docker/dockerfile:1.7

# Build context is the workspace ROOT holding sibling checkouts of manager/ and
# web/ (the release workflow arranges this). A bare `docker build .` from inside
# the manager repo will not resolve the manager/ and web/ COPY paths.
#
# Build with deploy/build-image.sh rather than a bare `docker build`: it passes
# the VERSION, COMMIT, BUILD_DATE and WEB_REF args below, without which the
# image reports placeholders at /version and in its labels.
#
# Every base image is pinned by digest as well as tag, so a rebuild of the same
# commit starts from the same bytes. The tag is kept for the reader; the digest
# is what is pulled. Bump both together.

# Stage 1: build the web bundle. The build context holds sibling checkouts of
# the manager and web repos; the resulting dist is embedded by the Go stage.
FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
ENV VITE_FLEET_MODE=live-auth
# The SPA is served by the manager itself, so the API is same-origin. Without
# this the fallback in web/src/lib/fleet/client.ts bakes http://localhost:8080
# into the bundle and the shipped UI calls the operator's own machine.
ARG VITE_FLEET_API=/
ENV VITE_FLEET_API=${VITE_FLEET_API}
RUN npm run build

# Stage 2: build the manager with the web bundle embedded.
FROM golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /src
COPY manager/go.mod manager/go.sum ./
RUN go mod download
COPY manager/ ./
COPY --from=web /web/dist ./internal/webui/dist
# Build identity, stamped at link time (#81). A running manager has to be able
# to say which build it is: the image copies the repo without a usable .git, so
# nothing can derive this at runtime. Defaults keep a bare `docker build`
# working and honest -- it reports "dev", not a version it does not have.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG WEB_REF=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE} \
        -X main.webRef=${WEB_REF}" \
      -o /out/manager ./cmd/manager
# The runtime image has no shell to mkdir with, so the one directory the
# manager writes to is made here and copied across with its owner.
RUN mkdir -p /out/state/node-creds

# Stage 3: minimal runtime. Runs as nonroot (uid 65532) and is built to run
# with a read-only root filesystem: the only path it writes is the node
# credential directory below, which a deployment mounts as a volume.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# The same identity as /version, on the image itself, so `docker inspect` can
# answer "which build is this" without starting it (#89). ARGs do not cross
# stages, so they are declared again here with the same defaults.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG WEB_REF=unknown
LABEL org.opencontainers.image.title="CryptOS Fleet Manager" \
      org.opencontainers.image.source="https://github.com/CryptOS-PKI/cryptos-manager" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      io.github.cryptos-pki.web.revision="${WEB_REF}"
COPY --from=build /out/manager /manager
# Where adoption writes each managed node's admin key (MANAGER_NODE_CREDS_DIR).
# Owned by nonroot so an empty named volume mounted here inherits a directory
# the manager can write; without a volume the keys die with the container.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/cryptos-manager
USER 65532:65532
EXPOSE 8443 8080
# The binary probes its own /healthz: distroless has no shell or curl. The
# config path must match CMD, since the probe reads the listen address from it.
# The start period covers the manager's own wait for Postgres at startup.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["/manager", "-healthcheck", "-config", "/etc/cryptos/fleet/config.yaml"]
ENTRYPOINT ["/manager"]
CMD ["-config", "/etc/cryptos/fleet/config.yaml"]
