# syntax=docker/dockerfile:1.7

# Build context is the workspace ROOT holding sibling checkouts of manager/ and
# web/ (the release workflow arranges this). A bare `docker build .` from inside
# the manager repo will not resolve the manager/ and web/ COPY paths.

# Stage 1: build the web bundle. The build context holds sibling checkouts of
# the manager and web repos; the resulting dist is embedded by the Go stage.
FROM node:22-bookworm-slim AS web
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
FROM golang:1.26-bookworm AS build
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

# Stage 3: minimal runtime.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/manager /manager
USER nonroot:nonroot
ENTRYPOINT ["/manager"]
CMD ["-config", "/etc/cryptos/fleet/config.yaml"]
