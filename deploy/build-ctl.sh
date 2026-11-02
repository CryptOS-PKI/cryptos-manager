#!/usr/bin/env bash
# Cross-build cryptos-managerctl for every platform a release ships, with a
# SHA256SUMS file beside the binaries. Static, so they run anywhere.
#
#   deploy/build-ctl.sh dist vX.Y.Z "$(git rev-parse HEAD)"
set -euo pipefail

out="${1:?usage: build-ctl.sh <output dir> [version] [commit]}"
version="${2:-dev}"
commit="${3:-unknown}"
pkg=github.com/CryptOS-PKI/cryptos-manager/internal/ctl

mkdir -p "$out"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="cryptos-managerctl-$os-$arch"
  [ "$os" = windows ] && name="$name.exe"
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit" \
    -o "$out/$name" ./cmd/cryptos-managerctl
done
(cd "$out" && sha256sum cryptos-managerctl-* > SHA256SUMS)
