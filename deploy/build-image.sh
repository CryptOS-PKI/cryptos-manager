#!/usr/bin/env bash
# Build the manager image with its build identity stamped in.
#
# /version and the image's OCI labels can only report what the build was told:
# the Dockerfile copies the checkouts without their .git, so the identity has to
# be resolved here, on the host, and passed in as build args (#89). Use this
# instead of a bare `docker build` for anything you intend to deploy.
#
#   manager/deploy/build-image.sh                        # tags manager:local
#   IMAGE=fleet/manager:local manager/deploy/build-image.sh --pull
#
# The build context is the directory holding the manager and web checkouts side
# by side -- by default the parent of this repo. Override it with CONTEXT.
# Any arguments are passed through to `docker build`.
#
# A checkout without usable git metadata still builds: that field degrades to
# the Dockerfile's placeholder ("dev" / "unknown") rather than failing.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
context="${CONTEXT:-$(cd "$here/../.." && pwd)}"
image="${IMAGE:-manager:local}"

# rev prints the checked-out commit of a repo, suffixed -dirty when the tree
# has uncommitted changes, or the given fallback when git cannot say.
rev() {
  local sha
  sha="$(git -C "$1" rev-parse HEAD 2>/dev/null)" || { echo "$2"; return; }
  if ! git -C "$1" diff --quiet HEAD -- 2>/dev/null; then
    sha="$sha-dirty"
  fi
  echo "$sha"
}

version="$(git -C "$context/manager" describe --tags --always --dirty 2>/dev/null || echo dev)"
commit="$(rev "$context/manager" unknown)"
web_ref="$(rev "$context/web" unknown)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "building $image: version=$version commit=$commit webRef=$web_ref buildDate=$build_date"

exec docker build \
  -f "$context/manager/Dockerfile" \
  --build-arg "VERSION=$version" \
  --build-arg "COMMIT=$commit" \
  --build-arg "BUILD_DATE=$build_date" \
  --build-arg "WEB_REF=$web_ref" \
  -t "$image" \
  "$@" \
  "$context"
