#!/usr/bin/env bash
# Build the Obsideo provider binary with the release version stamped in.
#
# A plain `go build` produces a working binary, but the version string
# stays at its source default and the node then reports an older version
# to the coordinator. Always build through this script (or pass the same
# -X main.Version ldflag yourself) so the coordinator sees the real one.
#
# Usage:
#   ./build.sh                 # -> ./obsideo-provider for the host OS/arch
#   ./build.sh myname          # -> ./myname
#   GOOS=linux GOARCH=amd64 ./build.sh obsideo-provider-linux-amd64
set -euo pipefail

VERSION="provider-v1-6-init"
OUT="${1:-obsideo-provider}"

CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.Version=${VERSION}" \
  -o "${OUT}" .

echo "built ${OUT} (${VERSION})"
"./${OUT}" version
