#!/usr/bin/env bash
# Clean-directory verification: build, vet and run the full test suite once.
# The module depends on the Go standard library only, so GOPROXY=off proves
# there is no dependency download step.
set -euo pipefail
cd "$(dirname "$0")"

echo "== go version =="
go version

echo "== go build ./... =="
GOPROXY=off go build ./...

echo "== go vet ./... =="
GOPROXY=off go vet ./...

echo "== go test ./... -count=1 =="
GOPROXY=off go test ./... -count=1

echo "ALL CHECKS PASSED"
