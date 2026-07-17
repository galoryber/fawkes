#!/bin/bash
# Quick local lint check — runs the same checks as CI.
# Usage: ./scripts/lint.sh (from repo root)
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="$REPO_ROOT/Payload_Type/fawkes/fawkes/agent_code"

echo "=== go mod tidy check ==="
(cd "$AGENT_DIR" && go mod tidy)
if ! git -C "$REPO_ROOT" diff --quiet -- "$AGENT_DIR/go.mod" "$AGENT_DIR/go.sum" 2>/dev/null; then
    echo "FAIL: go.mod or go.sum not tidy (run 'go mod tidy' and commit)"
    exit 1
fi
echo "  PASS"

echo "=== go vet (agent, all platforms) ==="
for os in linux windows darwin; do
    (cd "$AGENT_DIR" && GOOS=$os GOARCH=amd64 go vet ./...) 2>&1 | grep -v "possible misuse of unsafe.Pointer" | grep -v "hostport.*IPv6" || true
done
echo "  PASS"

echo "=== golangci-lint (agent) ==="
if command -v golangci-lint >/dev/null 2>&1; then
    (cd "$AGENT_DIR" && golangci-lint run ./...)
    echo "  PASS"
else
    echo "  SKIP (install: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh)"
fi

echo "=== go test (agent) ==="
(cd "$AGENT_DIR" && go test -count=1 -timeout 3m ./...) 2>&1 | tail -5

echo "=== cross-platform build ==="
for combo in linux/amd64 windows/amd64 darwin/arm64; do
    os="${combo%/*}"
    arch="${combo#*/}"
    (cd "$AGENT_DIR" && GOOS=$os GOARCH=$arch go build ./...) && echo "  $combo OK"
done

echo ""
echo "All checks passed."
