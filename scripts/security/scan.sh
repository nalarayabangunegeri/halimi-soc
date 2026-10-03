#!/usr/bin/env bash
# Run the security checks that CI runs, locally.
#
# A failing scan is reported as a failure. Findings are never suppressed to make
# the script exit zero.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "==> gofmt"
out=$(gofmt -l .)
if [[ -n "$out" ]]; then
  echo "not gofmt-clean:" >&2
  echo "$out" >&2
  exit 1
fi

echo "==> go vet"
go vet ./...

echo "==> govulncheck"
if command -v govulncheck >/dev/null 2>&1; then
  govulncheck ./...
else
  echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
  exit 1
fi

echo "==> gitleaks"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --no-git --redact -v
else
  echo "gitleaks not installed: https://github.com/gitleaks/gitleaks" >&2
  exit 1
fi

echo "==> all checks passed"
