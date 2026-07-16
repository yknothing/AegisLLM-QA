# AegisLLM Independent QA

This repository is the independently versioned black-box acceptance suite for [AegisLLM](https://github.com/yknothing/AegisLLM). It consumes a prebuilt Linux `aegis` binary and never imports or reads Aegis source.

## Trust boundary

- The SUT is identified by clean Go VCS build information, exact `--version`, and SHA-256 before and after execution.
- The QA runner is built from a protected full QA commit and embeds that commit.
- Required black-box cases run with the SUT in the same read-only Linux container under Docker `--init --network none --pids-limit 64`; only loopback remains for the hermetic TLS provider and Docker's init process reaps orphaned descendants.
- Test data is per-run synthetic. Reports contain codes, timing, hashes, and provenance—not raw prompts, completions, keys, tokens, headers, captures, or logs.

## Commands

```bash
GOWORK=off GOFLAGS=-mod=readonly go test -race -shuffle=on -count=3 ./...
go vet ./...

CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.qaCommit=$QA_SHA" \
  -o aegis-qa ./cmd/aegis-qa

./aegis-qa run \
  --sut /absolute/path/to/aegis \
  --source-sha "$SOURCE_SHA" \
  --head-sha "$SOURCE_SHA" \
  --qa-sha "$QA_SHA" \
  --artifact-sha256 "$ARTIFACT_SHA256" \
  --workflow-run-id local-diagnostic \
  --evidence /absolute/new/path/report-v1.json \
  --timeout 120s

./aegis-qa verify \
  --sut /absolute/path/to/aegis \
  --evidence /absolute/path/report-v1.json \
  --expect-source-sha "$SOURCE_SHA" \
  --expect-head-sha "$SOURCE_SHA" \
  --expect-qa-sha "$QA_SHA" \
  --expect-artifact-sha256 "$ARTIFACT_SHA256" \
  --expect-workflow-run-id local-diagnostic
```

The `run` command is an acceptance authority only in the documented Linux network-isolated runner. Direct macOS runs are diagnostic because macOS does not honor the per-run `SSL_CERT_FILE` needed by the unchanged Aegis binary.

See [BASELINE.md](BASELINE.md) for required truth surfaces and [GOVERNANCE.md](GOVERNANCE.md) for change control.
