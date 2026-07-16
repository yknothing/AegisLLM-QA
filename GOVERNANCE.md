# Governance

## Ownership

QA tests, oracles, workflows, evidence schema, baseline, and this policy are changed only through this repository. A source-code PR may not change them. Source integration pins one protected QA `main` commit and proves ancestry.

`@yknothing` is the bootstrap administrator. This does not satisfy independent-human review by itself. Before claiming that governance is complete, grant a real independent QA engineer or QA team the intended repository role, add that identity to CODEOWNERS, and verify a protected review. Until then, the ACL criterion remains an explicit gap.

## Required protection

`main` requires a pull request, one independent approval, code-owner review, stale approval dismissal, approval of the latest push, conversation resolution, and passing QA framework CI. Force-push, deletion, and routine bypass actors are forbidden.

Because authors cannot approve their own PR, enabling this rule before a real QA reviewer is assigned intentionally freezes future baseline changes rather than creating an owner-only self-approval exception.

## Change protocol

1. Change and review the QA baseline here.
2. Merge it under the QA ruleset.
3. Open a separate AegisLLM PR that changes only `qa-baseline.lock`.
4. Require source CI to prove the pinned commit is an ancestor of this protected `main`.

Changing a required case ID, result semantics, evidence field, workflow job name, runner image, or lock schema is a governance change. A source feature and its oracle may not be merged atomically.

## Waivers and evidence

P0 cases cannot be skipped, quarantined, or waived. A P1/P2 quarantine requires an issue, owner, reason, non-release lane, and expiry within seven days. `not_run` never means pass.

Evidence is bound to tested/head/base source provenance, QA commit, SUT pre/post digest, clean Go build info, Linux environment, and workflow run. The required container uses Docker's init process, a PID limit, no external network, a read-only root, and a bounded tmpfs. CI retains sanitized JSON for at least 30 days. Raw gateway logs, temporary workspaces, captures, credentials, prompts, completions, and core dumps are not artifacts.

Vulnerability database unavailability is recorded as unavailable with snapshot/hash details for an approved local fallback; it is never reported as no vulnerabilities.
