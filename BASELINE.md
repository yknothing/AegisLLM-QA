# Required Baseline

Every listed case is required. `fail`, `not_run`, panic, output overflow, artifact mutation, evidence failure, or canary finding makes the overall verdict fail.

| Case | Contract |
| --- | --- |
| `artifact_identity` | Exact SHA-256, clean VCS revision, toolchain, executable type, and anchored version agree. |
| `network_namespace_isolation` | Linux runner is not PID 1 and every installed IPv4/IPv6 route is loopback-only; unrouted kernel tunnel devices are harmless. |
| `operator_lifecycle` | Revocation init, provider import via stdin, token issue, owner-only files, no overwrite or secret echo. |
| `http_unauthenticated_no_egress` | Missing/invalid auth returns 401 and cannot reach any external network or the fake provider. |
| `http_authenticated_provider_success` | Valid token traverses TLS 1.3 fake provider and returns exact synthetic 200 contract. |
| `http_revoked_no_egress` | Invalid-body polling observes 400 to 401 without provider hits; valid body remains 401. |
| `http_route_and_header_contract` | Documented method/path allowlist plus curated sensitive-route deny matrix and header filtering. Authenticated `GET /v1/models` may be unmounted (404) or return an OpenAI list that includes the virtual-key model. |
| `unsupported_capabilities_fail_closed` | Vault, Redis, quota without prices, provider-level TPM, BYOK, and reserved adapters do not start or become reachable. JWT `tpm` may stay reserved (401, no egress) or be enforced (429 with no extra egress, or 200). |
| `secret_canary_confinement` | Master/JWT/provider/token/prompt/completion/error canaries stay within explicit surface allowlists. |
| `process_lifecycle` | SIGTERM stops cleanly, children are reaped, bounded outputs do not overflow, workspace is scanned before deletion. |

Current non-claims: performance, soak, mutation, fuzz, multi-platform black-box, real-provider sandbox, multi-host revocation, and cross-restart rollback-anchor coverage are not part of baseline v1.
