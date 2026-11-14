# Spec facts for the three new checks (MCP 2026-07-28)

Sources fetched 2026-11-10:
- Changelog: https://modelcontextprotocol.io/specification/2026-07-28/changelog.md
- Caching: https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching.md
- SEP-2575 (stateless, incl. "Changes since SEP became Final"): https://modelcontextprotocol.io/seps/2575-stateless-mcp.md
- Tasks extension overview: https://modelcontextprotocol.io/extensions/tasks/overview.md
- Tasks spec text: github.com/modelcontextprotocol/ext-tasks, `specification/2026-07-28/tasks.md` (only the error-code and Security sections were read verbatim; schema from `packages/ext-tasks/schema/v2/schema.ts`, grep only)

## A. Identity or client fields in request `_meta`

Keys (SEP-2575, `RequestMetaObject`):
- `"io.modelcontextprotocol/protocolVersion"`: string, required. On HTTP it must equal the `MCP-Protocol-Version` header, else 400.
- `"io.modelcontextprotocol/clientInfo"`: `Implementation` (`name` and `version` required, other fields optional).
- `"io.modelcontextprotocol/clientCapabilities"`: `ClientCapabilities`, required.
- `"io.modelcontextprotocol/logLevel"`: optional.
- Server side: `io.modelcontextprotocol/serverInfo` in result `_meta`.
- Also documented in the changelog: `traceparent`, `tracestate`, `baggage` in `_meta`.

Quote (SEP-2575, "Changes since SEP became Final"): "Client identity became optional request metadata. #3002 made `io.modelcontextprotocol/clientInfo` optional. Clients SHOULD include it on every request unless specifically configured not to do so."

Quote (SEP-2575, Open Questions): "`clientInfo` serves a different purpose (identity/UI) than capabilities (feature negotiation)."

Quote (SEP-2575, Security Implications): "Without a session handshake, every request must be independently authenticated and authorized. Implementations MUST ensure that authentication is not bypassed by the removal of the initialization phase."

**Finding for Task A:** the spec defines NO user, principal or tenant identity field in `_meta`. `clientInfo` names the client software (`name`, `version`). It is self-asserted and is not a user identity. So the check is "does the server let a request-supplied `_meta` value (clientInfo, or an invented key such as a user id) override or influence the identity it authorizes against (the bearer token)?" It is not "does it honour a standard identity claim." That is a behavioural probe on non-standard use of the field, not a conformance check.

UNCONFIRMED: whether any extension defines a principal or user key in `_meta`. I did not search the extensions registry.

## B. Long-running operations (Tasks extension `io.modelcontextprotocol/tasks`)

It is an extension, not core. The client declares `extensions: {"io.modelcontextprotocol/tasks": {}}` inside `_meta["io.modelcontextprotocol/clientCapabilities"]` on each request. The server advertises it in `server/discover` capabilities.

- Start: the server decides per request. A supported request such as `tools/call` may return a `CreateTaskResult` with `resultType: "task"`. It carries a `Task` with `taskId`, initial `status`, `ttlMs` and `pollIntervalMs`. There is no client-side "start a task" flag.
- Handle: `taskId` (string), passed as `params.taskId`.
- Poll: `tasks/get` with `params.taskId`. Returns the task state and, when terminal, `result` (completed) or `error` (failed).
- Input: `tasks/update` with `taskId` and `inputResponses`. Returns an empty ack.
- Cancel: `tasks/cancel` with `taskId`. Returns an empty ack. It is cooperative.
- Status values: `working`, `input_required`, `completed`, `failed`, `cancelled`. The last three are terminal.
- `tasks/result` was REMOVED, and so was `tasks/list`. There is no way to enumerate tasks.
- Optional push: `notifications/tasks`, opted into via `subscriptions/listen` (`taskIds`).

Quote (Tasks spec, Security Considerations): "**Auth binding.** Servers **MUST** perform authentication and authorization checks on each task-related request to ensure that the client has permission to access a task."

Quote: "**Task ID unguessability.** A server **MAY** use task IDs as bearer tokens for a server's stored state. Servers **MUST** generate them with sufficient entropy that a third party cannot enumerate or guess them."

Quote (errors): "Invalid or nonexistent `taskId`: `-32602` (Invalid params) - Servers **MUST** return this error for `tasks/get`."

Without the extension capability: `-32021` (Missing Required Client Capability) for `tasks/get`, `tasks/update` and `tasks/cancel`.

**Finding for Task B ("saved references"):** a taskId is a server-minted handle. The spec requires an auth check on every task request, but it does NOT say which error code means "task exists but belongs to another identity."

UNCONFIRMED:
1. The error a server must return when identity B presents identity A's valid `taskId`. Only the nonexistent-ID case is specified (`-32602`). The probe should treat "same error as nonexistent" or "any error" as safe and "returns A's status or result" as a leak. It should not insist on one code.
2. (RESOLVED, see full field list below.)
3. Whether the task-creating servers in this repo's corpus implement the extension at all. Local servers may need a purpose-built practice server.

## C. `ttlMs` and `cacheScope`

Where they appear (Caching, "Cacheable Results"): "Servers MUST include caching hints on results with `resultType: "complete"` returned by ... `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`."

Values:
- `ttlMs`: integer milliseconds, "Servers MUST provide a `ttlMs` value that is `>= 0`."
- `cacheScope`: `"public"` or `"private"`.

Quote (meaning of `"private"`): "The response contains private data that is not meant to be shared between callers. Cached responses MAY be reused for the same authorization context. Caches MUST NOT be shared across authorization contexts (e.g. a different access token requires a different cache)."

Quote (meaning of `"public"`): "The response does not contain user-specific data. Any client, shared gateway, or caching proxy MAY store and serve the cached response to any user."

Quote (Security): "Servers ... MUST apply appropriate per-primitive access controls, and MUST NOT rely on `cacheScope` alone to prevent unauthorized access to primitives."

Other: every page of a paginated list must carry the same `cacheScope`. Results from MRTR retries (`inputResponses` or `requestState`) must not be cached.

**Finding for Task C:** the testable leak is a server that labels a user-specific `resources/read` or list result `cacheScope: "public"`, or omits `cacheScope`. A shared cache would then serve one identity's data to another. Grade as follows: identity A and identity B read the same `uri` with different tokens; if A's content differs from B's (or contains A-only data) and the response is `"public"` (or the field is missing), that is a leak. `"private"` with identity-specific content is correct.

UNCONFIRMED: what a client should assume when `cacheScope` is absent. The spec says `ttlMs` absent means 0, but I found no default for a missing `cacheScope`. Treat a missing field as a spec violation and grade it "not safe to cache," not as a confirmed leak.

## Gaps and proposals (for your go-ahead)

- Task A: SKIPPED by founder decision (2026-11-10): `_meta` carries client software identity only, so there is no standard user-identity field to override. (Original proposal, not built: build it as a behavioural probe (does `_meta` override the token identity?). It needs a practice server that reads identity from `_meta`. This is not a conformance check, so the report must say so.
- Task B: build it, with a loose error-code grade (see B above).
- Task C: build it, and read the missing-`cacheScope` case as "unsafe to cache," not as a confirmed leak.

## Full Task field list (tasks extension schema v2, read 2026-11-10)

Source: ext-tasks `packages/ext-tasks/schema/v2/schema.ts`.

- `Task`: `taskId: string` (req); `status: TaskStatus` (req); `statusMessage?: string`; `createdAt: string` ISO 8601 (req); `lastUpdatedAt: string` ISO 8601 (req); `ttlMs: number | null` (req, null = unlimited); `pollIntervalMs?: number`.
- `TaskStatus`: `"working" | "input_required" | "completed" | "failed" | "cancelled"`.
- `DetailedTask` variants: working (no extras); input_required (+ `inputRequests`, req); completed (+ `result` object, req); failed (+ `error` JSON-RPC error object, req); cancelled (no extras).
- `CreateTaskResult` = Result & Task & `{resultType: "task"}`.
- `tasks/get` params `{taskId}` -> `GetTaskResult` = Result & DetailedTask & `{resultType: "complete"}`.
- `tasks/update` params `{taskId, inputResponses}` -> `{resultType: "complete"}` (empty ack).
- `tasks/cancel` params `{taskId}` -> `{resultType: "complete"}` (empty ack; cooperative, eventually consistent).
- Errors: nonexistent/invalid taskId `-32602`; missing tasks capability `-32021`.
