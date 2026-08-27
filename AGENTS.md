# AGENTS.md

Guidance for AI coding agents working in this repo. Optimized for the review
and implementation flow used by `/review`, `/security-review`, and similar
tools.

## Repo at a glance

- Single Go module: `github.com/ironsh/iron-proxy` (Go 1.26+).
- One binary: `cmd/iron-proxy` (the MITM egress proxy).
- Core packages live under `internal/`. The transform pipeline lives in
  `internal/transform/` with one subpackage per transform
  (`allowlist`, `secrets`, `bodycapture`, `headerallowlist`, `annotate`,
  `judge`, `grpc`, `hmacsign`, `oauth`, `awsauth`, `gcpauth`).
- Integration tests against real backends (AWS, 1Password, GCP, Postgres,
  gRPC, MCP) live in `integration_test/`. Unit tests sit next
  to the code they exercise.

The README is the source of truth for product behavior. When in doubt about
intended behavior, read it before changing code.

## This is the Litmus fork

This checkout is `litmus-team/iron-proxy`, a fork of `ironsh/iron-proxy`
(remote `upstream`). The Litmus delta rides on top of an upstream tag and is
re-landed by cherry-pick when we rebase; `git log --oneline <tag>..HEAD` shows
it. Two invariants matter more than anything else in this file:

- **The audit record's body-capture fields are top-level and must stay that
  way.** `internal/transform/audit.go` and `otelaudit.go` emit `request_body`,
  `request_body_truncated`, `response_body`, `response_body_truncated` as
  top-level attributes. Upstream ships its own `internal/transform/bodycapture`
  at the SAME import path and transform name (`body_capture`) that emits a
  NESTED `body_capture` group instead — ours deliberately replaces it on every
  rebase. Do not adopt upstream's shape while resolving a conflict: the
  consumer (`infra/hostd/hostd.py` in the `litmus` repo) reads the top-level
  fields, so nesting them drops every captured prompt silently. Capture keeps
  appearing to work and produces nothing.
- **`internal/transform/mirror` must stream, never buffer.** It serves
  multi-hundred-megabyte editor downloads, so `TransformRequest` returns once
  the mirror's headers are in and hands the live upstream body through. Its
  host rules come from config (in the `litmus` repo), not from this tree.
  `internal/transform/mirror/streaming_test.go` fails if either property
  regresses; a test that merely reads a large body back intact does not.

## Go conventions

- Use `github.com/stretchr/testify/require` for assertions. Never
  `t.Errorf` / `t.Fatalf` for value comparisons when `require.Equal` would do.
- Table-driven tests are the default for any function with more than two
  meaningful input shapes. Name the table `cases` or `tests`, iterate with
  `t.Run(tc.name, ...)`.
- `require.NoError(err)` on every error returned from a function under test.
  Never silently ignore errors. In tests, the only acceptable place to drop
  an error is inside a background goroutine (e.g. an HTTP handler) and it
  must use `_` with a comment explaining why the error is unreachable or
  irrelevant.
- Production code: never silently swallow errors. If an error truly cannot
  occur, suppress with `_` and a one-line comment stating why.
- Respect `context.Context` on every network or I/O call. Background
  goroutines need an explicit lifecycle (shutdown channel, context, or
  errgroup).
- Prefer the standard library and the existing dependencies in `go.mod` over
  adding new ones.

## Simplicity

- Aim for the smallest change that solves the problem. Don't add features,
  abstractions, or configuration knobs the task didn't ask for.
- Don't design for hypothetical future requirements. Two similar code
  blocks are fine; if the same shape appears a third time, factor a helper
  and update the call sites in the same change.
- Prefer deleting code over adding it. If a refactor leaves dead branches,
  unused config fields, or backwards-compat shims behind, remove them.
- No premature interfaces. Introduce an interface when a second concrete
  implementation actually exists, not in anticipation of one.

## Security invariants (do not weaken)

These are load-bearing properties of the proxy. Treat any change that
weakens one as blocking until discussed.

- **Default-deny egress.** Every request must pass the `allowlist` transform
  (or an equivalent policy gate) before the proxy dials upstream. Code paths
  that reach `net.Dial` / `http.Transport.RoundTrip` before policy
  evaluation are not acceptable.
- **Upstream IP deny.** Resolved upstream addresses are checked against
  `proxy.upstream_deny_cidrs` (loopback and `169.254.169.254` by default)
  before dialing. Changes to the dialer must keep this check in place.
- **Secret confinement.** Real secret values returned from any
  `internal/transform/secrets` resolver must never appear in:
  - logs (structured or otherwise),
  - error strings returned to a caller or surfaced in audit events,
  - panic messages,
  - responses sent back to the client.
  Proxy tokens (the sandbox-side placeholder) may appear in audit logs
  per the README; real upstream credentials must not.
- **Audit integrity.** Every proxied request emits a JSON audit entry and,
  when OTLP is configured, an OTEL log record with the same shape. Both
  carry `action`, `request_transforms` (with per-transform decisions and
  `rejected_by` on denials). Changes that make these fields optional, drop
  them on error paths, or shortcut emission are not acceptable.
- **Cleanup on error.** Any error path that returns to the caller must
  close opened upstream connections, release any acquired semaphore /
  circuit-breaker slot (see `internal/transform/judge`), and still emit
  the audit event for the request.
- **MCP and Postgres policy gates.** The MCP interceptor's default-deny
  tool allowlist and the Postgres proxy's `SET ROLE` injection /
  role-mutation rejection are both load-bearing. Don't add bypass paths.

## Concurrency

- Flag any new shared mutable state without synchronization. The proxy
  serves many concurrent requests; transforms and resolvers are reused
  across goroutines.
- Caches (LRU cert cache, secret-resolver TTL caches) must be safe for
  concurrent use. `failure_ttl` exists so a transient backend outage does
  not get pinned by a long success TTL — don't collapse the two.

## Review guidance (for `/review`, `/security-review`, code-review agents)

When reviewing changes in this repo:

**Focus on:**
- The security invariants above. Cite the specific invariant a change
  violates rather than describing the symptom in the abstract.
- Concurrency correctness, error-path cleanup, and context propagation.
- Missing or weak tests for the categories under "Testing expectations".
- Behavior drift from what the README documents.

**Do not comment on:**
- Style, naming, import order, or formatting. `gofmt`, `go vet`, and the
  existing linter handle these.
- Requests to add comments unless a specific piece of code is genuinely
  unclear and the reviewer can name what is unclear about it.
- Generic "consider adding tests" notes. If a behavior is untested, name
  the behavior and the file it lives in.
- Speculative future requirements ("you might also want to support X").
  Comment on the change in front of you.

Keep review comments terse and specific. One sentence per finding is
usually enough; cite `path/to/file.go:line` so the author can jump
straight to it.

## Build and test

```bash
go build ./...
go test ./...               # unit tests
go test ./integration_test/...   # integration; many require external creds
```

The integration suite uses testcontainers and real cloud backends; expect
many tests to skip in a clean environment. That is intended.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
