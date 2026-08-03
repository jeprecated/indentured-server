---
title: Add CLI session start, action, and stop commands
priority: high
frontloop_approval_task: a5f14b3bedd864c20620195197bf66bfc0e70d3fe255841336013673a912aaf2-4
---

## Goal

Give coding agents separate, scriptable CLI invocations for initializing a session, issuing one observe/act command per model turn, downloading action evidence, and explicitly tearing down.

## Acceptance Criteria

- Add `indentured session start TASK`, `indentured session action SESSION ACTION --input FILE_OR_DASH`, and `indentured session stop SESSION`; no session list/reset/workspace commands are introduced.
- Only `session start` snapshots and uploads source. It emits the opaque session ID in a machine-usable form while preserving human-readable diagnostics and private local evidence.
- `session action` validates IDs and input size client-side, accepts JSON only from a file or stdin rather than command-line interpolation, streams stdout/stderr/exit metadata, and downloads any advertised action archive into that invocation's unique mode-0700 evidence directory.
- `session stop` waits for teardown, preserves teardown status, and downloads an explicitly returned final archive without overwriting prior evidence or source.
- Every invocation writes atomic provenance containing session/action identity, status, timing, exit/timeout/interruption fields, artifact restrictions, and errors; screenshots and other action artifacts are left at clear paths agents can read.
- SIGINT during initialization or action drops/cancels the request, performs best-effort stop when a committed session ID is known, records interruption/cleanup outcome, and exits using the established controlled interruption convention.
- Authentication, global-capacity conflict, per-session conflict, missing/expired session, timeout, and teardown failure produce stable actionable diagnostics while retaining existing connection-fallback and exit-code conventions.
- A pre-session server returning 404 for `/v1/sessions` produces an explicit incompatible-server message rather than a stream parsing failure.
- Deterministic offline CLI tests cover argument authority, source upload only on start, stdin/file bounds, streamed output, artifact extraction safety, provenance, SIGINT, missing sessions, conflicts, and old-server behavior.

## Design Decisions

- Separate CLI invocations are the supported agent workflow; no attached interactive REPL or MCP transport is added.
- Session IDs are passed explicitly by callers; the client does not maintain hidden mutable current-session state.
- Existing local evidence safety and non-destructive artifact extraction rules apply unchanged.

## Implementation Notes

Depends on configured actions. Extend `src/bin/indentured.rs` by reusing endpoint/auth/evidence/stream/artifact helpers rather than creating a second client stack.


## Completion Summary

- Added `session start`, `session action`, and `session stop` CLI commands with explicit IDs and no hidden session state.
- Reused existing authentication, source packaging, streaming, evidence, provenance, fallback, and safe artifact extraction behavior; start stdout is machine-clean.
- Added bounded interruptible JSON input, deterministic SIGINT and best-effort cleanup handling, immediate identity persistence, teardown outcome preservation, and old-server/actionable diagnostics.
- Added comprehensive offline CLI boundary tests; fmt, clippy, full tests, release build, packaged-local, Linux flake check, repeated races, oracle adjudication, and independent review passed.

### Files Changed

- README.md
- src/bin/indentured.rs
- tests/indentured_session_cli.rs
