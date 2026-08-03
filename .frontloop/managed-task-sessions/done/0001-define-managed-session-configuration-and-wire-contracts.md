---
title: Define managed-session configuration and wire contracts
priority: critical
frontloop_approval_task: a5f14b3bedd864c20620195197bf66bfc0e70d3fe255841336013673a912aaf2-1
---

## Goal

Extend the generic task model with an optional managed-session contract while leaving existing one-shot build behavior and `/v1/builds` protocol unchanged. Establish strict configuration, request, event, lifecycle, artifact, and budget semantics before server implementation.

## Acceptance Criteria

- Bump the daemon configuration schema to 8; a schema-7 configuration migrated only by changing its version and containing no session blocks retains the existing one-shot behavior and `/v1/builds` request schema/version.
- Add an optional per-task session configuration covering nonzero bounded idle timeout, maximum lifetime, idempotent teardown execution/timeout, and named action execution/timeout/artifact specifications; action names obey the existing identifier rules.
- Validate initialization setup+run against the existing build timeout rule, validate each action and teardown timeout against the server maximum, require idle timeout to be less than maximum lifetime, and define output accounting as per initialization/action/teardown invocation rather than cumulative across a session.
- Define strict versioned session-start metadata, opaque session/action identifiers, action/exit events, and a maximum 64-KiB JSON-object action body; reject request-controlled argv, environment, cwd, timeout, artifacts, paths, and unknown authority fields.
- Define `POST /v1/sessions`, `POST /v1/sessions/{session_id}/actions/{action}`, and `DELETE /v1/sessions/{session_id}` contracts; the explicit-stop response reports teardown exit and timeout status, and action/final explicit-stop archives reuse the existing authenticated artifact storage/download mechanism and global restrictions.
- Document the Ready commit point: durable root-owned metadata commits the session before the ready event; a disconnect before commit cleans up, while a disconnect after commit leaves idle expiry responsible for an unread ready result.
- Document that session initialization and actions retain existing process-group reaping; persistent external state must be handed to an OS service outside the child process group or represented by files in the session workspace.
- Add deterministic offline configuration/protocol boundary tests, including size limits, timeout ordering, unknown fields, identifier validation, schema migration, and unchanged one-shot serialization.

## Design Decisions

- Indentured remains domain-agnostic; it does not contain simulator-specific commands or state parsing.
- Existing optional setup plus required run perform session initialization once; successful initialization transitions the fresh workspace to Ready.
- Action input is bounded JSON delivered only through child stdin, never interpolated into shell text, argv, environment, cwd, timeouts, or artifact patterns.
- No session list, reset, arbitrary command, workspace, or filesystem endpoints are added.
- Session and action artifacts reuse existing protected storage, restrictions, authentication, TTL, and GC behavior.
- Reuse the existing bearer authentication unchanged; do not add per-session ownership, per-token authorization, or another authentication mechanism.

## Implementation Notes

First task; establishes contracts consumed by every later task. Likely areas: `src/config/mod.rs`, `src/protocol.rs`, `README.md`, and focused unit tests. Keep the new session protocol separate from request protocol v1 for one-shot builds.


## Completion Summary

- Added schema-8 optional managed-session configuration with validated idle/lifetime, teardown, named action, timeout, artifact, and identifier contracts.
- Added strict versioned session protocol types, bounded JSON-object action input parsing, opaque identifiers, event/outcome contracts, and one-shot serialization compatibility tests.
- Documented Ready/disconnect, process-group handoff, per-invocation budgets, artifact reuse, teardown outcomes, and unchanged bearer authentication.
- Passed fmt, clippy, full offline tests, release build, x86_64 Linux flake check, and independent read-only review.

### Files Changed

- README.md
- config/config.toml
- src/build.rs
- src/config/mod.rs
- src/http.rs
- src/protocol.rs
- tests/indentured_log_capture.rs
- tests/packaged_local_integration.rs
