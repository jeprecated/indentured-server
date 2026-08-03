---
title: Implement server session lifecycle and deterministic cleanup
priority: critical
frontloop_approval_task: a5f14b3bedd864c20620195197bf66bfc0e70d3fe255841336013673a912aaf2-2
---

## Goal

Add the authenticated server-side start/stop lifecycle, persistent session workspace, retained admission lease, timers, and crash recovery with exactly-once bounded teardown.

## Acceptance Criteria

- `POST /v1/sessions` authenticates and validates before source upload, acquires one global admission permit immediately, runs existing setup+run initialization in a fresh session workspace, and retains both workspace and permit only after the durable Ready commit.
- A root-owned, non-symlink, mode-protected metadata directory is separate from the task-owned workspace and records only the generic data needed for cleanup/reconciliation; uploaded task code cannot replace its authority path.
- Session state transitions are explicit and race-safe; explicit stop, idle expiry, maximum lifetime, initialization failure, and competing cleanup triggers elect exactly one transition to Terminating and execute teardown at most once.
- Idle time is suspended while lifecycle work is active and resets after completed activity; maximum lifetime is hard. Explicit stop waits for bounded teardown and returns any configured final archive before metadata/workspace deletion.
- Automatic cleanup paths—idle, lifetime, pre-Ready disconnect/failure, and startup reconciliation—run best-effort teardown but do not create unreachable final archives, then remove workspace/metadata and release capacity exactly once.
- Startup reconciliation destroys rather than resumes all stale sessions before serving. Removed/renamed tasks or removed session configuration cause logged best-effort root cleanup instead of startup refusal.
- Initialization stream cancellation before Ready terminates its process group and tears down; disconnect after the durable Ready commit does not destroy the session and is covered by idle expiry.
- Deterministic offline lifecycle tests prove permit accounting, exactly-once teardown races, timer boundaries, protected metadata checks, failed initialization cleanup, Ready/disconnect ordering, stale-session reconciliation, and configuration drift.
- Capacity responses distinguish global admission exhaustion from per-session operation conflicts, and configuration/docs warn when long sessions share the default single global permit with one-shot builds.

## Design Decisions

- The global build semaphore is shared by one-shot builds and sessions; a session retains one permit for its full lifetime.
- Sessions never survive daemon restart; restart reconciliation tears them down.
- Teardown uses the configured task identity/environment/cwd, is idempotent by contract, and has a fixed server-configured timeout.
- Final artifacts are collected only for explicit stop, where the caller can discover them.

## Implementation Notes

Depends on the contracts task. Reuse existing workspace extraction, privilege drop, process-group cancellation, output forwarding, and artifact collection rather than introducing another execution engine. Likely areas: `src/http.rs`, `src/build.rs`, config-owned state structures, and HTTP/lifecycle tests.


## Completion Summary

- Implemented authenticated managed-session start/stop lifecycle with retained shared admission permits and root-isolated durable metadata.
- Added atomic Ready/termination election, hard lifetime and idle cleanup across upload through commit, bounded disconnect handling, and exactly-once teardown/resource release.
- Added startup stale-session reconciliation, configuration-drift cleanup, explicit-stop artifact/status semantics, and fail-closed authority-path policy while preserving non-root one-shot builds.
- Added deterministic lifecycle, race, cancellation-boundary, symlink, overflow, backpressure, timer, and cleanup tests; fmt, clippy, full offline tests, release build, and independent review passed.

### Files Changed

- README.md
- src/build.rs
- src/config/mod.rs
- src/http.rs
- src/lib.rs
- src/sessions.rs
