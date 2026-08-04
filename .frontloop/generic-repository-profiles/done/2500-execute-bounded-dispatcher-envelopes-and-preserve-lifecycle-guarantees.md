---
title: Execute bounded dispatcher envelopes and preserve lifecycle guarantees
priority: high
frontloop_approval_task: 423bb2369dfbc00127b81b1ec9e7071031ca2c1e57a13f7898822b156d79d4b6-2
---

## Goal

Run arbitrary validated action names through the retained fixed dispatcher using a versioned JSON stdin envelope, then prove the existing process, evidence, artifact, and teardown semantics still hold.

## Acceptance Criteria

- Define a distinct internal dispatcher-envelope schema-version constant and serializable envelope containing only `schema_version`, validated `action`, and the already-bounded JSON-object `input`.
- Construct child stdin after action reservation: named mode receives the input object exactly as before; dispatcher mode receives the exact compact envelope.
- Pass the retained SessionActionConfig through `run_session_action` and artifact collection instead of looking it up by caller-supplied name.
- Do not expose action data through argv, environment, cwd, executable selection, timeout selection, or artifact selection.
- Preserve action names in events, CLI output, and evidence/provenance without adding a public `dispatch` action or CLI subcommand.
- Preserve nonblocking stdin, output bounds, process-group reaping, timeout and disconnect destruction, destructive-action handling, action conflicts, final-delivery acknowledgment, artifact restrictions, session reuse after ordinary nonzero exits, and exactly-once teardown.
- Add the smallest deterministic regression coverage for exact envelope bytes, maximum accepted external request size plus fixed internal overhead, named-input compatibility, arbitrary dispatcher names, prompt unknown-name failure behavior, reuse after nonzero exit, timeout/disconnect cleanup, and dispatcher artifact snapshots.
- Extend the exact packaged-binary harness with one dispatcher session exercised under at least two arbitrary action names while retaining the existing named-action packaged regression.
- Pass `cargo fmt --all -- --check`, strict locked/offline Clippy, locked/offline all-target tests, locked/offline release build, and repeated `devenv tasks run integration:packaged-local`.

## Design Decisions

- The 64 KiB bound remains on the external encoded request body; child stdin is bounded by that request plus a fixed envelope and a validated action name of at most 64 bytes.
- Unknown names in dispatcher mode are repository data: dispatchers must reject unsupported names promptly with a nonzero exit. Existing session timeout semantics still destroy a session if a dispatcher hangs.
- No temporary input file is introduced. The established requirement that caller JSON is delivered through stdin only wins over Fable's suggested file handoff.

## Implementation Notes

Relevant files: src/http.rs, src/sessions.rs, src/build.rs, src/protocol.rs, src/bin/indentured.rs tests, tests/packaged_local_integration.rs, and packaged harness scripts/fixtures. Add an end-to-end packaged assertion that the pinned Devenv task runner preserves stdin rather than relying on an undocumented assumption.


## Completion Summary

- Executed fixed dispatchers with compact versioned JSON envelopes built after reservation while retaining server-owned command, timeout, environment, cwd, and artifact authority.
- Added HTTP coverage for the exact 64 KiB external body boundary through an arbitrary dispatcher action while preserving named-mode unknown-action and raw-input regressions.
- Extended exact packaged-binary validation with arbitrary dispatcher names, exact envelope artifacts, provenance, prompt unsupported-name failure, nonzero reuse, timeout destruction, disconnect cleanup, explicit teardown, and named-mode regression.
- Added and exercised a pinned Devenv stdin inheritance probe; repeated packaged-local validation passed.
- Passed formatting, strict locked/offline Clippy, 167 tests with 2 intentionally ignored packaged entrypoints, and locked/offline release build.

### Files Changed

- src/protocol.rs
- src/sessions.rs
- src/build.rs
- src/http.rs
- tests/packaged_local_integration.rs
- scripts/check-packaged-local-integration.sh
- devenv.nix
