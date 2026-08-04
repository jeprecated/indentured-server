---
title: Add schema-9 dispatcher configuration and retained action resolution
priority: high
frontloop_approval_task: 423bb2369dfbc00127b81b1ec9e7071031ca2c1e57a13f7898822b156d79d4b6-1
---

## Goal

Introduce one optional fixed action dispatcher per managed-session task and resolve its execution authority once at action reservation, without changing existing named-action behavior or public wire contracts.

## Acceptance Criteria

- Bump the server configuration schema from 8 to 9 and update all examples, fixtures, version-rejection tests, and literal `TaskSessionConfig` values.
- Add optional `session.action_dispatcher` using the existing session-action execution, timeout, and artifact-policy shape; deserialize omitted `actions` as empty.
- Reject session configurations with both modes or neither mode; accept exactly one nonempty named-action map or one dispatcher.
- Apply shell, execution-shape, argument, timeout, environment, and artifact validation to the dispatcher exactly as for named actions.
- Resolve named versus dispatcher mode in `SessionManager::start_action` and retain the resolved immutable action configuration and mode in `SessionActionReservation`.
- Remove all later by-name authority lookups from execution and artifact snapshotting so dispatcher names cannot reach `expect("reserved configured action")` or `unknown_action` internally.
- Keep named-mode unknown actions as pre-spawn 404 responses; dispatcher mode accepts every existing syntactically valid action identifier.
- Add focused deterministic configuration and reservation tests for the exactly-one-mode matrix, script validation, named compatibility, arbitrary dispatcher names, and invalid identifiers.

## Design Decisions

- The retained resolution prevents inconsistent duplicate lookups and dispatcher panics; it is not described as protection against live config drift because configuration and session task snapshots are already immutable.
- The public action request remains schema version 1 and bearer authentication is unchanged.
- One dispatcher intentionally has one server-owned timeout and artifact policy shared by all repository action names.

## Implementation Notes

Relevant files: src/config/mod.rs, src/sessions.rs, src/http.rs, src/protocol.rs, and their existing tests. Reuse SessionActionConfig rather than introducing a parallel execution type.


## Completion Summary

- Bumped configuration schema to 9 and added exactly-one-mode validation for named actions versus a fixed action dispatcher, including shell/execution/timeout/artifact checks and schema-8 migration coverage.
- Retained the resolved immutable action configuration and mode in each reservation, removing duplicate execution and snapshot lookups by caller-supplied name.
- Added versioned dispatcher stdin envelope encoding after reservation while preserving named-action input bytes and public HTTP/auth contracts.
- Added focused dispatcher configuration and reservation tests; all 167 tests passed and strict offline Clippy reported no issues.

### Files Changed

- src/config/mod.rs
- src/protocol.rs
- src/sessions.rs
- src/build.rs
- src/http.rs
- README.md
- config/config.toml
- docs/macos-launchd-tailscale-deployment.md
- docs/managed-session-ios-simulator-example.md
- tests/indentured_log_capture.rs
- tests/packaged_local_integration.rs
