---
title: Execute configured session actions and snapshot evidence
priority: critical
frontloop_approval_task: a5f14b3bedd864c20620195197bf66bfc0e70d3fe255841336013673a912aaf2-3
---

## Goal

Allow one synchronous configured action at a time against a Ready session, safely deliver bounded JSON input, stream output, snapshot configured artifacts such as screenshots, and destroy unsafe or abandoned sessions.

## Acceptance Criteria

- `POST /v1/sessions/{id}/actions/{action}` authorizes the opaque session, rejects unknown actions, and starts only fixed server-configured execution in the existing session cwd/environment/workspace.
- Action bodies must be JSON objects no larger than 64 KiB. The daemon writes the validated bytes to child stdin without blocking the runtime, closes stdin, handles early child exit/EPIPE, and never copies body fields into process authority.
- Only one action or artifact snapshot may own a session at a time; a concurrent action receives immediate conflict rather than queueing, including while the first action's artifact snapshot is being published.
- Each action has an independent output budget and configured timeout. Maximum lifetime or explicit stop during an action cancels and reaps the whole action process group before exactly-once teardown; explicit stop also preempts an in-flight artifact snapshot before teardown.
- An ordinary nonzero action exit is streamed with its code and leaves the session Ready for diagnosis; action timeout, output exhaustion, abnormal response disconnect, or internal execution failure terminates the session and runs teardown.
- Configured action artifacts are snapshotted before another action begins, apply task/global include/exclude and restricted-pattern rules, use existing bounded protected archive storage, and are advertised through an opaque authenticated artifact reference.
- Action stream events include sufficient stable action/session identity and exit metadata for the CLI to record provenance without exposing the workspace path or external-state details.
- Adversarial deterministic HTTP tests cover unknown/forbidden body fields, exact size boundaries, ignored stdin, early exit, nonzero reuse, action timeout, output exhaustion, process-group cleanup, disconnect teardown, concurrent action conflicts, restricted artifacts, stop during artifact snapshotting, maximum-lifetime races, and idle-expiry racing a new action; an action arriving after expiry begins must receive a missing/expired result rather than observe partial teardown.

## Design Decisions

- Actions launch discrete configured processes; Indentured does not proxy an opaque long-running driver protocol.
- Normal action failures remain inspectable; transport/resource failures destroy the session because its state is no longer trustworthy.
- Artifact snapshots are part of the serialized action critical section.

## Implementation Notes

Depends on server lifecycle. Reuse the existing phase runner/output channel/cancellation machinery with the minimum generalization needed for stdin and non-final workspace artifact snapshots. Do not add heartbeats, queues, selectors, or domain-specific payload validation.


## Completion Summary

- Added the configured session-action HTTP stream with strict bounded JSON-object stdin and fixed server-owned process authority.
- Serialized action execution and artifact snapshots with independent budgets, nonzero-reuse semantics, destructive failure cleanup, and stop/lifetime/disconnect cancellation.
- Hardened artifact snapshots with descriptor-relative no-follow traversal, protected publication cleanup, delivery acknowledgment, and post-spawn process-group reaping.
- Added deterministic adversarial action, stdin, artifact, delivery, conflict, teardown, expiry, and race tests; full Rust checks, packaged-local, Linux flake check, and independent review passed.

### Files Changed

- README.md
- src/artifacts.rs
- src/build.rs
- src/config/mod.rs
- src/http.rs
- src/protocol.rs
- src/sessions.rs
