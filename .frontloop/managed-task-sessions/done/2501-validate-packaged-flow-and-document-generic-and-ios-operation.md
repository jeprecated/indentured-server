---
title: Validate packaged flow and document generic and iOS operation
priority: high
frontloop_approval_task: a5f14b3bedd864c20620195197bf66bfc0e70d3fe255841336013673a912aaf2-5
---

## Goal

Prove the complete packaged session lifecycle without network dependencies, preserve one-shot behavior, and document how operators configure external systems such as iOS Simulator without embedding that domain in Indentured.

## Acceptance Criteria

- Extend `integration:packaged-local` with server-configured fake external state to cover start, multiple successful and nonzero actions, action artifacts, explicit stop, idle cleanup, maximum lifetime, action disconnect, and retained permit behavior using exact packaged binaries.
- Add a restart test that genuinely terminates the daemon with a Ready session, restarts it, observes stale-session teardown/removal, and confirms configuration-drift cleanup.
- Retain an exact one-shot packaged regression for source packaging/upload, setup/run event sequence, exit status, artifacts, cancellation, and workspace cleanup.
- Update `README.md` and macOS deployment documentation for the generic session lifecycle, capacity consequences, cleanup guarantees, restart semantics, action JSON trust boundary, and reuse of existing bearer behavior without a new session-auth model.
- Add an operator-owned iOS Simulator session configuration example in `docs/` showing initialization wrappers that build once, boot/install/launch and write the UDID to workspace state; named observe/act wrappers; and idempotent teardown. The example is documentation/configuration, not built-in simulator behavior or a packaged MCP dependency.
- Document that initialization/action process groups are reaped and any persistent external service must be handed to launchd/CoreSimulator or represented by workspace state; never recommend daemonizing merely to evade cleanup.
- Document and exercise the macOS task-identity/CoreSimulator acceptance gate, including Xcode/runtime pinning, explicit UDIDs rather than `booted`, task-user launchd/bootstrap access, simulator deletion, and credential/control-path separation.
- Run the required offline Cargo fmt/clippy/test/release checks and `devenv tasks run integration:packaged-local`; run `nix flake check --print-build-logs` natively on supported platforms and `scripts/check-darwin.sh` on Apple Silicon Darwin, recording any platform not natively attested rather than claiming cross-platform success.

## Design Decisions

- iOS integration remains operator policy expressed through configured commands and documentation.
- No third-party MCP package, Node runtime, idb dependency, simulator executable, or iOS-specific Rust type is added to Indentured.
- The packaged deterministic test uses fake external state; native CoreSimulator behavior is separately attested on the Mac mini.

## Implementation Notes

Depends on all prior tasks. Required because package/upload/task/stream/exit/artifact behavior changes. Incorporates Fable's review: keep process-group reaping, specify capacity impact and Ready race, avoid unreachable automatic-cleanup artifacts, and test real crash reconciliation.


## Completion Summary

- Extended packaged-local validation with exact Nix binaries across one-shot regression, full managed-session lifecycle, actions/artifacts, retained capacity, automatic cleanup, restart reconciliation, configuration drift, and task identity.
- Added fail-closed Linux PID/user-namespace containment, guarded child cleanup, unambiguous teardown evidence, and repeated packaged runs with no leaked processes or temporary state.
- Documented generic lifecycle and macOS operational gates, and added an operator-owned iOS Simulator example with explicit UUIDs, durable pending ownership, safe idempotent teardown, and no built-in domain dependency.
- Passed fmt, clippy, full offline tests, release build, packaged-local repetitions, native x86_64 Linux flake check, and independent review; Darwin/CoreSimulator remains explicitly unattested.

### Files Changed

- README.md
- docs/macos-launchd-tailscale-deployment.md
- docs/managed-session-ios-simulator-example.md
- scripts/check-darwin.sh
- scripts/check-packaged-local-integration.sh
- tests/packaged_local_integration.rs
