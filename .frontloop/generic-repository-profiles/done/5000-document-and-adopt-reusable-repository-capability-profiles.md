---
title: Document and adopt reusable repository capability profiles
priority: medium
frontloop_approval_task: 423bb2369dfbc00127b81b1ec9e7071031ca2c1e57a13f7898822b156d79d4b6-3
---

## Goal

Replace the repository-specific Quartz bootstrap task with reusable `repo_check` and `repo_session` conventions, while clearly separating host policy from arbitrary uploaded repository code and preserving the strict named-action iOS example.

## Acceptance Criteria

- Add this repository's `indentured:check` Devenv task invoking `scripts/check-darwin.sh`; document that the convention means the repository's check for the selected host capability profile, not a cross-platform local task.
- Replace the Darwin-specific `darwin_check` bootstrap example with one-time Quartz `repo_check` configuration that invokes an absolute operator-selected Devenv executable with fixed `devenv tasks run indentured:check` arguments.
- Document `repo_session` mapping fixed setup/start/action/stop execution to conventional `indentured:session:setup`, `indentured:session:start`, `indentured:session:action`, and `indentured:session:stop` Devenv tasks, with the action task consuming the dispatcher envelope directly from stdin.
- Document one shared dispatcher timeout/artifact policy, fixed artifact directories, the bounded envelope, valid action-name charset, prompt nonzero rejection of unsupported names, and source pinning for a session's lifetime.
- State plainly that uploaded repository hooks are arbitrary code under the configured task identity; task names are not per-script security boundaries, and distinct profiles are justified only by identity, permissions, limits, lifecycle, artifact policy, or operator-owned capability.
- Keep the iOS Simulator document as the strict operator-owned named-action exemplar and add a concise cross-reference to repository dispatch rather than weakening its root-owned wrapper model.
- Update README.md, config examples, `.indentured-server/config.toml` guidance, and macOS deployment documentation consistently for schema 9 and both action modes.
- Run native Linux `nix flake check --print-build-logs`; record Apple-silicon Darwin and live CoreSimulator as explicitly unattested until the generic profiles and schema-9 server are deployed and exercised on Quartz.

## Design Decisions

- Generic names describe reusable host capability profiles across repositories; they do not promise one check implementation works on every operating system.
- This repository's `indentured:check` remains deliberately Apple-silicon Darwin-only because its Quartz profile exists to obtain native Darwin attestation.
- Direct stdin inheritance through the pinned Devenv runner is retained and verified end to end; no workspace input file or caller-controlled path is added.
- The iOS example remains the operator-owned named-action security checklist; generic repository dispatch is documented separately.

## Implementation Notes

Relevant files: devenv.nix, README.md, config/config.toml, .indentured-server/config.toml, docs/macos-launchd-tailscale-deployment.md, and docs/managed-session-ios-simulator-example.md.


## Completion Summary

- Added this repository's Apple-silicon-Darwin `indentured:check` Devenv convention and secret-free client guidance for reusable `repo_check`/`repo_session` profiles.
- Replaced the repository-specific `darwin_check` bootstrap with complete one-time schema-9 Quartz profile configuration and conventional repository setup/start/action/stop hooks.
- Documented dispatcher envelope, stdin inheritance, shared timeout/artifact policy, prompt unsupported-name handling, source pinning, arbitrary repository-code authority, and when separate host profiles are warranted.
- Preserved the operator-owned named-action iOS Simulator example and linked it to the separate repository-dispatch convention.
- Passed all required Cargo checks, repeated packaged-local validation, and native x86_64 Linux flake checks; Darwin/CoreSimulator remains explicitly unattested.

### Files Changed

- devenv.nix
- README.md
- config/config.toml
- config/client.toml.example
- .indentured-server/config.toml
- docs/macos-launchd-tailscale-deployment.md
- docs/managed-session-ios-simulator-example.md
