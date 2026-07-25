## Development guidelines

- Use Jujutsu (`jj`) for repository work. Use `jj st`, `jj diff`, `jj edit`, `jj new`, and other Jujutsu commands as appropriate. Do not use direct Git workflow commands such as `git status`, `git diff`, `git add`, `git commit`, `git checkout`, `git branch`, `git reset`, or `git rebase`. The `jj git` namespace is permitted for remote synchronization.
- For any new feature or behavior change, add or update deterministic, offline tests and update the relevant documentation in `README.md` or `docs/`.
- When updating Rust code, run:
  ```sh
  cargo fmt --all -- --check
  cargo clippy --locked --offline --all-targets --all-features -- -D warnings
  cargo test --locked --offline --all-targets --all-features
  cargo build --locked --offline --release --all-features
  ```
- Use the pinned Nix flake and Devenv tasks for reproducible package and development dependencies. Do not use Nix channels, `nix-env`, or imperative dependency installation.
- Run `nix flake check --print-build-logs` natively on each supported platform; evaluation from another platform is not build attestation. On native Apple-silicon Darwin, also run `scripts/check-darwin.sh`.
- Run `devenv tasks run integration:packaged-local` when changing package layout or the packaged upload/task/stream/exit/artifact flow.
