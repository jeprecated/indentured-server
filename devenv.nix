{ pkgs, ... }:

{
  packages = [
    pkgs.rustc
    pkgs.cargo
    pkgs.rustfmt
    pkgs.clippy
    pkgs.cmake
    pkgs.pkg-config
    pkgs.stdenv.cc
    pkgs.nix
    pkgs.jujutsu
  ];

  env.AWS_LC_SYS_CMAKE_BUILDER = "1";

  tasks."cargo:fmt".exec = "cargo fmt --all -- --check";
  tasks."cargo:clippy".exec =
    "cargo clippy --locked --offline --all-targets --all-features -- -D warnings";
  tasks."cargo:test".exec = "cargo test --locked --offline --all-targets --all-features";
  tasks."cargo:release-build".exec = "cargo build --locked --offline --release --all-features";
  tasks."integration:packaged-local".exec = "scripts/check-packaged-local-integration.sh";
  tasks."nix:flake-check".exec = "nix flake check --print-build-logs";
}
