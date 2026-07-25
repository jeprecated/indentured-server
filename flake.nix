{
  description = "Nix packages and checks for indentured-server";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      cargoPackage = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
              ./tests
            ];
          };
          package = pkgs.rustPlatform.buildRustPackage {
            pname = cargoPackage.package.name;
            inherit (cargoPackage.package) version;
            src = source;

            outputs = [
              "out"
              "client"
            ];
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--bins"
              "--all-features"
            ];
            cargoInstallFlags = [
              "--bins"
              "--all-features"
            ];
            doCheck = false;
            strictDeps = true;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.pkg-config
            ];
            AWS_LC_SYS_CMAKE_BUILDER = "1";

            postInstall = ''
              mkdir -p "$client/bin"
              mv "$out/bin/indentured" "$client/bin/indentured"
              test -x "$out/bin/indentured-server"
              test ! -e "$out/bin/indentured"
              test -x "$client/bin/indentured"
              test ! -e "$client/bin/indentured-server"
            '';

            meta = {
              description = cargoPackage.package.description;
              license = pkgs.lib.licenses.mit;
              mainProgram = "indentured-server";
              platforms = systems;
            };
          };
          clientPackage = package.client // {
            meta = package.meta // {
              mainProgram = "indentured";
            };
          };
        in
        {
          default = package;
          indentured-server = package;
          indentured = clientPackage;
        }
      );

      apps = forAllSystems (
        system:
        let
          server = {
            type = "app";
            program = "${self.packages.${system}.indentured-server}/bin/indentured-server";
            meta.description = "Run the indentured-server daemon";
          };
          client = {
            type = "app";
            program = "${self.packages.${system}.indentured}/bin/indentured";
            meta.description = "Run the indentured client";
          };
        in
        {
          default = server;
          indentured-server = server;
          indentured = client;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          server = self.packages.${system}.indentured-server;
          client = self.packages.${system}.indentured;
        in
        {
          indentured-server-package = server;
          indentured-package = client;
          package-layout = pkgs.runCommand "indentured-package-layout" { } ''
            test -x "${server}/bin/indentured-server"
            test ! -e "${server}/bin/indentured"
            test -x "${client}/bin/indentured"
            test ! -e "${client}/bin/indentured-server"
            touch "$out"
          '';
        }
      );

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixfmt-tree);
    };
}
