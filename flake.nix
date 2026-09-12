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
              "host"
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
              mkdir -p "$client/bin" "$host/bin"
              mv "$out/bin/indentured" "$client/bin/indentured"
              mv "$out/bin/indentured-host" "$host/bin/indentured-host"
              test -x "$out/bin/indentured-server"
              test ! -e "$out/bin/indentured"
              test -x "$client/bin/indentured"
              test ! -e "$client/bin/indentured-server"
              test -x "$host/bin/indentured-host"
              test ! -e "$out/bin/indentured-host"
              test ! -e "$client/bin/indentured-host"
              test ! -e "$host/bin/indentured-server"
              test ! -e "$host/bin/indentured"
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
          indentured-host = package.host // {
            meta = package.meta // {
              mainProgram = "indentured-host";
            };
          };
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
          indentured-host = {
            type = "app";
            program = "${self.packages.${system}.indentured-host}/bin/indentured-host";
            meta.description = "Observe the macOS desktop through a private per-user helper";
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          server = self.packages.${system}.indentured-server;
          client = self.packages.${system}.indentured;
          host = self.packages.${system}.indentured-host;
        in
        {
          indentured-server-package = server;
          indentured-package = client;
          indentured-host-package = host;
          package-layout = pkgs.runCommand "indentured-package-layout" { } ''
            test -x "${server}/bin/indentured-server"
            test ! -e "${server}/bin/indentured"
            test -x "${client}/bin/indentured"
            test ! -e "${client}/bin/indentured-server"
            test -x "${host}/bin/indentured-host"
            test ! -e "${server}/bin/indentured-host"
            test ! -e "${client}/bin/indentured-host"
            test ! -e "${host}/bin/indentured-server"
            test ! -e "${host}/bin/indentured"
            "${host}/bin/indentured-host" --help >/dev/null
            touch "$out"
          '';
        }
      );

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixfmt-tree);
    };
}
