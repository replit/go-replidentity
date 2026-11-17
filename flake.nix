{
  description = "Reproducible checks for go-replidentity";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { nixpkgs, ... }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      inherit (pkgs) lib;
    in
    {
      checks.x86_64-linux.coverage = pkgs.buildGo124Module {
        pname = "go-replidentity-coverage";
        version = "0";
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./go.mod
            ./go.sum
            (lib.fileset.difference
              (lib.fileset.fileFilter (file: file.hasExt "go") ./.)
              ./examples)
          ];
        };
        vendorHash = "sha256-eDbCuT054SI99IhvvgXlsM80xg2iKMosWCJMKqkl+4s=";
        buildPhase = "true";
        checkPhase = ''
          runHook preCheck
          go test -cover -covermode=atomic -coverprofile coverage.out
          runHook postCheck
        '';
        installPhase = ''
          mkdir -p "$out"
          cp coverage.out "$out/"
        '';
      };
    };
}
