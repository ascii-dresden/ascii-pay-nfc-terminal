{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, naersk, utils, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        package = pkgs.callPackage ./derivation.nix {
          src = ./.;
          naersk = naersk.lib.${system};
        };
      in
      rec {
        checks = packages;
        defaultPackage = package;
        packages.ascii-pay-nfc-terminal = package;
        overlay = (final: prev: {
          ascii-pay-nfc-terminal = package;
          ascii-pay-nfc-terminal-src = ./.;
        });

        hydraJobs = {
          ascii-pay-nfc-terminal."${system}" = package;
        };
      }
    );
}
