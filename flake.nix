{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    naersk = {
      url = "github:nix-community/naersk";
    };

    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, naersk, utils, ... }: 
   utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      in rec {
        checks = packages;
        packages.ascii-pay-nfc-terminal = pkgs.callPackage ./derivation.nix {
          src = ./.;
          naersk = naersk.lib.${system};
        };
        overlay = (final: prev: {
          ascii-pay-nfc-terminal = pkgs.callPackage ./derivation.nix {
            src = ./.;
            naersk = naersk.lib.${system};
          };
          ascii-pay-nfc-terminal-src = ./.;
        });
      }
    );
}
