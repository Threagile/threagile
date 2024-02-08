{
  description = "threagile flake";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, lib, ... }: {
        packages.default = pkgs.buildGoModule rec {
          pname = "threagile";
          version = "0.9.0";
          src = pkgs.lib.cleanSource ./.;
          vendorHash = "sha256-ef566Pvu1yGAqdOe0nSCwGaN1DR20IbhKlHMMNP8/YY=";
          #vendorHash = pkgs.lib.fakeHash;
          meta = with lib; {
            description = "an open-source toolkit for agile threat modeling";
            homepage = "https://github.com/Threagile/threagile";
            license = licenses.mit;
            maintainers = with maintainers; [ mrvandalo ];
          };
        };
        devShells.default = pkgs.mkShell {
          buildInputs = [
            self'.packages.default
          ];
        };
      };
      flake = { };
    };
}
