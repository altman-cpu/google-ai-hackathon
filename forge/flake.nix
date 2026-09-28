{
  description = "forge -- intent-driven code design, content-addressed, PGP-signed, settled in SEI";

  # One input. forge has no runtime dependencies, so the flake should not
  # acquire any either -- eachSystem is a dozen lines of lib, not a dependency.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f {
          inherit system;
          pkgs = nixpkgs.legacyPackages.${system};
        });
    in
    {
      # ---- packages -----------------------------------------------------

      packages = forAllSystems ({ pkgs, ... }: rec {
        forge = pkgs.callPackage ./nix/package.nix { };
        default = forge;
      });

      apps = forAllSystems ({ pkgs, system, ... }: rec {
        forge = {
          type = "app";
          program = "${self.packages.${system}.forge}/bin/forge";
        };
        default = forge;
      });

      # ---- development --------------------------------------------------

      devShells = forAllSystems ({ pkgs, ... }: {
        default = pkgs.mkShell {
          name = "forge-dev";

          packages = with pkgs; [
            python311
            gnupg          # detached manifest signatures
            jq             # the CLI emits canonical JSON
            curl           # poking the REST API
            ruff
          ];

          shellHook = ''
            export PYTHONPATH="$PWD/src:$PWD:$PYTHONPATH"

            # Reproducible builds: pin the epoch so artifact digests are stable.
            export SOURCE_DATE_EPOCH=0

            # Safety rails, on by default in every dev shell.
            export FORGE_SEI_NETWORK="atlantic-2"   # testnet
            unset FORGE_ALLOW_MAINNET               # mainnet must be opt-in, always

            echo "forge dev shell"
            echo "  python   $(python3 --version)"
            echo "  gpg      $(gpg --version | head -1)"
            echo "  network  $FORGE_SEI_NETWORK (testnet; FORGE_ALLOW_MAINNET is unset)"
            echo
            echo "  python -m forge doctor"
            echo "  python -m unittest discover -s tests -t ."
            echo
          '';
        };
      });

      # ---- checks: `nix flake check` runs the full suite -----------------

      checks = forAllSystems ({ pkgs, system, ... }: {
        forge = self.packages.${system}.forge;

        # Reproducibility as a build-time gate: build the same intent twice in
        # separate sandboxes and require identical merkle roots. This is the
        # property the whole signing story rests on, so it is checked by the
        # build system rather than trusted.
        reproducible = pkgs.runCommand "forge-reproducible"
          {
            nativeBuildInputs = [ self.packages.${system}.forge pkgs.jq ];
          } ''
          export SOURCE_DATE_EPOCH=0
          export FORGE_SEI_NETWORK=atlantic-2

          forge build ${./examples/scan-billing.intent.json} \
            --workdir "$TMPDIR/a" --out "$TMPDIR/out-a" --no-sign --json \
            | jq -r .merkle_root > "$TMPDIR/root-a"

          forge build ${./examples/scan-billing.intent.json} \
            --workdir "$TMPDIR/b" --out "$TMPDIR/out-b" --no-sign --json \
            | jq -r .merkle_root > "$TMPDIR/root-b"

          if ! diff -q "$TMPDIR/root-a" "$TMPDIR/root-b" >/dev/null; then
            echo "build is not reproducible:"
            echo "  first:  $(cat "$TMPDIR/root-a")"
            echo "  second: $(cat "$TMPDIR/root-b")"
            exit 1
          fi

          diff -r "$TMPDIR/out-a" "$TMPDIR/out-b"
          echo "reproducible: $(cat "$TMPDIR/root-a")" | tee $out
        '';
      });

      # ---- NixOS --------------------------------------------------------

      nixosModules = rec {
        forge = import ./nix/module.nix;
        default = forge;
      };

      overlays.default = final: _prev: {
        forge = final.callPackage ./nix/package.nix { };
      };

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixpkgs-fmt);
    };
}
