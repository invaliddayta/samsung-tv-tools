{
  description = "Samsung TV tools: root commands, keys, screenshots and app cleanup for Tizen TVs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      packageFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
          runtime = with pkgs; [ python3 bash coreutils openssl ];
        in pkgs.stdenvNoCC.mkDerivation {
          pname = "samsung-tv-tools";
          version = "0.3.0";
          src = pkgs.lib.cleanSourceWith {
            src = self;
            filter = path: type:
              let
                relative = pkgs.lib.removePrefix ("${self}/") (toString path);
                top = builtins.head (pkgs.lib.splitString "/" relative);
              in (toString path == toString self) || (
                builtins.elem top [ "tools" "profiles" "docs" "README.md" "compatibility.json"
                  "CONTRIBUTING.md" "SECURITY.md" "THIRD_PARTY.md" "LICENSE" "flake.nix" "flake.lock" ]
                && relative != "tools/app_sync_guard/build"
                && !(pkgs.lib.hasPrefix "tools/app_sync_guard/build/" relative)
                && builtins.match "tools/tv_dns/[^/]+/build(/.*)?" relative == null
                && relative != "tools/tv_access/config.json"
                && !(pkgs.lib.hasInfix "/__pycache__" relative)
                && !(pkgs.lib.hasSuffix ".pyc" relative)
              );
          };
          nativeBuildInputs = with pkgs; [ makeWrapper mono python3 sqlite openssl util-linux ];
          buildPhase = ''
            runHook preBuild
            export HOME=$TMPDIR/home
            mkdir -p "$HOME"
            bash tools/app_sync_guard/build.sh
            for tool in tv_access app_sync_guard; do
              (cd tools/$tool && sha256sum -c SHA256SUMS)
            done
            runHook postBuild
          '';
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            python3 -m unittest discover -s tools/tv_access/tests
            python3 -W error::ResourceWarning -m unittest discover -s tools/app_sync_guard/tests
            python3 -W error::ResourceWarning -m unittest discover -s tools/tests
            python3 tools/tv_access/compat.py --check
            # TV-local DNS: component tests and an unsigned package assembly, nothing shipped
            bash tools/tv_dns/service/build.sh
            rm -rf tools/tv_dns/service/build
            mcs -warn:4 -main:ProtocolTests -out:"$TMPDIR/ProtocolTests.exe" \
              tools/tv_dns/boot/DnsBootProbe.cs tools/tv_dns/boot/tests/ProtocolTests.cs
            mono "$TMPDIR/ProtocolTests.exe"
            python3 tools/tv_dns/boot/build.py --out "$TMPDIR/dnsboot"
            runHook postCheck
          '';
          installPhase = ''
            runHook preInstall
            destination=$out/share/samsung-tv-tools
            mkdir -p "$destination" "$out/bin"
            cp -R tools profiles docs README.md compatibility.json CONTRIBUTING.md SECURITY.md THIRD_PARTY.md LICENSE "$destination/"
            find "$destination/tools" -type d '(' -name __pycache__ -o -name tests ')' -prune -exec rm -rf {} +
            for tool in tv-access tv-key tv-shot; do
              makeWrapper "$destination/tools/tv_access/$tool" "$out/bin/$tool" --prefix PATH : ${pkgs.lib.makeBinPath runtime}
            done
            makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/tv-setup" --add-flags "$destination/tools/tv-setup.py" --prefix PATH : ${pkgs.lib.makeBinPath runtime}
            runHook postInstall
          '';
          meta = {
            description = "Root commands, keys, screenshots and app cleanup for Samsung Tizen TVs";
            license = [ pkgs.lib.licenses.mit pkgs.lib.licenses.unlicense ];
            platforms = systems;
            mainProgram = "tv-access";
          };
        };
    in {
      packages = eachSystem (system: { default = packageFor system; });
      apps = eachSystem (system:
        let
          app = name: {
            type = "app";
            program = "${self.packages.${system}.default}/bin/${name}";
            meta.description = "${name} for Samsung Tizen TVs";
          };
        in {
          default = app "tv-access";
          tv-access = app "tv-access";
          tv-setup = app "tv-setup";
          tv-key = app "tv-key";
          tv-shot = app "tv-shot";
        });
      checks = eachSystem (system: { offline = self.packages.${system}.default; });
      devShells = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = with pkgs; [ python3 bash coreutils openssl mono sqlite util-linux ];
        }; });
    };
}
