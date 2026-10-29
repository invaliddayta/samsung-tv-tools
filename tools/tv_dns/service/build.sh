#!/usr/bin/env bash
# Local compilation and offline tests only. Never contacts the TV or installs anything.
# build/ receives the four files installed in /opt/var/tv-local-dns; startup.sha256
# lists the other three with their installed absolute paths (sha256sum -c format).
set -euo pipefail
cd -- "$(dirname -- "$0")"
installed=/opt/var/tv-local-dns
mono=()
command -v mcs >/dev/null 2>&1 || mono=(nix shell nixpkgs#mono -c)
rm -rf build
mkdir -p build/tests
"${mono[@]}" mcs -target:exe -out:build/DnsSupervisor.dll DnsSupervisor.cs
"${mono[@]}" mcs -target:exe -main:PolicyTests -out:build/tests/PolicyTests.exe DnsSupervisor.cs tests/PolicyTests.cs
"${mono[@]}" mono build/tests/PolicyTests.exe
cp DnsSupervisor.runtimeconfig.json startup.command extra-domains.conf.example build/
for file in startup.command DnsSupervisor.dll DnsSupervisor.runtimeconfig.json; do
    printf '%s  %s/%s\n' "$(sha256sum < "build/$file" | cut -d ' ' -f 1)" "$installed" "$file"
done > build/startup.sha256
cat build/startup.sha256
