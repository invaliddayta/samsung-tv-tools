# TV-local DNS blocking (advanced)

On-device DNS blocking for rooted Samsung Tizen TVs, using the TV's native
resolver and firewall. **Unlike tv-access, it adds a component that runs at every
boot.** It briefly changes the Developer Mode IP and makes native DNS depend on
a local service. No separate LAN resolver or proxy is required.
Read [the risks](../SECURITY.md) first.

There is no installer, uninstaller or rollback tool. The steps below are manual,
and each one is yours to check.

## Status: read this first

The implementation targets rooted Tizen TVs that meet the prerequisites below;
there is no model whitelist. Compatibility must be validated per firmware.

**Validated: version 0.0.6 on QE77S90C, Tizen 7,
`T-PTMCDEUC-REL-202408210126`.** Real-profile signing, an in-place upgrade from
0.0.5 (numeric NTP and loopback DNS already configured) and one fresh-boot test
passed:

- Automatic root bootstrap and DNS readiness at about 65 seconds, with the
  Developer Mode IP restored and zero worker or supervisor restarts.
- 60 blocked-name queries returned NXDOMAIN: three domains × A/AAAA × UDP/TCP ×
  five local/hardcoded destinations. Allowed names resolved; external IPv6 DNS
  was rejected.
- Six loopback listeners, UID/GID 99, empty worker capability sets,
  `NoNewPrivs=1` and dedicated cgroup/firewall ownership.
- Native DNS and numeric NTP settings were preserved; firmware and updater
  safeguards were unchanged.
- YouTube/Netflix HTTPS checks and TizenTube's trusted proxy TLS and app startup
  passed. Playback was not retested with 0.0.6.

First-time installation and rollback with 0.0.6, other models, slow/offline
startup and interruption during the Developer Mode IP change remain unverified.
This is not a guarantee against every update popup or encrypted DNS (DoH).
Removal is not automatically safe; see
[Disable and roll back](#disable-and-roll-back).

## What it does

1. The on-boot app `dnsbootprb.Service` waits 8 seconds and arms a recovery
   watchdog. It then sets the Developer Mode IP to `127.0.0.1` and uses the same
   SDB root path as tv-access, locally, to run one signed root payload. Then it
   restores your computer's IP.
2. The payload checks the activation flags, the owner and mode of every
   installed file, and `startup.sha256`. It then runs `startup.command` with
   `/bin/sh -c "$(cat …)"`. Do not change this to `sh startup.command`: Samsung's
   UEP can refuse to execute unsigned script files.
3. `startup.command` creates the transient `tv-local-dns.service` unit. It has
   limited capabilities and no `SYS_ADMIN` or `SYS_PTRACE`. The unit runs the TV's
   own dnsmasq as UID 99 on `127.0.0.1`, `127.0.0.2` and `::1` only.
4. The supervisor redirects all other IPv4 DNS (UDP/TCP 53) to that resolver and
   rejects external IPv6 DNS. Only the resolver's own cgroup is exempt.

Blocked: `osb-v2.samsungqbe.com`, `osb.samsungqbe.com` and
`osbstg-v2.samsungqbe.com`, including subdomains. Other names go to AdGuard DNS
(`94.140.14.14`, `94.140.15.15`), the tested choice. **AdGuard also filters ads and
trackers.** Changing the upstreams means editing the source, and is untested.
There is no query log. Blocking these domains can prevent firmware/security
update checks: see [SECURITY.md](../SECURITY.md).

## Limits

- **Startup gap.** DNS is unavailable for about a minute after each boot until
  the service is ready. Apps with hard-coded DNS are unfiltered until the rules
  exist. A slow or offline network at boot was not tested.
- **Developer Mode flip.** For a few seconds per boot, the Developer Mode IP is
  `127.0.0.1`. The app restores it, and watchdogs restore it after 120 s (app) and
  45 s (root). The watchdogs die with the boot. A reboot, power loss or standby
  during the flip can leave `127.0.0.1` in place. You then have to re-enter your
  computer's IP in Developer Mode. The app refuses to start if the stored IP is
  already a loopback or invalid address.
- **One SDB client.** sdbd serves one client at a time. Keep tv-access and other
  SDB clients idle for the first few minutes after a boot. Our tests waited 240 s.
  If the app's handshake fails, nothing retries until the next boot.
- **`127.0.0.2` is shared.** The service adds `127.0.0.2/32` to `lo` and removes it
  whenever it stops. Anything else using that address loses it too: on our TV,
  TizenTube's local proxy uses `127.0.0.2:8101`. The service never claims or
  removes an address that existed before it started.
- **Restart limits.** Worker and supervisor restarts are each limited to 5 in
  60 seconds. After that the unit stays failed. With loopback-only native DNS the
  TV then has no DNS until you start the service again.
- The firewall hook is checked for presence, not for being first in `OUTPUT`.
  The worker checks expect the tested firmware's `/proc` fields (UID/GID 99, empty
  capability sets, `NoNewPrivs 1`). Other firmware may fail them.

## Prerequisites

- Root through tv-access (`id -u` prints 0), plus the firmware's dnsmasq,
  iptables/ip6tables, `net_cls` cgroup support, systemd and compatible .NET runtime.
  Root access alone does not prove these prerequisites or on-boot behavior.
- Developer Mode stays on, with your computer's IPv4 address.
- **Your own Samsung TV author and distributor certificates** (`.p12`) for this
  TV. None are provided. The validated package used a profile created at the
  Partner privilege level, and the TV ran its `on-boot="true"` service. It
  is unknown whether TVs run on-boot services from packages signed at other
  privilege levels or with other profiles.
- Numeric NTP, and a written backup of the clock and DNS settings (below).
- `nix develop --no-write-lock-file`, or Mono, Python 3, OpenSSL and `setsid`.

## Build

```sh
nix develop --no-write-lock-file
bash tools/tv_dns/service/build.sh        # tests, then tools/tv_dns/service/build/
python3 tools/tv_dns/boot/build.py --out tools/tv_dns/boot/build   # UNSIGNED, not installable
read -rsp 'Author .p12 password: ' TIZEN_AUTHOR_P12_PASSWORD; echo
read -rsp 'Distributor .p12 password: ' TIZEN_DISTRIBUTOR_P12_PASSWORD; echo
export TIZEN_AUTHOR_P12_PASSWORD TIZEN_DISTRIBUTOR_P12_PASSWORD
python3 tools/tv_dns/boot/build.py --out tools/tv_dns/boot/build \
  --author-p12 /path/to/author.p12 --distributor-p12 /path/to/distributor.p12
```

Builds are not reproducible. Install `DnsSupervisor.dll` only together with the
`startup.sha256` from the same build. Do not commit `build/`.

## Install

Run each step separately and check its output before the next one.

**1. Numeric NTP.** With loopback-only DNS, the TV cannot resolve NTP host names
until the service is ready. A boot clock at 1970 can make apps such as TizenTube
cache invalid TLS certificates. Numeric time servers allow synchronization
before local DNS is ready. Choose the provider yourself: the TV will send
unauthenticated NTP requests to it. The validated configuration uses
Cloudflare's published `162.159.200.1` and `162.159.200.123`.

```sh
tv-access 'busctl call net.connman / net.connman.Clock GetProperties'   # keep this output
tv-access 'busctl call net.connman / net.connman.Clock SetProperty sv Timeservers as 2 162.159.200.1 162.159.200.123'
```

Leave `TimeUpdates` and `TimezoneUpdates` unchanged. To roll back, set the recorded
list again, for example `as 0` if it was empty. Samsung's `TimeUpdated` flag can
stay false after a successful sync, so check `date -u` instead.

**2. Stage the service.** tv-access has no file upload, so each file is sent as
base64 and its SHA-256 is printed for comparison:

```sh
tv-access 'set -e; test ! -e /opt/var/tv-local-dns; mkdir -m 700 /opt/var/tv-local-dns; chown 0:0 /opt/var/tv-local-dns'
put() { tv-access "set -e; umask 077; printf %s '$(base64 -w0 "$1")' | base64 -d > '$2.new'; chown 0:0 '$2.new'; mv '$2.new' '$2'; sha256sum '$2'"; }
for f in startup.command startup.sha256 DnsSupervisor.dll DnsSupervisor.runtimeconfig.json; do
  put "tools/tv_dns/service/build/$f" "/opt/var/tv-local-dns/$f"
done
tv-access 'umask 077; echo on > /opt/var/tv-local-dns/enabled'
```

**3. Start and check it** while native DNS is unchanged:

```sh
tv-access --timeout 60 'cd /opt/var/tv-local-dns && sha256sum -c startup.sha256 && /bin/sh -c "$(cat startup.command)"'
q='/usr/bin/dotnet /opt/var/tv-local-dns/DnsSupervisor.dll query'
tv-access "$q 127.0.0.2 udp osb-v2.samsungqbe.com 1"   # rcode=3 answers=0
tv-access "$q ::1 tcp osb.samsungqbe.com 28"           # rcode=3 answers=0
tv-access "$q 8.8.8.8 udp osbstg-v2.samsungqbe.com 1"  # rcode=3 answers=0 (redirected)
tv-access "$q 127.0.0.1 tcp example.com 1"             # rcode=0 answers=1 or more
tv-access "$q 2001:4860:4860::8888 udp example.com 28" # must fail
tv-access 'ip6tables -nvL TV_LOCAL_DNS6'               # REJECT counters rose
```

The IPv6 check is only meaningful if the TV has IPv6 connectivity.

`query` is read-only and changes no service state. It exits 0 for any DNS
response, 1 on error or timeout and 2 on bad arguments.

**4. Install the package, then enable boot start.** Installing or updating the
package launches the app at once. Without `/opt/dnsboot/dns-enabled` it only logs
"disabled" and exits. `put` is the helper from step 2.

```sh
tv-access 'test ! -e /opt/dnsboot/dns-enabled'
put tools/tv_dns/boot/build/dnsbootprb-0.0.6.tpk /opt/var/tv-local-dns/dnsbootprb.tpk
tv-access --timeout 90 'pkgcmd -i -t tpk -p /opt/var/tv-local-dns/dnsbootprb.tpk; s=$?; rm -f /opt/var/tv-local-dns/dnsbootprb.tpk; exit $s'
tv-access 'set -e; test ! -L /opt/dnsboot; mkdir -p /opt/dnsboot; chown 0:0 /opt/dnsboot; chmod 755 /opt/dnsboot
echo on > /opt/dnsboot/dns-enabled; chmod 644 /opt/dnsboot/dns-enabled; chsmack -a System::Shared /opt/dnsboot/dns-enabled'
```

**5. Native DNS.** Switch only after steps 3 and 4 succeeded. Find the connected
service (marked with `*` and `O` or `R`) and record its exact array, mode tokens
and order included. Keep this private. Do not read ConnMan's settings files,
which can contain Wi-Fi credentials.

```sh
tv-access 'connmanctl services'
tv-access 'connmanctl services SERVICE | grep -F "Nameservers.Configuration ="'
# example: Nameservers.Configuration = [ ipv4.manual, ipv6.dhcp, 192.0.2.53 ]
tv-access 'busctl call net.connman /net/connman/service/SERVICE net.connman.Service SetProperty sv Nameservers.Configuration as 5 ipv4.manual ipv6.manual 127.0.0.1 127.0.0.2 ::1'
tv-access 'connmanctl services SERVICE | grep -F "Nameservers.Configuration ="; cat /opt/etc/resolv.conf'
```

`/opt/etc/resolv.conf` should then list only `127.0.0.1` and `127.0.0.2`.

- **Use two different IPv4 loopbacks.** With one IPv4 loopback plus `::1`, or the
  same loopback twice, our TV added `8.8.8.8` as a second resolver.
- `ipv6.manual` sets the DNS mode only. Address assignment is unchanged.
- **Never write `resolv.conf` and never restart ConnMan.** TV boot services depend
  on it.
- The setting belongs to this network service. On another network the TV uses
  that network's own DNS settings.

**6. After the next normal restart**, keep SDB idle for a few minutes, then check
the following. Do not use `systemctl reboot --force`.

```sh
tv-access 'cat /proc/sys/kernel/random/boot_id /opt/dnsboot/proof.txt /opt/var/tv-local-dns/status.json'
tv-access 'tail -n 20 /opt/usr/home/owner/apps_rw/dnsbootprb/data/probe.log'
```

`proof.txt` must show the current boot ID, `uid=0(`, `dns_ready=1` and
`payload done`. Also repeat the queries from step 3.

## Update

Stop the old service before replacing anything. `systemctl stop` runs the
installed (old) DLL's cleanup, which removes its firewall chains and the
`127.0.0.2` it added.

1. Remove `/opt/dnsboot/dns-enabled` if the package changes too.
2. Note the addresses on `lo` and whether the service added `127.0.0.2` in this
   boot, then stop it. With loopback-only DNS, the TV has no DNS from here until
   step 5.

   ```sh
   tv-access 'ip -4 address show dev lo; cat /proc/sys/kernel/random/boot_id /opt/var/tv-local-dns/loopback-owned'
   tv-access 'systemctl stop tv-local-dns.service'
   ```

   The service owns `127.0.0.2` only if `loopback-owned` exists and holds the
   current boot ID. A missing file means it does not.
3. Check that the cleanup ran. A failing `iptables -S TV_LOCAL_DNS4` is **not**
   proof that the chain is gone; it also fails when, for example, the xtables
   lock is busy. Inspect both whole tables instead. The IPv6 chain is in the
   filter table.

   ```sh
   tv-access 'for t in "iptables -w 5 -t nat" "ip6tables -w 5"; do s=$($t -S) || { echo "$t -S FAILED"; continue; }; printf "%s\n" "$s" | grep -e "^-P OUTPUT " -e TV_LOCAL_DNS; done'
   tv-access 'ip -4 address show dev lo; cat /opt/var/tv-local-dns/loopback-owned'
   ```

   The first command must print exactly two `-P OUTPUT` lines (one per table)
   and nothing else: no `FAILED`, no `TV_LOCAL_DNS` chain (`-N`) or jump (`-j`).
   If the service owned `127.0.0.2` in step 2, that address and `loopback-owned`
   must now be gone. Any other address, including a `127.0.0.2` the service did
   not own, must still be listed as in step 2.

   **If any check fails or is unclear, stop here and keep every installed file.**
   The old service keeps its ownership markers. Once the cause is gone (for
   example the xtables lock), run its cleanup by hand (below) and check again.
4. Replace all four files from one build, using `put` as in Install step 2.
5. Start and check the service as in Install step 3.
6. Install the package and recreate the flag as in Install step 4.

**Never overwrite the running DLL first.** A restart or stop would then run the
new code against the old chains. This version treats them as unowned: it refuses
to start and leaves them in place. With loopback-only DNS the TV then has no
DNS. These chains are runtime state, and a normal reboot normally clears them.
That is not a guaranteed repair. Downgrades work the same way: stop first.

Run `DnsSupervisor.dll cleanup` by hand only after a stop. It refuses while the
supervisor runs:
`tv-access '/usr/bin/dotnet /opt/var/tv-local-dns/DnsSupervisor.dll cleanup'`.

## Disable and roll back

**Restore native DNS first, and keep the local service running until the TV no
longer uses loopback DNS.** On our TV, restoring the saved array still left a
stale `127.0.0.1` in the generated resolver list. Switching DNS modes or using
`connmanctl` did not clear it.

1. Restore the exact recorded array, with mode tokens and order:
   `busctl call net.connman /net/connman/service/SERVICE net.connman.Service SetProperty sv Nameservers.Configuration as 3 ipv4.manual ipv6.dhcp 192.0.2.53`.
2. Check both the property and `/opt/etc/resolv.conf`.
3. **If either still lists a loopback address, stop here and leave the service and
   flags in place.** A later normal restart may refresh it; this was not tested as
   a rollback. Do not restart ConnMan or edit the file.
4. Once only your real resolvers are listed, remove `/opt/dnsboot/dns-enabled`
   and `/opt/var/tv-local-dns/enabled`. Record `lo` and `loopback-owned` as in
   [Update](#update) step 2, then stop it with
   `tv-access 'systemctl stop tv-local-dns.service'`. Native DNS is already
   restored at this point; Update's temporary DNS-outage warning does not apply.
5. Check the cleanup as in Update step 3. **If any check fails or is unclear,
   stop and keep the package and all files;** retry the cleanup as described
   there. A leftover hook sends every DNS query to the stopped resolver.
6. Check native resolution: `tv-access 'nslookup example.com'` must name your
   restored resolver as the server, not a loopback address, and return an
   address.
7. Roll back NTP separately if you want (step 1 of Install).

Without `/opt/dnsboot/dns-enabled` the installed app exits at boot without
touching SDB. Removing the package and the files was not tested; never remove
them after an unclear cleanup.
