#!/bin/sh
# Root payload of the dnsbootprb on-boot app. Runs as root via the vendored
# archive-root bootstrap (sdbd-tarlauncher --to-command) at every boot where
# the on-boot service app submits this job.
# Starts only the explicitly enabled, root-owned TV-local DNS installation.
# No firmware, resolver settings, global firewall flush or unit enablement.
set -u
JOB=archive-root-d0cb000000000001
D=/home/owner/share/tmp/sdk_tools/$JOB
# Samsung's appinstall entry point may evaluate the launch twice.
# Keep this marker until the next app launch explicitly re-stages the job.
if ! mkdir "$D/run.once" 2>/dev/null; then exit 0; fi
REQUEST=$(cat "$D/request.id") || exit 1
case "$REQUEST" in *[!0-9a-f]*|'') exit 1;; esac
test "${#REQUEST}" = 32 || exit 1
ORIGINAL=$(cat "$D/original.peer") || exit 1
case "$ORIGINAL" in *[!0-9.]*|127.*|0.0.0.0|255.255.255.255|'') exit 1;; esac

# Safety net if the app-side finally-restore fails: after 45 s, restore the
# recorded original SDK peer if it is still loopback. Like every process
# watchdog it dies with the boot, so it does NOT cover a reboot or power loss
# during the peer flip, and it may not survive standby.
# The watchdog MUST be setsid-detached: if the job (and its process group) is
# killed mid-run, a plain subshell watchdog dies with it and the peer flip is
# stranded. Without setsid, refuse rather than run an unsafe watchdog.
if [ -x /usr/bin/setsid ]; then
  /usr/bin/setsid /bin/sh -c "sleep 45; if vconftool get db/sdk/develop/ip | grep -F 'value = 127.0.0.1 (String)' >/dev/null; then vconftool set -f -t string db/sdk/develop/ip '$ORIGINAL'; fi" </dev/null >/dev/null 2>&1 &
else
  echo 'Missing setsid; refusing an unsafe recovery watchdog' >&2
  exit 1
fi

umask 022
test ! -L /opt/dnsboot || exit 1
mkdir -p /opt/dnsboot
chown 0:0 /opt/dnsboot
chmod 755 /opt/dnsboot
test ! -L /opt/dnsboot/proof.txt || exit 1
if test -e /opt/dnsboot/proof.txt; then chmod 644 /opt/dnsboot/proof.txt; fi
{
  echo "=== dnsbootprb proof $(date -u '+%FT%TZ') ==="
  echo "boot_id=$(head -1 /proc/sys/kernel/random/boot_id)"
  echo "request_id=$REQUEST"
  echo "uptime=$(head -1 /proc/uptime)"
  id
} > /opt/dnsboot/proof.txt 2>&1
/bin/chsmack -a "System::Shared" /opt/dnsboot/proof.txt 2>/dev/null || true

# Root-controlled activation, staged manually as root and checked here.
DNS=/opt/var/tv-local-dns
test -f /opt/dnsboot/dns-enabled && test -f "$DNS/enabled" || exit 1
test ! -L "$DNS" && test "$(stat -c "%u:%g:%a" "$DNS")" = 0:0:700 || exit 1
for file in startup.command startup.sha256 DnsSupervisor.dll DnsSupervisor.runtimeconfig.json; do
  test ! -L "$DNS/$file" && test "$(stat -c "%u:%g:%a" "$DNS/$file")" = 0:0:600 || exit 1
done
sha256sum -c "$DNS/startup.sha256" >> /opt/dnsboot/proof.txt 2>&1 || exit 1
/bin/sh -c "$(cat "$DNS/startup.command")" >> /opt/dnsboot/proof.txt 2>&1 || exit 1
echo dns_ready=1 >> /opt/dnsboot/proof.txt
echo "payload done $(date -u '+%FT%TZ')" >> /opt/dnsboot/proof.txt
exit 0
