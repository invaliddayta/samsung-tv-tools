set -eu
D=/opt/var/tv-local-dns
test -f "$D/enabled"
if ! systemctl is-active --quiet tv-local-dns.service; then
 systemctl reset-failed tv-local-dns.service 2>/dev/null || true
 sleep 1
 /usr/bin/systemd-run --unit=tv-local-dns --service-type=simple -p 'Description=TV-local DNS filter' -p After=network.target -p User=root -p Group=root -p SmackProcessLabel=User -p UMask=0077 -p NoNewPrivileges=yes -p 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_KILL CAP_CHOWN' -p 'ExecStopPost=/usr/bin/dotnet /opt/var/tv-local-dns/DnsSupervisor.dll cleanup' -p Restart=on-failure -p RestartSec=2 -p TimeoutStopSec=15 -p KillMode=control-group -p StartLimitIntervalSec=60 -p StartLimitBurst=5 /usr/bin/dotnet "$D/DnsSupervisor.dll" run
fi
boot=$(cat /proc/sys/kernel/random/boot_id)
ready=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
 pid=$(systemctl show tv-local-dns.service -p MainPID --value)
 if test "$pid" != 0 && systemctl is-active --quiet tv-local-dns.service && test -f "$D/status.json" &&
    grep -F '"ready":true' "$D/status.json" >/dev/null &&
    grep -F "$boot" "$D/status.json" >/dev/null &&
    grep -F "\"supervisor_pid\":$pid," "$D/status.json" >/dev/null; then ready=1; break; fi
 sleep 1
done
test "$ready" = 1
cat "$D/status.json"
