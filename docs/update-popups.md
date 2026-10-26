# Suppress update-offer popups with DNS

Optional, external DNS filtering for Samsung's OS-upgrade offers. It does not
install a filter on the TV, and setup does not require root or Developer Mode.
You need a DNS resolver you control, such as Pi-hole, AdGuard Home or a router
with domain blocking. A plain public resolver such as Google Public DNS cannot
apply this custom list; a configurable hosted DNS service may support it.

**This blocks update infrastructure, not just the popup.** It can prevent
firmware checks and access to security updates. Use it only if you deliberately
want to keep the current firmware. It is not a guarantee against all updates,
advertising, telemetry or other notifications. Read [the risks](../SECURITY.md).

## What was tested

QE77S90C, Tizen 7, firmware 2000.2, build `T-PTMCDEUC-REL-202408210126`.
Turning auto-update off did not stop the OS-upgrade offer. On this TV, the
updater contacted `osb-v2.samsungqbe.com` and displayed the offer outside the
TV's ordinary notification controls.

An external dnsmasq resolver configured to return NXDOMAIN for the names in
[the blocklist](../blocklists/samsung-update-offers.txt) stopped that observed
check: after a normal standby wake, the updater logged a name-resolution
failure and cancelled the search. The offer counter remained unchanged from
19 to 26 October 2026. That is not continuous visual monitoring or proof against
every popup. The two other names appear to be related update endpoints;
neither was independently shown necessary to suppress the observed offer.
Our TV's DNS was set through ConnMan; the menu route below was not separately
tested.

Other models, firmware builds and resolver blocking modes are unverified.
The root-access reports in the README do **not** establish popup-filter support.

## Set it up

1. Record the TV's current DNS settings and any resolver configuration you change
   so you can undo this. Do not change firmware or start an update check.
2. Review [the three-domain list](../blocklists/samsung-update-offers.txt).
   Add its entries to your resolver's blocklist:
   - **Pi-hole:** add each name as an exact denylisted domain in the web interface.
   - **AdGuard Home:** paste the three names into **Filters → Custom filtering
     rules**, one per line. Its [domains-only syntax](https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#domains-only-syntax)
     supports these exact-domain rules; no remote-list subscription is needed.
   - **Router:** use its DNS domain-blocking feature, if available. URL/content
     filtering is not necessarily DNS filtering.

   Scope the rules to the TV where supported; otherwise they affect other clients
   using that resolver too. **Do not block all of `samsungqbe.com`**: unrelated
   Samsung services also use it.

   To match the tested response, select **NXDOMAIN** in your resolver's blocking
   mode setting. In Pi-hole and AdGuard Home this changes responses for all
   blocked domains on that resolver, not just this list. Review the impact on
   other clients before changing it.
3. In the TV's network/IP settings, set DNS manually to your filtering resolver's
   LAN address. Menu names vary by model. Alternatively, configure your network
   to supply that resolver to the TV.
4. Any secondary resolver supplied to the TV must apply the same list. An
   unfiltered public fallback can bypass it. Check IPv6 DNS supplied by your
   router as well; setting an IPv4 DNS address alone may not cover that path.
   Keep the resolver available while the TV is online.

This does not intercept apps using hardcoded resolvers or encrypted DNS.
A hardcoded public resolver was seen in use on our TV; encrypted-DNS use was
not established. Filtering may not suppress an offer already cached on the TV.
Do not clear system databases or upgrade flags trying to force a result.

## Check it without triggering an update

On a client permitted to query your resolver, replace `192.0.2.53` below with
its actual LAN address:

```sh
nslookup osb-v2.samsungqbe.com 192.0.2.53
nslookup example.com 192.0.2.53
```

The update domain should get a blocked response while the ordinary domain
resolves. Our tested setup used NXDOMAIN; some blockers instead return `0.0.0.0`
or `::`. Those responses are not yet verified for popup suppression on this TV.
A timeout on both queries is a resolver/connectivity problem, not success.

If you already have root access, the same DNS-only check can run from the TV:

```sh
tv-access 'nslookup osb-v2.samsungqbe.com 192.0.2.53'
```

An explicit lookup proves only that resolver's answer. Check your resolver's
query log for the TV's ordinary A/AAAA requests during normal use or its next
usual standby wake. A blocked query does not prove all DNS uses that resolver.
Check streaming, sign-in and other services you use. Do not trigger an updater
scan, firmware download or reboot just to test this.

## Undo

Remove the three block entries, restore any DNS settings and resolver blocking
mode you changed, and allow existing DNS cache entries to expire. This
allows update checks and offers again; it does not restore removed apps or
change firmware. Undo the rules if normal services break rather than expanding
the block to whole Samsung domains.

To report a result, [open an issue](https://github.com/invaliddayta/samsung-tv-tools/issues/new)
with the model, firmware/build, resolver and blocking mode, whether offers
stopped, and any side effects. Do not post raw DNS logs, IP addresses, serials
or account details.
