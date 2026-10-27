# Samsung TV tools

![Samsung TV tools](docs/banner.svg)

Root commands, remote control, screenshots, app cleanup and persistent on-device
DNS blocking for Samsung Tizen TVs. Uses
[chris-ritsen's archive-root bootstrap](https://github.com/chris-ritsen/samsung-tv-root).
No firmware flash.

## Features

| Feature | What it does |
|---|---|
| Root shell | Run bounded commands over SDB with stdout, stderr and exit status |
| Remote control | Send key presses with `tv-key` |
| Screenshots | Capture the compositor with `tv-shot` (not protected video) |
| App cleanup | Preview and apply selected settings and app removals on supported builds |
| [TV-local DNS blocking](docs/tv-local-dns.md) | Filter Samsung update-offer domains on the TV, with automatic boot startup and UDP/TCP diagnostics |

## Quick start

Use a trusted LAN and enable Developer Mode with your computer's LAN IP
([instructions](docs/usage.md#developer-mode)). Turn off automatic firmware and
app updates first. **Do not update, downgrade or flash firmware to match a listed
build.** Read [the risks](SECURITY.md).

```sh
git clone https://github.com/invaliddayta/samsung-tv-tools.git
cd samsung-tv-tools
export TV_HOST=192.0.2.10  # replace with your TV's address
nix run .#tv-access -- --probe
nix run .#tv-access -- 'id -u'  # must print 0
```

Without Nix, use `./tools/tv_access/tv-access` with Python 3, Bash and OpenSSL.
`tv-access` gets root on demand: no developer certificate or permanent boot
service is needed. The optional DNS service has separate requirements below.
SMACK/UEP and read-only filesystem restrictions still apply.

## Commands

| Command | Purpose |
|---|---|
| `tv-access 'command'` | Run a root command |
| `tv-access --probe` | Check root access and whether the build is listed |
| `tv-access --report` | Generate a shareable compatibility report |
| `tv-key XF86Home` | Send remote-control keys |
| `tv-shot /tmp/tv.png` | Save a compositor screenshot |
| `tv-setup plan/apply/verify` | Preview, apply or verify settings and app removals |

Use `nix run .#COMMAND -- ...`, or install the
[local symlinks](docs/usage.md#local-installation).

## TV-local DNS blocking

An optional boot service runs the TV's native dnsmasq, blocking three Samsung
update-offer domains and their subdomains. Other names go to AdGuard DNS, which
also filters ads and trackers. It redirects other IPv4 DNS requests (UDP/TCP
port 53) to the local resolver and rejects external IPv6 DNS. No separate LAN
DNS server or proxy is required. Encrypted DNS such as DoH is not blocked.

Setup requires root access, Developer Mode, your own Samsung TV signing
certificates (validated with a Partner-level profile) and DNS-independent time
synchronization. The service briefly changes the Developer Mode IP at each boot.
Filtering starts once the service is ready, not immediately at power-on. It can
prevent firmware/security update checks, and native DNS rollback requires care.

See [setup, prerequisites, validation and rollback](docs/tv-local-dns.md).
Compatibility depends on firmware capabilities; root access alone does not
establish DNS-service compatibility.

## App cleanup

`tv-setup` is restricted to the firmware/model combination marked `cleanup` in
the [compatibility table](#compatibility). The included profile selects 24 ad
components and Ambient themes; streaming apps and device integrations are kept
unless selected.

```sh
mkdir -p local
cp profiles/s90c.json local/my-tv.json
# Review the consequences and edit remove: true/false.
nix run .#tv-setup -- plan --profile local/my-tv.json
nix run .#tv-setup -- apply --profile local/my-tv.json
nix run .#tv-setup -- verify --profile local/my-tv.json
```

Apply requires confirmation. App removal can delete data and is not fully
reversible; run it when nobody is watching. The full automated apply workflow
has offline tests only. See [cleanup, guard and recovery](docs/debloat.md).

## Compatibility

Support is feature- and firmware-specific. The table records tested features,
not blanket support for every tool. DNS-specific validation is documented in
the [DNS guide](docs/tv-local-dns.md#status-read-this-first).

<!-- compatibility:start -->
| Model | Tizen | Firmware build | Works | Source |
|---|---|---|---|---|
| QE77S90C (S90C, 2023) | 7.0 | `T-PTMCDEUC-REL-202408210126` | root, keys, screenshot, cleanup | maintainer-tested |
| QE65S85D (S85D, 2024) | 9.0 | `T-PTMDDEUC-0090-REL-202609252355` | root, keys | [ibrahimvarola](https://github.com/invaliddayta/samsung-tv-tools/issues/3) |
| S90C | 9.0 | `T-PTMCDEUC-0090-REL-202603190158` | root, keys, screenshot | [ondererguven](https://github.com/invaliddayta/samsung-tv-tools/issues/4) |
| S90C | 9.0 | `T-PTMCAKUC-0090-REL-202603190200` | root, screenshot | [chriseivert](https://github.com/invaliddayta/samsung-tv-tools/issues/5) |
| S90D | 8.0 | `T-PTMDDEUC-REL-202601212151` | root | [rkorn86](https://github.com/invaliddayta/samsung-tv-tools/issues/1) |
| S90D | 9.0 | `T-PTMDAKUC-0090-REL-202605141701` | root | [tpollard64](https://github.com/invaliddayta/samsung-tv-tools/issues/1#issuecomment-6391371635) |
| S95C | 9.0 | `T-PTMCDEUC-0090-REL-202603190158` | root | [magne4000](https://github.com/invaliddayta/samsung-tv-tools/issues/2) |
<!-- compatibility:end -->

To report another TV or additional features, run `tv-access --report`.
The report excludes IP addresses and serial numbers and links to a prefilled
issue. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

```sh
nix develop --no-write-lock-file
nix flake check --no-write-lock-file  # offline tests, no TV access
```

[Usage and builds](docs/usage.md) · [Contributing](CONTRIBUTING.md) ·
[Attribution and binary provenance](THIRD_PARTY.md)

First-party code: [MIT](LICENSE). Upstream bootstrap: Unlicense.
Not affiliated with Samsung.
