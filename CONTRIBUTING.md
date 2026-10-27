# Contributing

## Report a TV

The most useful contribution is a report from a TV that is not in the
[compatibility list](README.md#compatibility) yet.

1. Follow the [root access steps](README.md#quick-start).
2. Run `tv-access --report`. It runs the read-only probe and prints the firmware
   build, Tizen version, kernel and architecture. It leaves out IP addresses,
   serial numbers and account data.
3. Open the link it prints. The issue form is prefilled; add your model from
   Settings > Support > About This TV and tick what you tried.

Please don't run `tv-setup` (app cleanup) on unlisted builds. It refuses them anyway.
If you tried `tv-key` or `tv-shot`, say so: the list tracks each feature separately.
A report for a build that is already listed is still useful if you tested more features.

Reports go into [compatibility.json](compatibility.json), which drives the README
table and `--probe`. Community reports are listed as such, not as maintainer-tested.

## Code

```sh
nix develop --no-write-lock-file
nix flake check --no-write-lock-file  # offline tests, no TV access
```

After editing `compatibility.json`, regenerate the README table:

```sh
python3 tools/tv_access/compat.py --write
```

Keep changes small and say which TV and build you tested on. Do not commit
firmware images, screenshots, reports or anything with account data.
Security issues: see [SECURITY.md](SECURITY.md).
