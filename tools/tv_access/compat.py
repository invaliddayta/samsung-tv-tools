#!/usr/bin/env python3
"""Compatibility registry: which TVs and firmware builds are known to work.

compatibility.json is the single source for --probe, --report and the README
table. Run `python3 tools/tv_access/compat.py --write` after editing it.
"""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / 'compatibility.json'
README = ROOT / 'README.md'
REPO = 'https://github.com/invaliddayta/samsung-tv-tools'
START, END = '<!-- compatibility:start -->', '<!-- compatibility:end -->'
SOURCES = {'maintainer', 'community'}
BUILD_RE = re.compile(r'^T-[A-Z0-9]+(-[A-Z0-9]+)*$')
REQUIRED = ('model', 'build', 'tizen', 'kernel', 'arch', 'source', 'date', 'works')


def validate(data):
    """Raise ValueError unless the registry is consistent."""
    if not isinstance(data, dict) or data.get('schema') != 1:
        raise ValueError('compatibility.json: schema must be 1')
    features, devices = data.get('features'), data.get('devices')
    if not isinstance(features, dict) or not isinstance(devices, list) or not devices:
        raise ValueError('compatibility.json: features and devices are required')
    seen = set()
    for index, device in enumerate(devices):
        where = f'compatibility.json device {index}'
        missing = [key for key in REQUIRED if not device.get(key)]
        if missing:
            raise ValueError(f'{where}: missing {", ".join(missing)}')
        build = device['build']
        if not BUILD_RE.match(build):
            raise ValueError(f'{where}: invalid build {build!r}')
        # One firmware build can ship on several models (S90C and S95C share builds).
        if (build, device['model']) in seen:
            raise ValueError(f'{where}: duplicate entry for {device["model"]} {build}')
        seen.add((build, device['model']))
        if device['source'] not in SOURCES:
            raise ValueError(f'{where}: source must be maintainer or community')
        unknown = set(device['works']) - set(features)
        if unknown or 'root' not in device['works']:
            raise ValueError(f'{where}: works must include root and only known features')
        if device['source'] == 'community':
            if not device.get('reporter') or not str(device.get('report', '')).startswith(REPO + '/'):
                raise ValueError(f'{where}: community reports need reporter and report link')
            # App removal is destructive; it stays limited to maintainer-tested builds.
            if 'cleanup' in device['works']:
                raise ValueError(f'{where}: cleanup can only be listed for maintainer-tested builds')
    return data


def load(path=REGISTRY):
    return validate(json.loads(Path(path).read_text()))


def lookup(build, data=None):
    """All entries for a firmware build, maintainer-tested first."""
    data = data or load()
    matches = [d for d in data['devices'] if d['build'] == build]
    return sorted(matches, key=lambda d: (d['source'] != 'maintainer', d['date']))


def assessment(build, data=None):
    """One-line support statement for a probed build."""
    devices = lookup(build, data)
    if not devices:
        return ('the root chain WORKS on this device, but this firmware build is not in the '
                'compatibility list yet. Please share it: tv-access --report')
    first = devices[0]
    if first['source'] == 'maintainer':
        return f'maintainer-tested on {first["model"]} ({first["date"]}): {", ".join(first["works"])}'
    reports = '; '.join(f'{d["model"]} by {d["reporter"]} ({d["date"]}): {", ".join(d["works"])}'
                        for d in devices)
    return (f'the root chain WORKS on this device. Reported working on {reports}. '
            'Not tested by the maintainer; tv-setup (app cleanup) is unsupported on this build')


def render_table(data=None):
    data = data or load()
    rows = ['| Model | Tizen | Firmware build | Works | Source |', '|---|---|---|---|---|']
    order = sorted(data['devices'], key=lambda d: (d['source'] != 'maintainer', d['model'], d['tizen']))
    for d in order:
        source = ('maintainer-tested' if d['source'] == 'maintainer'
                  else f'[{d["reporter"]}]({d["report"]})')
        rows.append(f'| {d["model"]} | {d["tizen"]} | `{d["build"]}` | {", ".join(d["works"])} | {source} |')
    return '\n'.join(rows)


def render_readme(text, data=None):
    if text.count(START) != 1 or text.count(END) != 1 or text.index(START) > text.index(END):
        raise ValueError('README.md: compatibility markers missing or out of order')
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    return f'{head}{START}\n{render_table(data)}\n{END}{tail}'


def report(info, present, missing, data=None):
    """Privacy-filtered Markdown report and a prefilled issue link.

    Contains no IP address, serial number, account or network identifiers.
    """
    build = info.get('build') or 'unknown'
    devices = lookup(build, data) if build != 'unknown' else []
    listed = ('listed: ' + ', '.join(f'{d["model"]} ({d["source"]})' for d in devices)
              if devices else 'not listed yet')
    lines = [
        '| Field | Value |', '|---|---|',
        f'| Firmware build | `{build}` |',
        f'| Tizen | {info.get("tizen") or "?"} |',
        f'| Kernel | {info.get("kernel") or "?"} |',
        f'| Architecture | {info.get("arch") or "?"} |',
        f'| Root (`id -u`) | {info.get("uid") or "?"} |',
        f'| Helpers present | {", ".join(present) or "none"} |',
    ]
    if missing:
        lines.append(f'| Helpers missing | {", ".join(missing)} |')
    lines.append(f'| Compatibility list | {listed} |')
    body = '\n'.join(lines)
    params = {'template': 'compatibility.yml',
              'title': f'Compatibility report: Tizen {info.get("tizen") or "?"}, {build}',
              'probe': body}
    return body, f'{REPO}/issues/new?{urlencode(params)}'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='validate and check the README table')
    group.add_argument('--write', action='store_true', help='regenerate the README table')
    args = parser.parse_args()
    try:
        data = load()
        current = README.read_text()
        expected = render_readme(current, data)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    if args.write:
        if expected != current:
            README.write_text(expected)
        return 0
    if expected != current:
        print('README.md compatibility table is stale; run tools/tv_access/compat.py --write',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
