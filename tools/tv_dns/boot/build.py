#!/usr/bin/env python3
"""Build the dnsbootprb on-boot TPK offline. Never contacts a TV.

Needs mcs (mono) and openssl on PATH, for example inside `nix develop`, and
the service's tools/tv_dns/service/DnsSupervisor.runtimeconfig.json.

Without signing options the result is an UNSIGNED package for inspection and
integration checks only: a TV will not install it. --author-p12 and
--distributor-p12 sign it with your own author/distributor certificates.
The .p12 passwords are read only from TIZEN_AUTHOR_P12_PASSWORD and
TIZEN_DISTRIBUTOR_P12_PASSWORD. Signing does not establish TV compatibility;
see docs/tv-local-dns.md.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
ACCESS = HERE.parents[1] / 'tv_access'
RUNTIMECONFIG = HERE.parent / 'service' / 'DnsSupervisor.runtimeconfig.json'
PACKAGE = 'dnsbootprb'
BOOTSTRAP = ('SamsungTvArchiveRoot.dll', 'SamsungTvArchiveRoot.runtimeconfig.json')
PASSWORDS = {'author': 'TIZEN_AUTHOR_P12_PASSWORD', 'distributor': 'TIZEN_DISTRIBUTOR_P12_PASSWORD'}

sys.path.insert(0, str(ACCESS))
from tv_sdb import build_package  # noqa: E402  (ephemeral per-build payload key)


def fail(message):
    raise SystemExit('build.py: ' + message)


def constant(source, name):
    """Read a string constant from DnsBootProbe.cs, the single source."""
    match = re.search(rf'const string {name} = "([^"]+)";', source)
    if not match:
        fail(f'no {name} constant in DnsBootProbe.cs')
    return match.group(1)


def vendored_bootstrap():
    """Read the tv_access bootstrap after checking it against its SHA256SUMS."""
    sums = {}
    for line in (ACCESS / 'SHA256SUMS').read_text().splitlines():
        digest, _, name = line.partition('  ')
        sums[name] = digest
    files = {}
    for name in BOOTSTRAP:
        data = (ACCESS / 'bootstrap' / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sums.get('bootstrap/' + name):
            fail(f'tools/tv_access/bootstrap/{name} does not match tools/tv_access/SHA256SUMS')
        files['bin/' + name] = data
    return files


def manifest(version):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<manifest xmlns="http://tizen.org/ns/packages" api-version="3.0" package="{PACKAGE}" version="{version}">
  <profile name="tv-samsung"/>
  <service-application appid="{PACKAGE}.Service" exec="DnsBootProbe.dll" type="dotnet" on-boot="true" auto-restart="false">
    <label>DNS boot probe</label>
  </service-application>
  <privileges>
    <privilege>http://tizen.org/privilege/internet</privilege>
  </privileges>
</manifest>
'''.encode()


def compile_app(work):
    out = Path(work) / 'DnsBootProbe.dll'
    result = subprocess.run(['mcs', '-target:exe', f'-out:{out}', str(HERE / 'DnsBootProbe.cs')],
                            capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        fail('compiling DnsBootProbe.cs failed')
    return out.read_bytes()


def package_files(work, version, job):
    """Return the TPK entries in signing order: manifest first, then sorted."""
    launch = (HERE / 'launch.sh').read_bytes()
    if f'\nJOB={job}\n'.encode() not in launch:
        fail('launch.sh JOB does not match DnsBootProbe.cs')
    if not RUNTIMECONFIG.is_file():
        fail(f'missing {RUNTIMECONFIG}; the service provides the one runtimeconfig')
    public, passwd, archive, signature = build_package(work, launch)
    files = vendored_bootstrap()
    files.update({
        'bin/DnsBootProbe.dll': compile_app(work),
        'bin/DnsBootProbe.runtimeconfig.json': RUNTIMECONFIG.read_bytes(),
        'bin/public.pem': Path(public).read_bytes(),
        'bin/passwd': Path(passwd).read_bytes(),
        f'bin/on-demand/{job}.tar.gz': Path(archive).read_bytes(),
        f'bin/on-demand/{job}.tar.gz.signature': Path(signature).read_bytes(),
    })
    return [('tizen-manifest.xml', manifest(version))] + sorted(files.items())


# Author/distributor XML signer, as used for the build tested on the TV.

def canonical_prop(sid, role, literal=False):
    ns = '' if literal else ' xmlns="http://www.w3.org/2000/09/xmldsig#"'
    return (f'<Object{ns} Id="prop">'
            '<SignatureProperties xmlns:dsp="http://www.w3.org/2009/xmldsig-properties">'
            f'<SignatureProperty Id="profile" Target="#{sid}"><dsp:Profile URI="http://www.w3.org/ns/widgets-digsig#profile"></dsp:Profile></SignatureProperty>'
            f'<SignatureProperty Id="role" Target="#{sid}"><dsp:Role URI="http://www.w3.org/ns/widgets-digsig#{role}"></dsp:Role></SignatureProperty>'
            f'<SignatureProperty Id="identifier" Target="#{sid}"><dsp:Identifier></dsp:Identifier></SignatureProperty>'
            '</SignatureProperties></Object>')


def digest_b64(data):
    return base64.b64encode(hashlib.sha512(data).digest()).decode()


def signed_info(files, prop_digest):
    # Canonical (exc-c14n) form: no self-closing tags, default namespace present.
    refs = []
    for name, data in files:
        uri = name.replace('/', '%2F')
        refs.append(f'<Reference URI="{uri}"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></DigestMethod><DigestValue>{digest_b64(data)}</DigestValue></Reference>')
    refs.append(f'<Reference URI="#prop"><Transforms><Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></DigestMethod><DigestValue>{prop_digest}</DigestValue></Reference>')
    return ('<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>'
            '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"></SignatureMethod>'
            + ''.join(refs) + '</SignedInfo>').encode()


def p12_blocks(p12, password_env):
    """Return the private key and the first two certificates of a .p12."""
    result = subprocess.run(['openssl', 'pkcs12', '-in', str(p12), '-passin', 'env:' + password_env,
                             '-nodes', '-nomacver'], capture_output=True)
    if result.returncode:
        fail(f'cannot unlock {p12.name} with {password_env} (details withheld)')
    blocks = re.findall(r'-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----', result.stdout.decode(), re.S)
    keys = [b for b in blocks if 'PRIVATE KEY' in b.splitlines()[0]]
    certs = [b for b in blocks if 'CERTIFICATE' in b.splitlines()[0]][:2]
    if not keys or not certs:
        fail(f'{p12.name} has no private key or certificate')
    return keys[0], certs


def sign_files(files, sid, role, p12, password_env, work):
    """Return the complete signature XML over files, a list of (name, bytes)."""
    info = signed_info(files, digest_b64(canonical_prop(sid, role).encode()))
    key, certs = p12_blocks(p12, password_env)
    key_file = Path(work) / (role + '.pem')
    with os.fdopen(os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
        handle.write(key)
    try:
        value = subprocess.run(['openssl', 'dgst', '-sha512', '-sign', str(key_file)],
                               input=info, capture_output=True, check=True).stdout
    finally:
        key_file.unlink()
    certxml = ''.join('<X509Certificate>\n' + '\n'.join(l for l in c.splitlines() if '-----' not in l)
                      + '\n</X509Certificate>' for c in certs)
    return (f'<Signature Id="{sid}" xmlns="http://www.w3.org/2000/09/xmldsig#">'
            + info.decode()
            + f'<SignatureValue>{base64.b64encode(value).decode()}</SignatureValue>'
            + f'<KeyInfo><X509Data>{certxml}</X509Data></KeyInfo>'
            + canonical_prop(sid, role, literal=True) + '</Signature>')


def sign(files, author_p12, distributor_p12, work):
    author = sign_files(files, 'AuthorSignature', 'role-author', author_p12, PASSWORDS['author'], work).encode()
    signed = [('author-signature.xml', author)] + files
    distributor = sign_files(signed, 'DistributorSignature', 'role-distributor',
                             distributor_p12, PASSWORDS['distributor'], work).encode()
    return files + [('author-signature.xml', author), ('signature1.xml', distributor)]


def write_tpk(directory, name, files):
    directory.mkdir(parents=True, exist_ok=True)
    target, partial = directory / name, directory / (name + '.part')
    with zipfile.ZipFile(partial, 'w', zipfile.ZIP_DEFLATED) as tpk:
        for entry, data in files:
            tpk.writestr(entry, data)
    os.replace(partial, target)
    return target


def main():
    parser = argparse.ArgumentParser(description='Build the dnsbootprb TPK offline (unsigned unless both .p12 are given).')
    parser.add_argument('--out', type=Path, required=True, help='output directory for the .tpk')
    parser.add_argument('--author-p12', type=Path, help=f'author .p12; password in ${PASSWORDS["author"]}')
    parser.add_argument('--distributor-p12', type=Path,
                        help=f'distributor .p12; password in ${PASSWORDS["distributor"]}')
    args = parser.parse_args()
    signing = bool(args.author_p12 or args.distributor_p12)
    if signing:
        if not (args.author_p12 and args.distributor_p12):
            parser.error('--author-p12 and --distributor-p12 must be given together')
        for path in (args.author_p12, args.distributor_p12):
            if not path.is_file():
                parser.error(f'no such file: {path}')
        missing = [name for name in PASSWORDS.values() if not os.environ.get(name)]
        if missing:
            parser.error('set ' + ' and '.join(missing))
    for tool in ('mcs', 'openssl'):
        if not shutil.which(tool):
            fail(f'{tool} is not on PATH; run inside `nix develop`')

    source = (HERE / 'DnsBootProbe.cs').read_text()
    version, job = constant(source, 'Version'), constant(source, 'Job')
    with tempfile.TemporaryDirectory(prefix='dnsbootprb-') as work:
        files = package_files(work, version, job)
        if signing:
            files = sign(files, args.author_p12, args.distributor_p12, work)
    target = write_tpk(args.out, f'{PACKAGE}-{version}{"" if signing else "-unsigned"}.tpk', files)

    print(f'{target}  sha256={hashlib.sha256(target.read_bytes()).hexdigest()}')
    for entry, data in files:
        print(f'  {entry}  {len(data)} bytes')
    if signing:
        print('SIGNED with the supplied profile. Signing does not establish TV compatibility; validate before enabling native DNS.')
    else:
        print('UNSIGNED: NOT installable. For inspection and integration checks only.')


if __name__ == '__main__':
    main()
