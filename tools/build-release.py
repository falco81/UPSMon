#!/usr/bin/env python3
"""tools/build-release.py - one release of upsmon, as Settings → Upgrades takes it.

    UPSMON_RELEASE_KEY=/path/to/upsmon-release-1.key python3 tools/build-release.py

1. checks that upsmon.py and upsmon_admin.py say the same version, and that
   CHANGELOG.md has a section for it;
2. writes MANIFEST (the SHA-256 of every file of the package) and
   MANIFEST.sig (its Ed25519 signature, by the release key) into the root of
   the repository - which is the package unpacked;
3. packs release/upsmon-X.Y.Z.tar.gz (one folder, upsmon-X.Y.Z/) and checks
   it the way the server's root helper will (deploy/upsmon_upgrade.py
   --inspect, against deploy/release-keys/);
4. keeps the last ten packages in release/ and takes older ones away.

The private key never goes into the repository. Its public half is in
deploy/release-keys/, and every installed server trusts only that.
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEEP = 10
LEAVE_OUT = {'.git', '.github', 'release', '__pycache__', '.gitignore'}


def version_of(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as f:
        m = re.search(r"^__version__ = '([0-9]+\.[0-9]+\.[0-9]+)'", f.read(), re.M)
    if not m:
        raise SystemExit('%s says no version' % path)
    return m.group(1)


def files():
    out = []
    for top, dirs, names in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in LEAVE_OUT)
        for n in sorted(names):
            if n in LEAVE_OUT or n.endswith(('.pyc', '.key')) or n in ('MANIFEST', 'MANIFEST.sig'):
                continue
            rel = os.path.relpath(os.path.join(top, n), ROOT).replace(os.sep, '/')
            out.append(rel)
    return out


def main():
    key = os.environ.get('UPSMON_RELEASE_KEY')
    if not key or not os.path.isfile(key):
        raise SystemExit('UPSMON_RELEASE_KEY must name the private release key (it is never in the repository)')
    v = version_of('upsmon.py')
    if version_of('upsmon_admin.py') != v:
        raise SystemExit('upsmon.py and upsmon_admin.py do not say the same version')
    with open(os.path.join(ROOT, 'CHANGELOG.md'), encoding='utf-8') as f:
        if not re.search(r'^## %s\b' % re.escape(v), f.read(), re.M):
            raise SystemExit('CHANGELOG.md has no section "## %s"' % v)
    names = files()
    lines = []
    for rel in names:
        with open(os.path.join(ROOT, rel), 'rb') as f:
            lines.append('%s  %s\n' % (hashlib.sha256(f.read()).hexdigest(), rel))
    man = os.path.join(ROOT, 'MANIFEST')
    with open(man, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    sig = os.path.join(ROOT, 'MANIFEST.sig')
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', man,
                    '-out', sig], check=True)
    # The key that signed it must be one the servers trust.
    pubs = [os.path.join(ROOT, 'deploy', 'release-keys', n)
            for n in sorted(os.listdir(os.path.join(ROOT, 'deploy', 'release-keys')))]
    if not any(subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', p, '-rawin',
                               '-in', man, '-sigfile', sig], capture_output=True).returncode == 0
               for p in pubs):
        raise SystemExit('the signature is by none of the keys in deploy/release-keys/')
    top = 'upsmon-%s' % v
    rel_dir = os.path.join(ROOT, 'release')
    os.makedirs(rel_dir, exist_ok=True)
    out = os.path.join(rel_dir, top + '.tar.gz')

    def add(tf, rel):
        p = os.path.join(ROOT, rel)
        ti = tf.gettarinfo(p, '%s/%s' % (top, rel))
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = 'root'
        ti.mtime = int(os.path.getmtime(man))
        ti.mode = 0o755 if os.access(p, os.X_OK) else 0o644
        with open(p, 'rb') as f:
            tf.addfile(ti, f)
    with tarfile.open(out, 'w:gz', format=tarfile.PAX_FORMAT) as tf:
        d = tarfile.TarInfo(top)
        d.type, d.mode, d.mtime = tarfile.DIRTYPE, 0o755, int(os.path.getmtime(man))
        tf.addfile(d)
        for rel in names + ['MANIFEST', 'MANIFEST.sig']:
            add(tf, rel)
    # Checked as the server checks it.
    env = dict(os.environ, UPSMON_RELEASE_KEYS=os.path.join(ROOT, 'deploy', 'release-keys'),
               UPSMON_LIB=tempfile.mkdtemp(prefix='upsmon-lib-'))
    r = subprocess.run([sys.executable, '-I', os.path.join(ROOT, 'deploy', 'upsmon_upgrade.py'),
                        '--inspect', out], capture_output=True, text=True, env=env)
    got = json.loads(r.stdout or '{}')
    if not got.get('ok'):
        raise SystemExit('the package does not pass: %s' % (got.get('said') or r.stderr))
    # The last ten.
    have = sorted((n for n in os.listdir(rel_dir) if re.match(r'^upsmon-\d+\.\d+\.\d+\.tar\.gz$', n)),
                  key=lambda n: tuple(int(x) for x in re.findall(r'\d+', n)))
    for old in have[:-KEEP]:
        os.unlink(os.path.join(rel_dir, old))
        print('taken away: release/%s' % old)
    print('release/%s - %d files, signed by %s, %d bytes' % (
        os.path.basename(out), got.get('files'), got.get('signed_by'), os.path.getsize(out)))


if __name__ == '__main__':
    main()
