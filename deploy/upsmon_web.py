#!/usr/bin/python3 -I
"""upsmon_web.py - the web side of upsmon, put in place by root.

What the settings pages may ask for that needs root:

  * TLS - the certificate (with its chain, and the root it is checked
    against), the protocols, the ciphers and the DH parameters nginx uses;
  * port 80 answering the ACME CA for the automatic certificates;
  * the upsmon console when root signs in.

The daemon runs as `upsmon` and may not do any of this: it lays a request
down in /var/lib/upsmon/web/request.json and systemd (upsmon-web.path) starts
this as root. Nothing in the request is trusted: every value is checked
against the one shape it may have before it goes into a file, certificates
and keys are read by openssl, nginx is asked (nginx -t) before it is
reloaded and put back as it was when it says no, and the folder is used
through one descriptor, never a path the upsmon account could swap for a link.

It is upsmon's upsmon_web.py (upsmon 1.0.187), its TLS, ACME and console parts.

  upsmon_web.py            serve request.json (as root, from systemd)
  upsmon_web.py --status   what is in place here (JSON)
"""
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

STATE_DIR = os.environ.get('UPSMON_STATE', '/var/lib/upsmon')
WEB_DIR = os.path.join(STATE_DIR, 'web')
NGINX_DIR = os.environ.get('UPSMON_NGINX_DIR', '/etc/nginx/conf.d')
NGINX_MAIN = os.path.join(NGINX_DIR, 'upsmon.conf')
CERT_DIR = os.environ.get('UPSMON_CERT_DIR', '/etc/nginx/certs')
NO_SERVICES = bool(os.environ.get('UPSMON_NO_SERVICES'))      # tests: no systemctl
MARK = '# written by upsmon (upsmon_web.py) - upsmon keeps this file; change it on its pages'
ADDR_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z')

def plain(text, how):
    """An address, a network or an address with its prefix - and nothing
    else (1.0.57): ipaddress keeps an IPv6 scope id (fe80::1%eth0) with any
    character in it, newlines and braces included, and so into nginx,
    keepalived and ip6tables files root writes."""
    text = str(text or '').strip()
    if not ADDR_RE.match(text):
        raise ValueError('not a plain address')
    got = {'address': ipaddress.ip_address, 'network': lambda t: ipaddress.ip_network(t, strict=False),
           'interface': ipaddress.ip_interface}[how](text)
    if '%' in str(got):
        raise ValueError('a scope id is not taken')
    return got


class Refused(Exception):
    pass


# ---- the folder the upsmon account owns: one descriptor, never a path -----------------
FD = [None]


def web_fd():
    if FD[0] is None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        top = os.open(STATE_DIR, flags)
        try:
            FD[0] = os.open('web', flags, dir_fd=top)
        finally:
            os.close(top)
    return FD[0]


def read_req(name, most=262144):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=web_fd())
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused('%s is not a file' % name)
        data = os.read(fd, most + 1)
    finally:
        os.close(fd)
    if len(data) > most:
        raise Refused('the request is far bigger than any address needs')
    return data


def write_here(name, text):
    d = web_fd()
    tmp = '.%s.%d' % (name, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=d)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
        try:
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam('upsmon').gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)


def write_root(path, text, mode):
    """A file of root's, replaced whole."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.upsmon-', dir=folder)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---- what a request may hold ---------------------------------------------------------
NAME_RE = re.compile(r'^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)'
                     r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z')
IFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}\Z')
NODE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z')
CERT_RE = re.compile(r'^(\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----)+\s*\Z')
KEY_RE = re.compile(r'^\s*-----BEGIN (RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s:,-]+'
                    r'-----END (RSA |EC )?PRIVATE KEY-----\s*$')
PROTOCOLS = ('TLSv1.2', 'TLSv1.3')
DH_CHOICES = ('none', 'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'gen2048', 'gen3072', 'gen4096')


def openssl(args, what, data=None):
    got = subprocess.run(['openssl'] + args, capture_output=True, text=True, input=data)
    if got.returncode != 0:
        raise Refused('%s: %s' % (what, (got.stderr or got.stdout).strip().splitlines()[-1:]
                                  or ['openssl said no']))
    return got.stdout


def pem_set(cert, key, chain='', root=''):
    """A certificate, its key, the certificates between it and the root, and
    the root - each read by openssl, the key the certificate's own."""
    cert, key = str(cert or '').strip(), str(key or '').strip()
    chain, root = str(chain or '').strip(), str(root or '').strip()
    if not cert and not key:
        return None
    if not cert or not key:
        raise Refused('a certificate needs its key, and a key its certificate')
    for what, text in (('the certificate', cert), ('the chain', chain), ('the root', root)):
        if text and not CERT_RE.match(text):
            raise Refused('%s is not PEM (-----BEGIN CERTIFICATE-----)' % what)
    if not KEY_RE.match(key):
        raise Refused('the key is not a PEM private key without a passphrase')
    with tempfile.TemporaryDirectory(prefix='upsmon-web-') as t:
        cf, kf = os.path.join(t, 'c.pem'), os.path.join(t, 'k.pem')
        with open(cf, 'w') as f:
            f.write(cert + '\n')
        with open(kf, 'w') as f:
            f.write(key + '\n')
        os.chmod(kf, 0o600)
        a = openssl(['x509', '-in', cf, '-noout', '-pubkey'], 'the certificate')
        b = openssl(['pkey', '-in', kf, '-pubout'], 'the key')
        if a.strip() != b.strip():
            raise Refused('the key is not the one of this certificate')
    return {'cert': cert + '\n', 'key': key + '\n', 'chain': (chain + '\n') if chain else '',
            'root': (root + '\n') if root else ''}


def tls_checked(t, name):
    if t is None:
        return None
    if not isinstance(t, dict):
        raise Refused('the TLS of %s is not an object' % name)
    out = {'pem': pem_set(t.get('cert'), t.get('key'), t.get('chain'), t.get('root'))}
    # A second certificate (4.1.6): the ECDSA one beside the RSA one, as
    # Let's Encrypt advises - nginx offers it to the clients that take it.
    alt = t.get('alt')
    out['alt'] = None
    if alt and out['pem']:
        if not isinstance(alt, dict):
            raise Refused('the second certificate is not an object')
        out['alt'] = pem_set(alt.get('cert'), alt.get('key'), alt.get('chain'))
    prot = t.get('protocols') or list(PROTOCOLS)
    if not isinstance(prot, list) or not prot or any(p not in PROTOCOLS for p in prot):
        raise Refused('the protocols are TLSv1.2 and/or TLSv1.3')
    out['protocols'] = [p for p in PROTOCOLS if p in prot]
    ciphers = str(t.get('ciphers') or '').strip()
    if ciphers:
        if not re.match(r'^[A-Za-z0-9_+!@=:.-]{1,2000}\Z', ciphers):
            raise Refused('the ciphers are an OpenSSL cipher list: letters, digits, : + ! - =')
        openssl(['ciphers', ciphers], 'OpenSSL does not know that cipher list')
    out['ciphers'] = ciphers
    out['prefer'] = bool(t.get('prefer'))
    dh = str(t.get('dh') or 'none')
    if dh not in DH_CHOICES:
        raise Refused('the DH parameters are one of %s' % ', '.join(DH_CHOICES))
    out['dh'] = dh
    out['hsts'] = int(t.get('hsts') or 0)
    if not 0 <= out['hsts'] <= 63072000:
        raise Refused('HSTS is 0 to 63072000 seconds')
    return out



def checked(r):
    """The request, every value in the one shape it may have."""
    if not isinstance(r, dict):
        raise Refused('the request is not an object')
    out = {'id': re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:32],
           'hash': re.sub(r'[^0-9a-f]', '', str(r.get('hash') or ''))[:64]}
    node = str(r.get('node') or '')
    if not NODE_RE.match(node):
        raise Refused('the node\'s name is letters, digits, dots, dashes')
    out['node'] = node
    tls = r.get('tls') or {}
    out['tls_node'] = tls_checked(tls.get('node'), 'this server')
    names = r.get('acme')
    if names is None:
        out['acme'] = None
    else:
        if not isinstance(names, list) or len(names) > 10 or \
                not all(isinstance(n, str) and re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', n)
                        for n in names):
            raise Refused('the names of the ACME certificates are DNS names, 10 at most')
        out['acme'] = names
    return out


# ---- the parts of the machine it changes ---------------------------------------------
def run(cmd, what, ok=(0,)):
    got = subprocess.run(cmd, capture_output=True, text=True)
    if got.returncode not in ok:
        raise Refused('%s: %s' % (what, (got.stderr or got.stdout).strip()[-300:] or
                                  'ended with %d' % got.returncode))
    return got.stdout


def server_block(text):
    """(start, end) of the HTTPS server { } of an nginx file."""
    i = 0
    while True:
        m = re.search(r'(?m)^[ \t]*server[ \t]*\{', text[i:])
        if not m:
            return None
        start = i + m.start()
        depth, j = 0, i + m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[start:j + 1]
        if re.search(r'(?m)^\s*listen\s+[^;]*443[^;]*ssl', block) or \
                re.search(r'(?m)^\s*ssl_certificate\s', block):
            return start, j + 1
        i = j + 1


def set_directive(block, name, value):
    """`name value;` in a server { } - replaced where it is, put in after
    server_name where it is not, taken out for None. Only the server's own
    lines: a location { } inside is left alone."""
    lines = block.split('\n')
    depth, at, insert_at = 0, [], None
    for n, line in enumerate(lines):
        if depth == 1 and re.match(r'^\s*%s\s' % re.escape(name), line):
            at.append(n)
        if depth == 1 and insert_at is None and re.match(r'^\s*server_name\s', line):
            insert_at = n + 1
        depth += line.count('{') - line.count('}')
    if value is None:
        for n in reversed(at):
            del lines[n]
        return '\n'.join(lines)
    text = '    %-25s %s;' % (name, value)
    if at:
        lines[at[0]] = text
        for n in reversed(at[1:]):
            del lines[n]
    else:
        lines.insert(insert_at if insert_at is not None else 1, text)
    return '\n'.join(lines)


def also_directive(block, after, name, value, last=False):
    """One more `name value;` line in a server { }, right after the (first,
    or with last the last) `after` line of the server's own (4.1.6) - nginx
    takes ssl_certificate and ssl_certificate_key more than once."""
    lines = block.split('\n')
    depth, at = 0, []
    for n, line in enumerate(lines):
        if depth == 1 and re.match(r'^\s*%s\s' % re.escape(after), line):
            at.append(n)
        depth += line.count('{') - line.count('}')
    pos = (at[-1] if last else at[0]) + 1 if at else 1
    lines.insert(pos, '    %-25s %s;' % (name, value))
    return '\n'.join(lines)


CIPHERS_DEFAULT = ('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
                   'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                   'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305')


# How it is going, for the pages (1.0.50): the step, how many there are,
# what is being done, and - for the long one, making DH parameters - when it
# began and about how long it takes.
PROGRESS = {'step': 0, 'total': 6, 'id': ''}
DH_READY = {}
DH_EXPECT_S = {'gen2048': 15, 'gen3072': 120, 'gen4096': 600}


def progress(words, step=None, expect=None):
    if step is not None:
        PROGRESS['step'] = step
    try:
        write_here('progress.json', json.dumps({
            'id': PROGRESS['id'], 'step': PROGRESS['step'], 'total': PROGRESS['total'],
            'words': words, 'at': time.time(), 'expect_s': expect}))
    except OSError:
        pass


def dh_file(choice, path, had):
    """The DH parameters for `choice` in `path`: a group of RFC 7919, or made
    here (which takes a while - 4096 bits minutes). Made ones are made once."""
    if choice == 'none':
        return None
    if choice == had and os.path.exists(path):
        return path
    if choice.startswith('ffdhe'):
        pem = openssl(['genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt',
                       'group:%s' % choice], 'the DH group %s' % choice)
    else:
        progress('making DH parameters of %s bits' % choice[3:], 2, DH_EXPECT_S.get(choice))
        pem = openssl(['dhparam', choice[3:]], 'making DH parameters of %s bits' % choice[3:])
    write_root(path, pem, 0o644)
    return path


def tls_into(block, t, files, had_dh):
    """A server { } with the TLS of `t`: its files written, its lines set.
    Returns (block, words, dh made)."""
    said = []
    progress('writing the certificate and the TLS settings', 3)
    if t['pem']:
        full = t['pem']['cert'] + t['pem']['chain']
        write_root(files['cert'], full, 0o644)
        write_root(files['key'], t['pem']['key'], 0o600)
        block = set_directive(block, 'ssl_certificate', files['cert'])
        block = set_directive(block, 'ssl_certificate_key', files['key'])
        if t.get('alt'):
            write_root(files['cert2'], t['alt']['cert'] + t['alt']['chain'], 0o644)
            write_root(files['key2'], t['alt']['key'], 0o600)
            block = also_directive(block, 'ssl_certificate_key', 'ssl_certificate', files['cert2'])
            block = also_directive(block, 'ssl_certificate', 'ssl_certificate_key', files['key2'],
                                   last=True)
        if t['pem']['root']:
            write_root(files['root'], t['pem']['root'] + t['pem']['chain'], 0o644)
            block = set_directive(block, 'ssl_trusted_certificate', files['root'])
        else:
            block = set_directive(block, 'ssl_trusted_certificate', None)
        subj = openssl(['x509', '-noout', '-subject', '-enddate'], 'the certificate',
                       t['pem']['cert']).strip().replace('\n', ', ')
        said.append('certificate: %s' % subj)
        if t.get('alt'):
            said.append('and the second one (ECDSA) beside it')
    block = set_directive(block, 'ssl_protocols', ' '.join(t['protocols']))
    block = set_directive(block, 'ssl_ciphers', t['ciphers'] or CIPHERS_DEFAULT)
    block = set_directive(block, 'ssl_prefer_server_ciphers', 'on' if t['prefer'] else 'off')
    dh = DH_READY.get(files['dh'], 'none?')
    if dh == 'none?':
        dh = dh_file(t['dh'], files['dh'], had_dh)
    block = set_directive(block, 'ssl_dhparam', dh)
    if t['hsts']:
        block = set_directive(block, 'add_header Strict-Transport-Security',
                              '"max-age=%d" always' % t['hsts'])
    else:
        block = set_directive(block, 'add_header Strict-Transport-Security', None)
    said.append('%s; %s; DH %s%s' % (' '.join(t['protocols']),
                                     'ciphers as set' if t['ciphers'] else 'the usual ciphers',
                                     t['dh'], '; HSTS %d s' % t['hsts'] if t['hsts'] else ''))
    return block, said, t['dh']


NODE_FILES = {'cert': os.path.join(CERT_DIR, 'upsmon.pem'), 'key': os.path.join(CERT_DIR, 'upsmon.key'),
              'root': os.path.join(CERT_DIR, 'upsmon-ca.pem'),
              'cert2': os.path.join(CERT_DIR, 'upsmon-ecdsa.pem'),
              'key2': os.path.join(CERT_DIR, 'upsmon-ecdsa.key'),
              'dh': os.path.join(CERT_DIR, 'upsmon-dh.pem')}
VIP_FILES = {'cert': os.path.join(CERT_DIR, 'upsmon-vip.pem'),
             'key': os.path.join(CERT_DIR, 'upsmon-vip.key'),
             'root': os.path.join(CERT_DIR, 'upsmon-vip-ca.pem'),
             'cert2': os.path.join(CERT_DIR, 'upsmon-vip-ecdsa.pem'),
             'key2': os.path.join(CERT_DIR, 'upsmon-vip-ecdsa.key'),
             'dh': os.path.join(CERT_DIR, 'upsmon-vip-dh.pem')}


def snapshot(paths):
    got = {}
    for p in paths:
        try:
            with open(p, 'rb') as f:
                got[p] = (f.read(), os.stat(p).st_mode & 0o777)
        except FileNotFoundError:
            got[p] = None
    return got


def put_back(snap):
    for p, was in snap.items():
        if was is None:
            try:
                os.unlink(p)
            except OSError:
                pass
        else:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
            with os.fdopen(fd, 'wb') as f:
                f.write(was[0])
            os.chmod(tmp, was[1])
            os.replace(tmp, p)
            # Its SELinux label too, not the folder's (1.0.57).
            if shutil.which('restorecon'):
                subprocess.run(['restorecon', p], capture_output=True)


ACME_LOCATION = '''    # A certificate by ACME (1.0.169): the CA's HTTP-01 challenge answered on
    # port 80 by acme.php - the answer is in upsmon's database, so whichever node
    # the CA reaches gives it. Everything else goes to HTTPS.
    location ^~ /.well-known/acme-challenge/ {
        limit_req     zone=otp_all burst=20 nodelay;
        fastcgi_pass  unix:/run/php-fpm/upsmon.sock;
        fastcgi_param SCRIPT_FILENAME /var/www/upsmon/acme.php;
        include       fastcgi_params;
        fastcgi_read_timeout 10s;
    }
    location / {
        return 301 https://$host$request_uri;
    }'''
def http_block(text):
    """(start, end) of the port-80 server { } of an nginx file."""
    for m in re.finditer(r'(?m)^[ \t]*server[ \t]*\{', text):
        depth, j = 0, m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[m.start():j + 1]
        if re.search(r'(?m)^\s*listen\s+(\[::\]:)?80\b', block) and 'ssl' not in block.split('{', 1)[1][:400]:
            return m.start(), j + 1
    return None


def acme_into(main, names):
    """The port-80 server given the ACME location (1.0.169), and the names
    certificates are ordered for in its server_name - the web address's on
    every node, so the CA reaches upsmon on whichever node has it."""
    where = http_block(main)
    if not where:
        return main
    block = main[where[0]:where[1]]
    new = block
    if 'acme-challenge' not in new:
        new = re.sub(r'(?m)^[ \t]*return[ \t]+301[ \t]+https://\$host\$request_uri;[ \t]*$',
                     lambda m: ACME_LOCATION, new, count=1)
    m = re.search(r'(?m)^(\s*server_name\s+)([^;#]*);', new)
    if m and names:
        have = m.group(2).split()
        base = [x for x in have if not x.startswith('upsmon-acme:')]
        want = base + [n for n in names if n not in base]
        if want != have:
            new = new[:m.start()] + m.group(1) + ' '.join(want) + ';' + new[m.end():]
    return main[:where[0]] + new + main[where[1]:] if new != block else main



def nginx_part(r, last):
    """This server's HTTPS, with its TLS - and port 80 answering the ACME CA."""
    said, dh = [], {}
    t = r['tls_node']
    if t:
        DH_READY[NODE_FILES['dh']] = dh_file(t['dh'], NODE_FILES['dh'], (last.get('dh') or {}).get('node'))
    paths = [NGINX_MAIN] + list(NODE_FILES.values())
    snap = snapshot(paths)
    changed = False
    try:
        try:
            with open(NGINX_MAIN) as f:
                main = f.read()
        except OSError as e:
            raise Refused('upsmon\'s nginx file cannot be read (%s): %s' % (NGINX_MAIN, e))
        if r.get('acme') is not None:
            new_main = acme_into(main, r['acme'])
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                said.append('nginx: port 80 answers the ACME CA (%s)' % (', '.join(r['acme']) or
                                                                        'no name yet'))
        where = server_block(main)
        if not where:
            raise Refused('no HTTPS server { } was found in %s' % NGINX_MAIN)
        block = main[where[0]:where[1]]
        if t:
            new, words, dh['node'] = tls_into(block, t, NODE_FILES, (last.get('dh') or {}).get('node'))
            # OCSP stapling needs the issuer: off where nginx has no chain to check it with.
            if not (t.get('pem') or {}).get('root') and re.search(r'(?m)^\s*ssl_stapling\s', new):
                new = set_directive(new, 'ssl_stapling_verify', None)
                new = set_directive(new, 'ssl_stapling', None)
            if new != block:
                write_root(NGINX_MAIN, main[:where[0]] + new + main[where[1]:], 0o644)
                changed = True
            said += ['this server: ' + w for w in words]
        if changed and not NO_SERVICES:
            if shutil.which('restorecon'):
                subprocess.run(['restorecon', '-R', CERT_DIR, NGINX_MAIN], capture_output=True)
            progress('asking nginx, and reloading it', 4)
            tt = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if tt.returncode != 0:
                raise Refused('nginx does not take it, so it is as it was: %s'
                              % ((tt.stderr or '').strip().splitlines() or ['?'])[-1][:300])
            subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
            said.append('nginx reloaded')
    except BaseException:
        put_back(snap)
        raise
    return said, dh


def drop_ask(name, d):
    try:
        st = os.stat(name, dir_fd=d, follow_symlinks=False)
    except OSError:
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(os.path.join(WEB_DIR, name), ignore_errors=True)
        else:
            os.unlink(name, dir_fd=d)
    except OSError:
        pass


def status_read():
    try:
        got = json.loads(read_req('status.json').decode('utf-8'))
    except (OSError, ValueError, Refused):
        return {}
    if not isinstance(got, dict):
        return {}
    dh = got.get('dh') if isinstance(got.get('dh'), dict) else {}
    got['dh'] = {k: v for k, v in dh.items() if k == 'node' and v in DH_CHOICES}
    return got


# ---- the upsmon console when root signs in (1.0.141) ---------------------------------
# Asked in console.ask from the pages (Settings - About): on or off, written to
# /etc/upsmon-console-login as `upsmon --console-at-login` writes it.
CONSOLE_ASK = 'console.ask'
CONSOLE_FILE = 'console.json'
CONSOLE_FLAG = os.environ.get('UPSMON_CONSOLE_FLAG', '/etc/upsmon-console-login')


def console_flag_set(on):
    """Written beside it and put in its place: a link or a pipe found there is
    replaced, never followed."""
    tmp = '%s.%d.tmp' % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, b'on\n' if on else b'off\n')
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, CONSOLE_FLAG)


def console_part():
    d = web_fd()
    try:
        raw = read_req(CONSOLE_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(CONSOLE_ASK, d)
        return
    drop_ask(CONSOLE_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        if r.get('do') != 'set' or not isinstance(r.get('on'), bool):
            raise Refused('set, on or off')
        console_flag_set(r['on'])
        out['data'] = {'on': r['on']}
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(CONSOLE_FILE, json.dumps(out))



def _read_or(path, most=65536):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            return f.read(most).decode('utf-8', 'replace')
    except OSError:
        return None


def _put_file(path, text, mode=0o644):
    """Written whole, beside and renamed in; never through a link."""
    folder = os.path.dirname(path)
    if os.path.islink(path) or os.path.islink(folder):
        raise Refused('%s is a link - put the file itself there' % path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.upsmon-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which('restorecon'):
        subprocess.run(['restorecon', path], capture_output=True)


def _drop(path):
    try:
        if not os.path.islink(path):
            os.unlink(path)
    except FileNotFoundError:
        pass



# ---- restart and power off (upsmon 1.0.119), asked in net.ask -------------------------
NET_ASK = 'net.ask'
NET_FILE = 'net.json'
POWER_CMD = os.environ.get('UPSMON_POWER_CMD', '')        # tests: a file to write instead


def power_after(what, secs):
    """A reboot or a power-off a few seconds from now - after this helper
    has written its answer and the page has had it."""
    secs = max(3, int(secs or 5))
    if POWER_CMD:
        with open(POWER_CMD, 'a') as f:
            f.write('%s %d %s\n' % (what, secs, time.time()))
        return '%s in %d s (written to %s)' % (what, secs, POWER_CMD)
    if NO_SERVICES:
        return '%s in %d s (not here: tests)' % (what, secs)
    run(['systemd-run', '--on-active=%ds' % secs, '--unit',
         'upsmon-%s-%d' % (what, int(time.time())), '/usr/bin/systemctl', what],
        'systemd-run %s' % what)
    return '%s in %d s' % (what, secs)



def net_part():
    """net.ask: on upsmon only the restart and the power-off of this server."""
    d = web_fd()
    try:
        raw = read_req(NET_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(NET_ASK, d)
        return
    drop_ask(NET_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        if r.get('do') != 'power':
            raise Refused('power: reboot or poweroff')
        how = r.get('how')
        if how not in ('reboot', 'poweroff'):
            raise Refused('reboot or poweroff')
        try:
            secs = int(r.get('in') or 5)
        except (TypeError, ValueError):
            secs = 5
        out['data'] = {'said': [power_after(how, secs)]}
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NET_FILE, json.dumps(out))


# ---- the time: chrony (1.0.120) ---------------------------------------------------
# Asked in ntp.ask: how the clock is (read), chrony's servers set (apply), a
# step to the right time now (sync). /etc/chrony.conf keeps everything of its
# own; when upsmon sets the servers, the file's own server/pool/makestep/allow
# lines are commented out (#upsmon#) and upsmon's block is added between marks -
# put back as they were when upsmon stops setting them.
NTP_ASK = 'ntp.ask'
NTP_FILE = 'ntp.json'
CHRONYC = os.environ.get('UPSMON_CHRONYC', 'chronyc')
TIMEDATECTL = os.environ.get('UPSMON_TIMEDATECTL', 'timedatectl')
# Debian and Ubuntu read /etc/chrony/chrony.conf (1.0.146): the other was
# written there and never read, and "applied" said so.
CHRONY_CONF = os.environ.get('UPSMON_CHRONY_CONF') or next(
    (p for p in ('/etc/chrony.conf', '/etc/chrony/chrony.conf') if os.path.isfile(p)),
    '/etc/chrony.conf')
NTP_BEGIN = '# ---- upsmon: the time servers, set on its pages (Settings - Time) ----'
NTP_END = '# ---- upsmon: end ----'
NTP_KEYS = ('server', 'pool', 'peer', 'makestep', 'allow', 'minsources', 'maxdistance', 'sourcedir')
TZ_RE = re.compile(r'^[A-Za-z0-9_+-]{1,40}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z')


def ntp_read():
    out = {'chrony': bool(shutil.which(CHRONYC)), 'tracking': {}, 'sources': [], 'stats': {}}
    try:
        t = run([TIMEDATECTL, 'show'], 'timedatectl', ok=(0, 1))
        for line in t.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                if k in ('Timezone', 'NTP', 'NTPSynchronized', 'LocalRTC', 'CanNTP'):
                    out[k.lower()] = v
    except (Refused, OSError):
        pass
    out['time'] = time.time()
    if not out['chrony']:
        return out
    try:
        f = run([CHRONYC, '-c', 'tracking'], 'chronyc tracking').strip().split(',')
        if len(f) >= 14:
            out['tracking'] = {'ref_id': f[0], 'ref': f[1], 'stratum': int(f[2] or 0),
                               'ref_time': float(f[3] or 0), 'offset': float(f[4] or 0),
                               'last_offset': float(f[5] or 0), 'rms': float(f[6] or 0),
                               'freq': float(f[7] or 0), 'skew': float(f[9] or 0),
                               'root_delay': float(f[10] or 0), 'root_disp': float(f[11] or 0),
                               'interval': float(f[12] or 0), 'leap': f[13]}
    except (Refused, ValueError, OSError) as e:
        out['said'] = str(e)[:200]
    try:
        for line in run([CHRONYC, '-c', 'sources'], 'chronyc sources').splitlines():
            f = line.split(',')
            if len(f) < 10:
                continue
            try:
                out['sources'].append({'mode': f[0], 'state': f[1], 'name': f[2][:120],
                                       'stratum': int(f[3] or 0), 'poll': int(f[4] or 0),
                                       'reach': int(f[5] or 0, 8) if f[5] else 0,
                                       'last_rx': int(f[6]) if f[6].lstrip('-').isdigit() else None,
                                       'offset': float(f[7] or 0), 'measured': float(f[8] or 0),
                                       'error': float(f[9] or 0)})
            except ValueError:
                continue
    except (Refused, OSError):
        pass
    try:
        with open(CHRONY_CONF) as f:
            text = f.read()
        out['managed'] = NTP_BEGIN in text
        out['own'] = [l.strip() for l in text.splitlines()
                      if l.strip().split(' ')[0] in ('server', 'pool', 'peer')][:20]
    except OSError:
        out['managed'] = False
    return out


def ntp_checked(r):
    out = {'manage': bool(r.get('manage')), 'servers': [], 'allow': [],
           'makestep': [1.0, 3], 'minsources': 1, 'timezone': '', 'peers': []}
    for x in (r.get('servers') or [])[:12]:
        if not isinstance(x, dict):
            raise Refused('a server is an object')
        host = str(x.get('host') or '').strip().lower().rstrip('.')
        try:
            host = str(plain(host, 'address'))
        except ValueError:
            if not NAME_RE.match(host):
                raise Refused('%r is not a host name or an address' % host[:80])
        out['servers'].append({'host': host, 'pool': bool(x.get('pool')),
                               'iburst': bool(x.get('iburst', True)),
                               'prefer': bool(x.get('prefer')), 'nts': bool(x.get('nts'))})
    for p in (r.get('peers') or [])[:2]:
        try:
            out['peers'].append(str(plain(p, 'address')))
        except ValueError:
            raise Refused('%r is not the other node\'s address' % str(p)[:60])
    for a in (r.get('allow') or [])[:20]:
        try:
            out['allow'].append(str(plain(a, 'network')))
        except ValueError:
            raise Refused('%r is not a network (192.0.2.0/24)' % str(a)[:60])
    try:
        th = float((r.get('makestep') or [1.0, 3])[0])
        lim = int((r.get('makestep') or [1.0, 3])[1])
    except (TypeError, ValueError, IndexError):
        raise Refused('makestep is a threshold in seconds and a number of updates')
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise Refused('makestep: 0.001 - 3600 s, and -1 (always) to 1000 updates')
    out['makestep'] = [th, lim]
    try:
        out['minsources'] = max(1, min(10, int(r.get('minsources') or 1)))
    except (TypeError, ValueError):
        out['minsources'] = 1
    tz = str(r.get('timezone') or '').strip()
    if tz and not TZ_RE.match(tz):
        raise Refused('%r is not a time zone' % tz[:60])
    out['timezone'] = tz
    if out['manage'] and not out['servers'] and not out['peers']:
        raise Refused('at least one time server')
    return out


def ntp_conf_text(text, n):
    """chrony.conf with upsmon's block (or without it, put back as it was)."""
    lines = text.splitlines()
    out, inside = [], False
    for l in lines:
        if l.strip() == NTP_BEGIN:
            inside = True
            continue
        if l.strip() == NTP_END:
            inside = False
            continue
        if inside:
            continue
        if l.startswith('#upsmon# '):
            l = l[6:]                       # the file's own line, put back first
        out.append(l)
    if not n['manage']:
        return '\n'.join(out).rstrip('\n') + '\n'
    kept = []
    for l in out:
        if l.strip().split(' ')[0] in NTP_KEYS:
            kept.append('#upsmon# ' + l)
        else:
            kept.append(l)
    block = [NTP_BEGIN]
    for x in n['servers']:
        opts = [o for o, on in (('iburst', x['iburst']), ('prefer', x['prefer']),
                                ('nts', x['nts'])) if on]
        block.append('%s %s %s' % ('pool' if x['pool'] else 'server', x['host'], ' '.join(opts)))
    for p in n['peers']:
        # The other node of the cluster: one more source, and allowed to ask.
        block.append('server %s iburst' % p)
        block.append('allow %s' % p)
    for a in n['allow']:
        block.append('allow %s' % a)
    block.append('makestep %s %d' % (('%g' % n['makestep'][0]), n['makestep'][1]))
    if n['minsources'] > 1:
        block.append('minsources %d' % n['minsources'])
    block.append(NTP_END)
    return '\n'.join([l.rstrip() for l in kept]).rstrip('\n') + '\n\n' + '\n'.join(block) + '\n'


def ntp_apply(n):
    said = []
    if not shutil.which(CHRONYC) and not NO_SERVICES:
        if shutil.which('dnf'):
            run(['dnf', '-y', 'install', 'chrony'], 'dnf install chrony')
            said.append('chrony installed')
        else:
            raise Refused('chrony is not on this machine')
    try:
        with open(CHRONY_CONF) as f:
            had = f.read()
    except FileNotFoundError:
        had = 'driftfile /var/lib/chrony/drift\nrtcsync\nlogdir /var/log/chrony\n'
    new = ntp_conf_text(had, n)
    if new != had:
        if NTP_BEGIN not in had:
            try:
                write_root(CHRONY_CONF + '.upsmon-before', had, 0o644)
            except OSError:
                pass
        write_root(CHRONY_CONF, new, 0o644)
        said.append('%s: %s' % (CHRONY_CONF, ', '.join(x['host'] for x in n['servers'])
                                if n['manage'] else 'its own servers again'))
        if not NO_SERVICES and not os.environ.get('UPSMON_NTP_NO_SERVICE'):
            run(['systemctl', 'enable', '--now', 'chronyd'], 'systemctl enable chronyd')
            run(['systemctl', 'restart', 'chronyd'], 'systemctl restart chronyd')
            said.append('chronyd restarted')
    if n['timezone']:
        try:
            cur = run([TIMEDATECTL, 'show', '-p', 'Timezone', '--value'], 'timedatectl').strip()
        except Refused:
            cur = ''
        if cur != n['timezone']:
            run([TIMEDATECTL, 'set-timezone', n['timezone']], 'timedatectl set-timezone')
            said.append('time zone: %s' % n['timezone'])
    if not NO_SERVICES and shutil.which(TIMEDATECTL) and not os.environ.get('UPSMON_NTP_NO_SERVICE'):
        run([TIMEDATECTL, 'set-ntp', 'true'], 'timedatectl set-ntp', ok=(0, 1))
    return {'said': said}


def ntp_part():
    d = web_fd()
    try:
        raw = read_req(NTP_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(NTP_ASK, d)
        return
    drop_ask(NTP_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        what = r.get('do')
        if what == 'read':
            out['data'] = ntp_read()
            if r.get('zones'):
                try:
                    out['data']['zones'] = run([TIMEDATECTL, 'list-timezones'],
                                               'timedatectl').split()[:700]
                except Refused:
                    pass
        elif what == 'apply':
            out['data'] = ntp_apply(ntp_checked(r))
        elif what == 'sync':
            said = run([CHRONYC, 'makestep'], 'chronyc makestep').strip()
            run([CHRONYC, 'burst', '4/4'], 'chronyc burst', ok=(0, 1))
            out['data'] = {'said': [said or 'stepped']}
        else:
            raise Refused('read, apply or sync')
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NTP_FILE, json.dumps(out))


# ---- updates of the operating system (1.0.158) ------------------------------------------
# Asked with osup.ask, answered at once; the work itself - minutes of dnf or
# apt - runs as a unit of its own (systemd-run), so this oneshot service ends
# and the other asks are served meanwhile. Its progress and its last lines go
# into osup.json, every second or so.
OSUP_ASK = 'osup.ask'
OSUP_ANS = 'osup.ans'
OSUP_FILE = 'osup.json'
OSUP_LOCK = os.environ.get('UPSMON_OSUP_LOCK', '/run/upsmon-osup.lock')
OSUP_PM = os.environ.get('UPSMON_OSUP_PM', '')          # tests: a fake package manager
# The proxy dnf and apt go through (1.0.166): handed over in osup.ask, kept
# here for the job, readable by root only, never on a command line.
OSUP_PROXY = os.environ.get('UPSMON_OSUP_PROXY', '/run/upsmon-osup-proxy.json')


def osup_proxy_keep(r):
    url = str(r.get('proxy') or '').strip()
    if url and not re.match(r'^https?://[^\s]+\Z', url):
        raise Refused('the proxy is not an http:// address')
    no = ','.join(w for w in re.split(r'[\s,;]+', re.sub(r'[^A-Za-z0-9.*:/\[\],;\s_-]', '',
                                                          str(r.get('proxy_no') or ''))) if w)
    if not url:
        _drop(OSUP_PROXY)
        return
    fd = os.open(OSUP_PROXY + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps({'url': url, 'no': no}))
    os.replace(OSUP_PROXY + '.new', OSUP_PROXY)


def osup_proxy_env(env):
    try:
        got = json.loads(_read_or(OSUP_PROXY) or '{}')
    except ValueError:
        got = {}
    if got.get('url'):
        for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
            env[k] = got['url']
        if got.get('no'):
            env['no_proxy'] = env['NO_PROXY'] = got['no']
    return env


def osup_pm():
    if OSUP_PM:
        return 'fake'
    if shutil.which('dnf'):
        return 'dnf'
    if shutil.which('apt-get'):
        return 'apt'
    return ''


def osup_running():
    import fcntl
    try:
        fd = os.open(OSUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def osup_launch(ident, kind, security=False):
    if osup_running():
        raise Refused('an update or a look for updates is going on already')
    if not osup_pm():
        raise Refused('neither dnf nor apt-get is on this machine')
    me = os.path.abspath(__file__)
    argv = [sys.executable, '-I', me, '--os-job', ident, kind] + (['security'] if security else [])
    if (shutil.which('systemd-run') and not NO_SERVICES and os.path.isdir('/run/systemd/system')):
        got = subprocess.run(['systemd-run', '--unit', 'upsmon-os-%s-%s' % (kind, ident[:12]),
                              '--collect', '--quiet', '--property', 'TimeoutStopSec=30min'] + argv,
                             capture_output=True, text=True, timeout=30)
        if got.returncode != 0:
            raise Refused('systemd-run: %s' % (got.stderr or got.stdout).strip()[-200:])
        return
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)


def osup_part():
    d = web_fd()
    try:
        raw = read_req(OSUP_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(OSUP_ASK, d)
        return
    drop_ask(OSUP_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        kind = r.get('kind')
        if r.get('do') != 'run' or kind not in ('check', 'upgrade'):
            raise Refused('run: check or upgrade')
        osup_proxy_keep(r)
        osup_launch(out['id'], kind, bool(r.get('security')) and kind == 'upgrade')
        out['ok'] = True
        out['data'] = {'started': kind, 'pm': osup_pm(), 'security': bool(r.get('security'))}
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(OSUP_ANS, json.dumps(out))


# The packages a restart is needed for once they are updated, as dnf
# needs-restarting -r and Debian's reboot-required name them (1.0.159).
REBOOT_PKGS = {'kernel', 'kernel-core', 'kernel-rt', 'kernel-rt-core', 'kernel-modules',
               'kernel-uek', 'glibc', 'linux-firmware', 'systemd', 'dbus', 'dbus-broker',
               'dbus-daemon', 'microcode_ctl', 'zlib', 'zlib-ng-compat', 'libc6', 'linux-base',
               'intel-microcode', 'amd64-microcode'}


def reboot_for(packages):
    """Which of the packages waiting want a restart once updated."""
    out = []
    for p in packages:
        name = str(p).split()[0] if str(p).split() else ''
        if re.search(r'\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$', name):
            name = name.rsplit('.', 1)[0]
        if name in REBOOT_PKGS or name.startswith(('linux-image', 'kernel-core-', 'linux-modules')):
            out.append(name)
    return sorted(set(out))


def reboot_now(pm, env, say=None):
    """Whether this machine waits for a restart already."""
    if pm == 'fake':
        return subprocess.run([OSUP_PM, 'needs-restart'], stdout=subprocess.DEVNULL).returncode == 1
    if pm == 'dnf':
        nr = subprocess.run(['dnf', 'needs-restarting', '-r'], capture_output=True,
                            text=True, env=env, timeout=300)
        if nr.returncode == 1 and say:
            say(nr.stdout.strip().splitlines()[0] if nr.stdout.strip() else 'a restart is needed')
        return nr.returncode == 1
    return os.path.exists('/var/run/reboot-required')


def osup_job(ident, kind, security=False):
    """The work itself, as root, in a process of its own."""
    import fcntl
    fd = os.open(OSUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 1
    state = {'id': ident, 'kind': kind, 'state': 'running', 'pct': 1, 'lines': [],
             'began': time.time(), 'at': time.time(), 'packages': [], 'reboot': False,
             'pm': osup_pm(), 'phase': 'starting'}
    last = [0.0]

    def put(force=False):
        state['at'] = time.time()
        if force or time.time() - last[0] > 0.8:
            last[0] = time.time()
            state['lines'] = state['lines'][-400:]
            write_here(OSUP_FILE, json.dumps(state))

    def say(line):
        line = line.rstrip()
        if line:
            state['lines'].append(line[:300])
        put()

    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'DEBIAN_FRONTEND': 'noninteractive', 'HOME': '/root'}
    osup_proxy_env(env)

    def stream(cmd, on_line=None, ok=(0,)):
        say('$ ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             stdin=subprocess.DEVNULL, text=True, bufsize=1)
        for ln in p.stdout:
            say(ln)
            if on_line:
                on_line(ln)
        rc = p.wait()
        if rc not in ok:
            raise Refused('%s ended with %d' % (cmd[0], rc))
        return rc

    pm = state['pm']
    try:
        put(True)
        if kind == 'check':
            state['phase'] = 'asking for what is new'
            pk = []
            if pm == 'fake':
                stream([OSUP_PM, 'check'], lambda ln: pk.append(ln.strip())
                       if ln.strip() and not ln.startswith('#') else None)
            elif pm == 'dnf':
                rc_out = []
                stream(['dnf', '-q', '--refresh', 'check-update'], rc_out.append, ok=(0, 100))
                for ln in rc_out:
                    parts = ln.split()
                    if len(parts) >= 3 and '.' in parts[0] and not ln.startswith(' '):
                        pk.append('%s %s' % (parts[0], parts[1]))
                state['security'] = 0
                sec = subprocess.run(['dnf', '-q', 'updateinfo', 'list', '--security'],
                                     capture_output=True, text=True, env=env, timeout=300)
                state['security'] = len([x for x in sec.stdout.splitlines() if x.strip()])
            else:
                stream(['apt-get', 'update'])
                got = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True,
                                     text=True, env=env, timeout=300)
                for ln in got.stdout.splitlines():
                    if '/' in ln and '[upgradable' in ln:
                        name = ln.split('/', 1)[0]
                        ver = ln.split()[1] if len(ln.split()) > 1 else ''
                        pk.append('%s %s' % (name, ver))
            state['packages'] = pk[:1000]
            state['count'] = len(pk)
            # Whether the update will need a restart, told before it is made.
            state['phase'] = 'whether a restart is needed'
            state['reboot_why'] = reboot_for(pk)
            state['reboot_after'] = bool(state['reboot_why'])
            try:
                state['reboot_now'] = reboot_now(pm, env)
            except (OSError, subprocess.SubprocessError):
                state['reboot_now'] = False
            if state['reboot_now']:
                say('a restart is needed already, before any update')
            if state['reboot_why']:
                say('a restart will be needed after the update: %s' % ', '.join(state['reboot_why']))
            state['pct'] = 100
        else:
            seen = {'total': 0, 'done': 0}

            def count(ln):
                m = re.search(r'\b(\d+)/(\d+)\s*$', ln)
                if pm in ('dnf', 'fake') and m and re.search(
                        r'(Upgrading|Installing|Cleanup|Verifying|Running scriptlet|Erasing|'
                        r'Reinstalling|Downgrading|Obsoleting)\s*:', ln):
                    total = int(m.group(2)) * 2          # each one upgraded and then verified
                    seen['total'] = max(seen['total'], total)
                    seen['done'] = min(seen['total'], seen['done'] + 1)
                    state['phase'] = 'putting the packages in'
                if pm == 'dnf' and ln.startswith('Downloading Packages'):
                    state['phase'] = 'downloading'
                    state['pct'] = max(state['pct'], 8)
                if pm == 'apt':
                    m2 = re.match(r'^(\d+) upgraded, (\d+) newly installed', ln)
                    if m2:
                        seen['total'] = (int(m2.group(1)) + int(m2.group(2))) * 2
                    if ln.startswith(('Unpacking ', 'Setting up ')):
                        seen['done'] += 1
                        state['phase'] = 'putting the packages in'
                    if ln.startswith('Get:'):
                        state['phase'] = 'downloading'
                        state['pct'] = max(state['pct'], 8)
                if seen['total']:
                    state['pct'] = max(state['pct'], min(97, 10 + int(87 * seen['done'] /
                                                                      seen['total'])))
            state['phase'] = 'asking for what is new'
            # Only the security updates where asked (1.0.164): dnf's own
            # --security, unattended-upgrade on apt (it takes the security
            # sources only, as Debian and Ubuntu set it up).
            state['security_only'] = bool(security)
            if pm == 'fake':
                stream([OSUP_PM, 'upgrade'] + (['security'] if security else []), count)
            elif pm == 'dnf':
                stream(['dnf', '-y', '--refresh', 'upgrade'] + (['--security'] if security else []),
                       count)
            elif security:
                if not shutil.which('unattended-upgrade'):
                    raise Refused('only the security updates: unattended-upgrade is not on this '
                                  'machine (apt install unattended-upgrades)')
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['unattended-upgrade', '-v'], count)
            else:
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o',
                        'Dpkg::Options::=--force-confold', 'upgrade'], count)
            state['phase'] = 'whether a restart is needed'
            state['reboot'] = reboot_now(pm, env, say)
            state['pct'] = 100
        state['state'] = 'done'
        state['phase'] = 'done'
    except Refused as e:
        state.update(state='failed', said=str(e)[:300])
    except Exception as e:                              # noqa: BLE001
        state.update(state='failed', said='it broke: %s' % str(e)[:300])
    finally:
        put(True)
        os.close(fd)
    return 0



# ---- SELinux (upsmon 4.6.0, as otp 1.0.265 has it), asked in selinux.ask ------------------
# What SELinux needs for upsmon on this machine, and the way to enforcing: disabled ->
# permissive (a restart, every file labelled) -> what upsmon needs put in -> enforcing. Nothing
# changes unless asked. upsmon's own processes run unconfined (unconfined_service_t) as any
# service from /usr/local; what needs a word are the confined programs around it - nginx and
# php-fpm (httpd_t) reading the daemon's token and port in /run/upsmon and asking it on
# 127.0.0.1. Every value of the request is checked again here: booleans and port types from
# the lists below only, ports 1-65535, tcp or udp.
import base64
import errno
import hashlib
import io
import tarfile

ROOT_STATE_DIR = os.environ.get('UPSMON_ROOT_STATE', '/var/lib/upsmon-root')
SELINUX_ASK, SELINUX_FILE = 'selinux.ask', 'selinux.json'
SE_CONFIG = os.environ.get('UPSMON_SELINUX_CONFIG', '/etc/selinux/config')
SE_RELABEL = os.environ.get('UPSMON_SELINUX_RELABEL', '/.autorelabel')
SE_CMDLINE = os.environ.get('UPSMON_SELINUX_CMDLINE', '/proc/cmdline')
SE_MODULE = 'upsmon_server'
SE_CIL = os.environ.get('UPSMON_SELINUX_CIL', '/usr/local/lib/upsmon/upsmon_server.cil')
# What upsmon's files should be labelled; the label is the third field of the context.
SE_LABELS = (('/run/upsmon', 'httpd_var_run_t', 'the folder of the daemon\'s token and port'),
             ('/run/upsmon/admin-token', 'httpd_var_run_t', 'the token the settings pages ask with'),
             ('/run/upsmon/api-token', 'httpd_var_run_t', 'the token the dashboard asks with'),
             ('/var/www/upsmon', 'httpd_sys_content_t', 'the pages'))
SE_RESTORE = ('/run/upsmon', '/var/www/upsmon', '/etc/nginx/certs')
SE_BOOLEANS = ('httpd_can_network_connect',)
SE_PORT_TYPES = ('http_port_t',)
# The programs whose refusals are upsmon's business.
SE_DOMAINS = ('httpd_t', 'chronyd_t', 'syslogd_t', 'logrotate_t', 'unconfined_service_t', 'init_t',
              'smbd_t', 'smbcontrol_t')
SE_APPLIED = 'selinux-applied'      # when upsmon's needs were last put in - root's own folder


def _se_run(cmd, timeout=120, light=False, data=None):
    if not shutil.which(cmd[0]):
        return None
    if light:
        # The heavy ones (semanage loads the whole policy, ausearch reads the audit log since
        # the start) at the lowest priority: the UPS is watched meanwhile.
        if shutil.which('ionice'):
            cmd = ['ionice', '-c', '3'] + cmd
        if shutil.which('nice'):
            cmd = ['nice', '-n', '19'] + cmd
    try:
        return subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def root_state_write(name, text):
    os.makedirs(ROOT_STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(ROOT_STATE_DIR, 0o700)
    write_root(os.path.join(ROOT_STATE_DIR, name), text, 0o600)


def se_applied_at():
    # In root's own folder: in the service's, a time ahead written there would hide every
    # refusal of SELinux from the check before enforcing.
    try:
        fd = os.open(os.path.join(ROOT_STATE_DIR, SE_APPLIED), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            return float((json.load(f) or {}).get('at') or 0)
    except (OSError, TypeError, ValueError, AttributeError):
        return 0.0


def se_auditd():
    """Whether what SELinux refuses is written down at all: auditd running."""
    fake = os.environ.get('UPSMON_SELINUX_AUDITD')            # tests
    if fake:
        return fake == 'active'
    got = _se_run(['systemctl', 'is-active', 'auditd'], 20)
    return got is None or (got.stdout or '').strip() == 'active'


def se_mode():
    got = _se_run(['getenforce'], 20)
    if got is None:
        return 'absent'                 # no SELinux on this machine at all (Debian, Ubuntu)
    return (got.stdout or '').strip() or 'Disabled'


def se_config():
    text = _read_or(SE_CONFIG) or ''
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\s*(SELINUX|SELINUXTYPE)\s*=\s*([A-Za-z0-9_-]+)\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return {'mode': out.get('SELINUX', ''), 'type': out.get('SELINUXTYPE', ''), 'there': bool(text)}


def se_config_set(mode):
    """SELINUX= in /etc/selinux/config, the rest of the file as it is."""
    if mode not in ('permissive', 'enforcing'):
        raise Refused('permissive or enforcing')
    text = _read_or(SE_CONFIG)
    if text is None:
        raise Refused('%s is not there - is the SELinux policy installed? '
                      '(dnf install selinux-policy-targeted)' % SE_CONFIG)
    if re.search(r'(?m)^\s*SELINUX\s*=', text):
        new = re.sub(r'(?m)^(\s*)SELINUX\s*=.*$', r'\g<1>SELINUX=%s' % mode, text)
    else:
        new = text.rstrip('\n') + '\nSELINUX=%s\n' % mode
    if new != text:
        _put_file(SE_CONFIG, new)


def se_cmdline_off():
    """selinux=0 on the kernel's command line: the config alone does not switch it on."""
    return bool(re.search(r'(?:^|\s)selinux=0(?:\s|$)', _read_or(SE_CMDLINE) or ''))


def se_label(path):
    fake = os.environ.get('UPSMON_SELINUX_LABELS')         # tests: {path: label}
    if fake:
        try:
            return (json.load(open(fake)) or {}).get(path)
        except (OSError, ValueError):
            return None
    try:
        raw = os.getxattr(path, 'security.selinux', follow_symlinks=False)
    except (OSError, AttributeError):
        return None
    parts = raw.decode('utf-8', 'replace').rstrip('\0').split(':')
    return parts[2] if len(parts) >= 3 else None


def se_module_in():
    got = _se_run(['semodule', '-l'], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    return any(line.split()[:1] == [SE_MODULE] for line in got.stdout.splitlines())


def se_bool(name):
    got = _se_run(['getsebool', name], 20)
    if got is None or got.returncode != 0:
        return None
    return bool(re.search(r'-->\s*on\s*$', got.stdout.strip()))


def se_ports():
    """semanage port -l: {(type, proto): [(lo, hi), ...]}; None without semanage."""
    got = _se_run(['semanage', 'port', '-l'], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    out = {}
    for line in got.stdout.splitlines():
        m = re.match(r'^(\S+_port_t)\s+(tcp|udp|sctp|dccp)\s+(.+)$', line.strip())
        if not m:
            continue
        spans = []
        for p in m.group(3).split(','):
            a, _, b = p.strip().partition('-')
            try:
                spans.append((int(a), int(b or a)))
            except ValueError:
                continue
        out.setdefault((m.group(1), m.group(2)), []).extend(spans)
    return out


def se_port_has(ports, kind, proto, port):
    return any(lo <= port <= hi for lo, hi in (ports or {}).get((kind, proto), []))


def se_allowed_now(lines):
    """Which of the refusals (one line for each kind) the policy loaded now allows, as audit2why
    tells: "would be allowed by active policy" - a newer module or a boolean since."""
    if not lines:
        return []
    by_id = {}
    for key, line in lines.items():
        m = re.search(r'msg=audit\(([0-9.]+:\d+)\)', line)
        if m:
            by_id[m.group(1)] = key
    if not by_id:
        return []
    got = _se_run(['audit2why'], 300, light=True, data=''.join(lines[k] + '\n' for k in by_id.values()))
    if got is None or got.returncode != 0:
        return []
    now, cur = set(), None
    for line in (got.stdout or '').splitlines():
        m = re.search(r'msg=audit\(([0-9.]+:\d+)\)', line)
        if m and 'avc:' in line:
            cur = by_id.get(m.group(1))
            continue
        if cur is not None and 'would be allowed by active policy' in line:
            now.add(cur)
    return sorted(now)


def se_denials(since=0.0):
    """What SELinux refused since the machine started - or since upsmon's needs were last put
    in - for the programs upsmon works with."""
    got = _se_run(['ausearch', '-m', 'AVC,USER_AVC', '-ts', 'boot'], 120, light=True)
    if got is None:
        return {'tool': False, 'total': 0, 'groups': [], 'since': since}
    groups, lines, total = {}, {}, 0
    for line in (got.stdout or '').splitlines():
        if 'avc:' not in line or 'denied' not in line:
            continue
        when = re.search(r'msg=audit\((\d+)(?:\.\d+)?:', line)
        if since and when and int(when.group(1)) < since:
            continue
        perms = re.search(r'denied\s+\{([^}]*)\}', line)
        sc = re.search(r'scontext=(\S+)', line)
        tc = re.search(r'tcontext=(\S+)', line)
        cl = re.search(r'tclass=(\S+)', line)
        comm = re.search(r'comm=(\S+)', line)
        name = re.search(r'\bname=(\S+)', line)
        if not (perms and sc and tc and cl):
            continue
        st = (sc.group(1).split(':') + ['', '', ''])[2]
        tt = (tc.group(1).split(':') + ['', '', ''])[2]
        what = ' '.join(x for x in (comm.group(1) if comm else '', name.group(1) if name else '') if x)
        if st not in SE_DOMAINS and 'upsmon' not in line:
            continue
        total += 1
        key = (st, tt, cl.group(1), perms.group(1).strip())
        lines[key] = line
        g = groups.setdefault(key, {'source': st, 'target': tt, 'class': cl.group(1),
                                    'perms': perms.group(1).strip(), 'count': 0, 'what': ''})
        g['count'] += 1
        g['what'] = what.replace('"', '')[:120] or g['what']
        g['permissive'] = 'permissive=1' in line
    settled = 0
    for key in se_allowed_now(lines):
        settled += groups[key]['count']
        total -= groups.pop(key)['count']
    out = sorted(groups.values(), key=lambda g: -g['count'])[:30]
    return {'tool': True, 'total': total, 'groups': out, 'since': since, 'settled': settled}


def se_want_checked(r, left_out=None):
    """What the daemon says upsmon needs here: booleans and ports, checked against what may be.
    A port of a type this helper does not set is said and left out (a newer daemon) - not the
    whole request refused."""
    bools = []
    for b in (r.get('booleans') or [])[:8]:
        if not isinstance(b, dict) or b.get('name') not in SE_BOOLEANS:
            raise Refused('a boolean upsmon does not set')
        bools.append({'name': b['name'], 'why': str(b.get('why') or '')[:120]})
    ports = []
    for p in (r.get('ports') or [])[:16]:
        if left_out is not None and isinstance(p, dict) and p.get('proto') in ('tcp', 'udp') and \
                p.get('type') not in SE_PORT_TYPES and \
                re.match(r'^[a-z][a-z0-9_]{0,40}_port_t\Z', str(p.get('type') or '')):
            left_out.append('port %s/%s (%s) left out: this helper does not set %s - install.sh of '
                            'the daemon\'s version puts in one that does'
                            % (str(p.get('port'))[:6], p['proto'], str(p.get('why') or '')[:80], p['type']))
            continue
        if not isinstance(p, dict) or p.get('type') not in SE_PORT_TYPES or p.get('proto') not in ('tcp', 'udp'):
            raise Refused('a port type upsmon does not set')
        try:
            n = int(p.get('port'))
        except (TypeError, ValueError):
            raise Refused('a port is a number')
        if not 1 <= n <= 65535:
            raise Refused('a port is 1 to 65535')
        ports.append({'port': n, 'proto': p['proto'], 'type': p['type'], 'why': str(p.get('why') or '')[:120]})
    return bools, ports


def se_check(r):
    left = []
    bools, ports = se_want_checked(r, left)
    mode = se_mode()
    conf = se_config()
    out = {'mode': mode, 'config': conf['mode'], 'policy': conf['type'],
           'relabel_pending': os.path.exists(SE_RELABEL), 'cmdline_off': se_cmdline_off(),
           'tools': {'semanage': bool(shutil.which('semanage')), 'ausearch': bool(shutil.which('ausearch')),
                     'semodule': bool(shutil.which('semodule'))},
           'module': None, 'labels': [], 'booleans': [], 'ports': [],
           'denials': {'tool': False, 'total': 0, 'groups': []}, 'problems': [], 'left_out': left}
    if mode == 'absent':
        out['ready'] = False
        return out
    on = mode in ('Enforcing', 'Permissive')
    out['module'] = se_module_in()
    for path, want, why in SE_LABELS:
        if not os.path.exists(path):
            continue
        got = se_label(path) if on else None
        out['labels'].append({'path': path, 'label': got, 'want': want, 'why': why,
                              'ok': (got == want or (want == 'httpd_var_run_t' and got == 'httpd_runtime_t'))
                              if on else None})
    for b in bools:
        out['booleans'].append(dict(b, on=se_bool(b['name']) if on else None))
    known = se_ports() if on else None
    for p in ports:
        out['ports'].append(dict(p, labelled=(se_port_has(known, p['type'], p['proto'], p['port'])
                                             if known is not None else None)))
    if on:
        out['denials'] = se_denials(se_applied_at())
        out['auditd'] = se_auditd()
    probs = out['problems']
    if on:
        if out['module'] is False:
            probs.append('upsmon\'s module (%s) is not installed' % SE_MODULE)
        probs.extend('%s is labelled %s, not %s (%s)' % (x['path'], x['label'] or '?', x['want'], x['why'])
                     for x in out['labels'] if x['ok'] is False)
        probs.extend('the boolean %s is off (%s)' % (x['name'], x['why'])
                     for x in out['booleans'] if x['on'] is False)
        probs.extend('port %d/%s is not labelled %s (%s)' % (x['port'], x['proto'], x['type'], x['why'])
                     for x in out['ports'] if x['labelled'] is False)
        if known is None and ports:
            probs.append('semanage is not on this machine - the ports cannot be checked '
                         '(dnf install policycoreutils-python-utils)')
        if out['denials']['total']:
            probs.append(('SELinux refused %d thing(s) since upsmon\'s needs were put in'
                          if out['denials'].get('since') else
                          'SELinux refused %d thing(s) since the machine started') % out['denials']['total'])
        if not out.get('auditd', True):
            probs.append('auditd does not run - what SELinux refuses is not written down '
                         '(systemctl enable --now auditd)')
        if not out['denials']['tool']:
            probs.append('ausearch is not on this machine - what SELinux refused cannot be read '
                         '(dnf install audit)')
    out['ready'] = (mode == 'Permissive' and not probs)
    return out


def se_apply(bools, ports, said, mark=True):
    """upsmon's module, labels, booleans and ports - where SELinux is on. `mark`: when anything
    was changed, what SELinux refused before no longer counts (never on the way to enforcing)."""
    changed = False
    inpol = _read_or(SE_CIL + '.in-policy')
    if os.path.exists(SE_CIL) and shutil.which('semodule') and (
            se_module_in() is not True or inpol != _read_or(SE_CIL)):
        got = _se_run(['semodule', '-i', SE_CIL], 300)
        if got is None or got.returncode != 0:
            raise Refused('semodule -i %s: %s' % (SE_CIL, ((got.stderr or got.stdout) if got else '').strip()[-200:]))
        said.append('upsmon\'s module installed')
        changed = True
        try:
            shutil.copyfile(SE_CIL, SE_CIL + '.in-policy')
        except OSError:
            pass
    for b in bools:
        if se_bool(b['name']) is False:
            got = _se_run(['setsebool', '-P', b['name'], 'on'], 300)
            if got is None or got.returncode != 0:
                raise Refused('setsebool -P %s on: %s' % (b['name'], ((got.stderr or '') if got else '').strip()[-200:]))
            said.append('%s on' % b['name'])
            changed = True
    known = se_ports() if ports else {}
    for p in ports:
        if known is None:
            raise Refused('semanage is not on this machine (dnf install policycoreutils-python-utils)')
        if se_port_has(known, p['type'], p['proto'], p['port']):
            continue
        got = _se_run(['semanage', 'port', '-a', '-t', p['type'], '-p', p['proto'], str(p['port'])], 300)
        if got is not None and got.returncode != 0 and 'already defined' in (got.stderr or ''):
            # Never taken from the service it belongs to: -m would label it for upsmon's need,
            # and that service could not bind it at its next start.
            raise Refused('port %d/%s is another service\'s in the SELinux policy - choose another '
                          'port for it (%s)' % (p['port'], p['proto'], p['why']))
        if got is None or got.returncode != 0:
            raise Refused('semanage port %d/%s: %s' % (p['port'], p['proto'], ((got.stderr or '') if got else '').strip()[-200:]))
        said.append('port %d/%s labelled %s' % (p['port'], p['proto'], p['type']))
        changed = True
    if shutil.which('restorecon'):
        got = _se_run(['restorecon', '-R', '-v'] + [x for x in SE_RESTORE if os.path.exists(x)], 300)
        if got is not None and 'elabel' in (got.stdout or '') + (got.stderr or ''):
            said.append('upsmon\'s files labelled again')
            changed = True
    pending = os.path.join(ROOT_STATE_DIR, SE_APPLIED + '-pending')
    if mark and (changed or os.path.exists(pending)):
        root_state_write(SE_APPLIED, json.dumps({'at': time.time()}))
        try:
            os.unlink(pending)
        except OSError:
            pass
    elif changed:
        # Changed on the way to enforcing, which was refused: the next "Put in what upsmon
        # needs" marks it, though it finds nothing left to change - else what was refused
        # before it counted for good, and enforcing never came.
        root_state_write(SE_APPLIED + '-pending', json.dumps({'at': time.time()}))
    return changed


def se_do(r):
    do = r.get('do')
    left = []
    bools, ports = se_want_checked(r, left)
    said = list(left)
    if do == 'check':
        return se_check(r)
    if do == 'report':
        data = se_report_bytes(r, 'upsmon-selinux-report')
        write_here_bytes(SE_REPORT_FILE, data)
        return {'report': SE_REPORT_FILE, 'bytes': len(data), 'at': time.time()}
    mode = se_mode()
    if mode == 'absent':
        raise Refused('there is no SELinux on this machine')
    if do in ('prepare', 'apply'):
        if mode == 'Enforcing' and do == 'prepare':
            raise Refused('SELinux is enforcing already')
        if mode == 'Disabled':
            if do == 'apply':
                raise Refused('SELinux is disabled - "prepare" makes it ready first')
            se_config_set('permissive')
            said.append('%s: SELINUX=permissive' % SE_CONFIG)
            # Every file labelled at the next start, before anything runs (minutes); upsmon's
            # booleans are put in by this step again once it is permissive.
            open(SE_RELABEL, 'a').close()
            said.append('the files are labelled at the next start of the machine')
            if se_cmdline_off() and shutil.which('grubby'):
                got = _se_run(['grubby', '--update-kernel', 'ALL', '--remove-args', 'selinux'], 120)
                if got is None or got.returncode != 0:
                    raise Refused('grubby: %s' % ((got.stderr or '') if got else '')[-200:])
                said.append('selinux=0 taken off the kernel\'s command line')
            elif se_cmdline_off():
                said.append('the kernel\'s command line has selinux=0: take it away '
                            '(grubby --update-kernel ALL --remove-args selinux)')
            if os.path.exists(SE_CIL) and shutil.which('semodule'):
                got = _se_run(['semodule', '-i', SE_CIL], 300)     # may not work while disabled
                if got is not None and got.returncode == 0:
                    said.append('upsmon\'s module installed')
            said.append('restart the machine - it comes up permissive: nothing is refused yet, '
                        'what would be is written down')
        else:
            if mode == 'Permissive':
                se_config_set('permissive')
            se_apply(bools, ports, said)
    elif do == 'enforce':
        if mode != 'Permissive':
            raise Refused('SELinux is %s - it goes to enforcing from permissive only' % mode.lower())
        se_apply(bools, ports, said, mark=False)
        c = se_check(r)
        if c['problems']:
            raise Refused('not yet: ' + '; '.join(c['problems'][:4]))
        got = _se_run(['setenforce', '1'], 60)
        if got is None or got.returncode != 0:
            raise Refused('setenforce 1: %s' % ((got.stderr or '') if got else '')[-200:])
        se_config_set('enforcing')
        said.append('SELinux is enforcing, and stays so after a restart')
    elif do == 'permissive':
        if mode == 'Disabled':
            raise Refused('SELinux is disabled - "prepare" makes it permissive')
        if mode == 'Enforcing':
            got = _se_run(['setenforce', '0'], 60)
            if got is None or got.returncode != 0:
                raise Refused('setenforce 0: %s' % ((got.stderr or '') if got else '')[-200:])
        se_config_set('permissive')
        said.append('SELinux is permissive, and stays so after a restart')
    else:
        raise Refused('check, prepare, apply, enforce or permissive')
    out = se_check(r)
    out['said'] = said
    return out


def write_here_bytes(name, data):
    """write_here for bytes: by the folder's descriptor, never by its path."""
    d = web_fd()
    tmp = '.%s.%d' % (name, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=d)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        try:
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam('upsmon').gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)


# ---- what SELinux says here, gathered for whoever writes upsmon's module -----------------
SE_REPORT_FILE = 'selinux-report.tar.gz'
SE_REPORT_MOST = 2 * 1024 * 1024        # each part at most, before it is packed
SE_REPORT_PATHS = ('/run/upsmon', '/run/upsmon/admin-token', '/run/upsmon/api-token', '/var/lib/upsmon',
                   '/var/lib/upsmon/web', '/etc/upsmon', '/var/www/upsmon', '/usr/local/lib/upsmon',
                   '/var/log/upsmon', '/etc/nginx/certs', '/etc/nginx/conf.d', '/etc/chrony.conf',
                   '/run/php-fpm', '/etc/pki/ca-trust/source/anchors')
SE_REPORT_COMMS = ('python', 'upsmon', 'nginx', 'php-fpm', 'chronyd', 'rsyslogd', 'auditd', 'upsd', 'smbclient')
SE_REPORT_PORT_TYPES = ('http_port_t', 'http_cache_port_t', 'ntp_port_t', 'unreserved_port_t', 'smbd_port_t')


def _se_cut(text):
    b = text.encode('utf-8', 'replace')
    if len(b) <= SE_REPORT_MOST:
        return text
    return '(the first %d bytes left out - too long)\n' % (len(b) - SE_REPORT_MOST) + \
        b[-SE_REPORT_MOST:].decode('utf-8', 'replace')


def _se_out(cmd, timeout=120, data=None, light=True):
    """A command's words for the report - what it said, or why it said nothing."""
    if not shutil.which(cmd[0]):
        return '(%s is not on this machine)\n' % cmd[0]
    if light:
        if shutil.which('ionice'):
            cmd = ['ionice', '-c', '3'] + cmd
        if shutil.which('nice'):
            cmd = ['nice', '-n', '19'] + cmd
    try:
        got = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return '(%s: %s)\n' % (' '.join(cmd), e)
    text = (got.stdout or '') + (('\n--- stderr ---\n' + got.stderr) if got.stderr.strip() else '')
    if not text.strip():
        text = '(%s said nothing - it ended with %d)\n' % (cmd[0], got.returncode)
    return _se_cut(text)


def se_report_parts(r):
    """Every part of the report: {name: text}. Read only - nothing is changed."""
    parts = {'check.json': json.dumps(se_check(r), indent=1, sort_keys=True),
             'upsmon.json': json.dumps({'facts': r.get('facts') or {}, 'want': {
                 'booleans': r.get('booleans') or [], 'ports': r.get('ports') or []}}, indent=1, sort_keys=True)}
    kinds = 'AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR'
    raw = _se_out(['ausearch', '-m', kinds, '-ts', 'boot'], 300)
    parts['avc-raw.txt'] = raw
    parts['avc.txt'] = _se_out(['ausearch', '-m', kinds, '-ts', 'boot', '-i'], 300)
    if raw.startswith('('):
        parts['audit2why.txt'] = parts['audit2allow.te'] = raw
    else:
        parts['audit2why.txt'] = _se_out(['audit2why'], 300, data=raw)
        parts['audit2allow.te'] = _se_out(['audit2allow', '-m', 'upsmon_local'], 300, data=raw)
    sysw = []
    for name, cmd in (('os-release', ['cat', '/etc/os-release']), ('kernel', ['uname', '-a']),
                      ('started', ['uptime', '-s']), ('getenforce', ['getenforce']),
                      ('sestatus', ['sestatus', '-v']),
                      ('packages', ['rpm', '-q', 'selinux-policy', 'selinux-policy-targeted', 'policycoreutils',
                                    'policycoreutils-python-utils', 'libselinux-utils', 'audit', 'nginx',
                                    'php-fpm', 'chrony', 'nut']),
                      ('kernel command line', ['cat', SE_CMDLINE]), ('selinux config', ['cat', SE_CONFIG]),
                      ('auditd', ['systemctl', 'is-active', 'auditd'])):
        sysw.append('==== %s\n%s' % (name, _se_out(cmd, 60, light=False)))
    parts['system.txt'] = '\n'.join(sysw)
    lab = []
    for p in SE_REPORT_PATHS:
        if os.path.lexists(p):
            lab.append(_se_out(['ls', '-Zd', p], 20, light=False).rstrip())
            if os.path.isdir(p):
                lab.append(_se_out(['ls', '-Za', p], 20, light=False).rstrip())
            lab.append('  policy says: ' + _se_out(['matchpathcon', p], 20, light=False).strip())
    parts['labels.txt'] = '\n'.join(lab) + '\n'
    # -o label alone (4.6.1): -Z with -o is refused by procps ("can not use output modifiers
    # with user-defined output") - and the filter below threw that away, the file was empty.
    ps = _se_out(['ps', '-eo', 'label,user,pid,comm,args'], 60, light=False)
    keep = [x[:200] for x in ps.splitlines() if x.startswith('LABEL') or any(c in x for c in SE_REPORT_COMMS)]
    parts['processes.txt'] = '\n'.join(keep if len(keep) > 1 else ps.splitlines()[:40]) + '\n'
    ports = _se_out(['semanage', 'port', '-l'], 300)
    parts['ports.txt'] = '==== labelled\n' + '\n'.join(
        x for x in ports.splitlines() if x.split()[:1] and x.split()[0] in SE_REPORT_PORT_TYPES) + \
        '\n\n==== listening\n' + _se_out(['ss', '-lntupZ'], 60, light=False)
    bools = _se_out(['getsebool', '-a'], 60, light=False)
    parts['booleans.txt'] = '\n'.join(x for x in bools.splitlines() if re.match(
        r'^(httpd_|nis_enabled|daemons_|logging_|use_nfs|use_samba|samba_|domain_can)', x)) + '\n'
    mods = _se_out(['semodule', '-l'], 300)
    parts['modules.txt'] = '==== upsmon\n' + '\n'.join(x for x in mods.splitlines() if 'upsmon' in x.lower()) + \
        '\n\n==== %s\n%s\n==== in the policy\n%s\n' % (SE_CIL, _read_or(SE_CIL) or '(not there)',
                                                     _read_or(SE_CIL + '.in-policy') or '(none put in yet)')
    parts['README.txt'] = (
        'upsmon - what SELinux says on this machine, for whoever writes upsmon\'s module (upsmon_server).\n'
        'Made %s. Nothing was changed to make it.\n\n'
        'check.json      the card: mode, module, labels, booleans, ports, refusals\n'
        'avc*.txt        what SELinux refused since the machine started (raw and readable)\n'
        'audit2why.txt   why; audit2allow.te: what would allow it - a hint, not to be loaded\n'
        'labels.txt      the labels of upsmon\'s files and what the policy says they should be\n'
        'processes.txt   the domains the programs run in; ports.txt, booleans.txt, modules.txt\n'
        'system.txt      the system, the policy and the packages; upsmon.json: what upsmon uses here\n\n'
        'No password, key or token of upsmon is in it. The audit log holds the command lines of the\n'
        'programs refused something: upsmon never puts a secret on one - other programs on this\n'
        'machine may. Look through avc*.txt before sending it on.\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
    return parts


def se_report_bytes(r, top):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, text in se_report_parts(r).items():
            data = text.encode('utf-8', 'replace')
            info = tarfile.TarInfo('%s/%s' % (top, name))
            info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def selinux_part():
    d = web_fd()
    try:
        raw = read_req(SELINUX_ASK, 16384)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(SELINUX_ASK, d)
        return
    drop_ask(SELINUX_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = se_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(SELINUX_FILE, json.dumps(out))


def se_words(c):
    """`upsmon --selinux-check`: what se_check found, for a person."""
    lines = ['SELinux: %s (config: %s%s)' % (c['mode'], c.get('config') or '?',
                                            ', %s' % c['policy'] if c.get('policy') else '')]
    if c['mode'] == 'absent':
        lines.append('  no SELinux on this machine - nothing to do')
        return '\n'.join(lines)
    if c.get('relabel_pending'):
        lines.append('  the files are labelled at the next start of the machine')
    if c.get('cmdline_off'):
        lines.append('  the kernel\'s command line has selinux=0')
    if c['mode'] == 'Disabled':
        lines.append('  disabled - upsmon runs as always; "Make it ready (permissive)" on the pages '
                     '(Settings - SELinux) or upsmon --selinux prepare makes it permissive at the next start')
        return '\n'.join(lines)
    lines.append('  module %s: %s' % (SE_MODULE, {True: 'installed', False: 'NOT installed', None: '?'}[c['module']]))
    for x in c['labels']:
        lines.append('  %s %s: %s%s' % ('ok  ' if x['ok'] else 'FAIL', x['path'], x['label'] or '?',
                                        '' if x['ok'] else ' (want %s)' % x['want']))
    for x in c['booleans']:
        lines.append('  %s boolean %s: %s - %s' % ('ok  ' if x['on'] else 'FAIL', x['name'],
                                                   'on' if x['on'] else 'off', x['why']))
    for x in c['ports']:
        lines.append('  %s port %d/%s %s - %s' % ('ok  ' if x['labelled'] else 'FAIL', x['port'], x['proto'],
                                                 x['type'], x['why']))
    d = c['denials']
    lines.append('  refused%s: %s' % (' since upsmon\'s needs were put in' if d.get('since') else ' since the start',
                                      d['total'] if d['tool'] else '? (ausearch is not there)'))
    if d.get('settled'):
        lines.append('  refused before, allowed now (not counted): %d' % d['settled'])
    for g in d['groups'][:15]:
        lines.append('    %4dx %s -> %s %s { %s } %s' % (g['count'], g['source'], g['target'], g['class'],
                                                         g['perms'], g['what']))
    if c.get('auditd') is False:
        lines.append('  FAIL auditd does not run')
    lines.append('ready for enforcing' if c.get('ready') else
                 ('enforcing' if c['mode'] == 'Enforcing' and not c['problems'] else
                  'not ready: ' + '; '.join(c['problems'][:6]) if c['problems'] else ''))
    return '\n'.join(x for x in lines if x)


def selinux_cli(argv):
    """As root from `upsmon --selinux-check / --selinux STEP / --selinux-report`: what upsmon
    needs comes on stdin (read by the service), checked here as from the pages."""
    try:
        want = json.loads(sys.stdin.read() or '{}') if not sys.stdin.isatty() else {}
        if not isinstance(want, dict):
            want = {}
    except ValueError:
        want = {}
    as_json = '--json' in argv
    try:
        if argv[0] == '--selinux-report':
            out = argv[1] if len(argv) > 1 and not argv[1].startswith('--') else ''
            if not out:
                raise Refused('where to: --selinux-report FILE')
            data = se_report_bytes(dict(want, do='report'), 'upsmon-selinux-report')
            folder = os.path.dirname(os.path.abspath(out))
            fd, tmp = tempfile.mkstemp(dir=folder, prefix='.upsmon-selinux-')
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                os.fchmod(f.fileno(), 0o600)
            os.replace(tmp, out)
            return 0
        step = argv[1] if argv[0] == '--selinux-do' and len(argv) > 1 else 'check'
        c = se_do(dict(want, do=step))
    except Refused as e:
        print('upsmon: %s' % e, file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(c, indent=1))
    else:
        for s in c.get('said') or []:
            print('  ' + s)
        print(se_words(c))
    return 0 if (c.get('mode') in ('absent', 'Disabled') or not c.get('problems')) else 1


# ---- the system's trusted roots (upsmon 4.6.0, as otp 1.0.265 has it), osroots.ask ---------
# Certificate authorities of one's own put into the trust of the whole system - curl, dnf, LDAPS,
# SMTP, syslog over TLS, upsmon's own connections. Only by the system's own way of adding to it,
# never by touching the distribution's bundle: a file in the folder of local additions, then its
# own tool -
#   RHEL / AlmaLinux / Rocky: /etc/pki/ca-trust/source/anchors/*.pem, then update-ca-trust extract
#   Debian / Ubuntu:          /usr/local/share/ca-certificates/*.crt, then update-ca-certificates
# Both merge that folder with the distribution's list every time they run - also when an update
# of the ca-certificates package runs them. upsmon's files are named upsmon-<sha256 16>.pem
# (.crt): it lists, writes and removes only those; anything else in the folder was put there by
# somebody else and is only shown. Every certificate is read by openssl here again.
OSROOTS_ASK = 'osroots.ask'
OSROOTS_FILE = 'osroots.json'
OSROOTS_MAX = 50
OSROOTS_PEM_MAX = 16384
OSROOTS_NAME_RE = re.compile(r'^upsmon-[0-9a-f]{16}\.(pem|crt)\Z')
OSROOTS_BLOCK_RE = re.compile(r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----')
OSROOTS_FLAVOURS = {
    'rhel': {'dir': '/etc/pki/ca-trust/source/anchors', 'ext': '.pem', 'tool': ['update-ca-trust', 'extract'],
             'bundle': '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', 'pkg': ['rpm', '-q', 'ca-certificates']},
    'debian': {'dir': '/usr/local/share/ca-certificates', 'ext': '.crt', 'tool': ['update-ca-certificates'],
               'bundle': '/etc/ssl/certs/ca-certificates.crt',
               'pkg': ['dpkg-query', '-W', '-f=ca-certificates-${Version}', 'ca-certificates']}}


def osroots_where():
    """Which way this system adds to its trust - each part overridable for the tests, by the
    environment of the unit (root's alone)."""
    fl = os.environ.get('UPSMON_OSROOTS_FLAVOUR', '')
    if fl not in OSROOTS_FLAVOURS:
        fl = ''
        if os.path.isdir('/etc/pki/ca-trust/source') or shutil.which('update-ca-trust'):
            fl = 'rhel'
        elif os.path.isdir('/usr/local/share/ca-certificates') or shutil.which('update-ca-certificates'):
            fl = 'debian'
    if not fl:
        return None
    w = dict(OSROOTS_FLAVOURS[fl], flavour=fl)
    w['dir'] = os.environ.get('UPSMON_OSROOTS_DIR') or w['dir']
    w['bundle'] = os.environ.get('UPSMON_OSROOTS_BUNDLE') or w['bundle']
    if os.environ.get('UPSMON_OSROOTS_EXTRACT'):
        w['tool'] = os.environ['UPSMON_OSROOTS_EXTRACT'].split()
    if 'UPSMON_OSROOTS_PKG' in os.environ:
        w['pkg'] = os.environ['UPSMON_OSROOTS_PKG'].split()
    return w


def osroots_blocks(text):
    """Each certificate of a text as (pem, der) - nothing but certificates."""
    text = str(text or '')
    if re.search(r'PRIVATE KEY|BEGIN ENCRYPTED|BEGIN PKCS7|BEGIN TRUSTED CERTIFICATE', text):
        raise Refused('no private key and nothing but certificates (-----BEGIN CERTIFICATE-----)')
    out = []
    for body in OSROOTS_BLOCK_RE.findall(text):
        try:
            der = base64.b64decode(re.sub(r'\s+', '', body), validate=True)
        except ValueError:
            raise Refused('a certificate that is not base64')
        if not der or len(der) > OSROOTS_PEM_MAX * 3 // 4:
            raise Refused('a certificate of %d bytes - one is a few kB at most' % len(der))
        enc = base64.b64encode(der).decode('ascii')
        out.append(('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % '\n'.join(
            enc[i:i + 64] for i in range(0, len(enc), 64)), der))
    if not out:
        raise Refused('no certificate in it (-----BEGIN CERTIFICATE-----)')
    return out


def _osroots_time(s):
    import calendar
    try:
        return calendar.timegm(time.strptime(re.sub(r'\s+', ' ', s.strip()), '%b %d %H:%M:%S %Y %Z'))
    except ValueError:
        return 0


def osroots_facts(pem, der):
    """What one certificate is, as openssl reads it - and what stands against it (`refused`) or
    is to be known (`warn`). The same words as the daemon's osr_facts."""
    txt = openssl(['x509', '-noout', '-text', '-nameopt', 'RFC2253'], 'not a certificate openssl reads', data=pem)

    def one(rx):
        m = re.search(rx, txt, re.M)
        return m.group(1).strip() if m else ''
    f = {'fp': hashlib.sha256(der).hexdigest(), 'subject': one(r'^\s*Subject: ?(.*)$')[:400],
         'issuer': one(r'^\s*Issuer: ?(.*)$')[:400], 'not_before': _osroots_time(one(r'Not Before\s*: (.*)$')),
         'not_after': _osroots_time(one(r'Not After\s*: (.*)$')), 'sig': one(r'Signature Algorithm: (\S+)')[:60]}
    cn = re.search(r'(?:^|,)CN=((?:\\.|[^,])*)', f['subject'])
    f['cn'] = (cn.group(1) if cn else f['subject'])[:200]
    alg = one(r'Public Key Algorithm: (\S+)')
    bits = one(r'Public-Key: \((\d+) bit\)')
    curve = one(r'NIST CURVE: (\S+)') or one(r'ASN1 OID: (\S+)')
    f['key'] = ('RSA %s' % bits) if alg == 'rsaEncryption' else \
        ('EC %s' % (curve or bits)) if alg == 'id-ecPublicKey' else \
        (alg.replace('ED25519', 'Ed25519').replace('ED448', 'Ed448')[:40] if alg else '?')
    f['bits'] = int(bits) if bits.isdigit() else 0
    bc = re.search(r'X509v3 Basic Constraints:.*\n\s*(CA:(TRUE|FALSE))', txt)
    f['ca'] = bool(bc and bc.group(2) == 'TRUE')
    ku = re.search(r'X509v3 Key Usage:.*\n\s*(.*)', txt)
    f['ku_sign'] = None if not ku else ('Certificate Sign' in ku.group(1))
    f['root'] = f['subject'] == f['issuer']
    f['kind'] = 'root' if f['root'] else 'intermediate'
    refused, warn = [], []
    now = time.time()
    if not bc:
        refused.append('it says nothing of being an authority (no basicConstraints CA:TRUE) - only a '
                       'certificate authority goes here')
    elif not f['ca']:
        refused.append('it is not a certificate authority (CA:FALSE) - a server\'s own certificate does '
                       'not go here')
    if f['ku_sign'] is False:
        refused.append('its key usage does not let it sign certificates (no keyCertSign)')
    if f['not_after'] and f['not_after'] < now:
        warn.append('it ran out on %s - nothing it signed is trusted'
                    % time.strftime('%Y-%m-%d', time.gmtime(f['not_after'])))
    if f['not_before'] and f['not_before'] > now + 300:
        warn.append('it is valid only from %s' % time.strftime('%Y-%m-%d', time.gmtime(f['not_before'])))
    if not f['root'] and re.match(r'(?i)(sha1|md5|md2)', f['sig']):
        warn.append('it is signed with %s - the system\'s crypto policy (DEFAULT) refuses it, and every '
                    'chain through it' % f['sig'])
    if f['key'].startswith('RSA') and 0 < f['bits'] < 2048:
        warn.append('its key has %d bits - the system\'s crypto policy (DEFAULT) refuses fewer than 2048'
                    % f['bits'])
    f['refused'], f['warn'] = refused, warn
    return f


def osroots_dir_ok(d, make=False):
    """The folder of local additions: a folder of root's, never a link."""
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        if not make:
            return False
        os.makedirs(d, 0o755, exist_ok=True)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused('%s is not a folder (a link?) - nothing is written there' % d)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise Refused('%s is not root\'s alone (owner %d, mode %o) - nothing is written there'
                      % (d, st.st_uid, stat.S_IMODE(st.st_mode)))
    return True


def _osroots_read(path, most=1048576):
    """A plain file's bytes - None for a link (never followed), a folder, a pipe."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EISDIR, errno.ENXIO):
            return None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, most + 1)
    finally:
        os.close(fd)
    return data[:most]


def osroots_files(d):
    """[(relative name, path)] of the folder - one level of subfolders too (Debian reads them)."""
    out = []
    try:
        top = sorted(os.listdir(d))
    except OSError:
        return out
    for n in top[:500]:
        p = os.path.join(d, n)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                out += [(n + '/' + m, os.path.join(p, m)) for m in sorted(os.listdir(p))[:200]]
            except OSError:
                pass
        else:
            out.append((n, p))
    return out


def osroots_cert_of_file(path):
    """The certificates of a file somebody else put there - PEM or DER - with their facts."""
    raw = _osroots_read(path)
    if raw is None:
        return None
    text = raw.decode('ascii', 'replace')
    if '-----BEGIN CERTIFICATE-----' not in text:
        try:
            got = subprocess.run(['openssl', 'x509', '-inform', 'DER'], input=raw, capture_output=True, timeout=30)
            if got.returncode != 0:
                return []
            text = got.stdout.decode('ascii', 'replace')
        except (OSError, subprocess.SubprocessError):
            return []
    out = []
    try:
        blocks = OSROOTS_BLOCK_RE.findall(text) and osroots_blocks(
            '\n'.join(m.group(0) for m in OSROOTS_BLOCK_RE.finditer(text)))
    except Refused:
        return []
    for pem, der in (blocks or [])[:20]:
        try:
            f = osroots_facts(pem, der)
            out.append({k: f[k] for k in ('fp', 'cn', 'subject', 'issuer', 'not_before', 'not_after', 'key',
                                          'kind', 'ca')})
        except Refused:
            continue
    return out


def osroots_bundle(w):
    """The system's own list as its tool made it last - and the package that brings it."""
    out = {'path': w['bundle'], 'count': 0, 'bytes': 0, 'at': 0}
    try:
        st = os.stat(w['bundle'])
        out.update(bytes=st.st_size, at=st.st_mtime)
        with open(w['bundle'], 'rb') as f:
            out['count'] = f.read(64 * 1048576).count(b'-----BEGIN CERTIFICATE-----')
    except OSError:
        out['missing'] = True
    pkg = ''
    if w.get('pkg'):
        try:
            got = subprocess.run(w['pkg'], capture_output=True, text=True, timeout=30)
            if got.returncode == 0 and got.stdout.strip():
                pkg = got.stdout.strip().splitlines()[0][:120]
        except (OSError, subprocess.SubprocessError, IndexError):
            pkg = ''
    out['package'] = pkg
    return out


def _osroots_in_bundle(w, ders):
    try:
        with open(w['bundle'], 'rb') as f:
            flat = re.sub(rb'\s+', b'', f.read(64 * 1048576))
    except OSError:
        return {}
    return {hashlib.sha256(d).hexdigest(): base64.b64encode(d) in flat for d in ders}


def osroots_read(w):
    """upsmon's own, the others', the system's list."""
    ours, others = [], []
    if w and os.path.isdir(w['dir']):
        for rel, p in osroots_files(w['dir']):
            if OSROOTS_NAME_RE.match(rel):
                raw = _osroots_read(p, 65536)
                if raw is None:
                    others.append({'file': rel, 'certs': [], 'link': os.path.islink(p)})
                    continue
                try:
                    (pem, der), = osroots_blocks(raw.decode('ascii', 'replace'))
                    f = osroots_facts(pem, der)
                    f.pop('refused', None)
                    f.update(file=rel, der=der)
                    ours.append(f)
                except (Refused, ValueError):
                    ours.append({'file': rel, 'broken': True})
            else:
                if os.path.islink(p):
                    try:
                        to = os.readlink(p)[:300]
                    except OSError:
                        to = '?'
                    others.append({'file': rel, 'link': to, 'certs': []})
                    continue
                read_others = sum(1 for o in others if o.get('certs'))
                others.append({'file': rel, 'certs': (osroots_cert_of_file(p) or []) if read_others < 60 else []})
    inb = _osroots_in_bundle(w, [f['der'] for f in ours if f.get('der')]) if w else {}
    for f in ours:
        f.pop('der', None)
        if f.get('fp'):
            f['in_bundle'] = inb.get(f['fp'])
    return {'ours': ours, 'others': others[:200], 'system': osroots_bundle(w) if w else {},
            'flavour': (w or {}).get('flavour', ''), 'dir': (w or {}).get('dir', ''),
            'tool': ' '.join((w or {}).get('tool') or []), 'tool_there': bool(w and shutil.which(w['tool'][0]))}


def _osroots_put(d, name, pem):
    """Written beside it under a name of its own and renamed into place: root's, 0644."""
    fd, tmp = tempfile.mkstemp(prefix='.upsmon-', dir=d)
    try:
        os.fchmod(fd, 0o644)
        try:
            os.fchown(fd, 0, 0)
        except OSError:
            pass
        with os.fdopen(fd, 'w') as f:
            fd = None
            f.write(pem)
        os.replace(tmp, os.path.join(d, name))
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def osroots_sync(w, certs, force=False):
    """The folder made to hold exactly the certificates wanted of upsmon's - the others' left as
    they are - and the system's tool run when anything changed. (said, refused)."""
    if not w:
        raise Refused('this system has neither update-ca-trust (RHEL, AlmaLinux, Rocky) nor '
                      'update-ca-certificates (Debian, Ubuntu)')
    if not isinstance(certs, list) or len(certs) > OSROOTS_MAX:
        raise Refused('the certificates wanted: a list of %d at most' % OSROOTS_MAX)
    want, refused = {}, []
    for c in certs:
        if not isinstance(c, str) or len(c) > OSROOTS_PEM_MAX:
            raise Refused('each certificate as PEM text of %d bytes at most' % OSROOTS_PEM_MAX)
        blocks = osroots_blocks(c)
        if len(blocks) != 1:
            raise Refused('one certificate in each')
        pem, der = blocks[0]
        f = osroots_facts(pem, der)
        if f['refused']:
            refused.append({'fp': f['fp'], 'cn': f['cn'], 'why': '; '.join(f['refused'])})
            continue
        want['upsmon-%s%s' % (f['fp'][:16], w['ext'])] = pem
    osroots_dir_ok(w['dir'], make=bool(want))
    said, changed = [], False
    have = {rel: p for rel, p in osroots_files(w['dir']) if OSROOTS_NAME_RE.match(rel)} \
        if os.path.isdir(w['dir']) else {}
    for name, pem in sorted(want.items()):
        p = have.get(name)
        if p is not None:
            raw = _osroots_read(p, 65536)
            if raw is not None and raw.decode('ascii', 'replace') == pem and not os.path.islink(p):
                continue
            os.unlink(p)            # changed by somebody, or a link: put back as it is wanted
        _osroots_put(w['dir'], name, pem)
        said.append('added %s' % name)
        changed = True
        if shutil.which('restorecon') and os.path.isdir('/sys/fs/selinux') and \
                not os.environ.get('UPSMON_OSROOTS_DIR'):
            subprocess.run(['restorecon', '-F', os.path.join(w['dir'], name)], capture_output=True)
    for name, p in sorted(have.items()):
        if name not in want:
            os.unlink(p)
            said.append('removed %s' % name)
            changed = True
    if changed or force:
        if not shutil.which(w['tool'][0]):
            raise Refused('%s is not on this machine - the files are in %s, the system\'s list is not '
                          'made again until it runs' % (w['tool'][0], w['dir']))
        got = subprocess.run(w['tool'], capture_output=True, text=True, timeout=300)
        if got.returncode != 0:
            raise Refused('%s ended with %d: %s' % (' '.join(w['tool']), got.returncode,
                                                    ((got.stderr or got.stdout).strip() or '-')[-300:]))
        said.append('%s run' % ' '.join(w['tool']))
    return said, refused


def osroots_do(r):
    w = osroots_where()
    do = r.get('do')
    if do == 'list':
        return dict(osroots_read(w), said=[], refused=[])
    if do == 'check':
        text = r.get('text')
        if not isinstance(text, str) or len(text) > OSROOTS_MAX * OSROOTS_PEM_MAX:
            raise Refused('the certificates as PEM text')
        return {'certs': [dict(osroots_facts(pem, der), pem=pem)
                          for pem, der in osroots_blocks(text)[:OSROOTS_MAX + 1]]}
    if do == 'sync':
        said, refused = osroots_sync(w, r.get('certs'), bool(r.get('force')))
        return dict(osroots_read(w), said=said, refused=refused)
    raise Refused('list, check or sync')


def osroots_part():
    d = web_fd()
    try:
        raw = read_req(OSROOTS_ASK, OSROOTS_MAX * OSROOTS_PEM_MAX * 2 + 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(OSROOTS_ASK, d)
        return
    drop_ask(OSROOTS_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = osroots_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(OSROOTS_FILE, json.dumps(out))



def serve():
    d = web_fd()
    for part, words in ((console_part, 'the console at login'), (net_part, 'restart and power off'),
                        (ntp_part, 'the time'), (osup_part, 'the updates of the system'),
                        (selinux_part, 'SELinux'), (osroots_part, 'the system\'s trusted roots')):
        try:
            part()
        except Exception as e:                          # noqa: BLE001
            print('upsmon_web.py: %s: %s' % (words, e), file=sys.stderr)
    try:
        os.replace('request.json', 'request.taken', src_dir_fd=d, dst_dir_fd=d)
    except FileNotFoundError:
        return 0
    except OSError:
        drop_ask('request.taken', d)
        drop_ask('request.json', d)
        return 1
    last = status_read()
    out = {'at': time.time(), 'dh': last.get('dh') or {}}
    try:
        try:
            raw = json.loads(read_req('request.taken').decode('utf-8'))
        except ValueError as e:
            raise Refused('the request does not read: %s' % e)
        if isinstance(raw, dict):
            out.update(id=re.sub(r'[^A-Za-z0-9]', '', str(raw.get('id') or ''))[:32],
                       hash=re.sub(r'[^0-9a-f]', '', str(raw.get('hash') or ''))[:64])
        PROGRESS['id'] = str(out.get('id') or '')
        progress('checking what was asked', 1)
        r = checked(raw)
        out.update(id=r['id'], hash=r['hash'])
        said_n, dh = nginx_part(r, last)
        out['dh'] = dict(out['dh'], **dh)
        out.update(state='done', said=[s for s in said_n if s])
    except Refused as e:
        out.update(state='failed', said=[str(e)])
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out.update(state='failed', said=['it broke: %s' % e])
    finally:
        for name in ('request.taken', 'progress.json'):
            try:
                os.unlink(name, dir_fd=d)
            except OSError:
                pass
    write_here('status.json', json.dumps(out))
    return 0


def main(argv):
    if argv[:1] == ['--status']:
        print(json.dumps({'status': status_read()}))
        return 0
    if os.geteuid() != 0:
        print('upsmon_web.py: root only', file=sys.stderr)
        return 2
    if argv[:1] in (['--selinux-check'], ['--selinux-do'], ['--selinux-report']):
        return selinux_cli(argv)
    if argv[:1] == ['--os-job'] and len(argv) >= 3 and argv[2] in ('check', 'upgrade'):
        return osup_job(re.sub(r'[^A-Za-z0-9]', '', argv[1])[:40], argv[2],
                        argv[3:4] == ['security'])
    return serve()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
