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
        if t['pem']['root']:
            write_root(files['root'], t['pem']['root'] + t['pem']['chain'], 0o644)
            block = set_directive(block, 'ssl_trusted_certificate', files['root'])
        else:
            block = set_directive(block, 'ssl_trusted_certificate', None)
        subj = openssl(['x509', '-noout', '-subject', '-enddate'], 'the certificate',
                       t['pem']['cert']).strip().replace('\n', ', ')
        said.append('certificate: %s' % subj)
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
              'dh': os.path.join(CERT_DIR, 'upsmon-dh.pem')}
VIP_FILES = {'cert': os.path.join(CERT_DIR, 'upsmon-vip.pem'),
             'key': os.path.join(CERT_DIR, 'upsmon-vip.key'),
             'root': os.path.join(CERT_DIR, 'upsmon-vip-ca.pem'),
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



def serve():
    d = web_fd()
    try:
        console_part()
    except Exception as e:                              # noqa: BLE001
        print('upsmon_web.py: the console at login: %s' % e, file=sys.stderr)
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
    return serve()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
