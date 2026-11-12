"""The whole chain (4.7.0, 4.7.1 as plexmon 2.9.8 describes it): checked against the system's
roots, completed from CA Issuers as browsers do, the missing authority uploaded by hand, a
private CA's root, the file nginx has now, and upsmon asking itself as a client that fetches
nothing. A CA of its own: a root (as the system's), an intermediate served over HTTP at the
address in the leaf's AIA as DER, PEM and PKCS#7. python3 tests/chain/t_chain.py"""
import http.server, json, os, socket, subprocess, sys, tempfile, threading, time

W = tempfile.mkdtemp(prefix='upsmon-chain-')
os.environ['UPSMON_STATE'] = W
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
import upsmon_admin as ua  # noqa: E402

ok = bad = 0


def check(name, cond, got=None):
    global ok, bad
    if cond:
        ok += 1
        print('OK   ' + name)
    else:
        bad += 1
        print('FAIL %s  -> %r' % (name, got))


def ossl(*a):
    subprocess.run(['openssl'] + list(a), check=True, capture_output=True, cwd=W)


SERVE = os.path.join(W, 'www')
os.makedirs(SERVE)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=SERVE, **k)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = 'http://127.0.0.1:%d/' % PORT


def ca(name, cn, issuer=None, aia=None):
    """A CA certificate: self-signed, or signed by `issuer` (a name of one made before)."""
    if issuer is None:
        ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.pem', '-days', '3650',
             '-subj', '/CN=' + cn, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        return open(os.path.join(W, name + '.pem')).read()
    ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + cn)
    with open(os.path.join(W, name + '.ext'), 'w') as f:
        f.write('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' +
                ('authorityInfoAccess=caIssuers;URI:%s\n' % aia if aia else ''))
    ossl('x509', '-req', '-in', name + '.csr', '-CA', issuer + '.pem', '-CAkey', issuer + '.key', '-CAcreateserial',
         '-out', name + '.pem', '-days', '1825', '-extfile', name + '.ext')
    return open(os.path.join(W, name + '.pem')).read()


def leaf(name, issuer, aia=None):
    ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=monitor.example')
    with open(os.path.join(W, name + '.ext'), 'w') as f:
        f.write('basicConstraints=CA:FALSE\nsubjectAltName=DNS:monitor.example\n' +
                ('authorityInfoAccess=caIssuers;URI:%s\n' % aia if aia else ''))
    ossl('x509', '-req', '-in', name + '.csr', '-CA', issuer + '.pem', '-CAkey', issuer + '.key', '-CAcreateserial',
         '-out', name + '.pem', '-days', '90', '-extfile', name + '.ext')
    return open(os.path.join(W, name + '.pem')).read(), open(os.path.join(W, name + '.key')).read()


root = ca('root', 'Test Root G2')
inter = ca('int', 'Test TLS RSA CA G1', 'root')
ossl('x509', '-in', 'int.pem', '-outform', 'DER', '-out', 'www/int.cer')
ossl('crl2pkcs7', '-nocrl', '-certfile', 'int.pem', '-outform', 'DER', '-out', 'www/int.p7c')
with open(os.path.join(SERVE, 'int.pem'), 'w') as f:
    f.write(inter)
other = ca('other', 'Somebody Else CA')
with open(os.path.join(SERVE, 'other.pem'), 'w') as f:
    f.write(other)
# the system's roots, as this test has them: the test root among them
SYS = os.path.join(W, 'system-bundle.pem')
with open(SYS, 'w') as f:
    f.write(root)
ua.CHAIN_SYSTEM = (SYS,)

for kind in ('int.cer', 'int.pem', 'int.p7c'):
    lf, _k = leaf('leaf-' + kind.replace('.', '-'), 'int', base + kind)
    chain, st = ua.chain_complete(lf, [], '')
    check('the leaf alone, the issuer at its CA Issuers as %s: completed' % kind,
          st['ok'] is True and len(chain) == 1 and st['fetched'] == ['Test TLS RSA CA G1'], st)
check('… said: complete - 2 certificates up to Test Root G2 (fetched: … - it was not sent with the certificate)',
      st['words'] == 'complete - 2 certificates up to Test Root G2 (fetched: Test TLS RSA CA G1 - it was not sent with '
                     'the certificate)', st['words'])
lf, key = leaf('leaf', 'int', base + 'int.cer')
chain, st = ua.chain_complete(lf, [inter], '')
check('the chain given: complete, nothing fetched', st['ok'] is True and not st['fetched'] and
      st['words'] == 'complete - 2 certificates up to Test Root G2', st)
lfd, keyd = leaf('leaf-down', 'int', 'http://127.0.0.1:1/int.cer')
chain, st = ua.chain_complete(lfd, [], '')
check('the CA Issuers address does not answer: incomplete, the authority named, why',
      st['ok'] is False and chain == [] and st['missing'] == 'Test TLS RSA CA G1' and 'could not be fetched' in st['words'], st)
check('… openssl\'s words without the temporary files', 'upsmon-chain-' not in json.dumps(st), st['words'])
lfn, _k = leaf('leaf-noaia', 'int')
chain, st = ua.chain_complete(lfn, [], '')
check('no CA Issuers address: incomplete, said so', st['ok'] is False and 'names no CA Issuers address' in st['words'], st['words'])
lfo, _k = leaf('leaf-other', 'int', base + 'other.pem')
chain, st = ua.chain_complete(lfo, [], '')
check('the address holds another authority: nothing taken', st['ok'] is False and chain == [] and 'does not hold' in st['words'], st)
# a private CA: root (not the system's) -> intermediate (AIA -> its root) -> leaf
proot = ca('proot', 'Company Root CA')
with open(os.path.join(SERVE, 'proot.pem'), 'w') as f:
    f.write(proot)
pint = ca('pint', 'Company Issuing CA', 'proot', base + 'proot.pem')
with open(os.path.join(SERVE, 'pint.pem'), 'w') as f:
    f.write(pint)
plf, pkey = leaf('pleaf', 'pint', base + 'pint.pem')
chain, st = ua.chain_complete(plf, [], '')
check('a private CA: it leads to its root, which the system does not trust - said so',
      st['ok'] is False and st.get('private_root') == 'Company Root CA' and 'a root the system does not trust' in st['words']
      and len(chain) == 1, st)
chain, st = ua.chain_complete(plf, [pint], proot)
check('… with its root given: complete, "a private root: only clients that trust it take it"',
      st['ok'] is True and st['words'].endswith('a private root: only clients that trust it take it'), st['words'])
# self-signed
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ss.key', '-out', 'ss.pem', '-days', '30', '-subj', '/CN=ups.local')
chain, st = ua.chain_complete(open(os.path.join(W, 'ss.pem')).read(), [], '')
check('self-signed: ok is null, its words', st['ok'] is None and st['words'].startswith('self-signed - no chain'), st)
# the upload path
got = ua.cert_bundle(lf, key)
check('upload of the leaf alone: completed, nginx gets cert + intermediate',
      got['chain'].strip() == inter.strip() and got['chain_state']['ok'] and got['chain_state']['fetched'], got['chain_state'])
got = ua.cert_bundle(root + inter + lf, key)
check('upload with root and intermediate in any order: the root left out of the chain',
      got['chain'].strip() == inter.strip() and 'Test Root G2' in json.dumps(got['root_info']) and got['chain_state']['ok'], got['chain_state'])
# the certificate in place: Complete the chain, then Upload the missing authority
store = ua.Storage()
me = ua.node_name()
ua.tls_save(store, me, {'cert': lfd, 'chain': '', 'root': '', 'key': 'x', 'info': ua.cert_info(lfd)}, 'tester')
st, prof = ua.tls_chain_complete(store, me, 'tester')
check('Complete the chain, the address down: incomplete, said', st['ok'] is False and 'Test TLS RSA CA G1' in st['words'], st)
for txt, words in (('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----', 'no private key'),
                   ('hello', 'no certificate in it'), (other, 'none of these is the authority')):
    try:
        ua.tls_chain_add(store, me, txt, 'tester')
        check('Upload the missing authority refuses: %s' % words, False, 'taken')
    except ValueError as e:
        check('Upload the missing authority refuses: %s' % words, words in str(e), str(e))
st, prof = ua.tls_chain_add(store, me, inter, 'tester')
check('Upload the missing authority (the intermediate): complete, nginx gets it',
      st['ok'] is True and ua.tls_profile(store, me)['chain'].strip() == inter.strip(), st)
try:
    ua.tls_chain_add(store, me, inter, 'tester')
    check('the same again: "every certificate in it is there already"', False)
except ValueError as e:
    check('the same again: "every certificate in it is there already"', 'there already' in str(e), str(e))
# a private CA without its root, then its root uploaded by the dialog
ua.tls_save(store, me, {'cert': plf, 'chain': pint, 'root': '', 'key': 'x', 'info': ua.cert_info(plf)}, 'tester')
st, prof = ua.tls_chain_complete(store, me, 'tester')
check('a private CA kept without its root: not complete', st['ok'] is False, st)
st, prof = ua.tls_chain_add(store, me, proot, 'tester')
p2 = ua.tls_profile(store, me)
check('… its root uploaded: kept as the root (never in the chain), complete with a private root',
      st['ok'] is True and 'private root' in st['words'] and p2['root'].strip() == proot.strip() and
      p2['chain'].strip() == pint.strip() and p2['root_info'][0]['cn'] == 'Company Root CA', st)
check('… events written', 'added Company Root CA to the chain' in json.dumps(store.db.rows('SELECT * FROM events')), None)
# the file nginx has now (cert_now): leaf alone, then with its chain
f1 = os.path.join(W, 'nginx1.pem')
with open(f1, 'w') as f:
    f.write(lf)
n1 = ua.cert_now(f1)
with open(f1 + '2', 'w') as f:
    f.write(lf + inter)
n2 = ua.cert_now(f1 + '2')
check('the file nginx has: the leaf alone - chain_ok false; with the intermediate - true',
      n1['chain_ok'] is False and n2['chain_ok'] is True, (n1.get('chain_ok'), n1.get('chain_why'), n2.get('chain_ok')))


def free_port():
    x = socket.socket()
    x.bind(('127.0.0.1', 0))
    n = x.getsockname()[1]
    x.close()
    return n


ua.tls_save(store, me, {'cert': lf, 'chain': '', 'root': '', 'key': 'x', 'info': ua.cert_info(lf)}, 'tester')
for with_chain in (False, True):
    port = free_port()
    args = ['openssl', 's_server', '-accept', str(port), '-cert', os.path.join(W, 'leaf.pem'),
            '-key', os.path.join(W, 'leaf.key'), '-quiet']
    if with_chain:
        args += ['-cert_chain', os.path.join(W, 'int.pem')]
    srvp = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    os.environ['UPSMON_SELFCHECK_PORT'] = str(port)
    ua.SELF_CHECK.update(hash=None, busy=False)
    ua.web_self_check(store, me, 'h%s' % with_chain)
    for _ in range(40):
        time.sleep(0.5)
        if not ua.SELF_CHECK['busy']:
            break
    row = json.loads(store.get_meta('web:selfcheck:' + me) or '{}')
    srvp.kill()
    if with_chain:
        check('served with its chain: "checked as a client that fetches nothing: the whole chain is sent"',
              row.get('ok') is True and 'the whole chain is sent' in row.get('words', ''), row)
    else:
        check('served alone: refused - and an event', row.get('ok') is False and 'refuses what nginx sends' in row.get('words', '')
              and 'refuses what nginx sends' in json.dumps(store.db.rows('SELECT * FROM events')), row)
srv.shutdown()
print('%d ok, %d failed' % (ok, bad))
sys.exit(1 if bad else 0)
