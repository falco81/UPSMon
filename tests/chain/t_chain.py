"""The whole chain (4.7.0): a certificate uploaded without its intermediate is completed
from CA Issuers as browsers do - kept only when it then reaches a trusted root; a chain
given is ordered and kept; a fetch that fails or gives another authority keeps nothing.
A CA of its own: a root (as the system's), an intermediate served over HTTP at the address
in the leaf's AIA, as DER, PEM and PKCS#7. python3 tests/chain/t_chain.py"""
import http.server, json, os, subprocess, sys, tempfile, threading

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
# the CA: root -> intermediate -> leaf (AIA -> http://127.0.0.1:PORT/int.cer)
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '3650',
     '-subj', '/CN=Test Root G2', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=Test TLS RSA CA G1')
with open(os.path.join(W, 'int.ext'), 'w') as f:
    f.write('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
ossl('x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'int.pem',
     '-days', '1825', '-extfile', 'int.ext')
ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=monitor.example')


def leaf_with(url, out):
    with open(os.path.join(W, 'leaf.ext'), 'w') as f:
        f.write('basicConstraints=CA:FALSE\nsubjectAltName=DNS:monitor.example\n'
                'authorityInfoAccess=caIssuers;URI:%s\n' % url)
    ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'int.pem', '-CAkey', 'int.key', '-CAcreateserial', '-out', out,
         '-days', '90', '-extfile', 'leaf.ext')
    return open(os.path.join(W, out)).read()


ossl('x509', '-in', 'int.pem', '-outform', 'DER', '-out', 'www/int.cer')
ossl('crl2pkcs7', '-nocrl', '-certfile', 'int.pem', '-outform', 'DER', '-out', 'www/int.p7c')
with open(os.path.join(SERVE, 'int.pem'), 'w') as f:
    f.write(open(os.path.join(W, 'int.pem')).read())
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'other.key', '-out', 'www/other.pem', '-days', '30',
     '-subj', '/CN=Somebody Else CA', '-addext', 'basicConstraints=critical,CA:TRUE')
root = open(os.path.join(W, 'root.pem')).read()
inter = open(os.path.join(W, 'int.pem')).read()
key = open(os.path.join(W, 'leaf.key')).read()
# the system's roots, as this test has them: the test root among them
SYS = os.path.join(W, 'system-bundle.pem')
with open(SYS, 'w') as f:
    f.write(root)
ua.CHAIN_SYSTEM = (SYS,)
base = 'http://127.0.0.1:%d/' % PORT

for kind in ('int.cer', 'int.pem', 'int.p7c'):
    leaf = leaf_with(base + kind, 'leaf-%s.pem' % kind)
    chain, c = ua.chain_complete(leaf, [], [])
    check('the leaf alone, the issuer at its CA Issuers as %s: completed' % kind,
          c['ok'] and len(chain) == 1 and c['fetched'] == ['Test TLS RSA CA G1'] and c['top'] == 'Test Root G2', c)
leaf = leaf_with(base + 'int.cer', 'leaf.pem')
chain, c = ua.chain_complete(leaf, [inter], [])
check('the chain given: kept, nothing fetched', c['ok'] and not c['fetched'] and c['count'] == 2, c)
check('… said: complete (2 certificates up to Test Root G2)', ua.chain_words(c) == 'complete (2 certificates up to Test Root G2)',
      ua.chain_words(c))
leaf_down = leaf_with('http://127.0.0.1:1/int.cer', 'leaf-down.pem')
chain, c = ua.chain_complete(leaf_down, [], [])
check('the CA Issuers address does not answer: incomplete, the intermediate named', not c['ok'] and chain == [] and
      c['missing'] == 'Test TLS RSA CA G1' and 'could not be fetched' in c['error'], c)
check('… said: incomplete - the intermediate Test TLS RSA CA G1 is not sent',
      ua.chain_words(c) == 'incomplete - the intermediate Test TLS RSA CA G1 is not sent', ua.chain_words(c))
leaf_other = leaf_with(base + 'other.pem', 'leaf-other.pem')
chain, c = ua.chain_complete(leaf_other, [], [])
check('the address gives another authority: nothing taken', not c['ok'] and chain == [] and 'another authority' in c['error'], c)
# a chain to a root the system does not trust: what was fetched is not kept
ua.CHAIN_SYSTEM = (os.path.join(W, 'nothing.pem'),)
with open(ua.CHAIN_SYSTEM[0], 'w') as f:
    f.write(open(os.path.join(SERVE, 'other.pem')).read())
chain, c = ua.chain_complete(leaf, [], [])
check('a root the system does not trust: the fetched link not kept', not c['ok'] and chain == [] and not c['fetched'], c)
chain, c = ua.chain_complete(leaf, [], [root])
check('… with the company\'s root given beside it: completed against it', c['ok'] and len(chain) == 1, c)
ua.CHAIN_SYSTEM = (SYS,)
# self-signed
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ss.key', '-out', 'ss.pem', '-days', '30', '-subj', '/CN=ups.local')
chain, c = ua.chain_complete(open(os.path.join(W, 'ss.pem')).read(), [], [])
check('self-signed: said so, nothing fetched', c['self_signed'] and not c['fetched'], c)
# the upload path: cert_bundle with the leaf alone, and with the chain in the wrong order + the root
got = ua.cert_bundle(leaf, key)
check('upload of the leaf alone: the chain completed, nginx gets cert + intermediate',
      got['chain'].strip() == inter.strip() and got['chain_check']['ok'] and got['chain_check']['fetched'], got['chain_check'])
got = ua.cert_bundle(root + inter + leaf, key)
check('upload with root and intermediate in any order: the intermediate in the chain, the root left out',
      got['chain'].strip() == inter.strip() and 'Test Root G2' in json.dumps(got['root_info']) and got['chain_check']['ok']
      and not got['chain_check']['fetched'], got['chain_check'])
# the certificate in place, completed from the card
store = ua.Storage()
prof = {'cert': leaf, 'chain': '', 'root': '', 'key': 'x', 'info': ua.cert_info(leaf)}
ua.tls_save(store, ua.node_name(), prof, 'tester')
c, said = ua.tls_chain_complete(store, ua.node_name(), 'tester')
p2 = ua.tls_profile(store, ua.node_name())
check('Complete the chain on the certificate in place: saved, said', c['ok'] and p2['chain'].strip() == inter.strip() and
      said and p2['chain_check']['ok'], (c, said))
check('… an event', 'complete (2 certificates up to Test Root G2)' in json.dumps(store.db.rows('SELECT * FROM events')), None)
# upsmon asks itself once nginx has it: a server sending the leaf alone, then leaf + chain
import socket, time
def free_port():
    x = socket.socket(); x.bind(('127.0.0.1', 0)); n = x.getsockname()[1]; x.close(); return n
for with_chain in (False, True):
    port = free_port()
    args = ['openssl', 's_server', '-accept', str(port), '-cert', os.path.join(W, 'leaf.pem'), '-key', os.path.join(W, 'leaf.key'), '-quiet']
    if with_chain:
        args += ['-cert_chain', os.path.join(W, 'int.pem')]
    srvp = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    os.environ['UPSMON_SELFCHECK_PORT'] = str(port)
    ua.SELF_CHECK.update(hash=None, busy=False)
    ua.web_self_check(store, ua.node_name(), 'h%s' % with_chain)
    for _ in range(40):
        time.sleep(0.5)
        if not ua.SELF_CHECK['busy']:
            break
    row = json.loads(store.get_meta('web:selfcheck:' + ua.node_name()) or '{}')
    srvp.kill()
    if with_chain:
        check('served with its chain: 2 sent, a plain client trusts them', row.get('ok') and row.get('sent') == 2, row)
    else:
        check('served alone: 1 sent, refused - and an event', not row.get('ok') and row.get('sent') == 1 and
              'does not trust them' in json.dumps(store.db.rows('SELECT * FROM events')), row)
srv.shutdown()
print('%d ok, %d failed' % (ok, bad))
sys.exit(1 if bad else 0)
