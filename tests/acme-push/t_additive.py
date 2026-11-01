"""Chapter 0: every way of a certificate works as before - push off, and push on and paired."""
import sys, os, json, subprocess, datetime, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sender import Acme, make_cert
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
D = os.path.dirname(os.path.abspath(__file__))
def api(*calls):
    r = subprocess.run(['node', D + '/uiapi.js', json.dumps(list(calls))], capture_output=True, text=True, cwd=D)
    return json.loads(r.stdout.strip().splitlines()[-1])
R = {'ok': 0, 'bad': 0}
def check(name, cond, got=None):
    R['ok' if cond else 'bad'] += 1
    print(('OK   ' if cond else 'FAIL ') + name + ('' if cond else '   -> %r' % (str(got)[:400],)))
ME = api(['web', None])[0]
me = [t for t in ME['tls'] if t != 'vip'][0]
def sign_csr(csr_pem):
    ca = ec.generate_private_key(ec.SECP256R1())
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Own CA')]))
         .public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=60)).sign(ca, hashes.SHA256()))
    return c.public_bytes(S.Encoding.PEM).decode()
def round_(mode):
    print('---- push %s' % mode)
    t = me
    r = api(['web', {'action': 'tls_selfsigned', 'target': t, 'cn': 'ups.example.net', 'names': '', 'days': 30, 'kind': 'ec'}])[0]
    check(mode + ': self-signed made', 'error' not in r and (r.get('tls') or {}).get('how', '').startswith('self-signed'), r)
    r = api(['web', {'action': 'tls_csr', 'target': t, 'cn': 'ups.example.net', 'names': '', 'kind': 'rsa2048'}])[0]
    check(mode + ': a request (CSR) made', 'BEGIN CERTIFICATE REQUEST' in (r.get('csr') or ''), r)
    r = api(['web', {'action': 'tls_upload', 'target': t, 'cert': sign_csr(r['csr'])}])[0]
    check(mode + ': its answer uploaded (the key that waited)', 'error' not in r and r['tls']['how'] == 'uploaded', r)
    cert, key, fp = make_cert(['ups.example.net'], 'ec')
    r = api(['web', {'action': 'tls_upload', 'target': t, 'cert': cert, 'key': key}])[0]
    check(mode + ': a PEM uploaded by hand', 'error' not in r and r['tls']['how'] == 'uploaded', r)
    r = api(['web', {'action': 'tls_export', 'target': t, 'format': 'pfx', 'password': 'Export-pass-1'}])[0]
    check(mode + ': exported as PFX with its key', 'error' not in r and r.get('data'), list(r)[:5])
    r = api(['acme', {'action': 'care', 'target': t, 'on': True}], ['acme', None])[1]
    tg = [x for x in r['targets'] if x['target'] == t][0]
    check(mode + ': own ACME takes it back (Look after it)', tg['care'] is True, tg)
    r = api(['db', {'action': 'backup'}], ['db', {'action': 'check'}])
    check(mode + ': a copy of the databases, and the check', 'error' not in r[0] and 'error' not in r[1], r)
    r = api(['web', {'action': 'tls_selfsigned', 'target': t, 'cn': 'ups.example.net', 'names': '', 'days': 30, 'kind': 'rsa2048'}])[0]
    check(mode + ': self-signed again at the end', 'error' not in r, r)

api(['acme-push', {'action': 'on', 'on': False}])
round_('off')
v = api(['acme-push', {'action': 'on', 'on': True}], ['acme-push', {'action': 'code'}])[1]
a = Acme('acme@acme1'); a.hello(); st, _ = a.pair(v['code']); check('paired', st == 200)
round_('on and paired')
# a push, then each other way replaces it and is said so
cert, key, fp = make_cert(['ups.example.net'], 'ec')
r = a.call('install', {'slots': ['auto'], 'cert_pem': cert, 'fingerprint': fp, 'key': a.seal(key, fp)})
check('pushed', r[0] == 200 and r[1]['installed'][0]['state'] == 'installed', r)
r = api(['acme', None])[0]; tg = [x for x in r['targets'] if x['target'] == me][0]
check('own ACME leaves the pushed one alone (as after an upload)', tg['care'] is False, tg)
c2, k2, f2 = make_cert(['ups.example.net'], 'ec')
api(['web', {'action': 'tls_upload', 'target': me, 'cert': c2, 'key': k2}])
inv = a.call('inventory', {})[1]['slots'][0]
check('an upload by hand replaces it; the slot says manual', inv['managed_by'] == 'manual' and inv['current']['fingerprint'] == f2, inv)
api(['acme', {'action': 'care', 'target': me, 'on': True}])
r = api(['acme', None])[0]; tg = [x for x in r['targets'] if x['target'] == me][0]
check('own ACME can be given the slot back', tg['care'] is True, tg)
r = a.call('install', {'slots': ['auto'], 'cert_pem': cert, 'fingerprint': fp, 'key': a.seal(key, fp)})
check('pushed again after that: installed', r[0] == 200 and r[1]['installed'][0]['state'] == 'installed', r)
ev = api(['events', None])[0]
words = [e.get('words') or e.get('what') or '' for e in (ev.get('events') or ev.get('rows') or [])]
check('the push is an event "by acme push, key …"', any(('by acme push, key ' + a.kid) in w for w in words), words[:5])
api(['acme-push', {'action': 'on', 'on': False}])
r = api(['web', None])[0]
check('switched off: the certificate pushed stays in place', r['tls'][me]['how'].startswith('acme push'), r['tls'][me].get('how'))
print('%d ok, %d failed' % (R['ok'], R['bad']))
