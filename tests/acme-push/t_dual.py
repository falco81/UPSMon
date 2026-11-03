"""A dual certificate (RSA + its ECDSA twin) uploaded and downloaded by hand."""
import sys, os, json, subprocess, base64, io, zipfile, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sender import make_cert
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography import x509
D = os.path.dirname(os.path.abspath(__file__))
def api(*calls):
    r = subprocess.run(['node', D + '/uiapi.js', json.dumps(list(calls))], capture_output=True, text=True, cwd=D)
    return json.loads(r.stdout.strip().splitlines()[-1])
R = {'ok': 0, 'bad': 0}
def check(name, cond, got=None):
    R['ok' if cond else 'bad'] += 1
    print(('OK   ' if cond else 'FAIL ') + name + ('' if cond else '   -> %s' % (str(got)[:300],)))
me = [t for t in api(['web', None])[0]['tls'] if t != 'vip'][0]
cr, kr, fr = make_cert(['ups.example.net'], 'rsa'); ce, ke, fe = make_cert(['ups.example.net'], 'ec')
def kind_of_key(pem, pw=None):
    k = load_pem_private_key(pem.encode() if isinstance(pem, str) else pem, pw)
    return 'ec' if isinstance(k, ec.EllipticCurvePrivateKey) else 'rsa'
def export(fmt, which, pw='Export-pass-1'):
    x = api(['web', {'action': 'tls_export', 'target': me, 'format': fmt, 'password': pw, 'which': which}])[0]
    return x, (base64.b64decode(x['data']) if x.get('data') else b'')
def pfx_kind(data, pw='Export-pass-1'):
    k, c, _ = pkcs12.load_key_and_certificates(data, pw.encode())
    return 'ec' if isinstance(k, ec.EllipticCurvePrivateKey) else 'rsa'
# 1. PEM: both, in any order, all in one
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': ce + ke + cr + kr}])[0]
check('PEM with both certificates and both keys: taken', 'error' not in r, r)
check('… kept as dual: RSA first, its ECDSA twin beside it', r.get('tls', {}).get('info', {}).get('key', '').startswith('RSA') and r['tls'].get('alt', {}).get('info', {}).get('key', '').startswith('EC'), r.get('tls'))
time = __import__('time'); time.sleep(8)
req = json.load(open('/var/lib/upsmon/web/request.json'))['tls']['node']
check('… handed to nginx both (two ssl_certificate)', bool(req.get('alt')) and 'BEGIN' in req['alt']['cert'], list(req))
# 2. export
x, d = export('pfx', 'main'); check('PFX main: the RSA one and its key', x['name'].endswith('.pfx') and pfx_kind(d) == 'rsa', x.get('name'))
x, d = export('pfx', 'alt'); check('PFX alt: the ECDSA one and its key, -ecdsa in the name', x['name'].endswith('-ecdsa.pfx') and pfx_kind(d) == 'ec', x.get('name'))
x, d = export('pfx', 'both'); z = zipfile.ZipFile(io.BytesIO(d)); names = z.namelist()
check('PFX both: a .zip of two PFX, one each', x['name'].endswith('-dual.zip') and len(names) == 2 and sorted(pfx_kind(z.read(n)) for n in names) == ['ec', 'rsa'], (x.get('name'), names))
x, d = export('key', 'both', ''); z = zipfile.ZipFile(io.BytesIO(d))
check('the keys alone, both: two keys', sorted(kind_of_key(z.read(n)) for n in z.namelist()) == ['ec', 'rsa'], z.namelist())
x, d = export('pem_key', 'alt', ''); check('PEM with the key, alt: the ECDSA certificate and its key', 'BEGIN CERTIFICATE' in d.decode() and kind_of_key(d.decode()[d.decode().index('-----BEGIN PRIVATE'):]) == 'ec', x.get('name'))
x, d = export('pem', 'both', ''); z = zipfile.ZipFile(io.BytesIO(d))
check('PEM (public) both: two certificates, no key', len(z.namelist()) == 2 and all(b'PRIVATE' not in z.read(n) for n in z.namelist()), z.namelist())
x, d = export('der', 'main', ''); check('DER main as before', x['name'].endswith('.der') and d[:1] == b'\x30', x.get('name'))
# 3. two PFX files
def mkpfx(cpem, kpem, pw):
    return base64.b64encode(pkcs12.serialize_key_and_certificates(b'x', load_pem_private_key(kpem.encode(), None), x509.load_pem_x509_certificate(cpem.encode()), None, BestAvailableEncryption(pw.encode()))).decode()
cr2, kr2, _ = make_cert(['ups.example.net'], 'rsa'); ce2, ke2, _ = make_cert(['ups.example.net'], 'ec')
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': '', 'pfx': mkpfx(ce2, ke2, 'pfx-pass-1'), 'pfx2': mkpfx(cr2, kr2, 'pfx-pass-1'), 'password': 'pfx-pass-1'}])[0]
check('two PFX files (ECDSA first): dual, RSA first', 'error' not in r and r['tls']['info']['key'].startswith('RSA') and r['tls'].get('alt'), r)
# 4. one alone: the twin goes
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': ce + ke}])[0]
check('one alone afterwards: kept alone, no twin', 'error' not in r and not r['tls'].get('alt'), r.get('tls', {}).get('alt'))
x = api(['web', {'action': 'tls_export', 'target': me, 'format': 'pem', 'which': 'alt'}])[0]
check('alt asked of one alone: said so', 'error' in x and 'no second' in x['error'], x)
x, d = export('pfx', 'both'); check('both asked of one alone: just the one', x['name'].endswith('.pfx') and pfx_kind(d) == 'ec', x.get('name'))
# 5. refused
ca, ka, _ = make_cert(['ups.example.net'], 'rsa')
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': cr + kr + ca + ka}])[0]; check('two RSA: refused, said why', 'error' in r and 'one RSA and one ECDSA' in r['error'], r)
co, ko, _ = make_cert(['other.example.org'], 'ec')
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': cr + kr + co + ko}])[0]; check('different names: refused', 'error' in r and 'same names' in r['error'], r)
c3, k3, _ = make_cert(['ups.example.net'], 'ec')
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': cr + kr + ce + ke + c3 + k3}])[0]; check('three keys: refused', 'error' in r and '3 private keys' in r['error'], r)
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': cr + kr + ce}])[0]; check('a twin without its key: kept alone (as before)', 'error' not in r and not r['tls'].get('alt'), r)
r = api(['web', {'action': 'tls_upload', 'target': me, 'cert': ce + ke + cr + kr}])[0]; check('dual again, for the command line', r['tls'].get('alt'), r)
# 6. the command line
out = tempfile.mkdtemp()
p = subprocess.run(['python3', '/home/user/UPSMon/upsmon.py', '--cert-export', 'pfx', '--cert-which', 'both', '--out', out + '/c.zip'], env=dict(os.environ, UPSMON_PASSWORD='Export-pass-1'), capture_output=True, text=True, cwd=out)
z = zipfile.ZipFile(out + '/c.zip')
check('upsmon --cert-export pfx --cert-which both', p.returncode == 0 and sorted(pfx_kind(z.read(n)) for n in z.namelist()) == ['ec', 'rsa'], p.stdout + p.stderr)
print('%d ok, %d failed' % (R['ok'], R['bad']))
