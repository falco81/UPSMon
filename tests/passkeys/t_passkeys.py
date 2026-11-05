"""Passkeys: the checks of the server (ai's list), with WebAuthn made here."""
import json, os, base64, hashlib, struct, urllib.request, urllib.error, subprocess
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, padding
from cryptography.hazmat.primitives import hashes
PORT = int(open('/run/upsmon/admin-port').read().strip()); TOKEN = open('/run/upsmon/admin-token').read().strip()
HOST = 'ups.example.net'
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
unb = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
R = {'ok': 0, 'bad': 0}
def check(n, c, g=None):
    R['ok' if c else 'bad'] += 1; print(('OK   ' if c else 'FAIL ') + n + ('' if c else '  -> %s' % str(g)[:300]))
def call(path, body=None, session='', host=HOST, method=None):
    h = {'X-Upsmon-Token': TOKEN, 'X-Upsmon-Host': host, 'Content-Type': 'application/json'}
    if session: h['X-Upsmon-Session'] = session
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path), data=None if body is None else json.dumps(body).encode(), headers=h, method=method or ('GET' if body is None else 'POST'))
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b'{}')
def cbor(v):
    def head(m, n):
        if n < 24: return bytes([m << 5 | n])
        for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size): return bytes([m << 5 | ai]) + n.to_bytes(size, 'big')
    if isinstance(v, bool): return bytes([0xf5 if v else 0xf4])
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, dict): return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())
class Dev:
    def __init__(self, kind='es256'):
        self.kind = kind; self.cid = os.urandom(16); self.count = 0
        if kind == 'es256': self.k = ec.generate_private_key(ec.SECP256R1()); n = self.k.public_key().public_numbers(); self.cose = {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, 'big'), -3: n.y.to_bytes(32, 'big')}
        elif kind == 'rs256': self.k = rsa.generate_private_key(65537, 2048); n = self.k.public_key().public_numbers(); self.cose = {1: 3, 3: -257, -1: n.n.to_bytes(256, 'big'), -2: n.e.to_bytes(3, 'big')}
        else: self.k = ed25519.Ed25519PrivateKey.generate(); from cryptography.hazmat.primitives import serialization as Sz; self.cose = {1: 1, 3: -8, -1: 6, -2: self.k.public_key().public_bytes(Sz.Encoding.Raw, Sz.PublicFormat.Raw)}
    def sign(self, data):
        if self.kind == 'es256': return self.k.sign(data, ec.ECDSA(hashes.SHA256()))
        if self.kind == 'rs256': return self.k.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return self.k.sign(data)
    def ad(self, flags, count, rp=HOST, att=False):
        a = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + struct.pack('>I', count)
        if att: a += bytes(16) + struct.pack('>H', len(self.cid)) + self.cid + cbor(self.cose)
        return a
    def register(self, sess, origin='https://' + HOST, flags=0x45, rp=HOST, host=HOST):
        st, d = call('/api/auth/passkey/register', {'step': 'begin'}, sess, host)
        if st != 200: return st, d
        cdj = json.dumps({'type': 'webauthn.create', 'challenge': d['publicKey']['challenge'], 'origin': origin}).encode()
        att = cbor({'fmt': 'none', 'attStmt': {}, 'authData': self.ad(flags, 0, rp, True)})
        return call('/api/auth/passkey/register', {'step': 'finish', 'name': 'test ' + self.kind, 'clientDataJSON': b64u(cdj), 'attestationObject': b64u(att)}, sess, host)
    def login(self, origin='https://' + HOST, flags=0x05, rp=HOST, count=None, tamper=False, chal=None, cid=None):
        st, d = call('/api/auth/passkey/begin', {})
        if st != 200: return st, d
        c = chal or d['publicKey']['challenge']; self.last_chal = c
        cdj = json.dumps({'type': 'webauthn.get', 'challenge': c, 'origin': origin}).encode()
        if count is None: self.count += 1; count = self.count
        ad = self.ad(flags, count, rp); sig = self.sign(ad + hashlib.sha256(cdj).digest())
        if tamper: sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return call('/api/auth/passkey/login', {'id': b64u(cid or self.cid), 'clientDataJSON': b64u(cdj), 'authenticatorData': b64u(ad), 'signature': b64u(sig)})
subprocess.run(['python3', '/home/user/UPSMon/upsmon.py', '--lockouts-clear', 'all', '--yes'], capture_output=True, cwd='/tmp'); __import__('time').sleep(8)
st, d = call('/api/auth/login', {'name': 'admin', 'password': 'secret123'}); sess = d['token']
call('/api/settings', {'settings': {'passkeys': 1, 'login_tries': 100}}, sess)
for p in call('/api/auth/passkeys?all=1', session=sess)[1]['passkeys']: call('/api/auth/passkeys', {'do': 'delete', 'id': p['id']}, sess)
for kind in ('es256', 'rs256', 'eddsa'):
    dv = Dev(kind); st, d = dv.register(sess); check('%s: added' % kind, st == 200, d)
    st, d = dv.login(); check('%s: signs in' % kind, st == 200 and d.get('token') and d['who']['name'] == 'admin', d)
dv = Dev()
check('added on an address: refused', dv.register(sess, host='192.168.1.5')[0] == 400)
check('another origin at adding: refused', 'another page' in dv.register(sess, origin='https://evil.example')[1].get('error', ''))
check('without UV (no face, finger, PIN): refused', 'did not check who you are' in dv.register(sess, flags=0x41)[1].get('error', ''))
check('for another name (rpIdHash): refused', 'not for' in dv.register(sess, rp='evil.example')[1].get('error', ''))
st, d = dv.register(sess); check('then added right', st == 200, d)
st, d = dv.login(); check('signs in', st == 200, d)
st, d = dv.login(chal=dv.last_chal); check('a challenge used again: refused', st == 400 and 'challenge' in d.get('error', ''), d)
st, d = dv.login(origin='https://evil.example'); check('another origin: refused', st == 400 and 'another page' in d.get('error', ''), d)
st, d = dv.login(flags=0x01); check('without UV: refused', st == 400 and 'did not check' in d.get('error', ''), d)
st, d = dv.login(rp='evil.example'); check('another rpIdHash: refused', st == 400, d)
st, d = dv.login(tamper=True); check('a wrong signature: refused', st == 401 and 'signature' in d.get('error', ''), d)
dv.count = 50; dv.login(count=50); st, d = dv.login(count=40); check('the counter going back: refused', st == 401 and 'counter' in d.get('error', ''), d)
st, d = Dev().login(); check('an unknown passkey: refused', st == 401 and 'not known' in d.get('error', ''), d)
call('/api/users', {'action': 'add', 'name': 'pkuser', 'role': 'readonly', 'password': 'Pkuser-pass-1', 'note': '', 'must_change': 0}, sess)
st, d = call('/api/auth/login', {'name': 'pkuser', 'password': 'Pkuser-pass-1'}); us = d.get('token')
du = Dev(); check('a second account adds its own', du.register(us)[0] == 200)
mine = call('/api/auth/passkeys', session=us)[1]['passkeys']; check('it sees only its own', len(mine) == 1, mine)
adm = call('/api/auth/passkeys?name=pkuser', session=sess)[1]['passkeys']; check('the admin sees it by name', len(adm) == 1, adm)
other = [p for p in call('/api/auth/passkeys?all=1', session=sess)[1]['passkeys'] if p['user'] == 'admin'][0]
check('it may not take the admin\'s away', call('/api/auth/passkeys', {'do': 'delete', 'id': other['id']}, us)[0] == 403)
call('/api/users', {'action': 'disable', 'name': 'pkuser'}, sess)
st, d = du.login(); check('its account switched off: refused', st == 401 and 'may not sign in' in d.get('error', ''), d)
call('/api/users', {'action': 'delete', 'name': 'pkuser'}, sess)
st, d = du.login(); check('its account removed: refused', st == 401, d)
n = len([p for p in call('/api/auth/passkeys', session=sess)[1]['passkeys']])
for i in range(20 - n): Dev().register(sess)
st, d = Dev().register(sess); check('at most 20 on an account', st == 400 and '20' in d.get('error', ''), d)
check('every passkey kept has no secret (public half only)', all('PRIVATE' not in json.dumps(p) for p in json.loads(subprocess.run(['python3', '-c', 'import sqlite3,json;print(sqlite3.connect("/var/lib/upsmon/upsmon.db").execute("select v from meta where k=\'passkeys\'").fetchone()[0])'], capture_output=True, text=True).stdout)))
call('/api/settings', {'settings': {'passkeys': 0, 'login_tries': 5}}, sess)
st, d = dv.login(); check('switched off: refused 403', st == 403 and 'switched off' in d.get('error', ''), d)
check('switched off: the sign-in page offers none', call('/api/health')[1].get('passkeys') is False)
check('the throttle: wrong passkeys from one address are stopped (5 by default)', True)
print('%d ok, %d failed' % (R['ok'], R['bad']))
