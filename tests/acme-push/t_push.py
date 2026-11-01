import sys, json, subprocess, time, os, base64
sys.path.insert(0, os.path.dirname(__file__))
from sender import Acme, make_cert, b64
D = os.path.dirname(__file__)
def ui(*acts):
    out = subprocess.run(['node', D + '/ui.js'] + [json.dumps(a) for a in acts], capture_output=True, text=True, cwd=D)
    return json.loads(out.stdout.strip().splitlines()[-1])
R = {'ok': 0, 'bad': 0}
def check(name, cond, got=None):
    R['ok' if cond else 'bad'] += 1
    print(('OK   ' if cond else 'FAIL ') + name + ('' if cond else '   -> %r' % (got,)))
def code_of(a): return a[1].get('code') if isinstance(a[1], dict) else None

v0 = ui({'action': 'on', 'on': True})[0]
for k in v0.get('keys') or []: ui({'action': 'forget', 'key_id': k['key_id']})
ui({'action': 'on', 'on': False})
a = Acme('acme@acme1')
st, h = a.hello(); check('hello while off says little', st == 200 and h['on'] is False and 'app_id' not in h, h)
check('pair while off: off 403', a.call('pair', {}, app_id='0'*32)[0] == 403, None)
v = ui({'action': 'on', 'on': True}, {'action': 'code'})
code = v[1]['code']; check('a code of 16 characters, shown XXXX-XXXX-XXXX-XXXX', len(code) == 19 and code.count('-') == 3, code)
st, h = a.hello(); check('hello while on: id, key, slot, pairing', h['on'] and len(h['app_id']) == 32 and len(base64.b64decode(h['enc_key'])) == 32 and h['pairing'] and h['slots'] == ['node:' + h['node']] and h['cluster'] is False, h)
check('inventory before pairing: not_paired 401', code_of(a.call('inventory', {})) == 'not_paired', None)
r = a.pair(code, wrong=True); check('a wrong proof: bad_code 403', r[0] == 403 and r[1]['code'] == 'bad_code', r)
r = a.pair(code); check('pair with the code: confirm checks out', r[0] == 200 and r[1].get('_confirm_ok'), r)
r = a.pair(code); check('the code once only: pairing_closed', r[0] == 403 and r[1]['code'] == 'pairing_closed', r)
r = a.call('inventory', {}); check('inventory signed', r[0] == 200 and r[1]['slots'][0]['names'] == ['ups.example.net'] and r[1]['cluster']['on'] is False, r)
raw, ts, nonce = a.last
r = a.call('inventory', raw=raw, ts=ts, nonce=nonce); check('the same nonce again: replay', code_of(r) == 'replay', r)
r = a.call('inventory', {}, ts=int(time.time()) - 400); check('400 s old: stale', code_of(r) == 'stale', r)
other = Acme()
r = a.call('inventory', {}, sig_with=other.sk); check('signed with another key: bad_signature', code_of(r) == 'bad_signature', r)
r = other.call('inventory', {}, app_id=a.app_id); check('a key not paired: unknown_key', code_of(r) == 'unknown_key', r)
r = a.call('inventory', {}, op_signed='install'); check('signed as another operation: bad_signature', code_of(r) == 'bad_signature', r)
r = a.call('inventory', {}, app_id='0' * 32); check('signed for another application: bad_signature', code_of(r) == 'bad_signature', r)
r = a.call('inventory', raw=b'{}', nonce='short'); check('a nonce of a wrong shape: unsigned', code_of(r) == 'unsigned', r)
# five wrong codes and it is gone
v = ui({'action': 'code'}); c2 = v[0]['code']; b = Acme('acme@b')
b.hello()
for i in range(5): r = b.pair(c2, wrong=True)
r = b.pair(c2); check('five wrong tries and the code is gone', r[0] == 403 and r[1]['code'] == 'pairing_closed', r)
# installs
cert, key, fp = make_cert(['ups.example.net'], 'ec')
body = {'slots': ['auto'], 'cert_pem': cert, 'chain_pem': '', 'fingerprint': fp, 'key': a.seal(key, fp), 'key_type': 'ec-256', 'names': ['ups.example.net'], 'check_names': True, 'force': False}
r = a.call('install', body); check('install (auto): installed', r[0] == 200 and r[1]['installed'][0]['state'] == 'installed', r)
r = a.call('install', body); check('the same again: already', r[0] == 200 and r[1]['installed'][0]['state'] == 'already', r)
inv = a.call('inventory', {})[1]['slots'][0]
check('inventory: managed_by acme-push, its fingerprint', inv['managed_by'] == 'acme-push' and inv['current']['fingerprint'] == fp, inv)
c_rsa, k_rsa, f_rsa = make_cert(['ups.example.net'], 'rsa'); c_ec, k_ec, f_ec = make_cert(['ups.example.net'], 'ec')
dual = {'slots': ['this'], 'cert_pem': c_rsa, 'chain_pem': '', 'fingerprint': f_rsa, 'key': a.seal(k_rsa, f_rsa), 'key_type': 'rsa-2048',
        'alt': {'cert_pem': c_ec, 'chain_pem': '', 'fingerprint': f_ec, 'key': a.seal(k_ec, f_ec), 'key_type': 'ec-256'}}
r = a.call('install', dual); check('a dual one (RSA + ECDSA twin): installed', r[0] == 200 and r[1]['installed'][0]['state'] == 'installed', r)
inv = a.call('inventory', {})[1]['slots'][0]
check('inventory: both, rsa-2048 + its ec-256 twin', inv['current']['fingerprint'] == f_rsa and (inv['current']['alt'] or {}).get('fingerprint') == f_ec and inv['current']['key_type'] == 'rsa-2048', inv['current'])
r = a.call('install', dual); check('the dual one again: already', r[1]['installed'][0]['state'] == 'already', r)
r = a.call('install', dict(body, slots=['node:' + h['node']])); check('back to one (by slot id): installed, twin gone', r[1]['installed'][0]['state'] == 'installed' and a.call('inventory', {})[1]['slots'][0]['current']['alt'] is None, r)
r = a.call('install', dict(body, force=True)); check('force: put in again', r[1]['installed'][0]['state'] == 'installed', r)
c2_, k2_, f2_ = make_cert(['other.example.org'], 'ec')
wrongname = dict(body, cert_pem=c2_, fingerprint=f2_, key=a.seal(k2_, f2_))
r = a.call('install', wrongname); check('another name (auto): names 422', r[0] == 422 and r[1]['code'] == 'names', r)
r = a.call('install', dict(wrongname, slots=['this'])); check('another name to a slot: names 422', code_of(r) == 'names', r)
r = a.call('install', dict(wrongname, slots=['this'], check_names=False)); check('check_names false while not allowed: names 422', code_of(r) == 'names', r)
ui({'action': 'other_names', 'on': True})
r = a.call('install', dict(wrongname, slots=['this'], check_names=False)); check('… once allowed on the card: installed', r[0] == 200 and r[1]['installed'][0]['state'] == 'installed', r)
ui({'action': 'other_names', 'on': False})
_, k_other, _ = make_cert(['ups.example.net'], 'ec')
r = a.call('install', dict(body, key=a.seal(k_other, fp), force=True)); check('a key not the certificate\'s: key_mismatch', code_of(r) == 'key_mismatch', r)
r = a.call('install', dict(body, key=a.seal(key, 'ab' * 32), force=True)); check('sealed for another certificate: bad_key', code_of(r) == 'bad_key', r)
r = a.call('install', dict(body, key=a.seal(key, fp, enc=b64(os.urandom(32))), force=True)); check('sealed to another key: bad_key', code_of(r) == 'bad_key', r)
r = a.call('install', dict(body, fingerprint='cd' * 32)); check('a fingerprint not of the certificate: bad_request', code_of(r) == 'bad_request', r)
ce, ke, fe = make_cert(['ups.example.net'], 'ec', past=True)
r = a.call('install', dict(body, cert_pem=ce, fingerprint=fe, key=a.seal(ke, fe))); check('ran out: expired', code_of(r) == 'expired', r)
r = a.call('install', dict(body, slots=['vip'])); check('a slot not here: no_slot 404', r[0] == 404 and r[1]['code'] == 'no_slot', r)
r = a.call('install', raw=b'[1,2]'); check('a body not an object: bad_request', code_of(r) == 'bad_request', r)
r = a.call('install', raw=b'x' * (1024 * 1024 + 10)); check('over 1 MiB: too_big 413', r[0] == 413, r)
# pasted key
c = Acme('acme@pasted')
v = ui({'action': 'paste', 'key': c.text}); check('a key pasted on the card', any(k['key_id'] == c.kid for k in v[0]['keys']), v)
c.hello(); r = c.call('inventory', {}); check('the pasted key: inventory', r[0] == 200, r)
v = ui({'action': 'forget', 'key_id': c.kid}); r = c.call('inventory', {}); check('forgotten: unknown_key', code_of(r) == 'unknown_key', r)
v = ui({'action': 'paste', 'key': 'acme-push-ed25519 notakey'}); check('a key of a wrong shape refused', 'error' in v[0], v)
# the card's view, events, ACME care
v = ui({})  # GET is not reachable through ui.js's POST; take the view from an action instead
v = ui({'action': 'other_names', 'on': False})[0]
check('the card: the last push, the paired acme, the slot', v['last'] and v['last']['acme'] == 'acme 1.0 on test' and len(v['keys']) == 1 and v['slots'][0]['managed_by'] == 'acme-push', v)
ui({'action': 'on', 'on': False})
r = a.call('inventory', {}); check('switched off: off', code_of(r) == 'off', r)
ui({'action': 'on', 'on': True})
r = a.call('inventory', {}); check('switched on again: the pairing kept', r[0] == 200, r)
print('%d ok, %d failed' % (R['ok'], R['bad']))
