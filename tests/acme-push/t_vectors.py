"""acme push: the test vectors of docs/acme-push-protocol.md section 8, with the
cryptography package and in plain Python (python3 t_vectors.py pure)."""
import os, sys, hashlib, hmac, base64, time
pure = len(sys.argv) > 1
if pure: os.environ['UPSMON_PUSH_PURE'] = '1'
import tempfile
os.environ.setdefault('UPSMON_STATE', tempfile.mkdtemp(prefix='upsmon-vec-'))
sys.argv = sys.argv[:1]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
import upsmon_admin as U
g = vars(U)
print('using', g['PUSH_CRYPTO'])
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization as S
b64 = lambda b: base64.b64encode(b).decode()
seed = bytes(range(0, 32)); appx = bytes(range(32, 64)); eph = bytes(range(64, 96)); gn = bytes(range(96, 108))
sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
pub = sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
ok = lambda name, got, want: print(('OK  ' if got == want else 'BAD ') + name, '' if got == want else (got, want))
ok('acme public key', b64(pub), 'A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=')
kid = hashlib.sha256(pub).hexdigest()[:16]; ok('key id', kid, '56475aa75463474c')
APP = '00112233445566778899aabbccddeeff'
body = b'{"slots": ["auto"]}'
canon = '\n'.join(['acme-push/1', 'inventory', APP, kid, '1793534400', 'n0nce-0123456789ab', hashlib.sha256(body).hexdigest()]).encode()
sig = base64.b64decode('7nqJW4/NR3Et6pZx3B8qS3rvQGaQR0UTlNdptpRs4lxaZtc3Cf2zBRkOWPB0tV/rmQNfwbcl2/FKJ3Pu2h/bDg==')
ok('signature verifies', g['push_ed25519_verify'](pub, canon, sig), True)
ok('a changed message fails', g['push_ed25519_verify'](pub, canon + b'x', sig), False)
nine = (9).to_bytes(32, 'little')
apppub = g['push_x25519'](appx, nine); ok('application public key', b64(apppub), 'NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ=')
epk = g['push_x25519'](eph, nine); ok('epk', b64(epk), 'eaYx7t4b+cmPEgMs3q3Q56B5OY/HhriMyEbsia+FpRo=')
shared = g['push_x25519'](appx, epk); ok('shared (receiver side)', shared.hex(), '04c304fb1ca83cee75e206344231f33797e07d9929db670994b7c6fbeb1dc255')
ok('shared (sender side)', g['push_x25519'](eph, apppub).hex(), shared.hex())
ak = g['push_hkdf_sha256'](shared, epk + apppub, b'acme-push/1 key_pem'); ok('aes_key', ak.hex(), '14067e8e830df01ae120ce73359b5f01e9d26931fe6ecdfa4d1a00fb9fe2e7b0')
fp = 'ab' * 32; aad = ('acme-push/1 key\n%s\n%s' % (APP, fp)).encode()
ok('key.nonce', b64(gn), 'YGFiY2RlZmdoaWpr')
ct = g['push_gcm_seal'](ak, gn, b'KEY\n', aad); ok('key.ct', b64(ct), '2UbSrj9NwnCBu3qZW4U7MzxzlGw=')
ok('open', g['push_gcm_open'](ak, gn, ct, aad), b'KEY\n')
ok('open with another aad fails', g['push_gcm_open'](ak, gn, ct, aad + b'x'), None)
code = 'ABCDEFGHJKMNPQRS'
proof = hmac.new(code.encode(), '\n'.join(['acme-push/1 pair', APP, kid, 'n0nce-0123456789ab']).encode(), hashlib.sha256).hexdigest()
ok('pair proof', proof, 'e8e1978c03896460ce7f6e1697d5a5220c8f3a1cd8a01d2fc2e838dbd9318b39')
# a longer plaintext (a real key) both ways, against cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
pt = os.urandom(1700); k = os.urandom(32); n = os.urandom(12)
c1 = AESGCM(k).encrypt(n, pt, b'aad'); ok('AES-GCM 1700 bytes matches cryptography', g['push_gcm_seal'](k, n, pt, b'aad'), c1)
ok('AES-GCM opens cryptography\'s', g['push_gcm_open'](k, n, c1, b'aad'), pt)
t0 = time.time(); [g['push_ed25519_verify'](pub, canon, sig) for _ in range(3)]; print('3 verifies: %.2f s' % (time.time() - t0))
