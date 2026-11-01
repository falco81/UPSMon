"""An acme of our own, for the tests: signs, seals, as protocol 1 says."""
import base64, hashlib, hmac, json, os, time, urllib.request, urllib.error, datetime
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography import x509
from cryptography.x509.oid import NameOID
BASE = os.environ.get('BASE', 'http://127.0.0.1:8080/settings/')
b64 = lambda b: base64.b64encode(b).decode()
class Acme:
    def __init__(self, name='acme@test'):
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.pub = self.sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        self.kid = hashlib.sha256(self.pub).hexdigest()[:16]
        self.text = 'acme-push-ed25519 %s %s' % (b64(self.pub), name)
        self.app_id = self.enc = None
    def call(self, op, body=None, raw=None, ts=None, nonce=None, kid=None, sig_with=None, app_id=None, op_signed=None):
        if op == 'hello':
            req = urllib.request.Request(BASE + '?api=acme-push-hello')
        else:
            raw = raw if raw is not None else json.dumps(body or {}).encode()
            ts = str(ts if ts is not None else int(time.time())); nonce = nonce or os.urandom(16).hex()
            canon = '\n'.join(['acme-push/1', op_signed or op, app_id or self.app_id, kid or self.kid, ts, nonce, hashlib.sha256(raw).hexdigest()]).encode()
            sig = (sig_with or self.sk).sign(canon)
            req = urllib.request.Request(BASE + '?api=acme-push-' + op, data=raw, method='POST', headers={
                'Content-Type': 'application/json', 'X-Acme-Push-Version': '1', 'X-Acme-Push-Key': kid or self.kid,
                'X-Acme-Push-Time': ts, 'X-Acme-Push-Nonce': nonce, 'X-Acme-Push-Signature': b64(sig)})
            self.last_nonce = nonce; self.last = (raw, ts, nonce)
        try:
            with urllib.request.urlopen(req, timeout=60) as r: return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b'{}')
    def hello(self):
        st, h = self.call('hello'); self.app_id = h.get('app_id'); self.enc = h.get('enc_key'); return st, h
    def pair(self, code, wrong=False):
        nonce = os.urandom(16).hex()
        k = ''.join(c for c in code.upper() if c.isalnum()).encode()
        proof = hmac.new(k, '\n'.join(['acme-push/1 pair', self.app_id, self.kid, nonce]).encode(), hashlib.sha256).hexdigest()
        if wrong: proof = '0' * 64
        st, a = self.call('pair', {'acme_key': self.text, 'acme_name': 'acme 1.0 on test', 'proof': proof}, nonce=nonce)
        if st == 200:
            want = hmac.new(k, '\n'.join(['acme-push/1 paired', self.app_id, self.kid, nonce, a['enc_key']]).encode(), hashlib.sha256).hexdigest()
            a['_confirm_ok'] = hmac.compare_digest(want, a['confirm']) and a['enc_key'] == self.enc
        return st, a
    def seal(self, key_pem, fp, enc=None, app_id=None):
        app_pub = base64.b64decode(enc or self.enc)
        eph = x25519.X25519PrivateKey.generate()
        epk = eph.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(app_pub))
        aes = HKDF(hashes.SHA256(), 32, salt=epk + app_pub, info=b'acme-push/1 key_pem').derive(shared)
        n = os.urandom(12)
        aad = ('acme-push/1 key\n%s\n%s' % (app_id or self.app_id, fp)).encode()
        return {'alg': 'X25519-HKDF-SHA256-A256GCM', 'epk': b64(epk), 'nonce': b64(n), 'ct': b64(AESGCM(aes).encrypt(n, key_pem.encode(), aad))}
def make_cert(names, kind='ec', days=90, past=False):
    k = ec.generate_private_key(ec.SECP256R1()) if kind == 'ec' else rsa.generate_private_key(65537, 2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    nb, na = (now - datetime.timedelta(days=100), now - datetime.timedelta(days=10)) if past else (now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=days))
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    c = (x509.CertificateBuilder().subject_name(subj).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA R1')]))
         .public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False).sign(k, hashes.SHA256()))
    pem = c.public_bytes(S.Encoding.PEM).decode()
    key = k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()).decode()
    return pem, key, hashlib.sha256(c.public_bytes(S.Encoding.DER)).hexdigest()
