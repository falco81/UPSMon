# acme push - tests

The receiver of acme push (protocol 1, `docs/acme-push-protocol.md`) as upsmon has it.

| test | what | needs |
|---|---|---|
| `t_vectors.py` | the test vectors of section 8 (Ed25519, X25519, HKDF, AES-256-GCM, the pairing proof) - with `cryptography`, and `t_vectors.py pure` in plain Python | Python 3 with `cryptography` (to make the expected values) |
| `t_push.py` | an acme of its own (`sender.py`) against the running pages: hello, pairing (wrong code, five tries, once only), inventory, replay, stale, wrong signature, unknown key, install (auto, a slot, dual, already, force), every refusal of section 9, a key pasted, forgotten, switched off | the daemon and the pages running (php -S, port 8080), an account admin / secret123, Node with Playwright |
| `t_additive.py` | chapter 0: self-signed, a CSR and its answer, an upload, export as PFX, own ACME taking a certificate back, a copy of the databases and its check - with push off, and on and paired; then a push replaced by an upload and given back to own ACME | as above |
| `t_dual.py` | a dual certificate by hand: PEM with both keys, two PFX files, one alone afterwards, refusals (two RSA, other names, three keys); Download of the RSA one, the ECDSA twin, both in a .zip, every format; `upsmon --cert-export … --cert-which both` | as above |

`BASE=https://ups.example.net/settings/ python3 t_push.py` aims it elsewhere.
