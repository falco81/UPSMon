# The whole chain (4.7.0, 4.7.1)

- `python3 tests/chain/t_chain.py` - checked against the system's roots, completed from CA Issuers
  (DER, PEM, PKCS#7), refusals, a private CA with and without its root, the upload path, Complete the
  chain, Upload the missing authority, the file nginx has now, and upsmon asking itself (openssl
  s_server with the leaf alone, then with its chain) - 26 checks
- `CADIR=… node tests/chain/t_ui.js` - the card and the dialog on a test instance (the CA's root in the
  system's trust first: Trusted roots of the system)
