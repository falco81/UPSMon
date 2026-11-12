# The whole chain (4.7.0)

- `python3 tests/chain/t_chain.py` - completing a chain from CA Issuers (DER, PEM, PKCS#7), refusals,
  a company root, the upload path, Complete the chain, and upsmon asking itself (openssl s_server
  with the leaf alone, then with its chain)
- `CADIR=… node tests/chain/t_ui.js` - the card on a test instance (the CA's root in the system's
  trust first: Trusted roots of the system)
