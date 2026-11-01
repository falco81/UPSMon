# acme push - certificates from acme to our other applications (protocol 1)

## Shrnutí česky

> **Jen nová možnost navíc - nic stávajícího se nemění.** Všechny dosavadní
> způsoby správy a obnovy certifikátů v aplikacích musí zůstat beze změny a
> plně funkční: ruční nahrání (PEM/PFX), žádost (CSR), certifikát podepsaný
> sám sebou, *Automatické certifikáty* (vlastní ACME aplikace), nastavení TLS,
> u zigmonu server vpředu přes SSH a broker, zálohy, obnova a export.
> acme push je **ve výchozím stavu vypnutý**, sám nic nespouští a nic
> stávajícího nepřepisuje ani neblokuje - přidává jen novou kartu, nové
> požadavky a novou cestu, kudy certifikát do stejného místa přijde. Podrobně
> kapitola [0. Additive only](#0-additive-only---nothing-existing-changes).

**acme push** je způsob, jak acme (správce certifikátů) dává a obnovuje
certifikáty v našich dalších aplikacích - otp, isemon, zigmon i v jiném acme.
Aplikace k tomu potřebuje jen svou stránku **Nastavení → Certifikáty a TLS**
s novou kartou **Certifikáty z acme**; acme má nový cíl *Naše aplikace (acme
push)*.

- **Spojení:** HTTPS na administraci aplikace (`https://APP/admin/?api=acme-push-…`
  u otp a acme, `https://APP/?api=acme-push-…` u isemonu a zigmonu). Čtyři
  požadavky: `hello` (bez přihlášení: kdo jsem, mé klíče), `pair` (spárování),
  `inventory` (jaké sloty mám a co v nich je) a `install` (vlož certifikát).
- **Spárování:** v aplikaci *Spárovat s acme* ukáže jednorázový kód (16 znaků,
  platí 15 minut, 5 chybných pokusů ho zruší). Kód se vloží do cíle v acme a
  *Vyzkoušet* je spáruje: aplikace si uloží veřejný Ed25519 klíč acme, acme si
  uloží id aplikace a její X25519 klíč. Obě strany si to dokazují HMAC
  z kódu, takže ani prostředník bez kódu nic nepodvrhne. Náhradou je vložit
  do aplikace klíč acme (`acme-push-ed25519 AAAA…`) ručně.
- **Každý požadavek je podepsaný** (Ed25519 přes sedm řádků: verze, operace,
  id aplikace, id klíče, čas, nonce, SHA-256 těla). Aplikace odmítne posun
  času přes 300 s a opakovaný nonce.
- **Soukromý klíč certifikátu** cestuje navíc zapečetěný pro aplikaci:
  X25519 + HKDF-SHA256 + AES-256-GCM (přesný postup a testovací vektory níže,
  v PHP stačí `sodium` a `openssl`).
- **Objevování (Discover):** `inventory` vrací sloty - každý uzel, VIP adresa,
  server vpředu, broker… - s jmény, která musí certifikát obsahovat, se
  současným certifikátem a s tím, kdo ho drží (ručně, vlastní ACME, acme,
  `follows:` = řídí se jiným slotem). V acme tlačítko *Zjistit* ukáže tabulku a
  jedním klikem vytvoří certifikáty a nasazení (pro každý slot zvlášť, nebo
  jeden pro celý cluster: jména všech uzlů + VIP).
- **Co aplikace udělá s certifikátem:** ověří podpis, rozbalí klíč, ověří, že
  klíč patří k certifikátu, že je platný a že obsahuje jména slotu; uloží ho
  přesně tam, kam ho ukládá ruční nahrání na Certifikáty a TLS (profil uzlu /
  VIP), nginx ho do pár sekund načte, v clusteru se rozjede replikací jako
  ruční nahrání, a vlastní „Automatické certifikáty“ ho od té doby nechají být.
  Stejný otisk podruhé = „už tam je“.
- **Pro otp (stejný engine jako acme):** zkopírujte
  `acmelib/engine/467_certificates_pushed_here_by.py` do `otp.py`, změňte
  `PUSH_APP = 'otp'`, přidejte blok do `web/admin/index.php`, kartu do
  `admin.js` a české texty - přesný postup je v kapitole
  [Pro aplikaci na tomto enginu](#for-an-application-on-this-engine-otp).
  isemon a zigmon mají vlastní kapitoly.

The rest of this document is the implementer's specification, in English.

---

## 0. Additive only - nothing existing changes

acme push is **one more way** for a certificate to arrive. It replaces nothing.
An implementation MUST keep every existing way of managing and renewing the
application's certificates exactly as it is, working and reachable as before:

* upload by hand (PEM in any order, PFX/PKCS#12 with or without a password),
  a request (CSR) and its answer, a self-signed certificate, the TLS settings,
  download/export;
* the application's own ACME (*Automatic certificates*) - its CA, DNS APIs,
  schedule and alerts;
* zigmon: the server in front kept over SSH ("the same certificate as this
  machine" or its own), the MQTT broker reading the certificate;
* backup, restore, export/import and HA replication of the TLS profiles;
* the command line and the console menu for all of the above.

Rules:

1. **Off by default.** Until a person switches "Certificates from acme" on,
   `hello` says almost nothing and every other request is refused; nothing
   else in the application behaves differently. Switched off again, the
   pairings stay but nothing is accepted; the certificates already installed
   stay in place, as an uploaded one would.
2. **Same place, same path.** A pushed certificate is stored exactly where an
   upload by hand stores it and goes through the same install code (checks,
   files, nginx -t, reload, replication). No second store, no parallel nginx
   configuration, no change to the existing install code - call it, do not
   edit it. The receiver is a new, separate piece of code (a new engine part,
   a new PHP route, a new card); it must not redefine or patch an existing
   function. (In engine-based apps all parts share one namespace: check every
   new top-level name is unique - acme's `tools/lint-engine.py` and
   `test/test_engine_names.py` do; 1.0.6 shipped a helper that replaced the QR
   code's `_gf_mul` and broke the second factor's QR codes - fixed in 1.0.7.)
3. **Same precedence as an upload.** A pushed certificate counts as uploaded by
   hand: the application's own ACME leaves that slot alone from then on,
   exactly as after a manual upload, and nothing more. A person can at any
   time upload another certificate, make a CSR or a self-signed one, or switch
   the application's own ACME back on for that slot - all of it works as
   before and simply replaces the pushed certificate (the slot then shows
   `managed_by` of that way, and acme's next deploy says the slot is managed
   otherwise unless forced).
4. **No lock-in.** Unpairing, switching off or deleting acme's target leaves
   the application fully working with the certificate it has.
5. **Same audit.** Each install is an event like an upload ("by acme push,
   key …"), so the existing logs, alerts and SIEM see it.

Checklist addition: test that every existing certificate function still works
with push off **and** with push on and paired (upload, CSR, self-signed, own
ACME issue/renew, front server sync, backup/restore).


## 1. What it is

Two roles:

- **acme** (the *sender*): the certificate manager. A target of the kind
  `acme_push` (acmelib/plugins/targets/acme_push.py) holds the address of
  one application; each deployment of a certificate to it is one `install`.
  acme renews; every renewal pushes again by itself.
- **the application** (the *receiver*): otp, isemon, zigmon, or another acme.
  It answers four requests on its administration pages, and keeps what is
  pushed exactly where an upload on its **Settings → Certificates and TLS**
  keeps it.

The reference receiver is acme's own engine part
`acmelib/engine/467_certificates_pushed_here_by.py` (an acme can push to
another acme); the reference sender is the target module above. Both are
tested against each other in `test/test_acme_push.py`.

```
 acme (sender)                                      application (receiver)
 -------------                                      ----------------------
                                                    admin: Certificates from acme → on
                                                    admin: Pair with an acme → code ABCD-EFGH-JKMN-PQRS
 admin: target acme_push, url, Pairing code
 Try:
   GET  ?api=acme-push-hello  ──────────────────▶  {protocol:[1], app, app_id, enc_key, slots…}
   POST ?api=acme-push-pair   (signed, + proof) ─▶  checks proof(code), signature
                              ◀──────────────────   {app_id, enc_key, confirm}
   checks confirm(code); keeps pin {app_id, enc_key}
   POST ?api=acme-push-inventory (signed) ──────▶  {slots:[…], cluster}
 Discover → certificates + deployments made
 renewal / deploy:
   GET  hello  (enc_key, app_id = the pinned ones?)
   POST ?api=acme-push-install (signed; key sealed to enc_key) ─▶
                                                    verify, open the key, check, store like an upload,
                                                    nginx reload (each node within seconds), HA replicates
                              ◀──────────────────   {installed:[{slot, fingerprint, state}]}
   TLS handshake to each slot's name (SNI): is the new one served?
```

## 2. Transport and addresses

Everything is HTTPS to the application's **administration pages**, the ones
an administrator opens in a browser:

| application | administration | requests |
|---|---|---|
| acme, otp | `https://NAME/admin/` | `https://NAME/admin/?api=acme-push-OP` |
| isemon, zigmon | `https://NAME/` | `https://NAME/?api=acme-push-OP` |

`OP` is `hello` (GET), `pair`, `inventory`, `install` (POST,
`Content-Type: application/json`). In acme the target's `url` is that base
address; a URL with no path is taken as `/admin/`.

The pages' own access list applies (the nginx `allow` lines of the
administration): **acme's address must be among those that may reach the
administration** of the application. That is wanted - it is one more wall.

The PHP page **does not decide anything**: it hands the request to the
daemon as it came, on `POST /api/acme-push/OP` (`GET` for hello) with the
daemon's API token as for every other route -

```json
{"body": "BASE64 of the raw body, byte for byte",
 "headers": {"Version": "1", "Key": "…", "Time": "…", "Nonce": "…", "Signature": "…"}}
```

(the values of the five `X-Acme-Push-*` headers, each at most 300
characters, in the JSON rather than as headers of the relay: every
application's relay takes a JSON body, not all of them headers of another
name) - and passes the daemon's answer (status and JSON) back. The signature covers the raw body, so the page
must not decode and re-encode it. No session, no CSRF check is needed for
these four: nothing a browser can be made to send carries a valid signature.

Bodies are at most 1 MiB. Answers are JSON objects with `ok`.

## 3. Keys and identifiers

| what | where | form |
|---|---|---|
| **acme's key** | made once by acme, sealed in its database (meta `acme_push:identity`); every node of an acme cluster signs with the same | Ed25519; as text `acme-push-ed25519 BASE64(32 bytes) comment` |
| **key id** | | the first 16 hex characters of SHA-256(the 32-byte public key) |
| **the application's id** (`app_id`) | made once by the application | 32 hex characters (16 random bytes) |
| **the application's sealing key** (`enc_key`) | made once by the application, private half sealed (meta `acme_push:box`) | X25519; public half as BASE64(32 bytes) |
| **pairing code** | made on demand by the application, sealed, 15 minutes, once | 16 characters of `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, shown as `XXXX-XXXX-XXXX-XXXX` |

BASE64 is RFC 4648 §4 with padding everywhere. The application keeps at
most 8 acme keys (several acmes, or a new one while the old is still there).

The application's keys are made once and kept; in a cluster they are in the
replicated database, so every node of the application has the same `app_id`
and `enc_key` and acme may reach any of them (or the VIP address).

## 4. Pairing

The easiest safe way, and the default:

1. In the application: **Certificates from acme → Take certificates from
   acme** (on), then **Pair with an acme**. A code is shown once.
2. In acme: Targets → add *An application of ours (acme push)*: the address,
   and the code in **Pairing code**. **Try**.
3. acme: `hello` → learns `app_id`, `enc_key`. Then `pair` (below): its own
   public key in the body, the request signed with it (it proves acme holds
   the private half), and `proof` = HMAC(code) over the app id, its key id and
   the nonce (it proves acme was given the code).
4. The application checks the signature with the key **from the body**, the
   proof against the waiting code, takes the key, drops the code, and answers
   with `confirm` = HMAC(code) over the same and its `enc_key`.
5. acme checks `confirm` and that `enc_key` is the one of hello, and keeps
   `{app_id, enc_key}` as the **pin** of the target (the application proved by
   the code - so the key is never sealed to somebody in between even when the
   TLS certificate of the application is not checked yet, e.g. self-signed).

A wrong proof counts; after 5 the code is gone. The code is never sent.

The other way: **paste acme's key** in the application (*Or paste acme's
key*; acme's Try says it when not paired, and acme's own Certificates from
acme card shows *This acme's own key*). acme then pins the application's
`app_id` and `enc_key` as *first seen* at the next Try - with *Check the
application's certificate* on, that is as safe as the TLS certificate.

When the pin and the hello disagree later (the application set up anew, or
somebody in between), acme refuses until a new pairing code is given.

Forgetting acme's key in the application ends it: nothing more is taken
from that acme.

## 5. The signature

Every POST carries:

| header | value |
|---|---|
| `X-Acme-Push-Version` | `1` |
| `X-Acme-Push-Key` | the key id (16 hex) |
| `X-Acme-Push-Time` | Unix time, whole seconds |
| `X-Acme-Push-Nonce` | 16-64 characters of `[A-Za-z0-9_-]`, new for every request (acme: 32 hex) |
| `X-Acme-Push-Signature` | BASE64 of the 64-byte Ed25519 signature |

What is signed - the **canonical string** - is seven lines joined by LF
(`\n`, 0x0A), no LF after the last, UTF-8:

```
acme-push/1
OP                       hello | pair | inventory | install
APP_ID                   the application's id (from hello)
KEY_ID                   = X-Acme-Push-Key
TIME                     = X-Acme-Push-Time, as sent
NONCE                    = X-Acme-Push-Nonce
SHA256(body)             lower-case hex of SHA-256 of the raw body bytes
```

The operation and the app id are in it, so a request cannot be replayed as
another one, nor to another application paired with the same acme.

The receiver, in this order:

1. `X-Acme-Push-Version` empty or `1`, else `version`.
2. The four other headers in their shapes, else `unsigned` (401).
3. The key id is one of the paired keys (for `pair`: the key of the body),
   and is the key id of that key, else `unknown_key` (401).
4. `|now - TIME| <= 300`, else `stale` (401).
5. Ed25519 verify of the canonical string, else `bad_signature` (401).
6. The pair (key id, nonce) not seen in the last 900 s; keep it, else
   `replay` (401). Keep the seen nonces in the database (several PHP workers,
   daemon threads, HA nodes) - acme keeps them in meta `acme_push:nonces`,
   pruned, at most 20 000.

Only then is the body parsed (JSON object, no NaN/Infinity).

## 6. The requests

### `GET hello`

No signature. Switched off, only:

```json
{"ok": true, "protocol": [1], "app": "otp", "version": "1.0.210", "on": false}
```

Switched on:

```json
{"ok": true, "protocol": [1], "app": "otp", "version": "1.0.210", "on": true,
 "app_id": "4f0c2d0e8b7a4a6c9d3e1f2a3b4c5d6e",
 "enc_key": "NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ=",
 "enc_alg": "X25519-HKDF-SHA256-A256GCM",
 "node": "otp1", "cluster": true, "nodes": ["otp1", "otp2"],
 "vip": {"on": true, "fqdn": "otp.example.com", "address": "192.0.2.10/24"},
 "slots": ["node:otp1", "node:otp2", "vip"],
 "paired": 1, "pairing": false}
```

`protocol` lists every version spoken; acme speaks 1. `pairing`: a code is
waiting.

### `POST pair`

Signed (with the key in the body). Body:

```json
{"acme_key": "acme-push-ed25519 A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg= acme@acme1",
 "acme_name": "acme 1.0.5 on acme1",
 "proof": "e8e1978c03896460ce7f6e1697d5a5220c8f3a1cd8a01d2fc2e838dbd9318b39"}
```

`proof` = lower-case hex of HMAC-SHA256(key = the code, upper case, every
character but A-Z 0-9 dropped (`ABCDEFGHJKMNPQRS`), message =)

```
acme-push/1 pair
APP_ID
KEY_ID
NONCE                     (the request's X-Acme-Push-Nonce)
```

(lines joined by LF, none after the last). Answer:

```json
{"ok": true, "app": "otp", "app_id": "4f0c…", "key_id": "56475aa75463474c",
 "enc_key": "NYBy…", "enc_alg": "X25519-HKDF-SHA256-A256GCM",
 "confirm": "…"}
```

`confirm` = the same HMAC over `acme-push/1 paired`, APP_ID, KEY_ID, NONCE,
ENC_KEY (the BASE64 text as in the answer). Refusals: `pairing_closed`
(403, no code waiting or it ran out), `bad_code` (403).

### `POST inventory`

Signed; body `{}`. Changes nothing. Answer:

```json
{"ok": true, "app": "otp", "version": "1.0.210", "app_id": "4f0c…",
 "cluster": {"on": true, "node": "otp1", "nodes": ["otp1", "otp2"],
             "vip": {"on": true, "fqdn": "otp.example.com", "address": "192.0.2.10/24"}},
 "other_names": false,
 "slots": [SLOT, …]}
```

A **slot** is one place a certificate goes:

| key | |
|---|---|
| `id` | stable: `node:NAME` (a node's own pages), `vip`, `front` (a server in front), `broker`, … - what a deployment names |
| `kind` | `node` \| `vip` \| `front` \| `other` |
| `node` | the node's name for `kind: node`, else null |
| `title` | words for people |
| `names` | the DNS names (or addresses) the certificate there must hold: the node's FQDN, the VIP's FQDN, the front's `server_name` |
| `key_types` | what it takes: `["ec", "rsa"]` |
| `dual` | it takes a second certificate of another key type beside the first (ECDSA + RSA) |
| `current` | what is there now, or null: `{fingerprint, not_before, not_after, subject, issuer, names, key_type, alt: {fingerprint, not_after, key_type} or null}` (fingerprint: SHA-256 of the DER, lower-case hex) |
| `managed_by` | `none` \| `manual` (uploaded, self-signed, a request) \| `own-acme` (its own Automatic certificates) \| `acme-push` \| `follows:SLOT` (takes the certificate of SLOT by itself - nothing to push) |
| `installable` | false when a push cannot go there now; `why_not` says why |

**Any node answers for the whole cluster**: acme talks to one address (the
VIP address's name, or one node's), and an `install` to `node:otp2` sent to
otp1 is kept in the replicated database exactly as an upload for otp2 on
otp1's pages would be - otp2 puts it in its nginx within seconds. acme does
not have to reach each node.

### `POST install`

Signed. Body:

```json
{"slots": ["auto"],
 "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
 "chain_pem": "-----BEGIN CERTIFICATE-----\n… (the intermediates, nearest first)",
 "fingerprint": "9c1f…64 hex: SHA-256 of the DER of cert_pem",
 "key": {"alg": "X25519-HKDF-SHA256-A256GCM", "epk": "…", "nonce": "…", "ct": "…"},
 "key_type": "ec-256",
 "names": ["otp.example.com", "otp1.example.com", "otp2.example.com"],
 "not_after": 1801234567,
 "check_names": true,
 "force": false,
 "alt": {"cert_pem": "…", "chain_pem": "…", "fingerprint": "…", "key": {…},
         "key_type": "rsa-2048"}}
```

- `slots`: slot ids, or `auto` (each slot all of whose `names` the
  certificate holds - a wildcard `*.example.com` holds `otp1.example.com`),
  `nodes` (every `kind: node`), `vip`, `this` (the node answering). A node's
  name alone (`otp1`) is `node:otp1`.
- `key`: the private key of `cert_pem`, sealed (section 7). Never in clear.
- `alt`: a dual certificate's twin (another key type, the same names), or
  absent; sealed the same way with **its own** fingerprint.
- `check_names: false` is taken only when the application allows it
  (`other_names`, a switch on its card, off by default).
- `force`: put it in even when the same is there.

The receiver: checks `fingerprint` against `cert_pem`; opens the key; the key
is the one of the certificate (`key_mismatch`); the certificate is valid now
(`expired`, `not_yet_valid`); the slots exist (`no_slot`, 404); each holds
the slot's names (`names`, 422) unless allowed otherwise; then for each slot
installs it the way an upload does. Answer:

```json
{"ok": true,
 "installed": [{"slot": "node:otp1", "node": "otp1", "names": ["otp1.example.com"],
                "fingerprint": "9c1f…", "not_after": 1801234567, "state": "installed"},
               {"slot": "vip", "node": null, "names": ["otp.example.com"],
                "fingerprint": "9c1f…", "not_after": 1801234567, "state": "already"}],
 "said": "put in for node:otp1 - each node puts it into nginx within seconds; already there for vip"}
```

**Idempotent:** a slot holding the same fingerprint (and the same twin),
put there by acme push, is `already` and not touched (no nginx reload).

After the answer, acme makes a TLS handshake to each installed slot's name
(port 443, SNI = the name) a few times, 3 s apart, until the served
certificate's fingerprint is the new one (both, for a dual one: once offering
only ECDSA, once only RSA). The deployment fails when another one is served.

## 7. The private key, sealed

The certificate's key travels inside TLS **and** sealed to the
application's X25519 key, so neither a TLS-terminating proxy nor a log of
bodies ever has it.

Sender (acme), for each certificate (main, and alt with its own fingerprint):

```
eph      = 32 random bytes                        (X25519 private, ephemeral)
epk      = X25519(eph, 9)                          (its public half, 32 bytes)
app_pub  = BASE64-decode(enc_key)                  (32 bytes, the pinned one)
shared   = X25519(eph, app_pub)                    refuse 32 zero bytes
aes_key  = HKDF-SHA256(IKM = shared, salt = epk || app_pub,
                       info = "acme-push/1 key_pem", L = 32)
nonce    = 12 random bytes
aad      = "acme-push/1 key" LF APP_ID LF FINGERPRINT   (UTF-8; fingerprint lower-case hex)
ct       = AES-256-GCM(aes_key, nonce, plaintext = the key PEM as UTF-8, aad)
           || the 16-byte tag
key      = {"alg": "X25519-HKDF-SHA256-A256GCM",
            "epk": BASE64(epk), "nonce": BASE64(nonce), "ct": BASE64(ct || tag)}
```

Receiver: `shared = X25519(app_priv, epk)`, the same HKDF (salt = epk ||
its own public key), the same aad with **the fingerprint of the request**,
AES-256-GCM open; a tag that does not match is `bad_key` (400) - sealed to
another key of this server (pair again), or for another certificate.

The aad binds the key to this application and this certificate: a sealed key
cannot be moved to another certificate or another application.

## 8. Test vectors

Made by `test/test_acme_push.py` (`PUSH_VECTORS=1 python3 test/test_acme_push.py -v
Crypto.test_vectors_of_the_document` prints them; the test fails when they change).

Inputs:

```
acme's Ed25519 seed        00 01 02 … 1f                     (bytes 0..31)
the application's X25519   20 21 22 … 3f                     (bytes 32..63)
ephemeral X25519 (eph)     40 41 42 … 5f                     (bytes 64..95)
GCM nonce                  60 61 … 6b                        (bytes 96..107)
APP_ID                     00112233445566778899aabbccddeeff
op, time, nonce            inventory, 1793534400, n0nce-0123456789ab
body                       {"slots": ["auto"]}               (19 bytes, no LF)
fingerprint                abab…ab                           (64 hex)
plaintext key              "KEY\n"                           (4 bytes)
pairing code               ABCD-EFGH-JKMN-PQRS
```

Results:

```
acme public key            A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
as text                    acme-push-ed25519 A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg= acme@acme1
key id                     56475aa75463474c
canonical string           acme-push/1\ninventory\n00112233445566778899aabbccddeeff\n56475aa75463474c\n
                           1793534400\nn0nce-0123456789ab\n
                           d3a920a683e4d42e6f5a6971cb03c2fd4361964436db5f7460c4a638836222d8
X-Acme-Push-Signature      7nqJW4/NR3Et6pZx3B8qS3rvQGaQR0UTlNdptpRs4lxaZtc3Cf2zBRkOWPB0tV/rmQNfwbcl2/FKJ3Pu2h/bDg==
application public key     NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ=
epk                        eaYx7t4b+cmPEgMs3q3Q56B5OY/HhriMyEbsia+FpRo=
shared (hex)               04c304fb1ca83cee75e206344231f33797e07d9929db670994b7c6fbeb1dc255
aes_key (hex)              14067e8e830df01ae120ce73359b5f01e9d26931fe6ecdfa4d1a00fb9fe2e7b0
aad                        acme-push/1 key\n00112233445566778899aabbccddeeff\nabab…ab
key.nonce                  YGFiY2RlZmdoaWpr
key.ct                     2UbSrj9NwnCBu3qZW4U7MzxzlGw=
pair proof (nonce n0nce-0123456789ab)
                           e8e1978c03896460ce7f6e1697d5a5220c8f3a1cd8a01d2fc2e838dbd9318b39
```

(The canonical string is one string with `\n` as LF; it is broken here only
to fit.) The primitives themselves are checked against RFC 8032 (Ed25519
test 1), RFC 7748 §5.2 and §6.1 (X25519), RFC 5869 A.1 (HKDF).

## 9. Errors

Every refusal: an HTTP status and `{"ok": false, "code": CODE, "error": "words"}`.

| code | status | |
|---|---|---|
| `off` | 403 | the application takes no certificates from acme (switched off) |
| `not_paired` | 401 | switched on, but no acme key yet |
| `unsigned` | 401 | a header is missing or malformed |
| `unknown_key` | 401 | not a key paired here |
| `stale` | 401 | more than 300 s away - a clock is wrong |
| `bad_signature` | 401 | the signature does not match |
| `replay` | 401 | that nonce was seen |
| `version` | 400 | not protocol 1 |
| `bad_request` | 400 | the body is not what it should be |
| `bad_key` | 400 | the sealed key does not open |
| `pairing_closed` | 403 | no pairing code waits |
| `bad_code` | 403 | the proof is not of the waiting code |
| `no_slot` | 404 | no such slot |
| `not_installable` | 409 | the slot cannot take it now (`why_not`) |
| `names` | 422 | the certificate lacks a slot's name (or no slot matches `auto`) |
| `key_mismatch` | 422 | the key is not the certificate's |
| `bad_cert` | 422 | the certificate (or chain) cannot be read |
| `expired`, `not_yet_valid` | 422 | not valid now |
| `too_big` | 413 | over 1 MiB |
| `down` | 503 | the page cannot reach the daemon |

acme tries again later (its back-off) only for 5xx, `stale` and `replay`;
the others are said to the person as they are.

## 10. What the application does with a certificate

Exactly what an upload on its **Certificates and TLS** does, for the slot's
profile:

1. Keep the certificate, the chain (in order), the root if given, the key
   (sealed with the installation's own key, as every secret), its facts, and
   `how = "acme push: <acme's name>"`. Its TLS settings (protocols,
   ciphers, DH, HSTS) stay as they are.
2. A dual one: the twin as the second certificate of the same pages (otp/acme:
   the profile's `alt`, tied to the first by `tls_alt_for`).
3. Its own **Automatic certificates** told to leave the slot alone
   (`acme_care_set(…, False, …)`), as after an upload - it does not order one
   over it at its next renewal. *Look after it* there gives it back.
4. An event written: which slot, which certificate, until when, from which
   acme.
5. Every node puts its own into nginx within seconds, the VIP's whichever node
   holds the address (otp/acme: `web_tick`); the other node of a cluster takes
   it from the replicated database like any upload.

Nothing else changes. `inventory` and `hello` change nothing at all.

## 11. Clusters (HA)

- One `app_id` and `enc_key` for the whole cluster (they are in the
  replicated database), so acme can reach whichever node answers.
- Every node answers `inventory` for all of them: `node:` slots for every
  node, `vip` when the VIP address is on.
- An `install` for another node's slot is kept for it; that node applies it
  itself. acme talks to one URL (the VIP address's name is best).
- The nonces of recent requests are kept in the database, so a request
  replayed to the other node is refused there too (within replication).
- The **one certificate for the whole cluster** of Discover holds every node's
  name and the VIP's, and is pushed to every slot (`slots` = all of them);
  or one for each slot.

## 12. acme's side

The target `acme_push` (docs/targets.md): `url`, `pair_code`, `verify_tls`,
`ca_pem`, `timeout`; a deployment's `slots`, `check_names`, `verify_served`,
`verify`. Its state, in acme's database (both nodes): the **pin** of each
application by its address (meta `acme_push:pin:…`: `app_id`, `enc_key`, how
it was learned - so a Try before the target is saved pairs it for good), and
the target's last `inventory`.

- **Try** = hello, the pairing when a code is given, inventory. Nothing is
  changed there.
- **Discover** (the target's button): the slots, what each has, and whether
  a certificate of acme's covers it already; *Make the certificates* makes one
  for each slot chosen, or one for all of them, each with a deployment naming
  its slots (`POST /api/targets/discover`, `POST /api/targets/adopt`,
  acmelib/certs/api_push.py). Discover again later says what is new (a new
  node) and what is not covered. A `follows:` slot needs nothing; one that is
  not installable is left, and said.
- **Deploy** = hello (is it still the pinned one?), install, then the TLS check.

## 13. Security considerations

- **Who may push:** only holders of a paired Ed25519 key. Pairing needs both
  the code (shown once to an administrator of the application, 15 minutes,
  5 tries) and the private key. Switching off, or forgetting the key, ends it.
- **Who receives the key:** only the holder of the pinned X25519 key, pinned
  by the code (or by the first sight under a checked TLS certificate).
- **Replay:** time ±300 s and nonces kept 900 s; the operation and the
  application's id are signed.
- **What can be pushed:** only a certificate whose key is with it, valid now,
  holding the slot's names (unless the application allows otherwise). A
  certificate for another name cannot take a slot over silently.
- **The page:** keeps nothing, decides nothing; the daemon is reached on
  localhost with its token. The administration's access list still applies.
- **No secrets in logs:** the body is never logged; refusals are logged with
  their code only.
- **TLS:** keep *Check the application's certificate* on once the
  application has a proper certificate (the first push gives it one); paste
  the CA for a private one.
- **Clock:** both ends need NTP; a `stale` refusal says by how much.

## 14. Checklist for an implementer

- [ ] **Additive only (chapter 0):** off by default; existing upload, CSR,
      self-signed, own ACME, TLS settings, front server/broker, backup/restore
      and CLI untouched and tested with push off and on; no existing function
      redefined or edited - the install code is called, not changed.

- [ ] Settings → Certificates and TLS: card **Certificates from acme**:
      switch, *Pair with an acme* (shows the code once), *Take it back*,
      *Or paste acme's key*, the list of paired acmes with *Forget it*,
      *Take certificates of other names*, what acme sees here (the slots),
      the last push, Czech texts.
- [ ] Keys: app_id + X25519 made once, sealed, in the replicated database.
- [ ] The page: `?api=acme-push-(hello|pair|inventory|install)` before any
      session/CSRF check, `{"body": base64 of the raw body, "headers": {…}}`
      to the daemon.
- [ ] `hello` (GET, unsigned), says little while switched off.
- [ ] Signature check in the order of section 5; nonces in the database.
- [ ] `pair`: code sealed, 15 min, 5 tries, gone after use; `confirm`.
- [ ] `inventory`: every slot, with `names`, `current`, `managed_by`.
- [ ] `install`: fingerprint, open the key, key matches, valid now, names,
      install as an upload (its own ACME leaves it alone), `already` for the
      same, dual (`alt`).
- [ ] Events for pairing, wrong codes, forgetting, every install.
- [ ] Tests against the vectors of section 8, and one push end to end from
      a real acme.

## 15. Reference snippets

Python (`cryptography`):

```python
import base64, hashlib, hmac, json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

def canonical(op, app_id, key_id, ts, nonce, body: bytes) -> bytes:
    return '\n'.join(['acme-push/1', op, app_id, key_id, str(ts), nonce,
                      hashlib.sha256(body).hexdigest()]).encode()

def verify(pub32: bytes, headers, op, app_id, body: bytes) -> bool:
    msg = canonical(op, app_id, headers['X-Acme-Push-Key'], headers['X-Acme-Push-Time'],
                    headers['X-Acme-Push-Nonce'], body)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub32).verify(
            base64.b64decode(headers['X-Acme-Push-Signature']), msg)
        return True
    except Exception:
        return False

def open_key(sealed, app_priv32: bytes, app_id: str, fingerprint: str) -> str:
    priv = x25519.X25519PrivateKey.from_private_bytes(app_priv32)
    app_pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    epk = base64.b64decode(sealed['epk'])
    shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(epk))
    key = HKDF(hashes.SHA256(), 32, salt=epk + app_pub,
               info=b'acme-push/1 key_pem').derive(shared)
    aad = ('acme-push/1 key\n%s\n%s' % (app_id, fingerprint.lower())).encode()
    return AESGCM(key).decrypt(base64.b64decode(sealed['nonce']),
                               base64.b64decode(sealed['ct']), aad).decode()

def proof(code, words, *parts):
    k = ''.join(c for c in code.upper() if c.isalnum()).encode()
    return hmac.new(k, '\n'.join(['acme-push/1 ' + words] + list(parts)).encode(),
                    hashlib.sha256).hexdigest()
```

Python without `cryptography`: acme's engine part has Ed25519, X25519,
HKDF and AES-256-GCM in plain Python (`ed25519_verify`, `x25519`,
`hkdf_sha256`, `aes256gcm`) - copy them.

PHP 8 (`sodium` and `openssl`, both in every distribution's PHP):

```php
function push_canonical(string $op, string $appId, string $keyId, string $ts,
                        string $nonce, string $raw): string {
    return implode("\n", ['acme-push/1', $op, $appId, $keyId, $ts, $nonce,
                          hash('sha256', $raw)]);
}
$ok = sodium_crypto_sign_verify_detached(base64_decode($sig, true),
        push_canonical($op, $appId, $keyId, $ts, $nonce, $raw), base64_decode($pub, true));

function push_open_key(array $s, string $appPriv, string $appId, string $fp): ?string {
    $epk = base64_decode($s['epk'], true);
    $appPub = sodium_crypto_scalarmult_base($appPriv);
    $shared = sodium_crypto_scalarmult($appPriv, $epk);
    $key = hash_hkdf('sha256', $shared, 32, 'acme-push/1 key_pem', $epk . $appPub);
    $ct = base64_decode($s['ct'], true);
    $aad = "acme-push/1 key\n" . $appId . "\n" . strtolower($fp);
    $pem = openssl_decrypt(substr($ct, 0, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
                           base64_decode($s['nonce'], true), substr($ct, -16), $aad);
    return $pem === false ? null : $pem;
}
$proof = hash_hmac('sha256', "acme-push/1 pair\n$appId\n$keyId\n$nonce",
                   preg_replace('/[^A-Z0-9]/', '', strtoupper($code)));
```

(`hash_equals()` to compare proofs.)

## 16. For an application on this engine (otp)

otp's `otp.py` has every function the part stands on (`tls_targets`,
`tls_profile`, `tls_save`, `tls_alt`, `tls_alt_for`, `acme_care`,
`acme_care_set`, `acme_wanted`, `acme_name_of`, `vip_conf`, `cert_bundle`,
`PEM_CERT`, `seal_secret`, `unseal_secret`, `_meta_json`, `stamp`,
`node_name`, `route`, `ApiError`, `_no_constant`, `_Aes256`, `log`,
`__version__`). So:

1. **The daemon.** Copy `acmelib/engine/467_certificates_pushed_here_by.py`
   whole into `otp.py`, after the API routes (after `def route`/`ROUTES` and
   the `/api/web` routes), without its two first lines. Change only
   `PUSH_APP = 'otp'`. Do **not** rename anything that says `acme-push` or
   `acme_push` - those are the protocol's words and the meta keys. The sender
   half (`push_identity`, `push_signed`, `push_seal_key`) may stay: it is
   unused in otp.
2. **The page.** In `web/admin/index.php`, right after
   `$post = $_SERVER['REQUEST_METHOD'] === 'POST';`, the block of acme's
   `web/admin/index.php` that starts with the comment *acme push*
   (`preg_match('/^acme-push-(hello|pair|inventory|install)$/'…`), with
   `acme_call` → `otp_call` (isemon: `isemon_call`, zigmon: `zigmon_call`). Add `'acme-push' => '/api/acme-push'` to both
   `$reads` and `$writes`.
3. **The pane.** In the Certificates and TLS pane of `web/admin/index.php`,
   after the card holding `<div id="web-certs" …>`, the card
   `<div class="card full" id="web-push-card">…<div id="web-push"></div></div>`.
   In `web/assets/admin.js`: `loadPush();` in `loadWeb()` after its first
   line, and the functions `loadPush`, `pushDo`, `pushCode`, `drawPush` (the
   block *Certificates from acme* before `loadVip`), as they are - "acme" in their
   words is the certificate manager, never otp itself.
4. **Czech.** The strings of the card, from acme's `web/lang/cs.json`
   (search for *Certificates from acme*, *Pair with an acme*, *Paired with*,
   *Take this key*, …): copy each `source`/`text` pair with a new id.
5. **Tests.** Take `test/test_acme_push.py`'s `Crypto` and `Receiver` classes;
   they need only the engine (`import otp as E`) and a store.
6. **Docs and changelog.** A line in otp's docs on Certificates and TLS: *Certificates
   from acme*, pointing here.

Then in acme: a target *An application of ours* with
`url = https://otp.example.com/admin/`, the pairing code, Try, Discover.

Example inventories of otp:

One machine:

```json
{"ok": true, "app": "otp", "version": "1.0.210", "app_id": "…",
 "cluster": {"on": false, "node": "otp1", "nodes": ["otp1"],
             "vip": {"on": false, "fqdn": "", "address": ""}},
 "slots": [
  {"id": "node:otp1", "kind": "node", "node": "otp1", "title": "node otp1 (otp.example.com)",
   "names": ["otp.example.com"], "key_types": ["ec", "rsa"], "dual": true,
   "current": {"fingerprint": "5e1d…", "not_after": 1800000000, "subject": "CN=otp.example.com",
               "issuer": "CN=R11,O=Let's Encrypt,C=US", "names": ["otp.example.com"],
               "key_type": "ec-256", "alt": null},
   "how": "ACME", "managed_by": "own-acme", "installable": true, "why_not": ""}]}
```

Two nodes and a VIP address:

```json
{"ok": true, "app": "otp",
 "cluster": {"on": true, "node": "otp1", "nodes": ["otp1", "otp2"],
             "vip": {"on": true, "fqdn": "otp.example.com", "address": "192.0.2.10/24"}},
 "slots": [
  {"id": "node:otp1", "kind": "node", "node": "otp1", "names": ["otp1.example.com"],
   "current": {"fingerprint": "…", "issuer": "CN=otp1.example.com", "…": "…"},
   "managed_by": "manual", "installable": true},
  {"id": "node:otp2", "kind": "node", "node": "otp2", "names": ["otp2.example.com"],
   "current": null, "managed_by": "none", "installable": true},
  {"id": "vip", "kind": "vip", "node": null, "names": ["otp.example.com"],
   "current": {"fingerprint": "…", "…": "…"}, "managed_by": "own-acme", "installable": true}]}
```

Discover then offers one certificate each (`otp1.example.com` → `node:otp1`,
`otp2.example.com` → `node:otp2`, `otp.example.com` → `vip`), or one for the
cluster (`otp.example.com`, `otp1.example.com`, `otp2.example.com` → all three).

## 17. isemon

isemon is one machine with one certificate (`WebRoot.tls_conf()`, meta
`web_tls`), put in by root (`push()`); its own ACME is told with
`acme_care_set(wr, on, by, why)`.

- One slot: `{"id": "node:<host>", "kind": "node", "node": "<host>",
  "names": [acme_name(wr)], "current": <from tls_conf()>, "managed_by":
  "own-acme" | "manual" | "acme-push" | "none"}`.
- `install`: what `WebRoot.tls_do({'action': 'upload', 'pem': [cert_pem,
  chain_pem, key_pem]}, by='acme push')` does - then set `how` to
  `acme push: <acme>` so `managed_by` says it, and `acme_care_set(wr, False,
  …)` (tls_do's `acme_by_hand` does it while ACME is on).
- The page is `web/index.php` (`?api=acme-push-…` at `/`), the relay
  `isemon_call`. AES: isemon has no `_Aes256` - copy `_aes_tables`, `_xt`,
  `_Aes256` from acme's `acmelib/engine/220_a_zip_locked_with.py`, or rely on
  `cryptography` where it is installed.
- The card on its Certificates and TLS pane, as in section 16.

## 18. zigmon

zigmon keeps the dashboard's certificate (nginx `server.pem` RSA and
`server-ecdsa.pem` with *Both*), the MQTT broker reads the same RSA files,
and - when a **server in front** is set (Front server & router) - that
server's certificate too (`proxy_tls_*`): either *the same certificate as this
machine* (`follow`, put there by itself every half minute) or its own (an
upload for it goes over SSH, `proxy_tls_ask(pem=…)`).

Slots:

| slot | names | managed_by | install |
|---|---|---|---|
| `node:<name>` | the dashboard's name (`acme_name`) | `own-acme` / `manual` / `acme-push` | as an upload on Certificates (both pairs with `alt`) |
| `broker` | the broker's name | `follows:node:<name>` when it reads the dashboard's files | nothing: it follows |
| `front` | `proxy_tls_name(d)` | `follows:node:<name>` with *the same certificate as this machine*; else what it has | with `follow` on: nothing (pushing to `node:` is enough); with its own: `proxy_tls_ask(d, pem={cert, key, chain})`, `conf['how'] = 'acme push: …'`; `installable: false` with `why_not` while it is reached with a password (the key way is needed) |

The front following the dashboard:

```json
{"ok": true, "app": "zigmon", "version": "5.40.0",
 "cluster": {"on": false, "node": "house", "nodes": ["house"], "vip": {"on": false, "fqdn": "", "address": ""}},
 "slots": [
  {"id": "node:house", "kind": "node", "node": "house", "title": "the dashboard",
   "names": ["mqtt.example.cz"], "key_types": ["ec", "rsa"], "dual": true,
   "current": {"fingerprint": "…", "key_type": "rsa-2048",
               "alt": {"fingerprint": "…", "key_type": "ec-256"}, "…": "…"},
   "managed_by": "own-acme", "installable": true},
  {"id": "broker", "kind": "other", "node": null, "title": "the MQTT broker (8883)",
   "names": ["mqtt.example.cz"], "current": {"fingerprint": "…"},
   "managed_by": "follows:node:house", "installable": false,
   "why_not": "it reads the dashboard's certificate"},
  {"id": "front", "kind": "front", "node": null, "title": "the server in front (proxy.example.cz)",
   "names": ["mqtt.example.cz"], "current": {"fingerprint": "…"},
   "managed_by": "follows:node:house", "installable": true}]}
```

The front with its own certificate (another name there):

```json
  {"id": "front", "kind": "front", "node": null, "title": "the server in front (proxy.example.cz)",
   "names": ["home.example.cz"], "key_types": ["ec", "rsa"], "dual": true,
   "current": {"fingerprint": "…", "names": ["home.example.cz"], "issuer": "CN=R11,…"},
   "managed_by": "manual", "installable": true}
```

Discover then makes `mqtt.example.cz` → `node:house` (the broker and the
following front need nothing) and, in the second case, `home.example.cz` →
`front`. An `install` to `front` with `follow` on is refused with
`not_installable` (*it follows the dashboard: push to node:house*).

## 19. Versions

This is protocol 1. A later one is offered in `hello`'s `protocol` beside 1;
the canonical string's first line says which one a request is.
