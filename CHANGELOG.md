# Changelog

Every version is a package in `release/` (the last ten are kept), signed with
the release key whose public half is in `deploy/release-keys/`. The root of
the repository is the package unpacked.

## 4.2.4 - 2026-11-01

- **Only errors on the machine's console** (as otp 1.0.210): lines like
  `systemd-rc-local-generator: /etc/rc.d/rc.local is not marked executable,
  skipping` came in bursts over the login prompt and the upsmon console on tty1
  - systemd's generators write to the kernel's log at every daemon-reload (a dnf
  update, an upgrade), and a console log level of 7 put all of it on the screen.
  install.sh writes `/etc/sysctl.d/80-upsmon-console.conf` (`kernel.printk = 4 4
  1 7`, RHEL's own default) and applies it; the journal keeps everything
  (`journalctl -k`). A `kernel.printk` set by hand in another file is left alone;
  the same file on every run; taken away by --uninstall. rc.local is not made
  executable.

## 4.2.3 - 2026-10-31

**Settings → Proxy: a switch for each thing that may go through it** - all off
by default, and with "Go out through a proxy" off nothing goes through it
whatever they say:
- *New versions of upsmon* - Settings → Upgrades: the daily look and the
  download (GitHub).
- *System updates (dnf, apt)* - Settings → System updates: the look and the
  update, handed to root's helper.
- *Automatic certificates: the CA* - every question to Let's Encrypt (or your
  own CA): the account, the order, the certificate.
- *Automatic certificates: the DNS API* - DNS-01 through deSEC, Cloudflare or
  acme-dns.

Never through it, nothing to switch: the UPS, the plug and the sensors (on the
network), the backups (FTP, FTPS, SFTP, SCP, SMB), the time (NTP), RFC 2136
(nsupdate) - none of them speaks HTTP. *Try it* goes through the proxy whenever
it is on, to try the proxy itself.

Where the proxy was on before, its use for the updates has to be switched on
again here: the new switches start off.

## 4.2.2 - 2026-10-31

- **The proxy is for the updates only**: the new versions of upsmon (the daily
  look, the download) and the system updates (dnf, apt, when "The system updates
  through it too" is on). Nothing else goes through it, whatever is set: the
  automatic certificates (the CA, deSEC, Cloudflare, acme-dns) go straight
  again, as do the UPS, the plug, the sensors, mail and the backups - none of
  them can be stopped by a proxy that is down or wrongly set. Settings → Proxy
  says so.

## 4.2.1 - 2026-10-31

**Settings → Proxy** - a pane of its own, as OTP has it (Server, before Time):
- *Settings*: Go out through a proxy, the proxy, its user name and password
  (sealed), the names reached straight, and **the system updates through it
  too** (dnf, apt - handed to root's helper, never on a command line).
- *Try it*: an address asked the way upsmon asks the web - through the proxy as
  saved, or straight - drawn as OTP draws it: this server, the proxy, the
  address, each link green or red, and every step (looked up, connected, the
  tunnel, TLS and its certificate, the answer) with how long it took. Empty:
  where the new versions are looked for.
- `upsmon --proxy-test [URL]` on the command line (`--json` too).
- The proxy's settings are no longer in Settings → Upgrades.

## 4.2.0 - 2026-10-31

**Upgrades and maintenance, as OTP 1.0.197 has them (one server, no HA)**
(Settings → Upgrades):
- *The nodes*: this server with its version, when it was heard from, its state
  (in service / in maintenance, why, by whom, since when) and **Maintenance** /
  **Back in service**.
- **Maintenance** takes upsmon out of service the way OTP does for its node:
  the UPS, the plug and the sensors are still watched and their history kept,
  but nothing changes them - a command to the UPS, a value set on it, the plug
  switched or reset, a reset of what is recorded are refused (HTTP 503, "upsmon
  is in maintenance"); the dashboard says so at the top, `/api/status` and
  `/api/health` carry `maintenance` (health: `"state": "maintenance"`) for
  monitoring. An upgrade, a system update and a restart from these pages put it
  in maintenance and back by themselves.
- `upsmon --maintenance on --why "..." | off | status` (status exits 3 while in
  maintenance); the command-line card lists it.
- *What root said last* folded until opened, as in OTP 1.0.196.

**Automatic certificates → In your DNS**: laid out across the whole width,
every column a fixed share and the copy buttons in narrow columns of their own,
one under the other - nothing moves between a reload (F5) and Check DNS; the
last check is kept across a reload in that tab.

## 4.1.11 - 2026-10-31

- Automatic certificates → In your DNS: the copy buttons line up one under the
  other, right after the longest text of their column; the columns stay as
  wide as what they hold, with room between them.

## 4.1.10 - 2026-10-31

- Automatic certificates → In your DNS: each copy button right after its text;
  the columns as wide as what they hold, with room between them, instead of
  the first column taking all the width.

## 4.1.9 - 2026-10-31

- Automatic certificates → In your DNS: the copy buttons sit in a column of
  their own, right after the longest text and one under the other - laid out
  by the table itself, so they no longer jump at every refresh (they were
  measured and moved after drawing).
- The column "Record" there is "DNS record" ("Záznam DNS" in Czech; it read
  "Bilance", the dashboard's word).

## 4.1.8 - 2026-10-31

- Automatic certificates → The CA's own certificate (and every setting that
  holds a certificate in PEM): a large memo across the whole width instead of
  a one-line box - monospace, not wrapped, resizable; **Load a file…**
  (.pem, .crt, .cer) or a file dropped onto it; **Empty**; and under it what
  it holds: "1 certificate in PEM", not PEM, or a private key that does not
  belong there.

## 4.1.7 - 2026-10-31

- ACME: an order stopped with "the key is ec, ec384, rsa2048, rsa3072 or rsa4096" -
  the order's loop reused the name of the key's kind for the challenge's
  (dns-01 / http-01). Fixed; tested through the whole order with both challenges.
- Automatic certificates → What the last order did: the time stays one narrow
  column (+102 s no longer breaks into a line per character) and the words sit
  left beside it.

## 4.1.6 - 2026-10-31

Automatic certificates (ACME) take every key Let's Encrypt accepts
(https://letsencrypt.org/docs/integration-guide/):

- **The certificate's key:** RSA 2048, 3072, 4096 or ECDSA P-256, P-384 - and,
  the new default, **both**: two certificates for the name, RSA served by
  default and the much smaller ECDSA one to the clients that take it
  ("Both: RSA 2048 + ECDSA P-256", or "Both: RSA 4096 + ECDSA P-384").
  The second order only signs: the name is already proven. nginx gets two
  `ssl_certificate` / `ssl_certificate_key` pairs (`upsmon.pem` and
  `upsmon-ecdsa.pem`); a certificate put in another way on Certificates and
  TLS drops the ECDSA one.
- **The account's key** (new setting): ECDSA P-256 (ES256), P-384 (ES384) or
  RSA 2048, 3072, 4096 (RS256) - never a certificate's key. A change makes a
  new account at the next order.
- The keys show on the ACME card (Keys), on the certificate (Key) and beside
  the account; the order's steps say which keys were made.

## 4.1.5 - 2026-10-31

- Backups to an SMB share work: the service may now open netlink sockets (`AF_NETLINK` in `upsmon.service`), which smbclient needs to read the machine's network interfaces. Before, it stopped with "Could not determine network interfaces, you must use a interfaces config line".

## 4.1.4 - 2026-10-31

- Settings → System updates: the tag "restart after the update" (or "restart needed") sits on a line of its own under the server's name.
- Links on the pages (e.g. "back to the dashboard" on the sign-in page) are the application's blue, visited or not - no more hard-to-read purple.

## 4.1.3 - 2026-10-31

- **The newest Python** (as OTP chooses it): every install and upgrade puts
  upsmon on the newest Python the system offers beside its own - on AlmaLinux
  / RHEL 9 (whose own python3 is 3.9) python3.14, 3.13, 3.12 or 3.11, the
  first that AppStream has, installed when missing - and takes it only once
  it is shown to run upsmon. The choice is the link
  `/usr/local/lib/upsmon/python`; `upsmon.service` and the `upsmon` command
  start it. `--python PATH` or `--system-python` choose otherwise, and the
  choice is kept for later upgrades (the ones from the pages too).
- colorama installed for that Python (its own package, else pip).

## 4.1.2 - 2026-10-31

- **PHP on the stream php:8.3, at least 8.3.36** (php2shell): every install and
  upgrade now puts PHP on the AppStream stream `php:8.3` - from 8.0, 8.2 or
  any other stream: `dnf module reset php`, `dnf module enable php:8.3`,
  `dnf distro-sync 'php*'`, php-fpm restarted; on php:8.3 already, its newest
  build. It says whether 8.3.36 or later runs. `--php-stream X.Y` still
  chooses another stream (its own fixed build is then the one checked:
  8.2.35, 8.4.27, 8.5.12).

## 4.1.1 - 2026-10-31

- **PHP on the stream php:8.2, at least 8.2.35** (php2shell, CVE-2026-109618,
  CVE-2026-109619): `install.sh` - on a fresh install and on every upgrade,
  from the command line or from Settings → Upgrades - puts PHP on the
  AppStream stream `php:8.2` whatever was there before (AlmaLinux 9's own
  8.0, or another stream): `dnf module reset php`, `dnf module enable
  php:8.2`, every PHP package moved over (`dnf distro-sync 'php*'`), php-fpm
  restarted on it. Already on php:8.2, it is brought up to the newest build.
  It then says whether 8.2.35 or later runs, and how to get it where the
  mirror has not got it yet. `--php-stream X.Y` chooses another stream,
  `--remi` Remi's 8.4, `--no-php-update` leaves PHP alone.

## 4.1.0 - 2026-10-31

More of OTP's Settings, the same pages and the same functions, for upsmon:

- **Time** - the clock as chrony keeps it: how far off, its sources, stratum,
  the time servers set from here (or `/etc/chrony.conf` left as it is), the
  time zone, a step to the right time now. `install.sh` installs and starts
  chrony, as OTP's does.
- **The database** - both SQLite files (`history.db`, `upsmon.db`): how big,
  every table counted, the disk under them and how fast they grow; a copy of
  both a day (`backup_daily`, `backup_at`, `backup_keep`), a copy now,
  download one (with the key, locked with a passphrase, or without), put one
  back (shown first; a copy of what it replaces made first; the service
  restarts on it), read them through, give the disk back, forget old
  records, erase what was collected (the history of the UPS, its events,
  power failures, tests, the plug, the sensors, the events of the pages).
- **Backups** - everything (both databases, the key, config.json, RESTORE.md)
  to a folder, FTP, FTPS, SFTP, SCP or SMB, locked with a password
  (AES-256), on a schedule, the oldest taken away, tried (opened, every file
  checked, both databases read through), and put back.
- **System updates** - dnf looks every day, the updates put in from here or
  on a schedule (all, or security only), a restart offered or made when one
  is needed.
- **Restart and power off** - this server, now or on a schedule.
- **Certificates and TLS → Download** - a window to choose the format: PEM
  with the chain, the certificate alone (PEM or DER), PFX / PKCS#12 (AES-256,
  or 3DES for older Windows and Java), PEM with the private key or the key
  alone - with a password, typed unseen. Every export with the key goes into
  Events. On the command line: `upsmon --cert-export pfx --out FILE`.
- **PHP and php2shell** (CVE-2026-109618, CVE-2026-109619): `install.sh`
  does what OTP's does - PHP put on the AppStream stream 8.3 where there is
  none, an installed one brought up to the newest build, checked by its
  version and by its changelog (a backport keeps the old number), Remi's 8.4
  offered (`--remi`) where AppStream has no fixed build, and the guard always
  (`99-php2shell.ini`, a pool that takes no body apart, nginx refusing
  multipart). `--php-stream X.Y`, `--no-php-update`.
- Secrets saved on the pages (the password of the backups, of the proxy, the
  DNS keys) show as dots and their last two characters; typed, dots only.
- **The command line in OTP's colours** - `--help` in two columns, in colour
  (colorama, installed where it can be), every line of output coloured as
  OTP colours it; new: `--backup`, `--copies`, `--restore`,
  `--restore-bundle`, `--rbackup-now`, `--rbackup-status`, `--db-check`,
  `--time [sync]`, `--updates status|check|start|cancel`, `--restart-server`,
  `--poweroff-server`, `--restarts`, `--lockouts`, `--lockouts-clear`,
  `--cert-export`.
- **The console** - new menus: *The database and backups* and
  *Certificates, updates, restarts, the time*.
- `upsmon.service`: `ProtectSystem=full` (was strict), so a backup can go to
  a folder mounted anywhere; more room for keys and copies.

## 4.0.0 - 2026-10-31

The standalone upsmon rebuilt on the engine and the pages of OTP (1.0.187).
The dashboard does exactly what it did - the UPS, the smart plug, the sensors,
the history, the tests, the control behind the PIN - and still asks nobody to
sign in. Beside it, **Settings** (`/settings/`), which nobody reaches without
an account, with OTP's own pages, the same UI and the same functions:

- **Accounts** - full admin and read only, passwords (PBKDF2-SHA256), who is
  signed in now and ending a sign-in, lockouts after wrong passwords (per
  address and per name) and clearing them, the columns of every table laid
  out per person (Edit the columns), one's own settings exported and imported.
- **Certificates and TLS** - a certificate uploaded (PEM in any order, or
  PFX / PKCS#12 with its password), a request (CSR) made here and the answer
  uploaded, a self-signed one; the protocols and ciphers (standard,
  intermediate, modern, custom), DH parameters, HSTS. Put in nginx by root
  (`upsmon_web.py`, started by `upsmon-web.path`), nginx asked before it is
  reloaded and put back as it was when it says no.
- **Automatic certificates** - ACME (Let's Encrypt, its staging or another
  CA), HTTP-01 on port 80 or DNS-01 (by hand, RFC 2136, Cloudflare, acme-dns,
  deSEC), renewed by themselves; Try port 80, Check DNS, the certificate from
  before put back with a click.
- **Upgrades** - a signed package sent from the pages, or found on the web
  (`upgrade_url`, by default this repository's `release/` folder) once a day
  and put in with one click; checked (Ed25519 signature, every file) by the
  daemon and again by root (`upsmon_upgrade.py`, started by
  `upsmon-upgrade.path`), which runs its `install.sh --upgrade --yes`. Going
  back to an older version, only a safe one, when switched on.
- **About** - the version and what it runs on (Python, OpenSSL, SQLite,
  nginx, PHP and its extensions), the language of the pages, the debug log,
  the console at login.
- **Events** - every sign-in, account, setting, certificate and upgrade.

Also from OTP:

- **Czech and English** for every page, the dashboard included - CS / EN in
  the header of the dashboard and on the sign-in, each person's own language
  in their account, `ui_lang` for everybody else.
- **The console** - `upsmon --console`, the whole of upsmon by its menus on
  the terminal (the UPS, checks, the live log, accounts, settings,
  certificates, upgrades, the service), and at root's login
  (`upsmon --console-at-login on|off`).
- **The command line of Settings** - `--users`, `--add-user`, `--passwd`,
  `--set-role`, `--del-user`, `--disable-user`, `--enable-user`,
  `--settings`, `--setting KEY=VALUE`, `--audit`, `--cert`,
  `--cert-selfsigned`, `--acme`, `--acme-order`, `--upgrade-check`,
  `--upgrade-online`, `--upgrade-status`, `--upgrade-follow`,
  `--upgrade-cancel`, `--downgrade-check`, `--downgrade`, `--maintenance`.

What changed underneath:

- `upsmon_admin.py` beside `upsmon.py`: the daemon starts it in threads of its
  own; whatever happens to it, the UPS is watched. Its own SQLite database,
  `/var/lib/upsmon/upsmon.db` (the history stays in `history.db`), its own API
  on 127.0.0.1:9849 with its own token (`/run/upsmon/admin-token`).
- The pages run in a php-fpm pool of their own (`upsmon`, as `upsmon-www`),
  and speak to the daemon over a socket (no `allow_url_fopen`).
- nginx: `/etc/nginx/conf.d/upsmon.conf` in OTP's shape - the dashboard at
  `/`, Settings at `/settings/`, ACME on port 80; the certificate in
  `/etc/nginx/certs/upsmon.pem` / `upsmon.key`.
- `upsmon --diag` used a function it did not have (`ago`) when a sensor had
  pushed something; it has it now.

Upgrading from 3.x (`sudo ./install.sh --upgrade`): the configuration, the
history and the certificate are kept - `server.pem` / `server.key` /
`server.ca` are carried over to the new names, and the nginx file is written
afresh with the host name and the allow list of the old one (which is kept as
`/etc/nginx/upsmon.conf.before-4.0`). The first account of Settings is made
and its password printed. From then on, new versions come by Settings →
Upgrades.
