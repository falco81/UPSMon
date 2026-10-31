# Changelog

Every version is a package in `release/` (the last ten are kept), signed with
the release key whose public half is in `deploy/release-keys/`. The root of
the repository is the package unpacked.

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
