# The upgrade on the pages (4.8.0)

An upgrade restarts everything that serves the pages: `upsmon.service` (its API),
php-fpm and nginx. Since 4.8.0 the pages stay with it: a band under the header says
how far it is, nothing turns red while it is expected, and when it is done the page
loads the new version once by itself.

## The progress file - the only contract

`/var/www/upsmon/.upgrade.json` - beside the pages, so PHP may read it; a dot name,
which nginx never serves (`location ~ /\. { deny all; }`). Root's, 0644, written to a
temporary file beside it and renamed, never half written. Nothing secret in it.

```json
{"state": "running", "id": "k1", "version": "4.8.1", "from": "4.8.0",
 "by": "admin on the pages", "part": 11, "parts": 13, "words": "Configuring nginx",
 "started": 1794900000, "at": 1794900042, "said": "", "downgrade": false}
```

| Field | Meaning |
|---|---|
| `state` | `running`, `done` or `failed` - nothing else is believed |
| `id` | the upgrade's id (the request's from the pages, `sh-…` by hand) |
| `version`, `from` | to and from (digits and dots only - checked by PHP) |
| `by` | who asked - only to a page with a session cookie |
| `part`, `parts` | step N of M - install.sh counts its own steps (8, or 13 with the pages) |
| `words` | the step, as install.sh prints it (`==> Configuring nginx`) |
| `started`, `at` | when it began, when this was written |
| `said` | on `failed`: why, in one line - only with a session |
| `downgrade` | going back to an older version |

**Believed** for 30 minutes after `at` while `running`, 10 minutes once `done` or
`failed`; older, written in the future or anything else: as if there were no file.

### Who writes it

- **install.sh --upgrade** (from the pages, or by hand): every `step` writes
  `running N/M`, `done` at the end; an EXIT trap writes `failed` with the exit code and
  the step it stopped in, and Ctrl-C, a hangup or TERM (the helper's deadline) end as
  `failed` too, never left `running`. A dry run writes nothing; saying no to a notice
  before anything is changed removes it.
- **upsmon-upgrade** (the root helper): `running` when it takes the request (root checks
  the package), `failed` when the package is refused, `done`/`failed` at the end if
  install.sh did not say it. It hands install.sh the id (`UPSMON_UPGRADE_ID`), so it is
  one record. During an upgrade the helper that runs is the one installed before, so its
  part works from the upgrade after 4.8.0; install.sh's part works at once.

## The pages

- `web/upsmon-upgrading.php` reads and checks the file (once a request).
- Every call relayed while the daemon does not answer gets
  `503 {"ok": false, "upgrading": {...}, "error": "being upgraded"}` instead of
  "the daemon is not answering" - Settings and the dashboard, `/?api=health` included.
- `?api=status` carries `upgrading` while the daemon answers, so the band is there before
  anything restarts.
- `?api=upgrade-state` (Settings and the dashboard) answers without the daemon:
  `{"upgrading": {...}, "pages": "<version of the PHP files>", "api": <daemon answers>}`.
- **Settings**: one band under the header - *upsmon is being upgraded to X*, from, asked
  by, how long, a bar, `NN % · step words · step N of M`, and while something is away
  *The daemon is restarting with the new version - not answering for 7 s* or *nginx and
  PHP are restarting - these pages cannot be reached for 4 s*, asked every two seconds.
  The pill says *in maintenance*; no red "not answering" bar, no red toasts. Settings →
  Upgrades shows the progress from the disk while the daemon is away.
- **Done**: after having seen it running the page loads itself once (never in a loop;
  with changes not saved it says so and offers *Load it again*).
- **Failed**: a red band with the reason and *Open Upgrades* (the output of install.sh);
  × hides it for that upgrade.
- **The sign-in page** draws the band itself (from the file, without who asked) and loads
  itself again once the daemon answers.
- **The dashboard**: a blue band with the step, the pill *In maintenance*, loaded once
  when it is done.

## Testing it

`tests/upgrade-ui/t_sim.js` writes the file by hand step by step, kills and starts the
daemon and `php -S`, and checks each state (25 checks, English and Czech).
