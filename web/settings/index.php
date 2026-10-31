<?php
/**
 * settings/index.php — the Settings of upsmon, behind a sign-in.
 *
 * The dashboard (/) is for anybody on the allowed networks and asks nobody
 * who they are. Everything here may not be reached without an account: the
 * accounts themselves, the certificates and TLS of the web server, the
 * automatic certificates (ACME), the upgrades, About.
 *
 * These are the pages of OTP - the same header, the same rail of settings at
 * the left edge, the same popups. They collect nothing and decide nothing:
 * every word comes from the upsmon daemon over its settings API on
 * localhost, and the daemon decides whether whoever is signed in may have it.
 */
declare(strict_types=1);

define('UPS_COOKIE', 'upsmon_session');
define('UPS_COOKIE_PATH', '/settings/');
require_once dirname(__DIR__) . '/upsmon-page.php';
require_once dirname(__DIR__) . '/settings-api.php';

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    if ($what === 'lang' && !$post) {
        ups_serve_lang();
    }
    if ($what === 'software' && !$post) {
        /* What every node runs on (1.0.99) - and of the pages, what this
           PHP itself is: php-fpm's, not the command line's. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        [$status, $body] = ups_call('/api/software', 'GET', null, 20.0);
        $data = json_decode((string) $body, true);
        if ($status !== 200 || !is_array($data)) {
            http_response_code($status ?: 503);
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
            exit;
        }
        $ext = [];
        foreach (get_loaded_extensions() as $e) {
            $v = phpversion($e);
            $ext[$e] = ($v === false || $v === PHP_VERSION) ? '' : (string) $v;
        }
        ksort($ext, SORT_NATURAL | SORT_FLAG_CASE);
        $data['pages'] = [
            'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'extensions' => $ext,
            'opcache' => function_exists('opcache_get_status') && is_array(@opcache_get_status(false))
                && !empty(@opcache_get_status(false)['opcache_enabled']),
            'server' => (string) ($_SERVER['SERVER_SOFTWARE'] ?? ''),
            'os' => PHP_OS_FAMILY,
        ];
        echo json_encode($data);
        exit;
    }
    if ($post) {
        ups_guard_post();
    }
    if ($what === 'login' && $post) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $sent = sent_body();
        [$status, $body] = ups_call('/api/auth/login', 'POST', [
            'name'     => (string) ($sent['name'] ?? ''),
            'password' => (string) ($sent['password'] ?? ''),
        ], 30.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is upsmon.service running?']);
            exit;
        }
        $data = json_decode($body, true);
        if ($status === 200 && is_array($data) && !empty($data['token'])) {
            ups_set_session((string) $data['token']);
            unset($data['token']);
            echo json_encode($data);
            exit;
        }
        http_response_code($status === 200 ? 400 : $status);
        echo json_encode(is_array($data) ? $data : ['ok' => false, 'error' => 'sign-in failed']);
        exit;
    }
    if ($what === 'upgrade-package' && $post) {
        /* A new version of upsmon (1.0.37): the .tar.gz itself is the body, as a
           database being put back is. A full administrator only, asked before
           a byte is read; the daemon checks its signature, and root checks it
           again before putting it in. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $who = ups_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin') {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => is_array($who)
                ? 'only a full administrator may send a new version'
                : 'not signed in']);
            exit;
        }
        [$tmp, $why] = ups_take_body(64 * 1024 * 1024);
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        try {
            [$status, $body] = ups_send_file('/api/upgrade/package', $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is upsmon.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'db-restore' && $post) {
        /* A database somebody is putting back: the file itself is the body,
           written down a lump at a time as it arrives and going on to the
           daemon from there - never held in memory, never a multipart form. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        /* Who is sending it is asked first, before a byte of the body is read:
           the daemon would refuse it at the end anyway, but up to four
           gigabytes would have been written to disk by then on anybody's
           say-so. Only a full administrator may put a database back. */
        $who = ups_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin') {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => is_array($who)
                ? 'only a full administrator may put a database back'
                : 'not signed in']);
            exit;
        }
        [$tmp, $why] = ups_take_body(4 * 1024 * 1024 * 1024);
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        $ask = '/api/db/restore' . (isset($_GET['check']) ? '?check=1' : '');
        try {
            [$status, $body] = ups_send_file($ask, $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is upsmon.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'rbackup-upload' && $post) {
        /* A backup file being put back (1.0.109): as a database above - the
           file the body, written down as it comes, only a full administrator. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $who = ups_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin') {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => 'only a full administrator may put a backup back']);
            exit;
        }
        [$tmp, $why] = ups_take_body(4 * 1024 * 1024 * 1024);   // as nginx and the pool take (1.0.139)
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        try {
            [$status, $body] = ups_send_file('/api/rbackup/upload', $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' => 'the daemon is not answering — is upsmon.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'rbackup-download' && !$post) {
        /* A backup made now - or one fetched from a destination - a lump at a
           time to the browser. Only an id and a file name are passed on. */
        $id = preg_replace('/[^a-f0-9]/', '', (string) ($_GET['id'] ?? ''));
        $name = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($_GET['name'] ?? ''));
        $bits = [];
        if ($id !== '' && $name !== '') { $bits[] = 'id=' . $id; $bits[] = 'name=' . rawurlencode($name); }
        [$status, $body] = ups_pipe('/api/rbackup/download' . ($bits ? '?' . implode('&', $bits) : ''), $name, 1800.0);
        if ($status === 401) {
            header('Location: /settings/');
            exit;
        }
        if ($status !== 200) {
            http_response_code($status ?: 503);
            header('Content-Type: application/json');
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
        }
        exit;
    }
    if ($what === 'db-download' && !$post) {
        /* A copy or a dump as a file to save, from the daemon to the browser a
           lump at a time. Only a name and which folder are passed on - never a
           path: the daemon holds both folders. */
        $name = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($_GET['name'] ?? ''));
        $kind = ($_GET['kind'] ?? '') === 'dump' ? 'dump' : '';
        $ticket = preg_replace('/[^a-f0-9]/', '', (string) ($_GET['ticket'] ?? ''));
        $bits = [];
        if ($ticket !== '') { $bits[] = 'ticket=' . $ticket; }
        if ($name !== '') { $bits[] = 'name=' . rawurlencode($name); }
        if ($kind !== '') { $bits[] = 'kind=dump'; }
        $ask = '/api/db/download' . ($bits ? '?' . implode('&', $bits) : '');
        [$status, $body] = ups_pipe($ask, $name);
        if ($status === 401) {
            // Signed out meanwhile: back to the sign-in, not a page of JSON (1.0.36).
            header('Location: /settings/');
            exit;
        }
        if ($status !== 200) {
            http_response_code($status ?: 503);
            header('Content-Type: application/json');
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
        }
        exit;
    }
    if ($what === 'logout' && $post) {
        ups_call('/api/auth/logout', 'POST', [], 10.0);
        ups_clear_session();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }
    /* Reads apart from writes, so a GET can never reach a road that changes
       something, whatever is typed in the address bar. */
    $reads = [
        'status' => '/api/status', 'settings' => '/api/settings', 'users' => '/api/users',
        'sessions' => '/api/sessions', 'events' => '/api/events', 'log' => '/api/log',
        'whoami' => '/api/auth/whoami', 'my-settings' => '/api/auth/settings',
        'upgrade' => '/api/upgrade', 'web' => '/api/web', 'lockouts' => '/api/lockouts',
        'console-login' => '/api/console-login', 'acme' => '/api/acme',
        'db' => '/api/db', 'ntp' => '/api/ntp', 'power' => '/api/power', 'osup' => '/api/osup', 'proxy' => '/api/proxy',
        'rbackup' => '/api/rbackup',
    ];
    $writes = [
        'settings' => '/api/settings', 'users' => '/api/users', 'sessions' => '/api/sessions',
        'password' => '/api/auth/password', 'prefs' => '/api/auth/prefs',
        'columns' => '/api/auth/columns', 'my-settings' => '/api/auth/settings',
        'upgrade' => '/api/upgrade', 'web' => '/api/web', 'lockouts' => '/api/lockouts',
        'console-login' => '/api/console-login', 'acme' => '/api/acme',
        'db' => '/api/db', 'ntp' => '/api/ntp', 'power' => '/api/power', 'osup' => '/api/osup', 'proxy' => '/api/proxy',
        'rbackup' => '/api/rbackup',
    ];
    if ($post) {
        if (!isset($writes[$what])) {
            http_response_code(404);
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
            exit;
        }
        ups_relay($writes[$what], 'POST', sent_json(), 90.0);
        exit;
    }
    if (!isset($reads[$what])) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
        exit;
    }
    $query = $_GET;
    unset($query['api']);
    ups_relay($reads[$what] . ($query ? '?' . http_build_query($query) : ''), 'GET', null, 60.0);
    exit;
}

/* ---- the page ------------------------------------------------------------ */
$me      = ups_whoami();
/* Signed in with the password, the second step still to give (1.0.125): the
   sign-in page, asking for it - nothing of the pages yet. */
$mfa     = (is_array($me) && !empty($me['mfa'])) ? (string) $me['mfa'] : '';
if ($mfa !== '') { $me = null; }
$health  = ups_get('/api/health', 5.0);
$alive   = is_array($health);
$token_there = file_exists(UPS_TOKEN);
$token_ok    = ups_token() !== null;
$web_user    = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
    ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?';
/* What the sign-in page says when something is wrong is for the operator at
   the console: which account the pages run as, where the token is, whether
   any account exists yet. From anywhere but this machine the page says only
   that the daemon is not answering - and the lines that would have named the
   rest never get a chance to. */
if (!$me && !ups_local()) {
    $token_there = false;
    if (!$token_ok || empty($health['database']['ok']) || empty($health['users'])) {
        $alive = false;
    }
    /* Reduced to what the markup tests, all of it saying "fine": anything
       that is not fine has already turned this into "not answering" above.
       (1.0.19: only the language was kept, and the page then read the
       missing database as one that will not open.) */
    $health = ['lang' => (string) ($health['lang'] ?? 'cs'), 'database' => ['ok' => true],
               'users' => 1];
}
$initial = $me ? (ups_get('/api/status', 8.0) ?: null) : null;
$host    = (string) ($_SERVER['HTTP_HOST'] ?? php_uname('n'));
$site    = (string) ($initial['site'] ?? '');
$title   = ($site !== '' ? $site . ' · ' : '') . 'upsmon · Settings';
$lang    = ups_lang_pick($me, (string) ($health['lang'] ?? 'cs'));
$load    = $lang !== 'en' && ups_lang_pack($lang) !== null;
if ($me && ($_COOKIE['upsmon_lang'] ?? '') !== $lang) {
    setcookie('upsmon_lang', $lang, ['expires' => time() + 365 * 86400, 'path' => '/',
              'secure' => ups_https(), 'httponly' => false, 'samesite' => 'Strict']);
}
?>
<!doctype html>
<html lang="<?= h($lang) ?>" class="app-shell-root<?= $load ? ' i18n-wait' : '' ?>">
<head>
<?php ups_head($title, $lang, $load, $nonce, '/'); ?>
</head>
<body class="app-shell fold-words<?= $me ? ' framed' : '' ?>">
<div class="wrap">

<?php if (!$me): ?>
<div class="signin">
  <div class="signbox">
    <div class="card">
    <h1 data-no-i18n><?= h($title) ?></h1>
    <p class="lede">The settings of the UPS server on <span data-no-i18n><?= h($host) ?></span>. Sign in to go on.</p>
    <p class="note small">The dashboard needs no sign-in: <a href="/">back to the dashboard</a>.</p>
    <?php if (!$token_ok && $token_there): ?>
      <div class="offline">
        The daemon is running, but this page may not read what it wrote.<br><br>
        <span class="mono"><?= h(UPS_TOKEN) ?></span> exists and is not readable by
        <span class="mono"><?= h($web_user) ?></span>, which is what this page runs as.
        On the server:<br>
        <span class="mono">usermod -a -G upsmon <?= h($web_user) ?></span><br>
        <span class="mono">systemctl restart php-fpm nginx</span>
      </div>
    <?php elseif (!$alive): ?>
      <div class="offline">The daemon is not answering. Nobody can sign in until
        <span class="mono">upsmon.service</span> is running:<br>
        <span class="mono">systemctl status upsmon</span> ·
        <span class="mono">journalctl -u upsmon -n 50</span></div>
    <?php elseif (empty($health['database']['ok'])): ?>
      <div class="offline">The daemon is running, but its database will not open. On the
        server: <span class="mono">upsmon --check</span> · <span class="mono">journalctl -u upsmon -n 50</span></div>
    <?php elseif (empty($health['users'])): ?>
      <div class="offline">There is no account on this machine yet. Make one on the server:<br>
        <span class="mono">upsmon --add-user yourname --role fulladmin</span></div>
    <?php endif; ?>
    <div id="mfa-box" data-stage="<?= h($mfa) ?>" hidden></div>
    <form id="signin-form" autocomplete="on"<?= $mfa !== '' ? ' hidden' : '' ?>>
      <input type="text" id="in-name" name="username" placeholder="name" autocomplete="username"
             autocapitalize="none" spellcheck="false" required>
      <input type="password" id="in-pass" name="password" placeholder="password"
             autocomplete="current-password" required>
      <button class="btn primary cmd" type="submit" id="in-go"><svg
        viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
        stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
        ><path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="M14 12h7"/><path
        d="M18 9l3 3-3 3"/></svg><span>Sign in</span></button>
      <div class="said" id="in-said"></div>
    </form>
    <div style="margin-top:14px;display:flex;justify-content:space-between;align-items:center">
      <span class="muted small">upsmon <?= h(UPS_VERSION) ?></span>
      <span class="langpick" id="langpick"></span>
    </div>
    </div>
  </div>
</div>
</div>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(UPS_VERSION) ?>"></script>
<script nonce="<?= h($nonce) ?>">
(function () {
  var form = $('signin-form'), said = $('in-said'), go = $('in-go');
  /* The language, chosen before signing in - as on the enrolment pages (1.0.15). */
  var host = $('langpick');
  if (host && window.OTP_LANGS && window.OTP_LANGS.length > 1) {
    window.OTP_LANGS.forEach(function (l) {
      var b = el('button', l.code === window.OTP_LANG ? 'on' : '', l.code.toUpperCase());
      b.type = 'button';
      b.setAttribute('data-no-i18n', '');
      b.title = l.name;
      b.onclick = function () {
        document.cookie = 'upsmon_lang=' + encodeURIComponent(l.code) + '; path=/; max-age=31536000; '
          + 'samesite=strict' + (location.protocol === 'https:' ? '; secure' : '');
        location.reload();
      };
      host.appendChild(b);
    });
  }
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    said.className = 'said';
    said.textContent = '';
    go.disabled = true;
    var words = go.querySelector('span');
    words.textContent = 'Signing in…';
    api('login', {name: $('in-name').value, password: $('in-pass').value}).then(function (d) {
      if (d && d.mfa) { form.hidden = true; mfaStep(); return; }
      said.className = 'said good';
      said.textContent = 'Welcome back.';
      location.reload();
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
      go.disabled = false;
      words.textContent = 'Sign in';
      $('in-pass').value = '';
      $('in-pass').focus();
    });
  });
  if ($('mfa-box').dataset.stage) mfaStep(); else $('in-name').focus();
}());
</script>
</body>
</html>
<?php exit; endif; ?>

<header>
  <h1 data-no-i18n><?= h($site ?: 'upsmon') ?> <span class="host"><?= h($host) ?></span></h1>
  <span id="state-pill" class="pill unknown"><span class="dot"></span><span>…</span></span>
  <div class="spacer"></div>
  <div class="btnrow">
    <button type="button" class="btn small mebtn" id="me-btn" data-icon="person"
            title="The account you are signed in as: what it may do, its password, the language of these pages, the columns of the tables and your settings in a file."><span class="me-name" data-no-i18n><?= h($me['name']) ?></span></button>
    <button class="btn small" id="signout" data-icon="out">Sign out</button>
  </div>
  <div class="updated" id="updated" title="Click to pause or resume the live updates">
    <b>live</b><br><span id="updated-at">…</span></div>
</header>

<div id="offline" class="offline" hidden></div>
<div id="phpsafety" class="offline" hidden></div>
<div id="problems" class="offline warnish" hidden></div>
<div id="trials" class="trials" hidden></div>

<div class="tabs" role="tablist">
  <button type="button" data-href="/" data-icon="chart"
          title="The dashboard of the UPS, the plug and the sensors - for everybody, without signing in.">Dashboard</button>
  <button role="tab" aria-selected="false" data-tab="events" data-icon="history"
          title="Every sign-in, every change of an account or a setting, every certificate put in, every upgrade - and the daemon’s own log.">Events</button>
  <button role="tab" aria-selected="true" data-tab="settings" data-icon="gear"
          title="The accounts of these pages, the certificates and TLS of the web server, the automatic certificates, the upgrades and About.">Settings</button>
</div>

<section class="panel" id="tab-events" hidden>
  <div class="card full" data-hold>
    <h2>What this daemon has done</h2>
    <p class="note">Every token made, replaced or taken away, every change of a setting, every
      sign-in. Kept in the database, so it survives a restart.</p>
    <div class="btnrow filters">
      <input type="search" id="ev-q" placeholder="anything in an event…" style="flex:1;min-width:200px">
      <select id="ev-kind"><option value="">everything</option></select>
      <span id="ev-time" title="How far back the events go."></span>
    </div>
    <div id="ev-table" class="scroll rowsonly"></div>
    <div class="pager" id="ev-pager"></div>
  </div>
  <div class="card full fulladmin-only aside">
    <h2>The daemon's own log</h2>
    <p class="note">The tail of <span class="mono">/var/log/upsmon/upsmon.log</span>. Switch on
      <i>debug</i> in Settings → About to have it say every step of every request.</p>
    <div class="btnrow"><button class="btn cmd" id="log-read" data-icon="log">Read it</button>
      <select id="log-lines"><option>200</option><option selected>600</option><option>2000</option></select></div>
    <pre class="lines" id="log-out" style="margin-top:12px" hidden></pre>
  </div>
</section>

<!-- ===================== Settings ===================== -->
<section class="panel" id="tab-settings">
<div class="ctl-layout">
  <nav class="ctl-nav" id="ctl-nav" aria-label="Settings sections">
    <div class="ctl-navtop">
      <button type="button" class="ctl-pin" id="ctl-pin" aria-pressed="false" aria-label="Keep this menu open"></button>
      <div class="ctl-find-wrap">
        <input type="search" id="ctl-find" placeholder="Find a setting…" autocomplete="off" aria-label="Find a setting">
        <div class="ctl-found" id="ctl-found" hidden></div>
      </div>
    </div>
    <div class="ctl-group">Access</div>
    <button type="button" data-pane="people" data-icon="person" title="Who may open these pages, what each of them may do, and who is signed in right now.">Accounts</button>
    <button type="button" data-pane="web" data-icon="lock" title="The certificate of the web server, and how TLS is spoken.">Certificates and TLS</button>
    <button type="button" class="fulladmin-only" data-pane="acme" data-icon="lock" title="The certificate ordered from Let's Encrypt (or another ACME CA) and renewed by itself.">Automatic certificates</button>
    <div class="ctl-group">Server</div>
    <button type="button" class="fulladmin-only" data-pane="proxy" data-icon="globe" title="An HTTP proxy for the updates only - the new versions of upsmon and the system updates.">Proxy</button>
    <button type="button" class="fulladmin-only" data-pane="time" data-icon="clock" title="The clock of this server: chrony, its time servers, how far off it is.">Time</button>
    <button type="button" class="fulladmin-only" data-pane="power" data-icon="power" title="Restart or switch off this server.">Restart and power off</button>
    <div class="ctl-group">Data</div>
    <button type="button" data-pane="db" data-icon="db" title="Where everything lives, how big it is, copies of it, and erasing what was collected.">The database</button>
    <button type="button" data-pane="backup" data-icon="archive" title="Backups of everything to another machine - FTP, FTPS, SFTP, SCP, SMB or a folder - locked with a password, on a schedule, and putting one back.">Backups</button>
    <div class="ctl-group">Updates</div>
    <button type="button" class="fulladmin-only" data-pane="osup" data-icon="download" title="The operating system's packages updated; a restart offered when one is needed.">System updates</button>
    <button type="button" class="fulladmin-only" data-pane="upgrade" data-icon="up" title="A new version of upsmon, put in from here - sent by hand or found on the web.">Upgrades</button>
    <button type="button" data-pane="about" data-icon="info" title="Version, what is running, the language, the debug log, the console at login.">About</button>
  </nav>

  <div class="ctl-main">
  <div class="card full" id="readonly-note" hidden>
    <h2>You may look, but not change</h2>
    <p class="note" style="margin:0">This account may not change the settings. A full administrator can change that under <i>Accounts</i>.</p>
  </div>

  <div class="ctl-pane" id="pane-people" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Accounts</h2>
      <p class="ctl-lede">Who may open these pages. <b>full admin</b> may change everything;
        <b>read only</b> may look and change nothing. The dashboard itself asks nobody: these
        accounts are for Settings alone.</p></div>
    <div class="card full">
      <h2>Accounts <span class="right"><button class="btn cmd small primary admin-only" id="us-add" data-icon="add">Make an account</button></span></h2>
      <div id="us-table"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Signed in now</h2><div id="se-table"></div></div>
    <div class="card full fulladmin-only" id="lo-card"><h2>Locked out <span class="right" id="lo-tools"></span></h2>
      <p class="note">Addresses and names with wrong passwords still counted - at the limit they are locked
        out until the time runs out. Clear one, or all of them, and they may try again at once.</p>
      <div id="lo-table"></div></div>
    <div class="card full" id="cols-card">
      <h2>Columns of the tables <span class="right" id="cols-count"></span></h2>
      <p class="note">Every table on these pages can be laid out the way you read it. Press
        your name at the top right and switch on <b>Edit the columns</b>; then drag the edge of
        a column's heading to make it wider or narrower, and drag the heading itself to move
        the column. The right button on a heading hides a column, brings a hidden one back or
        adds an empty one for room. Twice on an edge puts that table's widths back. Each change
        is kept with your account the moment you let go, not in this browser, and comes back
        wherever you sign in; nobody else's tables change. The switch is for this sign-in
        only: signing out, the sign-in running out or the service restarting turn it off
        again, and the columns stay as you left them.</p>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd" id="cols-edit-go" data-icon="edit"
                title="The same switch as under your name: on for this sign-in only.">Edit the columns</button>
        <button class="btn cmd" id="cols-reset" data-icon="undo"
                title="Every table back as it comes: the widths and the order of the columns you set, on every page. Nobody else's are touched.">Put my columns back as they come</button>
        <button class="btn cmd" id="cols-export" data-icon="download"
                title="How you have set these pages up for yourself, saved as a JSON file.">Export my settings</button>
        <button class="btn cmd" id="cols-import" data-icon="upload"
                title="Read a file saved by Export my settings - here or on another machine running upsmon.">Import settings…</button>
      </div>
    </div>
    <div class="card full"><div id="sect-people"></div></div>
  </div>

  <div class="ctl-pane" id="pane-acme" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Automatic certificates</h2>
      <p class="ctl-lede">The certificate of this server ordered from Let's Encrypt or another ACME CA and
        renewed by itself well before it runs out. The CA checks the name by asking it on port 80 (HTTP-01), or by
        a record in DNS (DNS-01) for a server it cannot see from the internet.</p></div>
    <div id="ac-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-acme"></div></div>
  </div>
  <div class="ctl-pane" id="pane-web" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Certificates and TLS</h2>
      <p class="ctl-lede">How the dashboard and these pages speak HTTPS: the certificate
        with its chain, the protocols, the ciphers.</p></div>
    <div class="card full">
      <h2>Certificates</h2>
      <p class="note">The certificate of this server's name. It is sent as PEM files (the
        certificate, its key, the chain, the root - in any order, or all in one file) or as a
        PFX / PKCS#12 file, with its password or without; or the request is made here and only
        what the authority sends back is uploaded; or Automatic certificates orders it. Root
        puts it in nginx and asks nginx before reloading it.</p>
      <div id="web-certs" class="cert-grid"></div>
    </div>

  </div>
  <div class="ctl-pane" id="pane-upgrade" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Upgrades and maintenance</h2>
      <p class="ctl-lede">A new version put in from here: send the package, or take it from the
        web, and the server is upgraded - taken out of service first, its signature checked, put
        in by root, the service restarted, and brought back only once it answers again. The UPS
        is watched all the while; the history and the settings stay. The command line
        (install.sh --upgrade) works as it always has.</p></div>
    <div class="card full">
      <h2>The nodes</h2>
      <p class="note">A server in maintenance goes on watching the UPS, the plug and the sensors
        and keeps their history, but nothing changes them: a command to the UPS, a value set on
        it, the plug switched or reset are refused, the dashboard says so and /api/health says
        maintenance - so monitoring leaves it alone. These pages go on working.</p>
      <div id="up-nodes"></div>
    </div>
    <div class="card full admin-only" id="up-web-card">
      <h2>From the web</h2>
      <p class="note">Where new versions are published - the address below - is looked at once a
        day. A newer upsmon found there is offered here, and put in with one click: fetched, its
        signature checked like a package sent by hand, then the server upgraded.
        Nothing is put in by itself.</p>
      <div id="up-web"></div>
      <div id="sect-upgrade"></div>
    </div>
    <div class="card full admin-only">
      <h2>A new version</h2>
      <p class="note">The .tar.gz of a new upsmon, as it was released. It is checked before
        anything else: it must be signed by a release key this server trusts, every file in
        it must be the one signed, and it must not be older than what runs here. Root checks
        it all again before it is put in.</p>
      <div class="drop" id="up-drop">
        <input type="file" id="up-file" accept=".gz,.tgz,application/gzip,application/octet-stream" hidden>
        <span id="up-drop-says">Drop the upsmon-X.Y.Z.tar.gz here, or press to choose it</span>
      </div>
      <div id="up-pkg"></div>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd primary" id="up-start" data-icon="play" disabled>Upgrade</button>
        <button class="btn cmd" id="up-forget" data-icon="trash" hidden>Forget the package</button>
      </div>
      <div id="up-ready"></div>
    </div>
    <div class="card full admin-only" id="up-down-card" hidden>
      <h2>Going back to an older version</h2>
      <p class="note">Only to a version that is safe: one that reads what the newer versions
        wrote into the database the same, and has every security fix that matters - each version
        says how far back it may go, and the highest of what ran on this database and was
        installed on this machine counts. The database is not put back nor changed: its tables
        stay as they are and the older version runs on them, so it does not matter how big it
        is. The package is checked like an upgrade's, and against this database's tables, before
        anything is put in; then the server goes back, as in an upgrade.</p>
      <div id="up-down"></div>
    </div>
    <div class="card full" id="up-plan-card" hidden>
      <h2>The upgrade</h2>
      <div id="up-plan"></div>
      <p class="note small" id="up-retry" style="min-height:1.4em;margin:6px 0 0"></p>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd danger admin-only" id="up-cancel" data-icon="cancel" hidden>Stop it</button>
      </div>
    </div>
    <div class="card full">
      <h2>What root said last <span class="mono small muted" id="up-log-node" data-no-i18n></span></h2>
      <p class="note"><span>The output of install.sh, the last time this server was upgraded from these pages.</span>
        <span class="mono" data-no-i18n>/var/lib/upsmon/upgrade/last.log</span></p>
      <!-- Folded until asked for (as OTP 1.0.196): a long log pushed the rest down. -->
      <details class="fold" id="up-log-fold">
        <summary>the output</summary>
        <div class="seg" id="up-log-nodes" hidden style="margin:10px 0"></div>
        <pre class="lines" id="up-log">–</pre>
      </details>
    </div>
    <div class="card full">
      <h2>On the command line</h2>
      <p class="note">The same, by hand, as root:</p>
      <pre class="lines">upsmon --maintenance on --why "upgrade"  # out of service
upsmon --upgrade-check                     # what is on the web, and whether it is newer
upsmon --upgrade-online                    # the newest: fetched, checked, put in
tar xzf upsmon-X.Y.Z.tar.gz && cd upsmon-X.Y.Z
./install.sh --upgrade                     # takes it out and back by itself as well
upsmon --maintenance off                   # back in service (if it was put out by hand)
upsmon --maintenance status                # which it is
upsmon --upgrade-status                    # an upgrade started on these pages</pre>
    </div>
  </div>

  <div class="ctl-pane" id="pane-db" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The database</h2>
      <p class="ctl-lede">Two SQLite files on this machine hold everything: <code>history.db</code> - the UPS,
        the plug and the sensors: samples, events, power failures, tests - and <code>upsmon.db</code> - the
        accounts of these pages, their settings, the certificates, the events. The secrets in it are sealed
        with a key kept beside it, in the state folder - and every copy is kept with that key beside it.</p></div>
    <div class="card full"><div id="sect-db"></div></div>

    <div class="card full" id="db-tls-card" hidden>
      <h2>Encryption to the database server</h2>
      <p class="note">This daemon’s own connection to its database - on every node, moved over
        on the live database without stopping anything: tried apart first, then switched, and
        put back at once if the first statement on the new one does not go.</p>
      <div id="db-tls"></div>
    </div>

    <div class="card full" id="db-dump-card" hidden>
      <h2>The dumps it keeps <span class="right" id="db-dump-now"></span></h2>
      <p class="note">Every night at the time above, the database in use is dumped
        <b>by its own engine's own program</b> — <code>pg_dump</code> on PostgreSQL,
        <code>mariadb-dump</code> on MariaDB, and on the file SQLite's own backup, which is
        the file. It is a fraction of the size of the database, and it is the format the
        server's own tools read, so it can be put back by somebody who has never heard of
        this program.</p>
      <p class="note">A dump goes back into <b>the engine it came off</b>. What goes back
        into any of the three is a copy, which the card below makes — that is what carries an
        installation from the file to a server and back.</p>
      <div id="db-dump-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="db-dump-make" data-icon="save"
                title="Dump the database now, with the engine's own program, rather than waiting for tonight. It is kept with the others and counts as one of them.">Make one now</button>
        <button class="btn cmd" id="db-dump-get" data-icon="down"
                title="Dump the database now and save it to the machine you are sitting at. Nothing is kept here.">Download one</button>
      </div>
      <div id="db-dumps" style="margin-top:18px"></div>
      <div class="admin-only" id="db-dump-upload" style="margin-top:18px">
        <h4>Put a dump back</h4>
        <p class="note">A dump from somewhere else — one downloaded from here, or a file
          copied off the dumps folder. It replaces everything: every token, every request,
          every setting and every account. Nothing happens until it has been read, checked and
          shown to you.</p>
        <div class="drop" id="dump-drop">
          <input type="file" id="dump-file" accept=".pgc,.gz,.sql,.db,application/octet-stream" hidden>
          <span id="dump-drop-says">Drop a dump here, or press to choose one</span>
        </div>
        <div id="dump-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="dump-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full" id="db-engine-card" hidden>
      <h2>Which one it is <span class="right" id="db-engine-now"></span></h2>
      <p class="note">The settings above say which database to open and how to reach it, and
        they are the only settings kept in <b id="db-engine-file">the config file</b> rather
        than in the database — a database cannot hold the address of itself, and a machine
        whose database will not open still has to be able to be put right from this page.</p>
      <p class="note">Changing the setting moves nothing. The order is: fill the address in,
        <b>try it</b>, <b>set it up</b> if the database and the account are not there yet,
        <b>carry everything across</b>, and only then <b>start using it</b>. Until that last
        step this installation carries on exactly as it is, and what is in it is never
        touched by any of this.</p>
      <div id="db-engine-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="db-engine-test" data-icon="check"
                title="Reach that server with the address above, exactly as the daemon would, and say what answered. Nothing is saved and nothing is written.">Try it</button>
        <button class="btn cmd" id="db-engine-setup" data-icon="key"
                title="Make the database and the account on that server, and give that account rights on that one database and no other, with a password made here and shown once. The first time it asks for an administrator on the server, uses it for this one connection and stores it nowhere. Afterwards it needs none: it opens the database and puts its tables right, which is worth doing after every upgrade.">Set it up…</button>
        <button class="btn cmd primary" id="db-engine-move" data-icon="save"
                title="Copy everything that is here into that database: every token, every request, every setting and every account. What is here is left exactly as it is.">Carry everything across…</button>
        <button class="btn cmd danger" id="db-engine-empty" data-icon="forget"
                title="Throw away what is in the OTHER database, so that a move can be tried again. Never the one in use.">Empty it…</button>
        <button class="btn cmd" id="db-engine-use" data-icon="power"
                title="Start using it. This writes the address into the config file and restarts the daemon; nothing in either database is touched, and coming back is the same four steps the other way.">Start using it…</button>
      </div>
      <p class="btnhelp">Once everything is in the other database and it is the one in use,
        the one it came from is just a spare copy: the file may be deleted, or the server
        uninstalled. Going the other way is these same steps with the file chosen instead —
        which is what makes it safe to try a server at all.</p>
    </div>

    <div class="card full">
      <h2>The disk it is on</h2>
      <p class="note">How much room there is where this database's files live, how fast it is
        growing, and how long one will hold the other. Measured, not guessed: the size is
        noted once a day and what is shown is the slope of the last fortnight. On a database
        server the database is not on this machine at all — what is here then is the copies
        and the dumps, and the line below says so.</p>
      <div id="db-disk"></div>
    </div>

    <div class="card full" id="db-tune-card" hidden>
      <h2>The database server’s own settings</h2>
      <p class="note">A database server is installed with settings for a machine of any size,
        which is to say for a small one: PostgreSQL keeps 128 MB of the database in memory, and
        MariaDB likewise, on a machine of 32 GB. This reads what the machine the server runs on
        has — its memory, its processors, its disk — works the settings out for it, shows them
        beside what is there now, and puts them in when you say so.</p>
      <p class="note">Changing them takes an account that may: this program’s own where it has
        that right, otherwise an administrator on that server, asked for in the popup, used for
        that one request and stored nowhere — not in the settings, not in the database, not in
        any log.</p>
      <div id="db-tune-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd primary" id="db-tune" data-icon="gear"
                title="Read what the machine the database server runs on has, work its settings out for it and show them beside what is there now. Nothing is changed until you say so.">Tune it for this machine…</button>
        <button class="btn cmd" id="db-tune-restart" data-icon="power" hidden
                title="Restart PostgreSQL for the settings that take effect only at its start.">Restart the server…</button>
        <button class="btn cmd" id="db-tune-undo" data-icon="undo" hidden
                title="Put every setting this page changed back to what it was before.">Put back as it was…</button>
      </div>
    </div>

    <div class="card full">
      <h2>What is in it <span class="right" id="db-size"></span></h2>
      <p class="note">A copy is both files, consistent even while the daemon is writing to them
        (SQLite's own backup), with config.json to read - one .tar.gz, the key beside it.</p>
      <p class="btnhelp">These are <b>every row in each table</b>, which is not the number on
        the tabs above: those count what the page they belong to is showing.</p>
      <div id="db-counts"></div>
      <div class="going wide" id="db-going" hidden>
        <div class="bar"><span id="db-going-fill"></span></div>
        <div class="says" id="db-going-says"></div>
      </div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd admin-only" id="db-backup" data-icon="save"
                title="Copy the database as it is into the backups folder on this machine, now, rather than waiting for tonight.">Make a copy now</button>
        <button class="btn cmd admin-only" id="db-download" data-icon="down"
                title="Make a copy now and save it to the machine you are sitting at, with the key that opens the tokens inside it. Nothing is kept here.">Download it</button>
        <button class="btn cmd admin-only" id="db-check" data-icon="check"
                title="Ask the database to read itself through and say whether anything in it is broken - SQLite's integrity check, MariaDB's CHECK TABLE, and on PostgreSQL every table read through. It only reads; on a large one it takes a while.">Check it</button>
        <button class="btn cmd admin-only" id="db-tidy" data-icon="broom"
                title="Throws away exactly what the &quot;keep for&quot; numbers above already say is too old — the RADIUS requests, the checks of a code and the events, each by its own number of days. It happens by itself every hour; this is the same thing, now. Lowering one of those numbers deletes nothing by itself: this is what does it.">Apply what is kept, now</button>
        <button class="btn cmd danger admin-only" id="db-prune" data-icon="forget"
                title="Forgets the RADIUS requests and the checks of a code older than an age you choose here, whatever the &quot;keep for&quot; numbers say. Only those two kinds of record: the tokens, the accounts and the settings are not touched.">Forget records older than…</button>
        <button class="btn cmd admin-only" id="db-optimize" data-icon="db"
                title="Gives the space back to the DISK. Deleting rows frees room inside the database and the engine reuses it; nothing hands it back to the operating system until the whole thing is rebuilt. All three do that the same way — SQLite's VACUUM, MariaDB's OPTIMIZE TABLE, PostgreSQL's VACUUM FULL — and all three hold the table shut while they do it and need room for a second copy of the biggest one. Worth doing after throwing a lot away, and not otherwise.">Give the disk back</button>
      </div>
      <div id="db-backups" style="margin-top:18px"></div>
      <div class="admin-only" id="db-upload" style="margin-top:18px">
        <h4>Put a copy back</h4>
        <p class="note">A copy from somewhere else — one downloaded from here, or a file
          copied off the backups folder. It replaces everything: the whole history of the UPS,
          every setting and every account. Nothing happens until it has been read, checked
          and shown to you; then the service restarts on it.</p>
        <div class="drop" id="db-drop">
          <input type="file" id="db-file" accept=".gz,.enc,application/octet-stream" hidden>
          <span id="db-drop-says">Drop a copy (upsmon-copy-….tar.gz) here, or press to choose one</span>
        </div>
        <div id="db-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="db-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full">
      <h2>Erase the collected data <span class="right" id="erase-size"></span></h2>
      <p class="note">What is recorded of what happened can be thrown away without anything
        stopping to work: the UPS is watched as before and the charts start again. Choose
        what goes; nothing is erased that you have not ticked.</p>
      <p class="note"><b>The accounts, the certificates and every setting are never touched by
        this.</b> They are not options you could tick by mistake: they are not in the list at all.</p>
      <div id="erase-list" class="erase-list"></div>
      <div class="btnrow admin-only" style="margin-top:14px;align-items:center">
        <button class="btn cmd danger" id="erase-go" data-icon="forget"
                title="Erase everything ticked above. It cannot be undone — but a copy of the database is made just before it, and it can be restored.">Erase what is ticked…</button>
        <label class="check small" id="erase-tidy-wrap">
          <input type="checkbox" id="erase-tidy" checked
                 title="Rebuild the database afterwards so the space actually goes back to the disk. None of the three give room back by themselves when rows are deleted — it is reused inside instead.">
          <span>rebuild it afterwards, to give the disk back</span>
        </label>
      </div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-proxy" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Proxy</h2>
      <p class="ctl-lede">Where the server may reach the web only through an HTTP proxy: the updates go
        through it - the new versions of upsmon, and the system updates (dnf, apt). Nothing else does: the UPS,
        the plug, the sensors, the automatic certificates, mail and the backups never.</p></div>
    <div class="card full"><h2>Settings</h2><div id="sect-proxy"></div></div>
    <div id="px-host"></div>
  </div>

  <div class="ctl-pane" id="pane-time" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Time</h2>
      <p class="ctl-lede">Every sample, event and power failure is written with the time of this clock, and
        TLS and the automatic certificates need it right. The server keeps it with chrony; here is how far
        off it is, which servers it follows, and the time servers set for it.</p></div>
    <div id="ntp-host"></div>
  </div>

  <div class="ctl-pane" id="pane-power" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Restart and power off</h2>
      <p class="ctl-lede">This server restarted or switched off from here; the page follows it down and up
        again. Switched off, it comes back only by its button - or by the power coming back, where the
        machine is set to start then.</p></div>
    <div id="pw-host"></div>
    <div class="card full fulladmin-only"><h2>On a schedule</h2><div id="sect-power"></div></div>
  </div>

  <div class="ctl-pane" id="pane-osup" hidden>
    <div class="ctl-head"><h2 class="ctl-title">System updates</h2>
      <p class="ctl-lede">The operating system's packages, updated by dnf (or apt) - PHP among them, so its
        fixes (php2shell) come this way too. A restart an update needs is offered when it is done, or made
        by itself.</p></div>
    <div id="ou-host"></div>
    <div class="card full fulladmin-only"><h2>On a schedule</h2><div id="sect-osup"></div></div>
  </div>

  <div class="ctl-pane" id="pane-backup" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Backups</h2>
      <p class="ctl-lede">A backup is everything: both databases (the whole history of the UPS, the plug
        and the sensors; the accounts, every setting, the certificates), the key that opens the sealed
        secrets and this machine's config.json - with RESTORE.md, the exact steps to bring it all back on
        a machine installed from nothing. Locked with the password below; sent to every destination
        switched on - a folder, FTP, FTPS, SFTP, SCP or a Windows/Samba share.</p></div>
    <div id="rb-top"></div>
    <div class="card full" id="rb-tried-card" hidden><h2>Backups tried <span class="right" id="rb-tried-tools"></span></h2><div id="rb-tried"></div></div>
    <div class="card full"><h2>When, how many, and the password</h2><div id="sect-backup"></div></div>
    <div class="card full"><h2>Where they go <span class="right" id="rb-add-host"></span></h2>
      <div id="rb-targets"></div></div>
    <div class="card full"><h2>What was sent <span class="right" id="rb-runs-tools"></span></h2><div id="rb-runs"></div></div>
  </div>

  <div class="ctl-pane" id="pane-about" hidden>
    <div class="ctl-head"><h2 class="ctl-title">About</h2></div>
    <div class="card full"><div id="about-state"></div></div>
    <div class="card full"><div id="sect-about"></div></div>
  </div>

  <div class="card full" id="rest-card" hidden><div id="sect-rest"></div></div>

  <div class="save-bar admin-only" id="save-bar">
    <button class="btn cmd primary" id="set-save" data-icon="save"
            title="Save the changed settings into the database. They take effect the moment they are saved - nothing restarts.">Save the changes</button>
    <button class="btn cmd" id="set-reset" data-icon="undo"
            title="Throw away the changes on this page and read the settings back from the daemon as they are.">Put them back</button>
    <span class="muted small" id="set-said"></span>
  </div>
  </div>
</div>
</section>

</div><!-- /wrap -->

<div class="modal" id="modal" hidden>
  <div class="box" id="modal-box">
    <div class="head"><h3 id="modal-title">…</h3>
      <button class="xbtn" id="modal-x" data-icon="close" aria-label="Close"></button></div>
    <div class="body" id="modal-body"></div>
    <div class="foot" id="modal-foot"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script nonce="<?= h($nonce) ?>">
var ME = <?= json_encode($me, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
var STATUS = <?= $initial ? json_encode($initial, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
var PHP_SAFETY = <?= ($me['role'] ?? '') === 'fulladmin' ? json_encode(ups_php_safety(), JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
</script>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(UPS_VERSION) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/cols.js?v=<?= h(UPS_VERSION) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/settings.js?v=<?= h(UPS_VERSION) ?>"></script>
</body>
</html>

