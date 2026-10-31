<?php
/**
 * upsmon-api.php — the pages' side of the daemon API.
 *
 * Taken from isemon, where it has been the whole of the web side for a long
 * time. Neither page holds anything or decides anything: the daemon does all
 * the work and answers on http://127.0.0.1:<port>; this file is the thin
 * client that talks to it, for the administration pages (admin/index.php) and
 * for the enrolment pages (index.php) alike.
 *
 * Two things travel with every request that changes something: the API token
 * the daemon dropped in a file readable only by root and the web server's
 * group, and the session of whoever is signed in. The browser holds the
 * session in a cookie it cannot read itself (HttpOnly), and never sees the
 * token at all — so a page that somebody manages to run JavaScript in still
 * cannot lift anything worth having out of it.
 */
declare(strict_types=1);

// Included by index.php and admin/index.php, never a page of its own. The nginx
// vhost shipped with this refuses it by name, but a site's own vhost may not,
// and a file that answers when asked is a file somebody will one day put a
// side effect in. Asked for directly, it answers as though it were not there.
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

const UPS_HOST    = '127.0.0.1';
/* api_port in the settings, as the daemon wrote it down when it started
   (1.0.59); 9861 where it has not. */
define('UPS_PORT', (static function (): int {
    $p = (int) trim((string) @file_get_contents('/run/upsmon/admin-port'));
    return ($p >= 1024 && $p <= 65535) ? $p : 9849;
})());
const UPS_TOKEN   = '/run/upsmon/admin-token';

/* Two kinds of sign-in, never the same cookie: an administrator's, and a person
   enrolling their own token, who can reach nothing but that. Which one this
   page uses is said by the page before it includes this file. */
if (!defined('UPS_COOKIE')) {
    define('UPS_COOKIE', 'upsmon_session');
}
if (!defined('UPS_COOKIE_PATH')) {
    define('UPS_COOKIE_PATH', '/');
}

/** Whether this page was reached over TLS - directly, or through a proxy in
 *  front that terminates it and says so. */
function ups_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    return strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

/** Whether this request comes from the machine itself - the operator at the
 *  console, who may be told where things are and what the pages run as. */
function ups_local(): bool
{
    return in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), ['127.0.0.1', '::1'], true);
}

/** Read the API token the daemon wrote for us, or null if we can't. */
function ups_token(): ?string
{
    if (!is_readable(UPS_TOKEN)) {
        return null;
    }
    $token = trim((string) @file_get_contents(UPS_TOKEN));
    return $token !== '' ? $token : null;
}

/** The session of whoever is signed in, from the cookie. */
function ups_session(): string
{
    $got = (string) ($_COOKIE[UPS_COOKIE] ?? '');
    return preg_match('/^[A-Za-z0-9_-]{16,128}$/', $got) === 1 ? $got : '';
}

/** Start one. Same-site and HttpOnly, and Secure whenever the page is on TLS. */
function ups_set_session(string $token): void
{
    setcookie(UPS_COOKIE, $token, [
        'expires'  => 0,                 /* until the browser is closed */
        'path'     => UPS_COOKIE_PATH,
        'secure'   => ups_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function ups_clear_session(): void
{
    setcookie(UPS_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => UPS_COOKIE_PATH,
        'secure'   => ups_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

/**
 * Call the daemon. Returns [status, body-string]; status 0 means unreachable.
 * $payload, when given, is sent as a JSON body and turns this into a POST.
 */
function ups_call(string $path, string $method = 'GET', array|object|null $payload = null,
                     float $timeout = 30.0, array $extra = []): array
{
    $headers = ['Accept: application/json'];
    /* Headers of a caller's own (1.0.173): the scraper's token for /metrics,
       one line each, nothing that could start another header. */
    foreach ($extra as $line) {
        $line = (string) $line;
        if (preg_match('/^X-Upsmon-[A-Za-z-]{1,40}: [\x21-\x7e]{1,300}$/', $line)) {
            $headers[] = $line;
        }
    }
    $headers[] = 'X-Upsmon-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    // The name the pages were reached by, for the link in a token's mail
    // (1.0.33) - built by the daemon from this, never taken from the page.
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if (preg_match('/^([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?$/', $host)) {
        $headers[] = 'X-Upsmon-Host: ' . $host;
    }
    $session = ups_session();
    if ($session !== '') {
        $headers[] = 'X-Upsmon-Session: ' . $session;
    }
    // The language of the page (1.0.127): a code mailed from it is written in it.
    $lang = preg_replace('/[^a-z]/', '', (string) ($_COOKIE['upsmon_lang'] ?? ''));
    if (strlen($lang) === 2) {
        $headers[] = 'X-Upsmon-Lang: ' . $lang;
    }
    $token = ups_token();
    if ($token === null) {
        return [0, ''];
    }
    $headers[] = 'X-Upsmon-Token: ' . $token;

    $body = null;
    if ($payload !== null) {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            /* A number JSON cannot hold (1e400 is INF to PHP) - the request's
               fault, said so, not a 500 with an empty body (1.0.103). */
            return [400, json_encode(['ok' => false, 'error' => 'a number in the request is too big']) ?: ''];
        }
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Content-Length: ' . strlen($body);
    } elseif ($method !== 'GET') {
        $headers[] = 'Content-Length: 0';
    }

    /* A socket, spoken to by hand, rather than file_get_contents('http://…').
       That one needs allow_url_fopen, which a hardened php.ini switches off —
       and when it is off every call here fails silently and the dashboard
       says "the daemon is not answering" about a daemon that is running
       perfectly. A socket to localhost needs no ini setting at all.

       The daemon always sends a Content-Length and never chunks, so reading
       the body is reading that many bytes. */
    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client(
        'tcp://' . UPS_HOST . ':' . UPS_PORT, $errno, $errstr, $timeout,
        STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);

    $request = $method . ' ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . UPS_HOST . ':' . UPS_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if ($body !== null) {
        $request .= $body;
    }
    if (@fwrite($sock, $request) === false) {
        @fclose($sock);
        return [0, ''];
    }

    $raw = '';
    while (!feof($sock)) {
        $chunk = @fread($sock, 65536);
        if ($chunk === false || $chunk === '') {
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                @fclose($sock);
                return [0, ''];
            }
            break;
        }
        $raw .= $chunk;
    }
    @fclose($sock);

    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return [0, ''];
    }
    $head = substr($raw, 0, $split);
    $reply = substr($raw, $split + 4);
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', $head, $m)) {
        $status = (int) $m[1];
    }
    return [$status, $reply];
}

/** Call the daemon and return the decoded reply, or null. */
function ups_get(string $path, float $timeout = 30.0): ?array
{
    [$status, $body] = ups_call($path, 'GET', null, $timeout);
    if ($status !== 200) {
        return null;
    }
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

/** Pass a daemon reply straight through to the browser. */
function ups_relay(string $path, string $method = 'GET', array|object|null $payload = null,
                      float $timeout = 30.0): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if (ups_token() === null) {
        http_response_code(503);
        /* Where the token lives is for whoever is on the machine; from
           anywhere else it is a daemon that is not answering. */
        echo json_encode(['ok' => false, 'error' => ups_local()
            ? 'the API token is unreadable — is upsmon.service running, and is '
              . UPS_TOKEN . ' readable by the web server?'
            : 'the daemon is not answering — is upsmon.service running?']);
        return;
    }
    [$status, $body] = ups_call($path, $method, $payload, $timeout);
    if ($status === 0) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' =>
            'the daemon is not answering — is upsmon.service running?']);
        return;
    }
    /* A 401 is no longer taken as the end of the session here (1.0.73): while
       the web address moves between the nodes, or a node restarts during an
       upgrade, one answer may say so for a moment, and throwing the cookie
       away signed the person out in the middle of watching the upgrade. The
       page asks again (whoami) and goes to the sign-in only when the session
       is really gone; signing out takes the cookie away. */
    http_response_code($status);
    echo ups_squeeze($body);
}

/**
 * A large answer, compressed for a browser that says it takes gzip.
 *
 * A page of failed attempts with every field in it is a few hundred kilobytes
 * and shrinks to a tenth of that.
 */
function ups_squeeze(string $body): string
{
    $accepts = (string) ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '');
    if (strlen($body) < 2048 || !function_exists('gzencode') || headers_sent()
        || stripos($accepts, 'gzip') === false || ini_get('zlib.output_compression')) {
        return $body;
    }
    $packed = gzencode($body, 4);
    if ($packed === false) {
        return $body;
    }
    header('Content-Encoding: gzip');
    header('Vary: Accept-Encoding');
    header('Content-Length: ' . strlen($packed));
    return $packed;
}

/** Whoever is signed in, as the daemon sees them, or null. */
function ups_whoami(): ?array
{
    $got = ups_get('/api/auth/whoami', 5.0);
    $who = is_array($got) ? ($got['who'] ?? null) : null;
    if (is_array($who)) {
        $prefs = $who['prefs'] ?? null;
        $who['prefs'] = (is_array($prefs) && $prefs) ? $prefs : new stdClass();
        /* An empty layout is an object, not a list, to the page. */
        $cols = $who['cols'] ?? null;
        $who['cols'] = (is_array($cols) && $cols) ? $cols : new stdClass();
    }
    return $who;
}

/* ==========================================================================
   Files, in both directions
   --------------------------------------------------------------------------
   A copy of the database is not an answer to be held in memory and echoed:
   it is eighty megabytes on a good day and it would be held twice over -
   once as the reply, once as the string being printed. Both of these read a
   lump at a time and pass it straight on, so the memory used is the size of
   the lump however big the file is.
   ========================================================================== */

/** Ask the daemon for a file and hand it straight to the browser.

    Returns the HTTP status. On anything but 200 nothing has been printed and
    the JSON the daemon sent back is returned instead, so the caller can say
    what went wrong. */
function ups_pipe(string $path, string $filename, float $timeout = 600.0): array
{
    $token = ups_token();
    if ($token === null) {
        return [0, ''];
    }
    $headers = ['Accept: application/octet-stream', 'X-Upsmon-Token: ' . $token];
    $session = ups_session();
    if ($session !== '') {
        $headers[] = 'X-Upsmon-Session: ' . $session;
    }
    $headers[] = 'X-Upsmon-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client('tcp://' . UPS_HOST . ':' . UPS_PORT,
                                  $errno, $errstr, 20.0, STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);
    $request = 'GET ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . UPS_HOST . ':' . UPS_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if (@fwrite($sock, $request) === false) {
        @fclose($sock);
        return [0, ''];
    }

    /* The head, a line at a time, so that the body is never pulled into a
       string with it. */
    $head = '';
    while (($line = @fgets($sock, 8192)) !== false) {
        $head .= $line;
        if ($line === "\r\n" || $line === "\n") {
            break;
        }
    }
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', $head, $m)) {
        $status = (int) $m[1];
    }
    if ($status !== 200) {
        $body = '';
        while (!feof($sock)) {
            $lump = @fread($sock, 65536);
            if ($lump === false || $lump === '') {
                break;
            }
            $body .= $lump;
            if (strlen($body) > 1 << 20) {
                break;
            }
        }
        @fclose($sock);
        return [$status, $body];
    }

    $length = null;
    if (preg_match('/^Content-Length:\s*(\d+)/mi', $head, $m)) {
        $length = (int) $m[1];
    }
    $sent = (string) $filename;
    if ($sent === '' && preg_match('/filename="([^"]+)"/i', $head, $m)) {
        $sent = $m[1];
    }
    $sent = preg_replace('/[^A-Za-z0-9@._-]/', '', $sent) ?: 'upsmon.json.gz';

    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $sent . '"');
    header('Cache-Control: no-store');
    if ($length !== null) {
        header('Content-Length: ' . $length);
    }
    $left = $length ?? PHP_INT_MAX;
    while ($left > 0 && !feof($sock)) {
        $lump = @fread($sock, 262144);
        if ($lump === false || $lump === '') {
            break;
        }
        echo $lump;
        flush();
        $left -= strlen($lump);
    }
    @fclose($sock);
    return [200, ''];
}


/** Send a file on disk to the daemon as the body of a POST, a lump at a
    time, and return what it says. */
function ups_send_file(string $path, string $file, float $timeout = 900.0): array
{
    $token = ups_token();
    if ($token === null) {
        return [0, ''];
    }
    $size = @filesize($file);
    if ($size === false) {
        return [0, ''];
    }
    $in = @fopen($file, 'rb');
    if ($in === false) {
        return [0, ''];
    }
    $headers = ['Accept: application/json',
                'Content-Type: application/octet-stream',
                'Content-Length: ' . $size,
                'X-Upsmon-Token: ' . $token];
    $session = ups_session();
    if ($session !== '') {
        $headers[] = 'X-Upsmon-Session: ' . $session;
    }
    $headers[] = 'X-Upsmon-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client('tcp://' . UPS_HOST . ':' . UPS_PORT,
                                  $errno, $errstr, 20.0, STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        fclose($in);
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);
    $head = 'POST ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . UPS_HOST . ':' . UPS_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if (@fwrite($sock, $head) === false) {
        fclose($in);
        @fclose($sock);
        return [0, ''];
    }
    while (!feof($in)) {
        $lump = fread($in, 262144);
        if ($lump === false || $lump === '') {
            break;
        }
        if (@fwrite($sock, $lump) === false) {
            // The daemon stopped taking it (1.10.198): it says why before it
            // closes - not admin, too big, no room - and that answer is read
            // below rather than reported as a daemon that is not answering.
            break;
        }
    }
    fclose($in);

    $raw = '';
    while (!feof($sock)) {
        $lump = @fread($sock, 65536);
        if ($lump === false || $lump === '') {
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                @fclose($sock);
                return [0, ''];
            }
            break;
        }
        $raw .= $lump;
    }
    @fclose($sock);
    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return [0, ''];
    }
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', substr($raw, 0, $split), $m)) {
        $status = (int) $m[1];
    }
    return [$status, substr($raw, $split + 4)];
}

/**
 * The body of a request, written to a temporary file as it arrives (1.10.218):
 * a database being put back, sent as the file itself rather than as a form.
 * Returns [path, ''] or [null, why]. At most $most bytes; never held whole in
 * memory. Read from php://input, which is there whether or not PHP takes
 * request bodies apart itself - and on this page it does not
 * (`enable_post_data_reading = Off` in .user.ini, against php2shell).
 */
function ups_take_body(int $most): array
{
    $told = (int) ($_SERVER['CONTENT_LENGTH'] ?? -1);
    if ($told === 0) {
        return [null, 'no file arrived'];
    }
    if ($told > $most) {
        return [null, 'that file is bigger than this page takes ('
            . round($told / 1048576) . ' MB sent, at most '
            . round($most / 1048576) . ' MB)'];
    }
    $tmp = @tempnam(ups_spool_dir(), 'upsmon-restore-');
    if ($tmp === false) {
        return [null, 'this web server could not write the file down while it arrived'];
    }
    @chmod($tmp, 0600);
    /* Whatever goes wrong from here, the file goes: the page may be a
       gigabyte in when the connection drops, and nothing else will tidy up. */
    $fail = function (string $why) use ($tmp): array {
        @unlink($tmp);
        return [null, $why];
    };
    $in = @fopen('php://input', 'rb');
    $out = @fopen($tmp, 'wb');
    if ($in === false || $out === false) {
        if ($in !== false) { fclose($in); }
        if ($out !== false) { fclose($out); }
        return $fail('this web server could not write the file down while it arrived');
    }
    $got = 0;
    $broken = false;
    try {
        while (!feof($in)) {
            $lump = fread($in, 1048576);
            if ($lump === false) {
                $broken = true;
                break;
            }
            if ($lump === '') {
                continue;
            }
            $got += strlen($lump);
            if ($got > $most) {
                $broken = true;
                break;
            }
            if (fwrite($out, $lump) !== strlen($lump)) {
                return $fail('this web server could not write the file down while it arrived');
            }
        }
    } catch (\Throwable $e) {
        return $fail('this web server could not write the file down while it arrived');
    } finally {
        fclose($in);
        fclose($out);
    }
    if ($got === 0) {
        return $fail('no file arrived');
    }
    if ($broken || ($told > 0 && $got !== $told)) {
        return $fail($got > $most ? 'that file is bigger than this page takes'
                                  : 'the file did not arrive whole');
    }
    return [$tmp, ''];
}

/** Where a file arriving is written down: a folder of this pool's own under
    the temporary folder (0700, so nothing else on the machine reads a
    database on its way through), or upload_tmp_dir when the pool names one,
    or the temporary folder itself when neither can be had. */
function ups_spool_dir(): string
{
    $named = (string) ini_get('upload_tmp_dir');
    if ($named !== '' && is_dir($named) && is_writable($named)) {
        return $named;
    }
    $base = sys_get_temp_dir();
    $own = $base . '/upsmon-restore';
    if (!is_dir($own) && !is_link($own)) {
        @mkdir($own, 0700);
    }
    /* Ours, and not a link somebody left there with our name on it. */
    if (is_dir($own) && !is_link($own) && is_writable($own)
            && function_exists('posix_geteuid') && @fileowner($own) === posix_geteuid()) {
        return $own;
    }
    return $base;
}

/**
 * Whether the PHP running this page is safe from php2shell (CVE-2026-109618,
 * CVE-2026-109619), as far as it can tell from inside: its version against
 * the fixed releases of 21 October 2026, and whether this page's own guard -
 * request bodies never taken apart by PHP, no upload progress - is in force.
 * A distribution that backported the fix keeps its old version number, so a
 * version below the fixed ones is "may be affected", not "is".
 */
function ups_php_safety(): array
{
    $fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
    $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    if (isset($fixed[$branch])) {
        $patched = version_compare(PHP_VERSION, $fixed[$branch], '>=');
        $needs = $fixed[$branch];
    } else {
        /* Newer than the branches fixed that day is fixed; older is end of
           life, with no fix from PHP itself. */
        $patched = version_compare($branch, '8.5', '>');
        $needs = $patched ? '' : '8.2.35';
    }
    $reading = (string) ini_get('enable_post_data_reading');
    $progress = (string) ini_get('session.upload_progress.enabled');
    $off = function (string $v): bool {
        return in_array(strtolower($v), ['0', '', 'off', 'false', 'no'], true);
    };
    return [
        'version'  => PHP_VERSION,
        'sapi'     => PHP_SAPI,
        'patched'  => $patched,
        'needs'    => $needs,
        'guarded'  => $off($reading) && $off($progress),
        'post_reading' => !$off($reading),
        'upload_progress' => !$off($progress),
    ];
}
