<?php
/**
 * upsmon-page.php — what both pages share: the headers, the languages, the head.
 *
 * Included by index.php (the enrolment pages) and admin/index.php (the
 * administration pages), never a page of its own. Everything here is how
 * isemon's dashboard draws itself, so that the two look and behave alike:
 * one nonce per page in the Content-Security-Policy, nothing loaded from
 * anywhere but this server, and the words swapped into the chosen language
 * before the browser paints them.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

const UPS_VERSION = '4.3.3';
define('UPS_LANG_CODE', '/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/');

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

/* The address bar, as it was typed. nginx counts sign-in attempts by looking
   for api=login in it, and PHP takes the last of two `api=` or decodes `%61pi`
   into `api` where nginx does not; a request written so that the two read it
   differently is nobody's, and is refused before either page looks at it. */
$ups_query = (string) ($_SERVER['QUERY_STRING'] ?? '');
if (substr_count($ups_query, 'api=') > 1 || preg_match('/(^|&)[^=&]*%/', $ups_query)
    // ...nor in its value (1.0.33): api=lo%67in is login to PHP and not to
    // nginx, which then counted no sign-in attempt at all. No endpoint name
    // has anything to escape.
    || preg_match('/(^|&)api=[^&]*[%+]/', $ups_query)
    // ...nor a name PHP reads otherwise than nginx (1.0.61): "+api=login" is
    // api=login to PHP, its leading space dropped, and not to nginx's count.
    || preg_match('/(^|&)(?![A-Za-z0-9_-]*(=|&|$))/', $ups_query)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'that address is not one of this page\'s']);
    exit;
}
unset($ups_query);

$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; "
     . "script-src 'self' 'nonce-$nonce'; "
     . "style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'nonce-$nonce'; "
     . "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
     . "base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

function h($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* The body as it came, objects kept objects (1.0.61): decoded into arrays,
   {} went on to the daemon as [] and was refused as "not an object". */
function sent_json(): object
{
    $raw = file_get_contents('php://input');
    $got = $raw === false || $raw === '' ? null : json_decode($raw, false);
    return is_object($got) ? $got : new stdClass();
}

function sent_body(): array
{
    $raw = file_get_contents('php://input');
    $got = $raw === false || $raw === '' ? null : json_decode($raw, true);
    return is_array($got) ? $got : [];
}

require_once __DIR__ . '/upsmon-lang.php';

/** Requests that were never this page's: refused before anything is read,
    as on isemon - JSON only, same origin only, a few hundred bytes. */
function ups_guard_post(): void
{
    $told = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    $kind = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    /* A database being put back (1.0.10, as isemon's): the file itself as the
       body, with a header of ours a form on another page cannot send, and a
       kind such a form cannot send without asking either. Never multipart. */
    // ...and a new version of upsmon sent from the pages, the same way (1.0.37).
    $restore = in_array(($_GET['api'] ?? ''), ['db-restore', 'upgrade-package', 'rbackup-upload'], true)
        && strpos($kind, 'application/octet-stream') === 0
        && (string) ($_SERVER['HTTP_X_OTP_RESTORE'] ?? '') === '1';
    if ($told > 8 * 1024 * 1024 && !$restore) {
        http_response_code(413);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'that is too much to send here']);
        exit;
    }
    $from = (string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
    /* A browser that says nothing of where the request came from, but sends
       an Origin of another site (1.0.101): refused as a cross-site one. */
    $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
    $foreign = false;
    if ($from === '' && $origin !== '' && $origin !== 'null') {
        $oh = strtolower((string) parse_url($origin, PHP_URL_HOST));
        $op = parse_url($origin, PHP_URL_PORT);
        $hh = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
        $want = $oh . ($op ? ':' . $op : '');
        $foreign = $oh === '' || ($hh !== $want && $hh !== $oh);
    }
    if ((strpos($kind, 'application/json') !== 0 && !$restore)
            || ($from !== '' && $from !== 'same-origin' && $from !== 'none') || $foreign) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'that request did not come from this page']);
        exit;
    }
}

/** The head of a page: the language, the words-swapper, the style. */
function ups_head(string $title, string $lang, bool $load, string $nonce, string $base): void
{
    $langs = ups_langs();
    $v = UPS_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/upsmon.css')
       . '-' . (int) @filemtime(__DIR__ . '/assets/core.js');
    echo "<meta charset=\"utf-8\">\n";
    echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    echo '<title>' . h($title) . "</title>\n";
    echo '<link rel="icon" href="' . h($base) . 'assets/favicon.svg" type="image/svg+xml">' . "\n";
    if ($load) {
        echo '<script nonce="' . h($nonce) . '" src="?api=lang&amp;code=' . h(rawurlencode($lang))
           . '&amp;v=' . (int) ($langs[$lang]['mtime'] ?? 0) . '"></script>' . "\n";
    }
    echo '<script nonce="' . h($nonce) . '">window.OTP_LANGS = '
       . json_encode(ups_lang_list(), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP)
       . '; window.OTP_LANG = ' . json_encode($lang) . ";</script>\n";
    echo '<script nonce="' . h($nonce) . '" src="' . h($base) . 'assets/i18n.js?v=' . h($v)
       . '"></script>' . "\n";
    echo '<link rel="stylesheet" nonce="' . h($nonce) . '" href="' . h($base) . 'assets/upsmon.css?v='
       . h($v) . '">' . "\n";
}
