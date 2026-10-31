<?php
/**
 * upsmon-lang.php — the languages of the pages: the dashboard and Settings.
 * Included, never a page of its own. As OTP's (and isemon's) engine: the pages are
 * English in their code, and lang/*.json says what each piece is in another language.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

if (!defined('UPS_LANG_CODE')) {
    define('UPS_LANG_CODE', '/^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$/');
}

/* ---- the languages ---------------------------------------------------------
   Exactly isemon's: every word is English in the code, and a file in lang/
   says what each English text is in that language. A file that is missing or
   broken is simply not offered, and the page is the English it always was. */
function ups_lang_dir(): string
{
    return __DIR__ . '/lang';
}

function ups_langs(): array
{
    static $known = null;
    if ($known !== null) {
        return $known;
    }
    $known = [];
    foreach (@glob(ups_lang_dir() . '/*.json') ?: [] as $file) {
        $code = basename($file, '.json');
        if (!preg_match(UPS_LANG_CODE, $code) || !is_readable($file)) {
            continue;
        }
        $fh = @fopen($file, 'rb');
        if (!$fh) {
            continue;
        }
        $head = (string) @fread($fh, 8192);
        fclose($fh);
        if (!preg_match('/"_meta"\s*:\s*(\{[^{}]*\})/s', $head, $m)) {
            continue;
        }
        $meta = json_decode($m[1], true);
        if (!is_array($meta) || ($meta['code'] ?? '') !== $code) {
            continue;
        }
        $name = trim((string) ($meta['name'] ?? ''));
        $known[$code] = ['code' => $code, 'name' => $name !== '' ? $name : $code,
                         'english' => trim((string) ($meta['english'] ?? $name)) ?: $code,
                         'file' => $file, 'mtime' => (int) @filemtime($file)];
    }
    ksort($known);
    return $known;
}

function ups_lang_pack(string $code): ?array
{
    $langs = ups_langs();
    if (!isset($langs[$code])) {
        return null;
    }
    $raw = @file_get_contents($langs[$code]['file']);
    $all = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($all)) {
        return null;
    }
    $pack = ['code' => $code, 'strings' => [], 'patterns' => [], 'rich' => []];
    foreach (['strings', 'patterns', 'rich'] as $part) {
        foreach (($all[$part] ?? []) as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $from = (string) ($entry['source'] ?? '');
            $to   = (string) ($entry['text'] ?? '');
            if ($from === '' || $to === '' || $to === $from) {
                continue;
            }
            if ($part === 'patterns') {
                $pack[$part][] = [$from, $to];
            } else {
                $pack[$part][$from] = $to;
            }
        }
    }
    $pack['strings'] = (object) $pack['strings'];
    $pack['rich']    = (object) $pack['rich'];
    return $pack;
}

/** The language a page is drawn in: the person's own choice, then this
    browser's, then what the installation says, then English. */
function ups_lang_pick(?array $me, string $default): string
{
    $want = '';
    if ($me && isset($me['prefs']) && is_array($me['prefs'])) {
        $want = (string) ($me['prefs']['lang'] ?? '');
    }
    if ($want === '') {
        $want = (string) ($_COOKIE['upsmon_lang'] ?? '');
    }
    if ($want === '') {
        $want = $default;
    }
    $langs = ups_langs();
    return ($want !== '' && isset($langs[$want])) ? $want : 'en';
}

/** Answer `?api=lang` - one language's texts as a script - and stop. */
function ups_serve_lang(): void
{
    $code = (string) ($_GET['code'] ?? '');
    $pack = preg_match(UPS_LANG_CODE, $code) ? ups_lang_pack($code) : null;
    header('Content-Type: application/javascript; charset=utf-8');
    if ($pack === null) {
        header('Cache-Control: no-store');
        echo "/* no such language here: the page stays in English */\n";
        exit;
    }
    header('Cache-Control: private, max-age=31536000, immutable');
    header_remove('Pragma');
    echo 'window.OTP_LANG_PACK = '
        . json_encode($pack, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP
                             | JSON_UNESCAPED_SLASHES) . ";\n";
    exit;
}

/** The language list, English first. */
function ups_lang_list(): array
{
    $langs = ups_langs();
    $out = [isset($langs['en'])
        ? ['code' => 'en', 'name' => $langs['en']['name'], 'english' => $langs['en']['english']]
        : ['code' => 'en', 'name' => 'English', 'english' => 'English']];
    foreach ($langs as $one) {
        if ($one['code'] !== 'en') {
            $out[] = ['code' => $one['code'], 'name' => $one['name'], 'english' => $one['english']];
        }
    }
    return $out;
}

