<?php
/**
 * upsmon-upgrading.php — how far an upgrade is, read straight from the disk (4.8.0).
 *
 * During an upgrade the daemon, its API, nginx and PHP restart. Whoever does the
 * upgrade - the root helper upsmon-upgrade, and install.sh --upgrade itself,
 * also when it is run by hand - writes how far it is into .upgrade.json beside
 * these pages: root's, 0644, written to a temporary file and renamed, nothing
 * secret in it, and never served (nginx: location ~ /\. { deny all; }).
 *
 * The pages read it here, not through the daemon, so that they can say "being
 * upgraded" while the daemon is not answering, instead of "not answering".
 * Included, never a page of its own.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

if (!defined('UPS_UPGRADE_FILE')) {
    define('UPS_UPGRADE_FILE', __DIR__ . '/.upgrade.json');
    /* How long each state is believed after it was written: running longer
       than install.sh may take, done and failed as long as a page may take to
       see them. Older, or written in the future: as if there were no file. */
    define('UPS_UPGRADE_RUNNING_S', 1800);
    define('UPS_UPGRADE_ENDED_S', 600);
}

/** One line of text from the file: no control characters, cut to $most. */
function ups_upgrade_line($v, int $most): string
{
    if (!is_string($v) && !is_int($v) && !is_float($v)) {
        return '';
    }
    $v = (string) $v;
    if (@preg_match('//u', $v) !== 1) {
        return '';                          /* not UTF-8 */
    }
    $v = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v);
    /* Cut by characters, without mbstring (not every PHP here has it). */
    if (preg_match('/^.{0,' . $most . '}/us', $v, $m)) {
        $v = $m[0];
    }
    return trim($v);
}

/** The file as it is, checked, or null - read once per request. */
function ups_upgrade_read(): ?array
{
    static $got = false;
    if ($got !== false) {
        return $got;
    }
    $got = null;
    $f = UPS_UPGRADE_FILE;
    clearstatcache(true, $f);
    if (!is_file($f) || is_link($f) || !is_readable($f)) {
        return null;
    }
    $size = @filesize($f);
    if ($size === false || $size < 2 || $size > 16384) {
        return null;
    }
    /* Root's alone: only root writes beside the pages. */
    $owner = @fileowner($f);
    if ($owner !== 0 && $owner !== @fileowner(__DIR__)) {
        return null;
    }
    $j = json_decode((string) @file_get_contents($f), true);
    if (!is_array($j)) {
        return null;
    }
    $state = (string) ($j['state'] ?? '');
    if (!in_array($state, ['running', 'done', 'failed'], true)) {
        return null;
    }
    $at = is_numeric($j['at'] ?? null) ? (float) $j['at'] : 0.0;
    $now = microtime(true);
    $keep = $state === 'running' ? UPS_UPGRADE_RUNNING_S : UPS_UPGRADE_ENDED_S;
    if ($at <= 0 || $at > $now + 60 || $now - $at > $keep) {
        return null;
    }
    $ver = function ($v): string {
        $v = is_string($v) ? $v : '';
        return preg_match('/^[0-9]+(\.[0-9]+){0,3}$/', $v) ? $v : '';
    };
    $parts = max(0, min(99, (int) ($j['parts'] ?? 0)));
    $part  = max(0, min(99, (int) ($j['part'] ?? 0)));
    $started = is_numeric($j['started'] ?? null) ? (float) $j['started'] : $at;
    if ($started <= 0 || $started > $at + 60) {
        $started = $at;
    }
    $id = is_string($j['id'] ?? null) && preg_match('/^[A-Za-z0-9._:-]{1,64}$/', $j['id']) ? $j['id'] : '';
    $got = [
        'state'     => $state,
        'id'        => $id,
        'version'   => $ver($j['version'] ?? ''),
        'from'      => $ver($j['from'] ?? ''),
        'by'        => ups_upgrade_line($j['by'] ?? '', 100),
        'part'      => $part,
        'parts'     => max($parts, $part),
        'words'     => ups_upgrade_line($j['words'] ?? '', 120),
        'started'   => (int) $started,
        'at'        => (int) $at,
        'now'       => (int) $now,
        'said'      => ups_upgrade_line($j['said'] ?? '', 300),
        'downgrade' => ($j['downgrade'] ?? false) === true,
    ];
    return $got;
}

/**
 * How far an upgrade is, for the pages, or null when none runs or ended a
 * short while ago. Who asked for it, what went wrong and its id only for a
 * page that has a session ($full) - the rest is what the dashboard shows
 * everybody anyway (the version going in, a step, a bar).
 */
function ups_upgrading(bool $full = false): ?array
{
    $u = ups_upgrade_read();
    if ($u === null) {
        return null;
    }
    if (!$full) {
        unset($u['by'], $u['said'], $u['id']);
    }
    return $u;
}

/**
 * The record of an upgrade running now, without who asked or why (4.9.1) - what answers
 * "being upgraded" while the daemon is away. A done or failed one does not: a daemon that is
 * down after an upgrade ended is down, and said so.
 */
function ups_upgrading_running(): ?array
{
    $u = ups_upgrading(false);
    return ($u !== null && $u['state'] === 'running') ? $u : null;
}

/**
 * A "running" left behind (4.9.1): the machine restarted, or the helper was killed, in the
 * middle of one - nothing wrote it failed. The daemon started well after the last step was
 * written (its uptime says when), while install.sh writes done within moments of starting it.
 */
function ups_upgrade_live(?array $u, $health): ?array
{
    if ($u === null || $u['state'] !== 'running' || !is_array($health) || !is_numeric($health['uptime'] ?? null)) {
        return $u;
    }
    $started = microtime(true) - (float) $health['uptime'];
    return ($started - (float) $u['at'] > 180) ? null : $u;
}

/** The 503 every relayed call answers while the daemon is away during an upgrade. */
function ups_upgrade_503(array $u): void
{
    if (!headers_sent()) {
        http_response_code(503);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('Retry-After: 2');
    }
    echo json_encode(['ok' => false, 'upgrading' => $u, 'error' => 'being upgraded'],
                     JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}
