<?php
/**
 * upsmon-api.php — the page's side of the daemon API.
 *
 * index.php collects nothing itself. The daemon does all the work and exposes
 * it on http://127.0.0.1:<port>; this file is the thin client that talks to it.
 * Read endpoints are open; the two that change something (running a command,
 * writing a variable) send the token the daemon dropped in a file readable only
 * by root and the web server's group.
 *
 * The browser never sees the token, and the web user holds no upsd credentials
 * — the daemon owns those and is the only thing that talks to the UPS.
 */
declare(strict_types=1);

const UPSMON_HOST  = '127.0.0.1';
const UPSMON_PORT  = 9848;
const UPSMON_TOKEN = '/run/upsmon/api-token';

/** Read the API token the daemon wrote for us, or null if we can't. */
function upsmon_token(): ?string
{
    if (!is_readable(UPSMON_TOKEN)) {
        return null;
    }
    $token = trim((string) @file_get_contents(UPSMON_TOKEN));
    return $token !== '' ? $token : null;
}

/**
 * Call the daemon. Returns [status, body-string]; status 0 means unreachable.
 * $payload, when given, is sent as a JSON body and turns this into a POST.
 */
function upsmon_call(string $path, string $method = 'GET', ?array $payload = null,
                     float $timeout = 10.0): array
{
    $headers = ['Accept: application/json'];
    $body    = null;

    if ($payload !== null) {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Content-Length: ' . strlen($body);
    }
    if ($method !== 'GET') {
        $token = upsmon_token();
        if ($token === null) {
            return [0, ''];
        }
        $headers[] = 'X-Upsmon-Token: ' . $token;
        if ($body === null) {
            $headers[] = 'Content-Length: 0';
        }
    }

    /* A socket spoken to by hand (4.0), as the Settings pages do: the pool
       of these pages has allow_url_fopen off, and file_get_contents('http://')
       would fail silently and say the daemon is not answering. The daemon
       always sends a Content-Length and never chunks. */
    $sock = @stream_socket_client('tcp://' . UPSMON_HOST . ':' . UPSMON_PORT, $errno, $errstr,
                                  $timeout, STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) ceil($timeout));
    $request = $method . ' ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . UPSMON_HOST . ':' . UPSMON_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n"
        . ($body ?? '');
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
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', substr($raw, 0, $split), $m)) {
        $status = (int) $m[1];
    }
    return [$status, (string) substr($raw, $split + 4)];
}

/** Call the daemon and return the decoded reply, or null. */
function upsmon_get(string $path, float $timeout = 10.0): ?array
{
    [$status, $body] = upsmon_call($path, 'GET', null, $timeout);
    if ($status !== 200) {
        return null;
    }
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

/** Pass a daemon reply straight through to the browser. */
function upsmon_relay(string $path, string $method = 'GET', ?array $payload = null,
                      float $timeout = 10.0): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if ($method !== 'GET' && upsmon_token() === null) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' =>
            'the API token is unreadable — is upsmon.service running, and is '
            . UPSMON_TOKEN . ' readable by the web server?']);
        return;
    }

    [$status, $body] = upsmon_call($path, $method, $payload, $timeout);
    if ($status === 0) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' =>
            'the monitoring daemon is not responding — is upsmon.service running?']);
        return;
    }
    http_response_code($status);
    echo $body;
}
