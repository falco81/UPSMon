<?php
/**
 * acme-push.php — acme push, protocol 1 (upsmon 4.3.0): the four requests of
 * acme, the certificate manager, handed to the daemon as they came.
 *
 *   GET  ?api=acme-push-hello                    who this is, its keys
 *   POST ?api=acme-push-(pair|inventory|install)  signed by acme (Ed25519)
 *
 * This page decides nothing and keeps nothing: the raw body (BASE64, byte for
 * byte - the signature covers it) and the five X-Acme-Push-* headers go to the
 * daemon on localhost with its token; its answer comes back as it is. No
 * session and no CSRF check: nothing a browser can be made to send carries a
 * valid signature. The access list of the pages (nginx allow) still applies.
 */
declare(strict_types=1);

require_once __DIR__ . '/settings-api.php';

function ups_acme_push_answer(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function ups_acme_push_serve(string $what): void
{
    if (!preg_match('/^acme-push-(hello|pair|inventory|install)$/', $what, $m)) {
        return;
    }
    $op = $m[1];
    $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if ($op === 'hello') {
        if ($method !== 'GET') {
            ups_acme_push_answer(405, ['ok' => false, 'code' => 'bad_request', 'error' => 'hello is a GET']);
        }
        [$status, $reply] = ups_call('/api/acme-push/hello', 'GET', null, 20.0);
    } else {
        if ($method !== 'POST') {
            ups_acme_push_answer(405, ['ok' => false, 'code' => 'bad_request', 'error' => $op . ' is a POST']);
        }
        if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 1048576) {
            ups_acme_push_answer(413, ['ok' => false, 'code' => 'too_big', 'error' => 'more than 1 MiB']);
        }
        $raw = (string) @file_get_contents('php://input', false, null, 0, 1048577);
        if (strlen($raw) > 1048576) {
            ups_acme_push_answer(413, ['ok' => false, 'code' => 'too_big', 'error' => 'more than 1 MiB']);
        }
        $heads = [];
        foreach (['Version', 'Key', 'Time', 'Nonce', 'Signature'] as $name) {
            $heads[$name] = substr((string) ($_SERVER['HTTP_X_ACME_PUSH_' . strtoupper($name)] ?? ''), 0, 300);
        }
        [$status, $reply] = ups_call('/api/acme-push/' . $op, 'POST',
                                     ['body' => base64_encode($raw), 'headers' => $heads], 120.0);
    }
    if ($status === 0 || $reply === '' || !is_array(json_decode($reply, true))) {
        ups_acme_push_answer(503, ['ok' => false, 'code' => 'down',
                                   'error' => 'the page cannot reach the upsmon daemon']);
    }
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo $reply;
    exit;
}
