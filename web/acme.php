<?php
/* acme.php - the answer to an ACME CA's HTTP-01 challenge (1.0.169).
   nginx sends http://NAME/.well-known/acme-challenge/TOKEN here, on port 80;
   the answer is kept in upsmon's database, so whichever node the CA reaches -
   the one with the web address, in a cluster - gives it. Nothing else is
   said, so anybody may ask. */
declare(strict_types=1);
require_once __DIR__ . '/settings-api.php';
header('Cache-Control: no-store');
$uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
if (!preg_match('#^/\.well-known/acme-challenge/([A-Za-z0-9_-]{8,256})$#', $uri, $m)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}
$got = ups_get('/api/acme/challenge?token=' . $m[1], 10.0);
if (!is_array($got) || !isset($got['auth']) || !is_string($got['auth'])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}
header('Content-Type: application/octet-stream');
echo $got['auth'];
