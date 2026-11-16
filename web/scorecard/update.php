<?php
/**
 * WBU – Selbst-Update für die Web-Programme (Scorecard + WBU Sports).
 * Holt neue Versionen aus dem öffentlichen GitHub-Bereich energyfighter/wbu-sc-download
 * und ersetzt NUR die fest eingetragenen Dateien. Prüft jede Datei per SHA-256.
 *
 * Aufruf (Cronjob oder Browser):  https://www.wbu-boxing.com/scorecard/update.php?key=GEHEIMER-SCHLÜSSEL
 * Der Schlüssel steht in config.php (liegt nur auf dem Server, wird nie überschrieben).
 */
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

$cfg = @include __DIR__ . '/config.php';
if (!is_array($cfg) || empty($cfg['update_key'])) { http_response_code(500); exit("config.php fehlt\n"); }
if (!hash_equals($cfg['update_key'], (string)($_GET['key'] ?? ''))) { http_response_code(403); exit("Nicht berechtigt\n"); }

// Bei jedem Cronjob-Lauf: Zahlungserinnerungen nach Anmeldeschluss verschicken (Aufgabe steckt in api.php)
$host = preg_replace('/[^a-z0-9.\-:]/i', '', $_SERVER['HTTP_HOST'] ?? '');
if ($host !== '') {
    $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $c = @json_decode((string)@file_get_contents("$proto://$host" . dirname($_SERVER['SCRIPT_NAME']) . '/api.php?a=cron&key=' . urlencode($cfg['update_key']),
        false, stream_context_create(['http' => ['timeout' => 20], 'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]])), true);
    if (!empty($c['sent'])) echo "Zahlungserinnerungen verschickt: {$c['sent']}\n";
}

$BASE = 'https://raw.githubusercontent.com/energyfighter/wbu-sc-download/main/web/';
$WEBROOT = dirname(__DIR__);                      // Ordner, in dem "scorecard" liegt
// Nur diese Dateien dürfen ersetzt werden (Ziel relativ zum Webroot)
$ALLOWED = [
    'scorecard/index.html', 'scorecard/api.php', 'scorecard/manifest.json', 'scorecard/icon-192.png', 'scorecard/.htaccess',
    'veranstalter/index.html', 'veranstalter/.htaccess',
    'anmeldung/index.html', 'anmeldung/.htaccess', 'scorecard/update.php',
    'live/index.html', 'live/.htaccess',
    'veranstalter/pdf.min.js', 'veranstalter/pdf.worker.min.js',
];

function fetch($url) {
    $url .= (strpos($url, '?') === false ? '?' : '&') . 't=' . time();
    if (function_exists('curl_init')) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 30,
                               CURLOPT_USERAGENT => 'WBU-Updater']);
        $d = curl_exec($c);
        $code = curl_getinfo($c, CURLINFO_HTTP_CODE);
        curl_close($c);
        return $code === 200 ? $d : false;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 30, 'header' => "User-Agent: WBU-Updater\r\n"]]);
    return @file_get_contents($url, false, $ctx);
}

$manifest = fetch($BASE . 'version.json');
$m = json_decode((string)$manifest, true);
if (!is_array($m) || empty($m['version']) || empty($m['files'])) exit("GitHub nicht erreichbar oder version.json fehlerhaft\n");

$localFile = __DIR__ . '/webversion.json';
$local = json_decode((string)@file_get_contents($localFile), true);
$have = (int)($local['version'] ?? 0);
if ($have >= (int)$m['version'] && !isset($_GET['force'])) exit("Aktuell (Version $have)\n");

// 1. alles laden und prüfen, 2. erst dann ersetzen
$new = []; $skipped = [];
foreach ($m['files'] as $target => $sha) {
    if (!in_array($target, $ALLOWED, true)) { $skipped[] = $target; continue; }
    $data = fetch($BASE . $target);
    if ($data === false) exit("Abbruch: $target konnte nicht geladen werden\n");
    if (!hash_equals($sha, hash('sha256', $data))) exit("Abbruch: Prüfsumme falsch bei $target\n");
    $new[$target] = $data;
}
foreach ($new as $target => $data) {
    $path = $WEBROOT . '/' . $target;
    if (!is_dir(dirname($path))) @mkdir(dirname($path), 0755, true);
    $tmp = $path . '.neu';
    if (file_put_contents($tmp, $data) === false || !rename($tmp, $path)) exit("Abbruch: $target konnte nicht geschrieben werden\n");
}
file_put_contents($localFile, json_encode(['version' => (int)$m['version'], 'at' => date('c')]));
// Die geöffneten Seiten fragen diese Datei ab und zeigen dann „Neue Version – neu laden“
@file_put_contents($WEBROOT . '/scorecard/webversion.json', json_encode(['version' => (int)$m['version']]));
@file_put_contents($WEBROOT . '/veranstalter/webversion.json', json_encode(['version' => (int)$m['version']]));
@file_put_contents($WEBROOT . '/anmeldung/webversion.json', json_encode(['version' => (int)$m['version']]));
echo "Aktualisiert auf Version {$m['version']} (" . count($new) . " Dateien)\n";
