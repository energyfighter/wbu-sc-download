<?php
/**
 * WBU Scorecard – Web-Version: kleiner Server für All-Inkl (PHP, ohne Datenbank).
 * Speichert jede Veranstaltung als JSON-Datei im Ordner "daten" (von außen gesperrt).
 *
 * Aktionen (POST, JSON):
 *   events      – heutige/aktuelle Veranstaltungen für die Punktrichter-Auswahl
 *   create      – Supervisor legt Veranstaltung an  -> id + Schlüssel
 *   push        – Scorecard oder Chat-Nachricht senden (Punktrichter; Supervisor-Chat mit Schlüssel)
 *   sup_pull    – Supervisor holt alle Scorecards + Nachrichten
 *   judge_pull  – Punktrichter holt seine Nachrichten
 *
 * Turnier-Anmeldung (WBU Sports + Seite /anmeldung/):
 *   t_publish   – Turnier veröffentlichen/ändern (neu: WBU-Passwort; ändern: Turnier-Schlüssel)
 *   t_list      – öffentlich: offene Turniere
 *   t_get       – öffentlich: ein Turnier
 *   t_register  – öffentlich: Sportler meldet sich an
 *   t_regs      – Veranstalter (Schlüssel): alle Anmeldungen
 *   t_paid      – Veranstalter: „bezahlt“ setzen/entfernen
 *   t_del       – Veranstalter: Anmeldung stornieren
 */
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
// WBU Sports darf auch als Datei vom Laptop aus zugreifen
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') exit;

// WBU-Supervisor-Passwort: steht als Prüfsumme in config.php (nur auf dem Server, nicht öffentlich)
$CFG = @include __DIR__ . '/config.php';
define('SUP_PASS_SHA256', is_array($CFG) && !empty($CFG['sup_pass_sha256']) ? $CFG['sup_pass_sha256'] : str_repeat('x', 64));

$DIR = __DIR__ . '/daten';
if (!is_dir($DIR)) {
    @mkdir($DIR, 0755, true);
}
if (!file_exists("$DIR/.htaccess")) {
    @file_put_contents("$DIR/.htaccess", "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
}

function out($a) { echo json_encode($a, JSON_UNESCAPED_UNICODE); exit; }
function fail($m, $c = 400) { http_response_code($c); out(['ok' => false, 'error' => $m]); }
function txt($s, $max = 200) { return mb_substr(trim((string)$s), 0, $max); }

$in = json_decode(file_get_contents('php://input'), true);
if (!is_array($in)) $in = [];
$a = $_GET['a'] ?? ($in['a'] ?? '');

function evfile($id) {
    global $DIR;
    if (!is_string($id) || !preg_match('/^[a-f0-9]{16}$/', $id)) fail('Veranstaltung unbekannt', 404);
    return "$DIR/ev_$id.json";
}

/** Veranstaltung gesperrt lesen (und optional ändern + speichern). */
function withEvent($id, $fn, $write = false) {
    $f = evfile($id);
    if (!file_exists($f)) fail('Veranstaltung nicht gefunden', 404);
    $h = fopen($f, 'c+');
    if (!$h) fail('Speicherfehler', 500);
    flock($h, $write ? LOCK_EX : LOCK_SH);
    $ev = json_decode(stream_get_contents($h), true);
    if (!is_array($ev)) { flock($h, LOCK_UN); fclose($h); fail('Datei beschädigt', 500); }
    $res = $fn($ev);
    if ($write) {
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, json_encode($ev, JSON_UNESCAPED_UNICODE));
        fflush($h);
    }
    flock($h, LOCK_UN);
    fclose($h);
    return $res;
}

function pinOk($ev, $pin) { return ($ev['pin'] ?? '') === '' || (string)$pin === (string)$ev['pin']; }


// ===================== Turnier-Anmeldung =====================
function tufile($id) {
    global $DIR;
    if (!is_string($id) || !preg_match('/^[a-f0-9]{16}$/', $id)) fail('Turnier unbekannt', 404);
    return "$DIR/tu_$id.json";
}
function withTurnier($id, $fn, $write = false) {
    $f = tufile($id);
    if (!file_exists($f)) fail('Turnier nicht gefunden', 404);
    $h = fopen($f, 'c+');
    if (!$h) fail('Speicherfehler', 500);
    flock($h, $write ? LOCK_EX : LOCK_SH);
    $t = json_decode(stream_get_contents($h), true);
    if (!is_array($t)) { flock($h, LOCK_UN); fclose($h); fail('Datei beschädigt', 500); }
    $res = $fn($t);
    if ($write) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($t, JSON_UNESCAPED_UNICODE)); fflush($h); }
    flock($h, LOCK_UN); fclose($h);
    return $res;
}
function tKeyOk($t, $key) { return is_string($key) && $key !== '' && hash_equals($t['key'], $key); }
// Öffentliche Angaben (ohne Schlüssel und ohne Anmeldedaten)
function tPublic($t) {
    $cnt = 0; foreach ($t['regs'] as $r) if (empty($r['storno'])) $cnt++;
    return ['id' => $t['id'], 'name' => $t['name'], 'ort' => $t['ort'], 'date' => $t['date'], 'promoter' => $t['promoter'],
            'schluss' => $t['schluss'], 'fee' => $t['fee'], 'inhaber' => $t['inhaber'], 'iban' => $t['iban'], 'bic' => $t['bic'],
            'info' => $t['info'], 'sports' => $t['sports'], 'open' => $t['open'], 'anz' => $cnt];
}
function tMeta(&$t, $m) {
    $t['name'] = txt($m['name'] ?? ''); $t['ort'] = txt($m['ort'] ?? ''); $t['promoter'] = txt($m['promoter'] ?? '');
    $t['date'] = preg_match('/^\d{4}-\d{2}-\d{2}$/', $m['date'] ?? '') ? $m['date'] : '';
    $t['schluss'] = preg_match('/^\d{4}-\d{2}-\d{2}$/', $m['schluss'] ?? '') ? $m['schluss'] : '';
    $t['fee'] = max(0, min(9999, round((float)str_replace(',', '.', (string)($m['fee'] ?? 0)), 2)));
    $t['inhaber'] = txt($m['inhaber'] ?? ''); $t['iban'] = txt(strtoupper(preg_replace('/\s+/', '', (string)($m['iban'] ?? ''))), 40);
    $t['bic'] = txt($m['bic'] ?? '', 20); $t['info'] = txt($m['info'] ?? '', 1500);
    $sp = array_values(array_intersect(['SP', 'K1', 'MB'], (array)($m['sports'] ?? [])));
    $t['sports'] = $sp ?: ['SP', 'K1', 'MB'];
    $t['open'] = !empty($m['open']);
}
function tOffen($t) {
    if (empty($t['open'])) return false;
    $bis = $t['schluss'] ?: $t['date'];
    return !$bis || date('Y-m-d') <= $bis;
}

switch ($a) {

case 'events':
    $list = [];
    foreach (glob("$DIR/ev_*.json") as $f) {
        $ev = json_decode(@file_get_contents($f), true);
        if (!is_array($ev)) continue;
        if (time() - ($ev['created'] ?? 0) > 48 * 3600) continue; // nur aktuelle (letzte 2 Tage)
        $list[] = ['id' => $ev['id'], 'name' => $ev['name'], 'ort' => $ev['ort'], 'date' => $ev['date'],
                   'sup' => $ev['sup'], 'pin' => ($ev['pin'] ?? '') !== '', 'created' => $ev['created']];
    }
    usort($list, function ($x, $y) { return $y['created'] - $x['created']; });
    out(['ok' => true, 'events' => $list]);

case 'auth':
    // Passwort prüfen, wenn eine bestehende Veranstaltung weitergeführt wird
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches Supervisor-Passwort', 403);
    out(['ok' => true]);

case 'create':
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches Supervisor-Passwort', 403);
    $id = bin2hex(random_bytes(8));
    $key = bin2hex(random_bytes(12));
    $pin = preg_replace('/\D/', '', (string)($in['pin'] ?? ''));
    $ev = ['id' => $id, 'key' => $key, 'name' => txt($in['name'] ?? ''), 'ort' => txt($in['ort'] ?? ''),
           'date' => txt($in['date'] ?? '', 20), 'sup' => txt($in['sup'] ?? ''), 'pin' => mb_substr($pin, 0, 8),
           'created' => time(), 'cards' => new stdClass(), 'msgs' => [], 'seen' => new stdClass()];
    if (file_put_contents(evfile($id), json_encode($ev, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
    out(['ok' => true, 'id' => $id, 'key' => $key]);

case 'push':
    $item = $in['item'] ?? null;
    if (!is_array($item) || empty($item['id'])) fail('Leere Sendung');
    withEvent($in['ev'] ?? '', function (&$ev) use ($in, $item) {
        $isSup = ($in['key'] ?? '') !== '' && hash_equals($ev['key'], (string)$in['key']);
        if (!$isSup && !pinOk($ev, $in['pin'] ?? '')) fail('Falsche PIN', 403);
        $item['srv'] = round(microtime(true) * 1000);
        if (($item['t'] ?? '') === 'msg') {
            if (($item['from'] ?? '') === 'sup' && !$isSup) fail('Nicht berechtigt', 403);
            if (!$isSup) $item['from'] = 'judge';
            $item['text'] = txt($item['text'] ?? '', 500);
            foreach ($ev['msgs'] as $m) if ($m['id'] === $item['id']) return;
            $ev['msgs'][] = $item;
            if (count($ev['msgs']) > 600) $ev['msgs'] = array_slice($ev['msgs'], -600);
        } else {
            $cards = (array)$ev['cards'];
            $old = $cards[$item['id']] ?? null;
            if ($old && ($old['rev'] ?? 0) > ($item['rev'] ?? 0)) return; // ältere Fassung ignorieren
            $cards[$item['id']] = $item;
            if (count($cards) > 400) $cards = array_slice($cards, -400, null, true);
            $ev['cards'] = $cards;
            $seen = (array)$ev['seen'];
            $seen[txt($item['judge'] ?? '')] = time();
            $ev['seen'] = $seen;
        }
    }, true);
    out(['ok' => true]);

case 'sup_pull':
    $r = withEvent($in['ev'] ?? '', function (&$ev) use ($in) {
        if (!hash_equals($ev['key'], (string)($in['key'] ?? ''))) fail('Nicht berechtigt', 403);
        $active = 0;
        foreach ((array)$ev['seen'] as $j => $t) if (time() - $t < 20) $active++;
        return ['cards' => array_values((array)$ev['cards']), 'msgs' => $ev['msgs'], 'judges' => $active];
    });
    out(['ok' => true] + $r);

case 'judge_pull':
    $judge = txt($in['judge'] ?? '');
    $r = withEvent($in['ev'] ?? '', function (&$ev) use ($in, $judge) {
        if (!pinOk($ev, $in['pin'] ?? '')) fail('Falsche PIN', 403);
        $seen = (array)$ev['seen'];
        $seen[$judge] = time();
        $ev['seen'] = $seen;
        $msgs = array_values(array_filter($ev['msgs'], function ($m) use ($judge) { return ($m['judge'] ?? '') === $judge; }));
        return ['msgs' => $msgs, 'name' => $ev['name'], 'sup' => $ev['sup']];
    }, true);
    out(['ok' => true] + $r);

case 't_publish':
    $m = $in['t'] ?? [];
    if (!is_array($m)) fail('Angaben fehlen');
    if (!empty($in['tid']) && file_exists(tufile($in['tid']))) {
        withTurnier($in['tid'], function (&$t) use ($in, $m) {
            if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
            tMeta($t, $m);
        }, true);
        out(['ok' => true, 'tid' => $in['tid'], 'key' => $in['key']]);
    }
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
    $t = ['id' => bin2hex(random_bytes(8)), 'key' => bin2hex(random_bytes(12)), 'created' => time(), 'regs' => [], 'nextNo' => 1];
    tMeta($t, $m);
    if (file_put_contents(tufile($t['id']), json_encode($t, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
    out(['ok' => true, 'tid' => $t['id'], 'key' => $t['key']]);

case 't_list':
    $list = [];
    foreach (glob("$DIR/tu_*.json") as $f) {
        $t = json_decode(@file_get_contents($f), true);
        if (!is_array($t) || empty($t['open'])) continue;
        if ($t['date'] && $t['date'] < date('Y-m-d', time() - 86400)) continue; // vorbei
        $p = tPublic($t); $p['offen'] = tOffen($t);
        $list[] = $p;
    }
    usort($list, function ($x, $y) { return strcmp($x['date'], $y['date']); });
    out(['ok' => true, 'turniere' => $list]);

case 't_get':
    $r = withTurnier($in['tid'] ?? '', function (&$t) { $p = tPublic($t); $p['offen'] = tOffen($t); return $p; });
    out(['ok' => true, 'turnier' => $r]);

case 't_register':
    $r = $in['r'] ?? null;
    if (!is_array($r)) fail('Angaben fehlen');
    if (!empty($r['website'])) out(['ok' => true, 'no' => 0]); // Spam-Falle
    $reg = ['vorname' => txt($r['vorname'] ?? '', 60), 'name' => txt($r['name'] ?? '', 60),
            'geb' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $r['geb'] ?? '') ? $r['geb'] : '',
            'sex' => ($r['sex'] ?? '') === 'w' ? 'w' : 'm', 'verein' => txt($r['verein'] ?? '', 100), 'land' => txt($r['land'] ?? '', 60),
            'trainer' => txt($r['trainer'] ?? '', 100), 'email' => txt($r['email'] ?? '', 120), 'tel' => txt($r['tel'] ?? '', 40),
            'sp' => txt($r['sp'] ?? '', 4), 'nr' => (int)($r['nr'] ?? 0), 'kg' => txt($r['kg'] ?? '', 8), 'klasse' => txt($r['klasse'] ?? '', 80),
            'bem' => txt($r['bem'] ?? '', 500)];
    if ($reg['vorname'] === '' || $reg['name'] === '' || $reg['geb'] === '') fail('Bitte Vorname, Name und Geburtsdatum angeben');
    if (!filter_var($reg['email'], FILTER_VALIDATE_EMAIL)) fail('Bitte eine gültige E-Mail-Adresse angeben');
    if ($reg['nr'] < 100 || $reg['nr'] > 999 || $reg['klasse'] === '') fail('Bitte eine Klasse wählen');
    $res = withTurnier($in['tid'] ?? '', function (&$t) use ($reg) {
        if (!tOffen($t)) fail('Die Anmeldung für dieses Turnier ist geschlossen', 403);
        if (!in_array($reg['sp'], $t['sports'], true)) fail('Diese Sportart wird bei diesem Turnier nicht angeboten');
        foreach ($t['regs'] as $x) {
            if (empty($x['storno']) && $x['nr'] === $reg['nr'] && $x['geb'] === $reg['geb']
                && mb_strtolower($x['name'] . $x['vorname']) === mb_strtolower($reg['name'] . $reg['vorname'])) fail('Dieser Sportler ist in dieser Klasse bereits angemeldet');
        }
        if (count($t['regs']) >= 3000) fail('Teilnehmerzahl erreicht', 403);
        $reg['id'] = bin2hex(random_bytes(6)); $reg['no'] = $t['nextNo']++; $reg['at'] = time(); $reg['paid'] = false;
        $t['regs'][] = $reg;
        return ['no' => $reg['no'], 'fee' => $t['fee'], 'inhaber' => $t['inhaber'], 'iban' => $t['iban'], 'bic' => $t['bic'], 'name' => $t['name']];
    }, true);
    out(['ok' => true] + $res);

case 't_regs':
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        return ['regs' => $t['regs'], 'turnier' => tPublic($t)];
    });
    out(['ok' => true] + $r);

case 't_paid':
case 't_del':
    withTurnier($in['tid'] ?? '', function (&$t) use ($in, $a) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        foreach ($t['regs'] as &$x) if ($x['id'] === ($in['rid'] ?? '')) {
            if ($a === 't_paid') $x['paid'] = !empty($in['paid']); else $x['storno'] = !empty($in['storno']);
            return;
        }
        fail('Anmeldung nicht gefunden', 404);
    }, true);
    out(['ok' => true]);

default:
    fail('Unbekannte Aktion');
}
