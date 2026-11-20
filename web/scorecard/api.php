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
 *
 * Live (WBU Sports ↔ Live-Seite ↔ Scorecard):
 *   l_create    – Live schalten (WBU-Passwort) -> lid + Schlüssel
 *   l_push      – WBU Sports schickt den aktuellen Stand (Kampfliste)
 *   l_pull      – WBU Sports holt die Ergebnisse vom Supervisor
 *   l_get       – öffentlich: Stand für Live-Seite / Fernseher
 *   l_list      – öffentlich: laufende Live-Veranstaltungen
 */
date_default_timezone_set('Europe/Berlin');
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
// Veranstalter-Passwort (Windows-Programm / Tablet-App: Veranstaltung erstellen und hochladen) – nur als bcrypt-Prüfsumme; config.php kann es ersetzen
define('ORG_PASS_HASH', is_array($CFG) && !empty($CFG['org_pass_hash']) ? $CFG['org_pass_hash'] : '$2y$12$mu3hUCOpiBNobm4ewm0nBOyEACcTuLKhmO5KkkRJ/gBfiBIuPcukC');
function orgPassOk($p) { $p = (string)$p; return $p !== '' && (hash_equals(SUP_PASS_SHA256, hash('sha256', $p)) || password_verify($p, ORG_PASS_HASH)); }
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
    $cnt = 0; $pers = []; $clubs = [];
    foreach ($t['regs'] as $r) if (regIn($t, $r)) {
        $cnt++; $pers[mb_strtolower($r['vorname'] . '|' . $r['name'] . '|' . $r['geb'])] = 1;
        if (trim($r['verein']) !== '') $clubs[mb_strtolower(trim($r['verein']))] = 1;
    }
    return ['id' => $t['id'], 'name' => $t['name'], 'ort' => $t['ort'], 'date' => $t['date'], 'promoter' => $t['promoter'],
            'schluss' => $t['schluss'], 'fee' => $t['fee'], 'inhaber' => $t['inhaber'], 'iban' => $t['iban'], 'bic' => $t['bic'],
            'info' => $t['info'], 'sports' => $t['sports'], 'open' => $t['open'], 'anz' => $cnt, 'pers' => count($pers), 'clubs' => count($clubs), 'docs' => $t['docs'] ?? new stdClass(),
            'feeMore' => $t['feeMore'] ?? 0, 'attest' => !empty($t['attest']), 'grace' => $t['grace'] ?? 3, 'rings' => $t['rings'] ?? 1, 'locked' => !empty($t['listpw'])];
}
function tMeta(&$t, $m) {
    $t['name'] = txt($m['name'] ?? ''); $t['ort'] = txt($m['ort'] ?? ''); $t['promoter'] = txt($m['promoter'] ?? '');
    $t['date'] = preg_match('/^\d{4}-\d{2}-\d{2}$/', $m['date'] ?? '') ? $m['date'] : '';
    $t['schluss'] = preg_match('/^\d{4}-\d{2}-\d{2}$/', $m['schluss'] ?? '') ? $m['schluss'] : '';
    $t['fee'] = max(0, min(9999, round((float)str_replace(',', '.', (string)($m['fee'] ?? 0)), 2)));
    $t['feeMore'] = max(0, min(9999, round((float)str_replace(',', '.', (string)($m['feeMore'] ?? 0)), 2)));
    $t['attest'] = !empty($m['attest']);
    $t['rings'] = (int)($m['rings'] ?? 1) === 2 ? 2 : 1;
    $t['grace'] = max(1, min(14, (int)($m['grace'] ?? 3)));
    // Fristen offener Anmeldungen an Anmeldeschluss/Nachfrist anpassen (außer schon gemahnte)
    foreach (($t['orders'] ?? []) as $k => $o) if (empty($o['reminded']) && empty($o['paid'])) $t['orders'][$k]['due'] = dueTs($t, $o['created']);
    if (array_key_exists('listpw', $m)) $t['listpw'] = trim((string)$m['listpw']) === '' ? '' : hash('sha256', trim((string)$m['listpw']));
    $t['inhaber'] = txt($m['inhaber'] ?? ''); $t['iban'] = txt(strtoupper(preg_replace('/\s+/', '', (string)($m['iban'] ?? ''))), 40);
    $t['bic'] = txt($m['bic'] ?? '', 20); $t['info'] = txt($m['info'] ?? '', 1500);
    $sp = array_values(array_intersect(['SP', 'K1', 'MB', 'SB'], (array)($m['sports'] ?? [])));
    $t['sports'] = $sp ?: ['SP', 'K1', 'MB', 'SB'];
    $t['open'] = !empty($m['open']);
}
function tOffen($t) {
    if (empty($t['open'])) return false;
    $bis = $t['schluss'] ?: $t['date'];
    return !$bis || date('Y-m-d') <= $bis;
}


// ===================== Kämpfer-Datenbank (geschlossen: nur Veranstalter, Supervisor, WBU) =====================
function kFile() { global $DIR; return "$DIR/kaempfer.json"; }
function kNorm($s) { return mb_strtolower(preg_replace('/\s+/u', ' ', trim((string)$s))); }
function withKaempfer($fn) {
    $neu = !file_exists(kFile());
    $h = fopen(kFile(), 'c+'); if (!$h) fail('Speicherfehler', 500);
    flock($h, LOCK_EX);
    $k = json_decode(stream_get_contents($h), true); if (!is_array($k)) $k = [];
    if ($neu && !$k) kBackfill($k);
    $res = $fn($k);
    ftruncate($h, 0); rewind($h); fwrite($h, json_encode($k, JSON_UNESCAPED_UNICODE)); fflush($h);
    flock($h, LOCK_UN); fclose($h);
    return $res;
}
/** Einen Kämpfer eintragen oder ergänzen. Der Name ist eindeutig (mit Geburtsdatum, wenn bekannt). */
function kPut(&$k, $x, $src) {
    $vn = txt($x['vn'] ?? '', 60); $nn = txt($x['nn'] ?? '', 60); $full = txt($x['name'] ?? '', 120);
    if ($full === '') $full = trim("$vn $nn");
    if (mb_strlen($full) < 3 || !preg_match('/\p{L}/u', $full)) return;
    $geb = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($x['geb'] ?? '')) ? $x['geb'] : '';
    $n = kNorm($full); $key = null;
    foreach ($k as $id => $o) if (kNorm($o['name']) === $n && ($geb === '' || ($o['geb'] ?? '') === '' || $o['geb'] === $geb)) { $key = $id; break; }
    if ($key === null) { $key = substr(hash('sha256', $n . '|' . $geb . '|' . microtime()), 0, 12); $k[$key] = ['name' => $full, 'vn' => $vn, 'nn' => $nn, 'geb' => $geb, 'first' => time(), 'n' => 0, 'src' => []]; }
    $o = &$k[$key];
    foreach (['vn' => 60, 'nn' => 60, 'sex' => 2, 'gym' => 100, 'land' => 60, 'kg' => 8, 'sp' => 4, 'klasse' => 80, 'trainer' => 100] as $f => $max) {
        $v = txt($x[$f] ?? '', $max); if ($v !== '' && $v !== '–') $o[$f] = $v;
    }
    $kg = txt($x['kg'] ?? '', 8); if ($kg !== '' && is_numeric(str_replace(',', '.', $kg))) { $h = $o['kgh'] ?? []; $last = end($h);
        if (!$last || $last['kg'] !== $kg || $last['d'] !== date('Y-m-d')) $h[] = ['d' => date('Y-m-d'), 'kg' => $kg, 'src' => $src]; $o['kgh'] = array_slice($h, -40); }
    if ($geb !== '') $o['geb'] = $geb;
    if (!in_array($src, $o['src'], true)) { $o['src'] = array_slice(array_merge($o['src'], [$src]), -30); $o['n'] = count($o['src']); }
    $o['at'] = time();
}
function kFromReg($r) {
    return ['vn' => $r['vorname'] ?? '', 'nn' => $r['name'] ?? '', 'name' => trim(($r['vorname'] ?? '') . ' ' . ($r['name'] ?? '')), 'geb' => $r['geb'] ?? '', 'sex' => in_array($r['sex'] ?? '', ['m', 'w'], true) ? $r['sex'] : '',
            'gym' => $r['verein'] ?? '', 'land' => $r['land'] ?? '', 'kg' => $r['kg'] ?? '', 'sp' => $r['sp'] ?? '', 'klasse' => $r['klasse'] ?? '', 'trainer' => $r['trainer'] ?? ''];
}
/** Beim ersten Mal: alle bisherigen Turnier-Anmeldungen und Galas übernehmen */
function kBackfill(&$k) {
    global $DIR;
    foreach (glob("$DIR/tu_*.json") as $f) { $t = json_decode((string)@file_get_contents($f), true); if (!is_array($t)) continue;
        foreach (($t['regs'] ?? []) as $r) if (empty($r['storno'])) kPut($k, kFromReg($r), 't:' . $t['id']); }
    foreach (glob("$DIR/lv_*.json") as $f) { $l = json_decode((string)@file_get_contents($f), true); if (!is_array($l) || empty($l['snap']) || ($l['snap']['type'] ?? '') !== 'gala') continue;
        foreach (($l['snap']['rows'] ?? []) as $row) { $x = $row['f'] ?? null; if (!is_array($x)) continue;
            foreach (['r', 'b'] as $s) kPut($k, ['name' => $x[$s === 'r' ? 'red' : 'blue'] ?? '', 'land' => $x[$s . 'l'] ?? '', 'geb' => $x[$s . 'g'] ?? '', 'kg' => $x[$s . 'w'] ?? '', 'gym' => $x[$s . 'v'] ?? '', 'klasse' => $x['cls'] ?? ''], 'l:' . $l['id']); } }
}
/** Wer darf die Datenbank sehen? Veranstalter- und Supervisor-Konten sowie das WBU-Passwort (Superadmin) */
function kAllowed($in) {
    if (hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) return true;
    $me = clubByToken($in['tok'] ?? '');
    return $me && in_array($me['rolle'], ['veranstalter', 'sup'], true);
}

// ===================== Kampfbilanz, Titel, K.O.-Sperre (nur in WBU Sports, nicht öffentlich) =====================
const K_ARTEN = ['Profi', 'Semi-Pro', 'Master', 'K1', 'Bare Knuckle', 'Hybrid'];
const K_SPERRE = ['KO' => 90, 'TKO' => 30];   // Tage; RTD (Aufgabe) = keine Sperre
function kArt($txt, $default) {
    $t = mb_strtolower((string)$txt);
    if (preg_match('/bare|knuckle/', $t)) return 'Bare Knuckle';
    if (strpos($t, 'hybrid') !== false) return 'Hybrid';
    if (preg_match('/k1|k-1|kick/', $t)) return 'K1';
    if (strpos($t, 'master') !== false) return 'Master';
    if (strpos($t, 'semi') !== false) return 'Semi-Pro';
    if (strpos($t, 'profi') !== false || strpos($t, 'pro') === 0) return 'Profi';
    return $default;
}
function kTs($d) { $d = (string)$d; if (preg_match('/^(\d{2})\.(\d{2})\.(\d{4})$/', $d, $m)) $d = "$m[3]-$m[2]-$m[1]"; return strtotime(substr($d, 0, 10)) ?: 0; }
define('TTS_VOICES', ['Fenrir','Algenib','Orus','Alnilam','Charon','Iapetus','Umbriel','Puck','Enceladus','Rasalgethi','Sadaltager','Schedar','Achird','Algieba','Zubenelgenubi']);
function ttsCfg() { global $DIR; $c = json_decode((string)@file_get_contents("$DIR/tts_cfg.json"), true); return ['voice' => (is_array($c) && in_array($c['voice'] ?? '', TTS_VOICES, true)) ? $c['voice'] : 'Fenrir', 'rate' => is_array($c) && isset($c['rate']) ? (float)$c['rate'] : 0.9, 'pitch' => is_array($c) && isset($c['pitch']) ? (float)$c['pitch'] : 1.0, 'nrate' => is_array($c) && isset($c['nrate']) ? (float)$c['nrate'] : 0.75, 'npitch' => is_array($c) && isset($c['npitch']) ? (float)$c['npitch'] : null, 'vowel' => is_array($c) && !empty($c['vowel'])]; }
function ttsKey() { global $DIR, $CFG; $k = is_array($CFG) ? (string)($CFG['gtts_key'] ?? '') : ''; if ($k === '') $k = trim((string)@file_get_contents("$DIR/tts_key.txt")); return $k; }
function kIsSuper($in) { if (hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) return true; return isSuper(clubByToken($in['tok'] ?? '')); }
/** Alle Kämpfe aus den Resultaten (auch alte, importierte) je Name: Art, Ergebnis, K.O., Titel */
function kResIndex() {
    global $DIR; static $IX = null; if ($IX !== null) return $IX;
    $IX = ['f' => [], 't' => []]; $seen = []; $lvk = [];
    foreach (glob("$DIR/res_*.json") as $f) {
        $r = json_decode((string)@file_get_contents($f), true); if (!is_array($r) || !empty($r['hidden'])) continue;
        $ts = kTs($r['date'] ?? '') ?: (int)($r['at'] ?? 0); $ev = trim(($r['name'] ?: 'Veranstaltung') . ' · ' . ($r['ort'] ?? ''), ' ·');
        $def = ($r['type'] ?? '') === 'turnier' ? 'Semi-Pro' : 'Profi';
        $lid = (string)($r['lid'] ?? '');
        if ($lid !== '' && !isset($lvk[$lid])) { $lvk[$lid] = []; $l = json_decode((string)@file_get_contents(lvfile($lid)), true);
            foreach ((array)($l['snap']['rows'] ?? []) as $row) $lvk[$lid][kNorm($row['a'] ?? '') . '|' . kNorm($row['b'] ?? '')] = (string)(($row['kind'] ?? '') ?: ($row['kl'] ?? '')); }
        foreach ((array)($r['fights'] ?? []) as $x) {
            $red = trim((string)($x['red'] ?? '')); $blue = trim((string)($x['blue'] ?? '')); $k = (string)($x['k'] ?? '');
            if ($red === '' || $blue === '' || $k === '' || $k === 'NC') continue;
            $key = ($r['grp'] ?? '') . '|' . kNorm($red) . '|' . kNorm($blue); if (isset($seen[$key])) continue; $seen[$key] = 1;
            $art = kArt(($x['art'] ?? '') . ' ' . ($lvk[$lid][kNorm($red) . '|' . kNorm($blue)] ?? '') . ' ' . ($x['title'] ?? ''), $def);
            $draw = in_array($k, ['UDRAW', 'SDRAW', 'MDRAW', 'TDRAW'], true); $w = (string)($x['w'] ?? '');
            if (!$draw && !in_array($w, ['R', 'B'], true)) continue;
            foreach (['R' => [$red, $blue], 'B' => [$blue, $red]] as $side => [$me, $geg]) {
                $res = $draw ? 'D' : ($w === $side ? 'W' : 'L');
                $IX['f'][kNorm($me)][] = ['name' => $me, 'ts' => $ts, 'date' => date('Y-m-d', $ts), 'ev' => $ev, 'geg' => $geg, 'art' => $art, 'res' => $res, 'k' => $k, 'ko' => in_array($k, ['KO', 'TKO'], true), 'r' => (int)($x['r'] ?? 0), 'title' => (string)($x['title'] ?? ''), 'id' => $key];
                if ($res === 'W' && preg_match('/meister|champion|titel|title|wm\b|em\b|dm\b|world|europ|international|cup|gürtel|belt/i', (string)($x['title'] ?? '')))
                    $IX['t'][kNorm($me)][] = ['t' => trim($x['title']) . ' (' . $art . ')', 'j' => date('Y', $ts), 'ext' => 0, 'auto' => 1, 'ev' => $ev];
            }
        }
        foreach ((array)($r['places'] ?? []) as $p) if (!empty($p['first']['n']))   // Turnier: 1. Platz = Titel
            $IX['t'][kNorm($p['first']['n'])][] = ['t' => 'Sieger ' . ($p['kl'] ?? '') . ' – ' . ($r['name'] ?? ''), 'j' => date('Y', $ts), 'ext' => 0, 'auto' => 1, 'ev' => $ev];
    }
    return $IX;
}
function kLeer() { return ['w' => 0, 'wko' => 0, 'l' => 0, 'lko' => 0, 'd' => 0]; }
/** Bilanz, Sperre und Titel eines Kämpfers */
function kProfil($id, $x) {
    $IX = kResIndex(); $n = kNorm($x['name'] ?? ''); $fs = $IX['f'][$n] ?? [];
    usort($fs, function ($a, $b) { return $b['ts'] - $a['ts']; });
    $rec = [];
    foreach ($fs as $f) { $a = $f['art']; $rec[$a] = $rec[$a] ?? ['auto' => kLeer(), 'ext' => kLeer()];
        if ($f['res'] === 'W') { $rec[$a]['auto']['w']++; if ($f['ko']) $rec[$a]['auto']['wko']++; }
        elseif ($f['res'] === 'L') { $rec[$a]['auto']['l']++; if ($f['ko']) $rec[$a]['auto']['lko']++; }
        else $rec[$a]['auto']['d']++; }
    foreach ((array)($x['rec'] ?? []) as $a => $v) { $rec[$a] = $rec[$a] ?? ['auto' => kLeer(), 'ext' => kLeer()]; $rec[$a]['ext'] = array_merge(kLeer(), array_map('intval', (array)$v)); }
    foreach ($rec as $a => &$v) { $v['sum'] = kLeer(); foreach ($v['sum'] as $f => $_) $v['sum'][$f] = $v['auto'][$f] + $v['ext'][$f]; } unset($v);
    // Sperre: Niederlage durch K.O. 90 Tage, T.K.O. 30 Tage – Aufgabe (RTD) ohne Sperre
    $sp = null; $frei = (int)($x['frei'] ?? 0);
    foreach ($fs as $f) if ($f['res'] === 'L' && isset(K_SPERRE[$f['k']]) && $f['ts'] > $frei) {
        $bis = $f['ts'] + K_SPERRE[$f['k']] * 86400;
        if ($bis > time() && (!$sp || $bis > $sp['bis'])) $sp = ['bis' => $bis, 'grund' => ($f['k'] === 'KO' ? 'K.O.' : 'T.K.O.') . '-Niederlage am ' . date('d.m.Y', $f['ts']) . ' (' . $f['ev'] . ')'];
    }
    foreach ((array)($x['sperren'] ?? []) as $m) { $bis = kTs($m['bis'] ?? '') + 86399;
        if ($bis > time() && ($m['at'] ?? 0) > $frei && (!$sp || $bis > $sp['bis'])) $sp = ['bis' => $bis, 'grund' => $m['grund'] ?? 'von der WBU eingetragen']; }
    if ($sp) $sp['bisText'] = date('d.m.Y', $sp['bis']);
    $titel = array_merge($IX['t'][$n] ?? [], array_values((array)($x['titel'] ?? [])));
    return ['rec' => $rec, 'kampf' => $fs, 'sperre' => $sp, 'titel' => $titel];
}
/** Kämpfer aus allen Resultaten (auch alten) in die Datenbank übernehmen – einmal je Veranstaltung */
function kAusResultaten(&$k) {
    $da = []; foreach ($k as $o) $da[kNorm($o['name'])] = 1;
    foreach (kResIndex()['f'] as $n => $fs) if (!isset($da[$n])) { kPut($k, ['name' => $fs[0]['name']], 'resultate'); $da[$n] = 1; }
}
/** Trainer-Konto: darf nur Kämpfer aus dem eigenen Gym sehen und deren Bilanz ergänzen */
function kTrainerGym($in) { $me = clubByToken($in['tok'] ?? ''); return $me && $me['rolle'] === 'trainer' ? kNorm($me['club'] ?? '') : ''; }
/** Info an die WBU: eine Veranstaltung wurde zum ersten Mal hochgeladen (einmal pro Veranstaltung) */
function neueVeranstaltungMail($eid, $art, $name, $date, $ort, $anzahl, $link, $tok) {
    global $DIR;
    $eid = preg_replace('/[^A-Za-z0-9_-]/', '', (string)$eid);
    $f = "$DIR/gemeldet.json";
    $h = fopen($f, 'c+'); if (!$h) return;
    flock($h, LOCK_EX);
    $g = json_decode(stream_get_contents($h), true); if (!is_array($g)) $g = [];
    $schon = $eid !== '' && isset($g[$eid]);
    if (!$schon && $eid !== '') { $g[$eid] = time(); ftruncate($h, 0); rewind($h); fwrite($h, json_encode($g)); fflush($h); }
    flock($h, LOCK_UN); fclose($h);
    if ($schon) return;
    $me = clubByToken($tok);
    $wer = $me ? ($me['trainer'] . ($me['club'] && $me['club'] !== '–' ? " ({$me['club']})" : '') . " – {$me['email']}") : 'ohne Konto (Tablet / Windows-Programm)';
    $d = $date ? date('d.m.Y', strtotime($date)) : '–';
    $body = "Eine neue Veranstaltung wurde in WBU Sports hochgeladen.\n\nArt: $art\nName: $name\nDatum: $d\nOrt: " . ($ort ?: '–') . "\n$anzahl\nVeranstalter: $wer\n\n" . ($link ? "Live-Seite: $link\n\n" : '') . "World Boxing Union";
    $host = preg_replace('/^www\./', '', preg_replace('/[^a-z0-9.\-]/i', '', $_SERVER['HTTP_HOST'] ?? '')) ?: 'wbu-boxing.com';
    $hdr = "From: WBU Sports <noreply@$host>\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
    @mail('info@wbu-boxing.com', '=?UTF-8?B?' . base64_encode("Neue Veranstaltung: $name ($d)") . '?=', $body, $hdr);
}


// ===================== Live =====================
// YouTube: läuft der Stream gerade? true / false / null (unbekannt) – liest die öffentliche YouTube-Seite (ohne Schlüssel)
function ytIstLive($u) {
    if (preg_match('~(?:v=|youtu\.be/|/live/|/embed/|/shorts/)([\w-]{11})~', $u, $m)) $url = 'https://www.youtube.com/watch?v=' . $m[1];
    elseif (preg_match('~/channel/(UC[\w-]{22})~', $u, $m)) $url = 'https://www.youtube.com/channel/' . $m[1] . '/live';
    elseif (preg_match('~youtube\.com/(@[\w.-]+)~', $u, $m)) $url = 'https://www.youtube.com/' . $m[1] . '/live';
    else return null;
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_HTTPHEADER => ['Accept-Language: de-DE,de;q=0.9,en;q=0.8', 'Cookie: SOCS=CAI; CONSENT=YES+cb'],
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36']);
    $h = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    if (!is_string($h) || $code !== 200 || strlen($h) < 5000) return null;
    if (strpos($h, '"isLiveNow":true') !== false) return true;
    if (strpos($h, '"isLiveNow":false') !== false) return false;
    if (strpos($h, 'ytInitialPlayerResponse') !== false) return false;   // Seite da, aber kein Livestream (beendet / Kanal sendet nicht)
    return null;
}
function lvfile($id) {
    global $DIR;
    if (!is_string($id) || !preg_match('/^[a-f0-9]{16}$/', $id)) fail('Live-Veranstaltung unbekannt', 404);
    return "$DIR/lv_$id.json";
}
// Live-Stand für die Öffentlichkeit: Geburtsdatum -> Alter am Veranstaltungstag, genaues Gewicht weg
function liveOeffentlich($sn) {
    if (!is_array($sn)) return $sn;
    $tag = strtotime((string)($sn['date'] ?? '')) ?: time();
    $alter = function ($g) use ($tag) { $t = strtotime((string)$g); if (!$t) return '';
        $a = (int)date('Y', $tag) - (int)date('Y', $t); if (date('md', $tag) < date('md', $t)) $a--; return ($a > 0 && $a < 100) ? $a : ''; };
    foreach ((array)($sn['rows'] ?? []) as $i => $r) {
        if (isset($r['f']) && is_array($r['f'])) {
            foreach (['r', 'b'] as $c) { $r['f'][$c . 'a'] = $alter($r['f'][$c . 'g'] ?? ''); unset($r['f'][$c . 'g'], $r['f'][$c . 'w']); }
        }
        foreach (['ai', 'bi'] as $k) if (isset($r[$k])) $r[$k] = trim(preg_replace('/(^| · )[\d.,]+ kg( · |$)/u', '$1$2', (string)$r[$k]), ' ·');
        $sn['rows'][$i] = $r;
    }
    return $sn;
}

function withLive($id, $fn, $write = false) {
    $f = lvfile($id);
    if (!file_exists($f)) fail('Live-Veranstaltung nicht gefunden', 404);
    $h = fopen($f, 'c+'); if (!$h) fail('Speicherfehler', 500);
    flock($h, $write ? LOCK_EX : LOCK_SH);
    $l = json_decode(stream_get_contents($h), true);
    if (!is_array($l)) { flock($h, LOCK_UN); fclose($h); fail('Datei beschädigt', 500); }
    $res = $fn($l);
    if ($write) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($l, JSON_UNESCAPED_UNICODE)); fflush($h); }
    flock($h, LOCK_UN); fclose($h);
    return $res;
}
const SUPER_ADMINS = ['1229d6a92e8ee18ddc6e38a831aeb6f769c980fd19be0826f5d4f9f310bd13ce'];
function isSuper($acc) { return $acc && in_array(hash('sha256', strtolower(trim((string)($acc['email'] ?? '')))), SUPER_ADMINS, true); }
// Supervisor hat sich mit dieser Gala verbunden -> ab jetzt erscheint der Live-Monitor auf der Startseite
function supTouch($lid) { if (!$lid || !file_exists(lvfile($lid))) return;
    try { withLive($lid, function (&$l) { $l['sup'] = time(); }, true); } catch (Throwable $e) {} }
function liveRows($lid) {
    $f = @file_get_contents(lvfile($lid));
    $l = json_decode((string)$f, true);
    return is_array($l) ? ($l['snap'] ?? null) : null;
}


// ---- Unterlagen (Ausschreibung, Formulare, unterschriebene Erklärungen) ----
const DOC_KINDS = ['aus' => 'Ausschreibung', 'ablauf' => 'Ablaufplan', 'haft' => 'Teilnahmeerklärung & Haftungsausschluss', 'eltern' => 'Einverständniserklärung der Eltern',
                   'attest' => 'Sportärztliches Attest / Medical Check', 'plakat' => 'Plakat'];
function docdir() {
    global $DIR; $d = "$DIR/docs";
    if (!is_dir($d)) @mkdir($d, 0755, true);
    return $d;
}
/** Base64-Datei prüfen (PDF, JPG, PNG, Word) – gibt [Daten, Endung] zurück */
function decodeFile($b64, $max = 12000000) {
    $data = base64_decode(preg_replace('/^data:[^,]*,/', '', (string)$b64), true);
    if ($data === false || $data === '') fail('Datei fehlerhaft');
    if (strlen($data) > $max) fail('Datei zu groß (höchstens ' . round($max / 1000000) . ' MB)');
    if (strncmp($data, '%PDF', 4) === 0) return [$data, 'pdf'];
    if (strncmp($data, "\xFF\xD8", 2) === 0) return [$data, 'jpg'];
    if (strncmp($data, "\x89PNG", 4) === 0) return [$data, 'png'];
    if (strncmp($data, "PK", 2) === 0) return [$data, 'docx'];
    fail('Nur PDF, Foto (JPG/PNG) oder Word-Datei erlaubt');
}
function sendFile($path, $ext, $name) {
    if (!file_exists($path)) { http_response_code(404); header('Content-Type: text/plain; charset=utf-8'); exit('Datei nicht gefunden'); }
    $types = ['pdf' => 'application/pdf', 'jpg' => 'image/jpeg', 'png' => 'image/png',
              'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
    header('Content-Disposition: ' . ($ext === 'docx' ? 'attachment' : 'inline') . '; filename="' . preg_replace('/[^\w.\- äöüÄÖÜß]/u', '_', $name) . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path); exit;
}
/** Welche Unterlagen muss dieser Sportler hochladen? */
function needDocs($t, $reg) {
    $need = [];
    $docs = (array)($t['docs'] ?? []);
    if (!empty($docs['haft'])) $need[] = 'haft';
    // Shadow Boxing Battle ist kontaktlos: keine Einverständniserklärung und kein Attest nötig
    if (!empty($t['attest']) && $reg['sp'] !== 'SB') $need[] = 'attest';
    if (!empty($docs['eltern']) && $reg['sp'] !== 'SB' && $reg['geb'] && $t['date']) {
        $g = new DateTime($reg['geb']); $d = new DateTime($t['date']);
        if ($g->diff($d)->y < 18) $need[] = 'eltern';
    }
    return $need;
}


// ---- Club-/Trainer-Konten (für alle Turniere): selbst gewähltes Passwort ----
function clubsFile() { global $DIR; return "$DIR/clubs.json"; }
function withClubs($fn, $write = false) {
    $h = fopen(clubsFile(), 'c+'); if (!$h) fail('Speicherfehler', 500);
    flock($h, $write ? LOCK_EX : LOCK_SH);
    $c = json_decode(stream_get_contents($h), true); if (!is_array($c)) $c = [];
    $res = $fn($c);
    if ($write) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($c, JSON_UNESCAPED_UNICODE)); fflush($h); }
    flock($h, LOCK_UN); fclose($h);
    return $res;
}
function clubPublic($email, $a) { return ['email' => $email, 'club' => $a['club'], 'trainer' => $a['trainer'], 'tel' => $a['tel'], 'rolle' => $a['rolle'] ?? 'club']; }
/** Nur mit Login (Turniere, Teilnehmer, Unterlagen) – der Live-Monitor bleibt frei */
/** Wie viele Konten sind registriert (nach Rolle)? */
function kontenZahl() {
    $c = json_decode((string)@file_get_contents(clubsFile()), true) ?: []; $n = ['gesamt' => count($c)];
    foreach ($c as $a) { $r = $a['rolle'] ?? 'club'; $n[$r] = ($n[$r] ?? 0) + 1; }
    return $n;
}

// ======================= Rechnung (PDF, ohne fremde Bibliotheken) =======================
$RECH_IMG = ['kopf' => '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', 'stempel' => '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'];
$PDFW = ['Helvetica' => [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,761,556,761,222,556,333,1000,556,556,333,1000,667,333,1000,761,611,761,761,222,222,333,333,350,556,1000,333,1000,500,333,944,761,500,667,278,333,556,556,556,556,260,556,333,737,370,556,584,333,737,333,400,584,333,333,333,556,537,278,333,333,365,556,834,834,834,611,667,667,667,667,667,667,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,500,556,556,556,556,278,278,278,278,556,556,556,556,556,556,556,584,611,556,556,556,556,500,556,500],
 'Helvetica-Bold' => [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,761,556,761,278,556,500,1000,556,556,333,1000,667,333,1000,761,611,761,761,278,278,500,500,350,556,1000,333,1000,556,333,944,761,500,667,278,333,556,556,556,556,280,556,333,737,370,556,584,333,737,333,400,584,333,333,333,611,556,278,333,333,365,556,834,834,834,611,722,722,722,722,722,722,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,556,556,556,556,556,278,278,278,278,611,611,611,611,611,611,611,584,611,611,611,611,611,556,611,556]];

function pdfTxt($s) { $s = @iconv('UTF-8', 'Windows-1252//TRANSLIT', (string)$s); return str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $s); }
function pdfW($s, $font, $size) { global $PDFW; $s = @iconv('UTF-8', 'Windows-1252//TRANSLIT', (string)$s); $w = 0;
    for ($i = 0; $i < strlen($s); $i++) { $c = ord($s[$i]); $w += $c >= 32 ? $PDFW[$font][$c - 32] : 556; } return $w * $size / 1000; }
function euroR($v) { $v = round((float)$v, 2); return abs($v - round($v)) < 0.005 ? number_format($v, 0, ',', '.') . ',-€' : number_format($v, 2, ',', '.') . ' €'; }
/** Rechnung im Stil der WBU-Musterrechnung (Kopfbild, Stempel mit Unterschrift, § 19 UStG) */
/** Rechnung in der Sprache der Seite (DE/EN/ES/FR; Russisch auf Englisch, weil die PDF-Grundschrift kein Kyrillisch kennt) */
function invTr($s) {
    static $M = ['en' => ['Rechnungsnummer: ' => 'Invoice number: ', 'Rechnung:' => 'Invoice:', 'Rechnung' => 'Invoice', 'Kunde:' => 'Customer:', 'Datum:  ' => 'Date:  ', 'Menge     -' => 'Qty     -', 'Beschreibung' => 'Description', '-  Einzelpreis' => '-  Unit price', '-   Gesamt' => '-   Total', 'Summe:' => 'Total:',
            'Ohne Mehrwertsteuer (§ 19 UStG). Der Rechnungsbetrag ist bereits vollständig bezahlt – vielen Dank!' => 'No VAT (§ 19 UStG). The invoice amount has already been paid in full – thank you!', 'Zahlung erfolgt am ' => 'Payment made on ', ' auf folgendes Konto:' => ' to the following account:', 'Startgeld ' => 'Entry fee ', '(Kat. ' => '(Cat. '],
        'es' => ['Rechnungsnummer: ' => 'N.º de factura: ', 'Rechnung:' => 'Factura:', 'Rechnung' => 'Factura', 'Kunde:' => 'Cliente:', 'Datum:  ' => 'Fecha:  ', 'Menge     -' => 'Cant.     -', 'Beschreibung' => 'Descripción', '-  Einzelpreis' => '-  Precio unit.', '-   Gesamt' => '-   Total', 'Summe:' => 'Total:',
            'Ohne Mehrwertsteuer (§ 19 UStG). Der Rechnungsbetrag ist bereits vollständig bezahlt – vielen Dank!' => 'Sin IVA (§ 19 UStG). El importe ya está pagado en su totalidad – ¡gracias!', 'Zahlung erfolgt am ' => 'Pago realizado el ', ' auf folgendes Konto:' => ' a la siguiente cuenta:', 'Startgeld ' => 'Cuota ', '(Kat. ' => '(Cat. '],
        'fr' => ['Rechnungsnummer: ' => 'N° de facture : ', 'Rechnung:' => 'Facture :', 'Rechnung' => 'Facture', 'Kunde:' => 'Client :', 'Datum:  ' => 'Date :  ', 'Menge     -' => 'Qté     -', 'Beschreibung' => 'Description', '-  Einzelpreis' => '-  Prix unit.', '-   Gesamt' => '-   Total', 'Summe:' => 'Total :',
            'Ohne Mehrwertsteuer (§ 19 UStG). Der Rechnungsbetrag ist bereits vollständig bezahlt – vielen Dank!' => 'Sans TVA (§ 19 UStG). Le montant de la facture est déjà entièrement payé – merci !', 'Zahlung erfolgt am ' => 'Paiement effectué le ', ' auf folgendes Konto:' => ' sur le compte suivant :', 'Startgeld ' => 'Frais d\'inscription ', '(Kat. ' => '(Cat. ']];
    $l = $GLOBALS['INV_LANG'] ?? 'de'; if ($l === 'ru') $l = 'en';
    if (!isset($M[$l])) return $s;
    return strtr((string)$s, $M[$l]);
}
function invoicePdf($t, $o, $inv) {
    global $RECH_IMG;
    $PW = 595.28; $PH = 841.89; $L = 71; $R = 479;
    $pages = []; $c = '';
    $txt = function ($x, $y, $s, $font = 'Helvetica', $size = 11, $rgb = '0 0 0') use (&$c) {
        $f = $font === 'Helvetica-Bold' ? 'F2' : 'F1';
        $c .= "BT $rgb rg /$f $size Tf " . round($x, 2) . ' ' . round($y, 2) . ' Td (' . pdfTxt(invTr($s)) . ") Tj ET\n"; };
    $rtxt = function ($x, $y, $s, $font = 'Helvetica', $size = 11) use ($txt) { $txt($x - pdfW(invTr($s), $font, $size), $y, $s, $font, $size); };
    $line = function ($x1, $y1, $x2, $y2, $w = 0.6, $rgb = '0 0 0') use (&$c) { $c .= "$rgb RG $w w $x1 $y1 m $x2 $y2 l S\n"; };
    $newPage = function () use (&$c, &$pages) { if ($c !== '') $pages[] = $c; $c = ''; };
    // Kopf
    $y = $PH - 70;
    $c .= "q 408 0 0 138.4 $L " . ($y - 138.4) . " cm /Im1 Do Q\n"; $y -= 138.4 + 15;
    $a = 'World Boxing Union V. , Beckmannstrasse 9 , 31863 Coppenbrügge , '; $txt($L, $y, $a);
    $ux = $L + pdfW($a, 'Helvetica', 11); $txt($ux, $y, 'www.wbu-boxing.com', 'Helvetica', 11, '0 0 1'); $line($ux, $y - 1.5, $ux + pdfW('www.wbu-boxing.com', 'Helvetica', 11), $y - 1.5, 0.5, '0 0 1');
    $y -= 15; $txt($L, $y, 'Rechnung:'); $line($L, $y - 1.5, $L + pdfW(invTr('Rechnung'), 'Helvetica', 11), $y - 1.5, 0.5); $rtxt($R + 4, $y, 'Rechnungsnummer: ' . $inv['no']);
    $y -= 15; $txt($L, $y, 'Kunde:'); $rtxt($R + 4, $y, 'Datum:  ' . date('d.m.Y', $inv['date']));
    $y -= 25;
    foreach (array_filter([$o['verein'] ?? '', $inv['name'] ?? '', $o['club'] ?? '']) as $k) { $txt($L, $y, $k); $y -= 14; }
    $y -= 22;
    $txt($L, $y, 'Menge     -'); $txt(178, $y, 'Beschreibung'); $txt(348, $y, '-  Einzelpreis'); $txt(436, $y, '-   Gesamt');
    $y -= 24; $sum = 0;
    foreach ($inv['items'] as $it) {
        if ($y < 230) { $newPage(); $y = $PH - 80; }
        $d = $it['text']; $fs = 11; while (pdfW($d, 'Helvetica', $fs) > 215 && $fs > 8) $fs -= 0.5;
        while (pdfW($d, 'Helvetica', $fs) > 215) $d = mb_substr($d, 0, -2) . '…';
        $txt($L, $y, '1'); $txt(126, $y, $d, 'Helvetica', $fs); $rtxt(404, $y, euroR($it['fee'])); $rtxt($R, $y, euroR($it['fee']));
        $sum += (float)$it['fee']; $y -= 24;
    }
    $rtxt($R + 2, $y + 8, '-----------'); $y -= 18;
    $txt(348, $y, 'Summe:'); $rtxt($R, $y, euroR($sum)); $y -= 70;
    if ($y < 300) { $newPage(); $y = $PH - 90; }
    $txt($L, $y, 'Ohne Mehrwertsteuer (§ 19 UStG). Der Rechnungsbetrag ist bereits vollständig bezahlt – vielen Dank!', 'Helvetica-Bold', 10.5);
    $y -= 12;
    $c .= "q 159 0 0 63 $L " . ($y - 63) . " cm /Im2 Do Q\n"; $y -= 63 + 20;
    $txt($L, $y, 'Zahlung erfolgt am ' . date('d.m.Y', strtotime(($t['date'] ?: date('Y-m-d')) . ' 12:00')) . ' auf folgendes Konto:'); $y -= 23;
    $txt($L, $y, 'Torsten Knille'); $y -= 25;
    foreach (['IBAN:  DE18 1001 0178 0614 8617 07', 'BIC: REVODEB2'] as $b) { $c .= "0 0 0 rg " . ($L + 4) . ' ' . ($y + 2.5) . " 3 3 re f\n"; $txt($L + 14, $y, $b, 'Helvetica', 10.5); $y -= 23; }
    $txt($L, $y, 'Revolut Bank UAB, Zweigniederlassung Deutschland', 'Helvetica-Bold', 10.5); $y -= 13;
    $txt($L, $y, 'FORA Linden Palais, Unter den Linden 40, 10117, Berlin, Germany', 'Helvetica-Bold', 10.5);
    $newPage();
    // PDF zusammensetzen
    $img = function ($b64) { $d = base64_decode($b64); $s = getimagesizefromstring($d); return [$d, $s[0], $s[1], ($s['channels'] ?? 3) === 1 ? 'DeviceGray' : 'DeviceRGB']; };
    [$i1, $w1, $h1, $cs1] = $img($RECH_IMG['kopf']); [$i2, $w2, $h2, $cs2] = $img($RECH_IMG['stempel']);
    $obj = [];
    $obj[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    $obj[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
    $obj[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
    $obj[5] = "<< /Type /XObject /Subtype /Image /Width $w1 /Height $h1 /ColorSpace /$cs1 /BitsPerComponent 8 /Filter /DCTDecode /Length " . strlen($i1) . " >>\nstream\n$i1\nendstream";
    $obj[6] = "<< /Type /XObject /Subtype /Image /Width $w2 /Height $h2 /ColorSpace /$cs2 /BitsPerComponent 8 /Filter /DCTDecode /Length " . strlen($i2) . " >>\nstream\n$i2\nendstream";
    $kids = []; $n = 7;
    foreach ($pages as $pc) {
        $z = gzcompress($pc);
        $obj[$n] = '<< /Length ' . strlen($z) . " /Filter /FlateDecode >>\nstream\n$z\nendstream";
        $obj[$n + 1] = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 $PW $PH] /Contents $n 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> /XObject << /Im1 5 0 R /Im2 6 0 R >> >> >>";
        $kids[] = ($n + 1) . ' 0 R'; $n += 2;
    }
    $obj[2] = '<< /Type /Pages /Kids [' . implode(' ', $kids) . '] /Count ' . count($kids) . ' >>';
    ksort($obj); $out = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"; $off = [];
    foreach ($obj as $i => $o2) { $off[$i] = strlen($out); $out .= "$i 0 obj\n$o2\nendobj\n"; }
    $x = strlen($out); $out .= "xref\n0 " . (count($obj) + 1) . "\n0000000000 65535 f \n";
    foreach ($obj as $i => $o2) $out .= sprintf("%010d 00000 n \n", $off[$i]);
    $out .= "trailer\n<< /Size " . (count($obj) + 1) . " /Root 1 0 R /Info << /Title (Rechnung " . $inv['no'] . ") /Author (World Boxing Union) >> >>\nstartxref\n$x\n%%EOF";
    return $out;
}
/** Rechnung ab dem Tag nach der Veranstaltung (Datum 00:00) */
function invoiceFrom($t) { return strtotime(($t['date'] ?: date('Y-m-d')) . ' 00:00:00') + 86400; }
/** Kürzel aus dem Turniernamen: „WBU DM 2027 – …“ -> WBU-DM27 */
function invPrefix($t) {
    $n = trim(explode(' – ', explode(' - ', $t['name'] ?? 'WBU')[0])[0]);
    $n = preg_replace_callback('/\b(19|20)(\d\d)\b/', function ($m) { return $m[2]; }, $n);
    $w = preg_split('/\s+/', strtoupper(preg_replace('/[^A-Za-z0-9 ]/', '', iconv('UTF-8', 'ASCII//TRANSLIT', $n))));
    $w = array_values(array_filter($w, 'strlen'));
    if (count($w) >= 2 && preg_match('/^\d+$/', end($w))) { $y = array_pop($w); $w[count($w) - 1] .= $y; }
    return substr(implode('-', $w), 0, 24) ?: 'WBU';
}
function nextInvoiceNo($ts) {
    $f = $GLOBALS['DIR'] . '/rechnung_nr.json'; $h = fopen($f, 'c+'); flock($h, LOCK_EX);
    $n = (int)stream_get_contents($h) + 1; ftruncate($h, 0); rewind($h); fwrite($h, (string)$n); flock($h, LOCK_UN); fclose($h);
    return date('ymd', $ts) . sprintf('%04d', $n);
}
/** Land · Alter · Gewicht eines Kämpfers (wie in WBU Sports) */
function fcInfo($f, $s, $date) {
    $p = [];
    if (($f[$s . 'l'] ?? '') !== '') $p[] = $f[$s . 'l'];
    $gb = strtotime((string)($f[$s . 'g'] ?? '')); $t = strtotime((string)$date) ?: time();
    if ($gb) { $age = (int)date('Y', $t) - (int)date('Y', $gb); if (date('md', $t) < date('md', $gb)) $age--; if ($age > 0 && $age < 100) $p[] = $age . ' J.'; }
    if (($f[$s . 'w'] ?? '') !== '') $p[] = str_replace('.', ',', (string)$f[$s . 'w']) . ' kg';
    return implode(' · ', $p);
}
function needLogin($tok) { $c = clubByToken($tok); if (!$c) fail('Bitte einloggen', 401); return $c; }
function newToken(&$a) { $tok = bin2hex(random_bytes(20)); $a['tok'] = array_slice(array_merge($a['tok'] ?? [], [hash('sha256', $tok)]), -10); return $tok; }
/** Eingeloggter Club zum Token (oder null) */
function clubByToken($tok) {
    // Veranstalter-Ansicht: „vk:<Turnier>:<Schlüssel>“ – sieht alles ohne eigenes Konto
    if (is_string($tok) && preg_match('/^vk:([A-Za-z0-9_-]+):(.+)$/', $tok, $m)) {
        $t = json_decode((string)@file_get_contents(tufile($m[1])), true);
        if (is_array($t) && tKeyOk($t, $m[2])) return ['email' => '__veranstalter__', 'club' => '–', 'trainer' => 'Veranstalter', 'tel' => '', 'rolle' => 'veranstalter', 'vtid' => $m[1]];
        return null;
    }
    if (!is_string($tok) || strlen($tok) < 20 || !file_exists(clubsFile())) return null;
    $c = json_decode((string)@file_get_contents(clubsFile()), true) ?: [];
    $hs = hash('sha256', $tok);
    foreach ($c as $em => $a) if (in_array($hs, $a['tok'] ?? [], true)) return clubPublic($em, $a);
    return null;
}


// ---- Bezahlung per Überweisung: jede Anmeldung (Warenkorb) hat einen Zahlungscode ----
// Status: cart (noch offen) -> open (abgeschlossen, Zahlung offen) -> paid; nach Ablauf der Frist ohne Zahlung: storno
function ostat($o) {
    if (!empty($o['paid'])) return 'paid';
    if (!empty($o['storno']) || time() > ($o['due'] ?? 0)) return 'storno';
    return empty($o['closed']) ? 'cart' : 'open';
}
/** Zählt dieser Sportler im System (Teilnehmerliste, Kategorien, Bracket)?
 *  Ja – sofort nach dem Eintragen. Raus erst, wenn die Zahlungsfrist ohne vollständige Zahlung abgelaufen ist (storno). */
/** Kopf-Ausschnitt [x,y,w,h] (0..1) prüfen */
function kopfOk($k) { if (!is_array($k) || count($k) !== 4) return null; $k = array_map('floatval', array_values($k));
    foreach ($k as $v) if ($v < 0 || $v > 1) return null; if ($k[2] < .03 || $k[3] < .03) return null; return array_map(fn($v) => round($v, 4), $k); }
/** Prüfcode für den QR-Code der Akkreditierungskarte */
function akkSig($tid, $kind, $id) { global $CFG; $sec = (is_array($CFG) && !empty($CFG['update_key'])) ? $CFG['update_key'] : SUP_PASS_SHA256;
    return substr(hash_hmac('sha256', "akk|$tid|$kind|$id", $sec), 0, 10); }
/** frei laut Ausschreibung: ab 1 Sportler 1 Trainer; Betreuer 2 pro angefangene 5 Sportler, höchstens 4 */
function staffMax($n) { return ['trainer' => $n > 0 ? 1 : 0, 'betreuer' => $n > 0 ? min(4, 2 * (int)ceil($n / 5)) : 0]; }
function myAthletes($t, $email) { $n = 0; foreach ($t['regs'] as $x) if (($x['club'] ?? '') === $email && regAlive($t, $x)) $n++; return $n; }
function regIn($t, $x) { return regAlive($t, $x); }
/** Ist die Zahlung vollständig da? */
function regPaid($t, $x) {
    if (!empty($x['storno'])) return false;
    if (empty($x['oid'])) return !empty($x['paid']) || ($x['club'] ?? '') === 'veranstalter' || empty($t['fee']);
    $o = $t['orders'][$x['oid']] ?? null;
    return $o && ostat($o) === 'paid';
}
/** Welche Pflicht-Unterlagen fehlen bei diesem Sportler noch? */
function docsMiss($x) { return array_values(array_diff((array)($x['need'] ?? []), array_keys((array)($x['docs'] ?? [])))); }
/** Attest muss aus dem Jahr der Veranstaltung sein */
function attestOk($t, $d) {
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$d)) fail('Bitte das Ausstellungsdatum des sportärztlichen Attests angeben');
    $y = substr($t['date'] ?: date('Y-m-d'), 0, 4);
    if (substr($d, 0, 4) !== $y) fail("Das sportärztliche Attest muss aus dem Jahr $y sein (ausgestellt am " . date('d.m.Y', strtotime($d)) . ')');
    if (strtotime($d) > time() + 86400) fail('Das Ausstellungsdatum des Attests liegt in der Zukunft');
    return $d;
}
/** Unterlage eines Sportlers speichern */
function saveRegDoc($t, &$x, $k, $file) {
    [$data, $ext] = decodeFile($file['data'], 8000000);
    foreach (glob(docdir() . "/r_{$t['id']}_{$x['id']}_{$k}.*") as $old) @unlink($old);
    file_put_contents(docdir() . "/r_{$t['id']}_{$x['id']}_{$k}.$ext", $data);
    $x['docs'] = (array)($x['docs'] ?? []);
    $x['docs'][$k] = ['name' => txt($file['name'] ?? $k, 120), 'ext' => $ext, 'at' => time()];
    $x['frei'] = !docsMiss($x);
}
/** Noch nicht verfallen (bezahlt, offen oder im Warenkorb; Unterlagen da oder Nachfrist läuft noch) */
function regAlive($t, $x) {
    if (!empty($x['storno'])) return false;
    if (!empty($x['docDue']) && time() > $x['docDue'] && docsMiss($x)) return false;
    if (empty($x['oid'])) return true;
    $o = $t['orders'][$x['oid']] ?? null;
    return $o && ostat($o) !== 'storno';
}
function newCode($t) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    do { $c = 'WBU-'; for ($i = 0; $i < 6; $i++) $c .= $chars[random_int(0, strlen($chars) - 1)];
         $dup = false; foreach (($t['orders'] ?? []) as $o) if ($o['code'] === $c) $dup = true; } while ($dup);
    return $c;
}
/** Zahlungsfrist: Anmeldeschluss + Nachfrist (Standard 3 Tage). Bis zum Anmeldeschluss fliegt niemand raus. */
function dueTs($t, $from) {
    $base = $t['schluss'] ?: $t['date'];
    if (!$base) return $from + 7 * 86400;
    return strtotime($base . ' 23:59:59') + max(1, (int)($t['grace'] ?? 3)) * 86400;
}
/** Startgeld neu berechnen (nur im Warenkorb): erster Start eines Sportlers voll, jeder weitere ermäßigt */
function recalcFees(&$t) {
    $seen = [];
    usort($t['regs'], function ($a, $b) { return $a['no'] - $b['no']; });
    foreach ($t['regs'] as &$x) {
        if (!regAlive($t, $x)) continue;
        $p = mb_strtolower($x['vorname'] . '|' . $x['name'] . '|' . $x['geb']);
        $fee = (isset($seen[$p]) && !empty($t['feeMore'])) ? $t['feeMore'] : $t['fee'];
        $seen[$p] = 1;
        if (!empty($x['oid']) && ostat($t['orders'][$x['oid']]) === 'cart') $x['fee'] = $fee;
    }
}
function orderTotal($t, $oid) { $s = 0; foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $oid && empty($x['storno'])) $s += (float)$x['fee']; return round($s, 2); }
/** E-Mail an den Verein (Absender noreply@<Domain>) */
function wbuMail($to, $subject, $body) {
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    $host = preg_replace('/^www\./', '', preg_replace('/[^a-z0-9.\-]/i', '', $_SERVER['HTTP_HOST'] ?? '')) ?: 'wbu-boxing.com';
    global $CFG;
    $rt = (is_array($CFG) && !empty($CFG['reply_to'])) ? $CFG['reply_to'] : 'dm@wbu-boxing.com';
    $hdr = "From: WBU Turniere <noreply@$host>\r\nReply-To: $rt\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
    return @mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body . "\n\nFragen? Einfach auf diese E-Mail antworten oder an $rt schreiben.\n\nWorld Boxing Union", $hdr);
}
function euro($v) { return number_format((float)$v, 2, ',', '.') . ' €'; }
function bankText($t, $o, $betrag) {
    $bis = !empty($o['reminded']) ? date('d.m.Y', $o['due']) : 'sofort, spätestens zum Anmeldeschluss ' . date('d.m.Y', strtotime($t['schluss'] ?: $t['date']));
    return "Betrag: " . euro($betrag) . "\nEmpfänger: {$t['inhaber']}\nIBAN: {$t['iban']}" . ($t['bic'] ? "\nBIC: {$t['bic']}" : '') .
           "\nVerwendungszweck: {$o['code']}\nZahlbar: $bis";
}
/** Nach einer Zahlungsänderung: Verein freundlich informieren (jede Nachricht nur einmal) */
function payMail(&$t, &$o) {
    $total = orderTotal($t, $o['id']); $amt = (float)($o['paidAmt'] ?? 0);
    $st = !empty($o['paid']) ? ($amt > $total + 0.004 ? 'zuviel' : 'ok') : ($amt > 0 ? 'zuwenig' : '');
    $key = $st . '|' . number_format($amt, 2);
    if ($st === '' || ($o['mailKey'] ?? '') === $key) return;
    $o['mailKey'] = $key;
    $names = []; foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $o['id'] && empty($x['storno'])) $names[] = "- {$x['vorname']} {$x['name']} (Kategorie {$x['nr']})";
    $list = implode("\n", $names);
    if ($st === 'ok') wbuMail($o['club'], "Zahlung eingegangen – {$t['name']}",
        "Hallo,\n\nvielen Dank! Deine Zahlung über " . euro($amt) . " (Code {$o['code']}) ist eingegangen.\nDiese Sportler sind damit für {$t['name']} fest angemeldet:\n\n$list\n\nWir freuen uns auf euch!");
    elseif ($st === 'zuviel') wbuMail($o['club'], "Zahlung eingegangen – etwas zu viel überwiesen – {$t['name']}",
        "Hallo,\n\nvielen Dank! Für deine Anmeldung {$o['code']} sind " . euro($amt) . " eingegangen, die Summe beträgt aber nur " . euro($total) . ".\n" .
        "Deine Sportler sind im System:\n\n$list\n\nDen zu viel gezahlten Betrag von " . euro($amt - $total) . " klären wir mit dir – wir melden uns.");
    else wbuMail($o['club'], "Zahlung unvollständig – bitte Restbetrag überweisen – {$t['name']}",
        "Hallo,\n\nfür deine Anmeldung {$o['code']} ist eine Zahlung über " . euro($amt) . " eingegangen – die Summe beträgt aber " . euro($total) . ".\n" .
        "Es fehlen noch " . euro($total - $amt) . ". Bitte überweise den Rest – sonst werden diese Sportler nach dem Anmeldeschluss und einer kurzen Nachfrist wieder entfernt:\n\n$list\n\n" .
        "Bitte überweise den Restbetrag:\n\n" . bankText($t, $o, $total - $amt) . "\n\nVielen Dank!");
}

function orderView($t, $o) {
    $items = [];
    foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $o['id'] && empty($x['storno']))
        $items[] = ['id' => $x['id'], 'no' => $x['no'], 'vorname' => $x['vorname'], 'name' => $x['name'], 'nr' => $x['nr'], 'klasse' => $x['klasse'], 'fee' => $x['fee']];
    return ['id' => $o['id'], 'code' => $o['code'], 'status' => ostat($o), 'created' => $o['created'], 'closed' => $o['closed'] ?? null, 'due' => $o['due'],
            'reminded' => $o['reminded'] ?? null, 'total' => orderTotal($t, $o['id']), 'paidAmt' => $o['paidAmt'] ?? null, 'paidAt' => $o['paid'] ?? null, 'verein' => $o['verein'], 'club' => $o['club'], 'items' => $items];
}


// ======================= WBU News (Berichte mit Bildern, optional auch auf Facebook) =======================
function newsFile() { global $DIR; return "$DIR/news.json"; }
function newsDir() { global $DIR; $d = "$DIR/news"; if (!is_dir($d)) @mkdir($d, 0755, true); return $d; }
function fbFile() { global $DIR; return "$DIR/facebook.json"; }

// ===================== WBU COIN – WHITELIST (Wallet-Anmeldung, ohne Coin) =====================
function wlFile() { global $DIR; return "$DIR/whitelist.json"; }
function wlKey() { global $DIR; $f = "$DIR/whitelist.key"; if (!file_exists($f)) { @file_put_contents($f, random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)); @chmod($f, 0600); } return file_get_contents($f); }
function wlEnc($a) { $n = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); return base64_encode($n . sodium_crypto_secretbox(json_encode($a, JSON_UNESCAPED_UNICODE), $n, wlKey())); }
function wlDec($b) { $r = base64_decode((string)$b); if (strlen($r) < 25) return []; $m = sodium_crypto_secretbox_open(substr($r, 24), substr($r, 0, 24), wlKey()); return $m === false ? [] : (json_decode($m, true) ?: []); }
function withWl($fn, $write = false) {
    $f = wlFile(); $h = fopen($f, 'c+'); flock($h, $write ? LOCK_EX : LOCK_SH);
    $d = json_decode(stream_get_contents($h) ?: '[]', true) ?: [];
    $r = $fn($d);
    if ($write) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($d, JSON_UNESCAPED_UNICODE)); }
    flock($h, LOCK_UN); fclose($h); return $r;
}
function b58dec($s) {
    $al = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; $b = [];
    for ($i = 0; $i < strlen($s); $i++) { $c = strpos($al, $s[$i]); if ($c === false) return null;
        for ($j = 0; $j < count($b); $j++) { $c += $b[$j] * 58; $b[$j] = $c & 255; $c >>= 8; }
        while ($c > 0) { $b[] = $c & 255; $c >>= 8; } }
    for ($i = 0; $i < strlen($s) && $s[$i] === '1'; $i++) $b[] = 0;
    return implode('', array_map('chr', array_reverse($b)));
}
// Werbe-Code im Format WBU-XXXXX (alt: 6 Hex-Zeichen, bleiben gültig)
function wlNewRef($d) { $al = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; do { $c = 'WBU'; for ($i = 0; $i < 5; $i++) $c .= $al[random_int(0, strlen($al) - 1)]; } while (array_filter($d, fn($x) => ($x['ref'] ?? '') === $c)); return $c; }
function wlRefShow($c) { return strpos($c, 'WBU') === 0 ? 'WBU-' . substr($c, 3) : $c; }
// Wegwerf-E-Mail-Adressen sperren
const WL_TRASH = ['mailinator.com','guerrillamail.com','guerrillamail.net','guerrillamail.org','sharklasers.com','grr.la','10minutemail.com','10minutemail.net','temp-mail.org','tempmail.com','tempmail.net','temp-mail.io','tempmail.dev','tempmailo.com','tempr.email','discard.email','discardmail.com','dispostable.com','yopmail.com','yopmail.net','yopmail.fr','trashmail.com','trashmail.de','trashmail.net','wegwerfmail.de','wegwerfmail.net','einrot.com','spambog.com','spamgourmet.com','maildrop.cc','mailnesia.com','getnada.com','nada.email','mohmal.com','emailondeck.com','fakeinbox.com','throwawaymail.com','mintemail.com','mytemp.email','tmpmail.org','tmpmail.net','moakt.com','burnermail.io','inboxkitten.com','mailcatch.com','mailpoof.com','spam4.me','byom.de','emailfake.com','fakemail.net','tempinbox.com','minuteinbox.com','dropmail.me','10mail.org','emltmp.com','luxusmail.org','smailpro.com','tempail.com','crazymailing.com','mail.tm','mail.gw','harakirimail.com','33mail.com','anonaddy.me','trash-mail.com','wegwerfemail.de','muellmail.com','sofort-mail.de','spoofmail.de','zehnminutenmail.de','emailtemporanea.net','correotemporal.org','jetable.org','mailinator.net','mailinator2.com'];
function wlTrash($email) { $dom = strtolower(substr(strrchr($email, '@'), 1)); foreach (WL_TRASH as $t) if ($dom === $t || substr($dom, -strlen('.' . $t)) === '.' . $t) return true; return false; }
function wlHash($s) { return substr(hash_hmac('sha256', mb_strtolower(trim($s)), wlSecret()), 0, 24); }
function wlIdHashes($pd) { return ['em' => wlHash($pd['email']), 'ph' => wlHash(preg_replace('/\D/', '', $pd['phone'])), 'pe' => wlHash(preg_replace('/\s+/', ' ', $pd['name']) . '|' . $pd['dob'])]; }
// Konto-Übersicht: Geworbene und Bonus-Liste (Spiele laufen noch im Testmodus → Belohnungen warten)
function wlAccount($d, $r) {
    $codes = array_filter([$r['ref'] ?? '', $r['refOld'] ?? '']);
    $team = []; foreach ($d as $x) if (!empty($x['refBy']) && in_array($x['refBy'], $codes, true)) $team[] = ['fighter' => $x['fighter'], 'created' => $x['created'], 'ok' => !empty($x['mailOk']), 'spent' => round((float)($x['spent'] ?? 0), 2), 'rew' => !empty($x['refPaid'])];
    $bonus = $r['bonus'] ?? []; $free = 0; $wait = 0; foreach ($bonus as $b) { if (($b['st'] ?? '') === 'ok') $free += $b['n']; else $wait += $b['n']; }
    return ['code' => wlRefShow($r['ref'] ?? ''), 'team' => $team, 'bonus' => $bonus, 'free' => $free, 'wait' => $wait, 'games' => (int)($r['games'] ?? 0)];
}
function wlSecret() { return hash('sha256', wlKey() . 'wl-token'); }
function wlTok($wallet) { $t = time(); return $wallet . '.' . $t . '.' . substr(hash_hmac('sha256', "$wallet|$t", wlSecret()), 0, 32); }
function wlAuth($tok) {
    $p = explode('.', (string)$tok); if (count($p) !== 3) fail('Please connect your wallet again', 401);
    [$w, $t, $h] = $p; if (time() - (int)$t > 30 * 86400 || !hash_equals(substr(hash_hmac('sha256', "$w|$t", wlSecret()), 0, 32), $h)) fail('Please connect your wallet again', 401);
    return $w;
}
function wlPublic($r) { return ['id' => $r['id'], 'wallet' => $r['wallet'], 'fighter' => $r['fighter'], 'klassen' => $r['klassen'], 'sport' => $r['sport'] ?? 'pro', 'ref' => $r['ref'], 'refs' => $r['refs'] ?? 0, 'ok' => !empty($r['mailOk']), 'blocked' => !empty($r['blocked']), 'created' => $r['created']]; }
const WL_KL = ['Heavyweight','Bridgerweight','Cruiserweight','Light Heavyweight','Super Middleweight','Middleweight','Super Welterweight','Welterweight','Super Lightweight','Lightweight','Super Featherweight','Featherweight','Super Bantamweight','Bantamweight','Super Flyweight','Flyweight','Light Flyweight','Minimumweight'];
function wlMail($to, $lang, $subj, $body) {
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    $hdr = "From: WBU Coin <noreply@wbu-boxing.com>\r\nReply-To: info@wbu-boxing.com\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
    return @mail($to, '=?UTF-8?B?' . base64_encode($subj) . '?=', $body . "\n\n— World Boxing Union · www.wbu-boxing.com/coin\nWBU never asks you to send coins to a private wallet.", $hdr);
}
function wlConfirmMail($r, $pd) {
    $sig = substr(hash_hmac('sha256', 'ok|' . $r['id'], wlSecret()), 0, 24);
    $url = 'https://www.wbu-boxing.com/scorecard/api.php?a=wl_ok&id=' . $r['id'] . '&s=' . $sig;
    $de = ($r['lang'] ?? 'en') === 'de';
    wlMail($pd['email'] ?? '', $r['lang'] ?? 'en', $de ? 'WBU Coin – bitte E-Mail bestätigen' : 'WBU Coin – please confirm your e-mail',
        ($de ? "Hallo {$pd['name']},\n\ndanke für deine Anmeldung zur WBU-Coin-Whitelist als „{$r['fighter']}“.\nBitte bestätige deine E-Mail-Adresse mit diesem Link:\n\n$url\n\nDein Werbe-Code: " . wlRefShow($r['ref']) . "\nDein Empfehlungslink: https://www.wbu-boxing.com/coin/?ref={$r['ref']}"
             : "Hi {$pd['name']},\n\nthank you for joining the WBU Coin whitelist as \"{$r['fighter']}\".\nPlease confirm your e-mail address with this link:\n\n$url\n\nYour referral code: " . wlRefShow($r['ref']) . "\nYour referral link: https://www.wbu-boxing.com/coin/?ref={$r['ref']}"));
}

function withNews($fn, $write = false) {
    $h = fopen(newsFile(), 'c+'); if (!$h) fail('Speicherfehler', 500);
    flock($h, $write ? LOCK_EX : LOCK_SH);
    $n = json_decode(stream_get_contents($h), true); if (!is_array($n)) $n = [];
    $res = $fn($n);
    if ($write) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($n, JSON_UNESCAPED_UNICODE)); fflush($h); }
    flock($h, LOCK_UN); fclose($h);
    return $res;
}
/** Darf dieses Konto Berichte schreiben? (WBU-Superadmin immer, sonst nur mit Freigabe) */
function newsStatus($me) {
    if (!$me || ($me['email'] ?? '') === '__veranstalter__') return 'none';
    if (isSuper($me)) return 'ok';
    $c = json_decode((string)@file_get_contents(clubsFile()), true) ?: [];
    return $c[$me['email']]['news'] ?? 'none';
}
function newsPublic($p) { return ['id' => $p['id'], 'd' => $p['d'], 't' => $p['t'], 'x' => $p['x'], 'n' => count($p['img'] ?? []), 'by' => $p['by'] ?? '', 'fb' => !empty($p['fb']), 'tr' => (object)($p['tr'] ?? [])]; }
// Automatische Übersetzung (Google-Übersetzer, frei zugängliche Schnittstelle) – für Berichte der Admins
function gTrPart($q, $tl, $sl) {
    $c = curl_init('https://translate.googleapis.com/translate_a/single?client=gtx&dt=t&sl=' . $sl . '&tl=' . $tl);
    curl_setopt_array($c, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query(['q' => $q]), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8]);
    $r = json_decode((string)curl_exec($c), true); curl_close($c);
    if (!is_array($r) || !is_array($r[0] ?? null)) return null;
    $o = ''; foreach ($r[0] as $seg) $o .= $seg[0] ?? '';
    return ['t' => $o, 'src' => is_string($r[2] ?? null) ? $r[2] : ''];
}
function gTr($text, $tl, $sl = 'auto') {
    $text = (string)$text; if (trim($text) === '') return ['t' => $text, 'src' => ''];
    $teile = []; $buf = '';
    foreach (preg_split('/(\n)/u', $text, -1, PREG_SPLIT_DELIM_CAPTURE) as $z) {
        if (mb_strlen($buf . $z) > 3500 && $buf !== '') { $teile[] = $buf; $buf = ''; }
        $buf .= $z;
    }
    if ($buf !== '') $teile[] = $buf;
    $out = ''; $src = '';
    foreach ($teile as $q) { $r = gTrPart($q, $tl, $sl); if (!$r) return null; $out .= $r['t']; if (!$src) $src = $r['src']; }
    return ['t' => $out, 'src' => $src];
}
function newsAutoTr($t, $x) {
    $d = gTr($t . "\n" . mb_substr($x, 0, 400), 'en'); if (!$d) return null;
    $src = substr(strtolower($d['src'] ?: 'en'), 0, 2); $o = [];
    foreach (['en','de','es','fr','ru'] as $l) {
        if ($l === $src) continue;
        $a = gTr($t, $l, $src); $b = gTr($x, $l, $src);
        if ($a && $b) $o[$l] = ['t' => txt($a['t'], 160), 'x' => mb_substr(trim($b['t']), 0, 20000)];
    }
    return $o;
}
function newsTr($v) { $o = []; foreach (['en','de','es','fr','ru'] as $l) { $e = $v[$l] ?? null; if (is_array($e) && trim((string)($e['t'] ?? '')) !== '') $o[$l] = ['t' => txt($e['t'], 160), 'x' => mb_substr(trim((string)($e['x'] ?? '')), 0, 20000)]; } return $o; }
function newsImgUrl($id, $i) { return 'https://www.wbu-boxing.com/scorecard/api.php?a=n_img&id=' . $id . '&i=' . $i; }
function fbHttp($method, $path, $params) {
    $url = 'https://graph.facebook.com/v24.0/' . ltrim($path, '/');
    $c = curl_init();
    if ($method === 'GET') { curl_setopt($c, CURLOPT_URL, $url . '?' . http_build_query($params)); }
    else { curl_setopt_array($c, [CURLOPT_URL => $url, CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($params)]); }
    curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60]);
    $r = json_decode((string)curl_exec($c), true); curl_close($c);
    if (!is_array($r)) return ['error' => ['message' => 'Facebook nicht erreichbar']];
    return $r;
}
/** Bericht auf der Facebook-Seite veröffentlichen – gibt Facebook-ID oder Fehlertext zurück */
function fbPublish($p) {
    $fb = json_decode((string)@file_get_contents(fbFile()), true);
    if (!is_array($fb) || empty($fb['page']) || empty($fb['tok'])) return ['err' => 'Facebook ist noch nicht verbunden'];
    $en = $p['tr']['en'] ?? ['t' => $p['t'], 'x' => $p['x']];   // Facebook immer Englisch, wenn vorhanden
    $msg = trim($en['t'] . "\n\n" . $en['x']) . "\n\nhttps://www.wbu-boxing.com/#news/" . $p['id'];
    $n = count($p['img'] ?? []);
    if ($n === 0) $r = fbHttp('POST', $fb['page'] . '/feed', ['message' => $msg, 'access_token' => $fb['tok']]);
    elseif ($n === 1) $r = fbHttp('POST', $fb['page'] . '/photos', ['url' => newsImgUrl($p['id'], 0), 'caption' => $msg, 'access_token' => $fb['tok']]);
    else {
        $media = [];
        for ($i = 0; $i < min($n, 10); $i++) {
            $u = fbHttp('POST', $fb['page'] . '/photos', ['url' => newsImgUrl($p['id'], $i), 'published' => 'false', 'access_token' => $fb['tok']]);
            if (!empty($u['id'])) $media['attached_media[' . count($media) . ']'] = json_encode(['media_fbid' => $u['id']]);
            elseif (!empty($u['error'])) return ['err' => 'Facebook: ' . ($u['error']['message'] ?? 'Fehler')];
        }
        $r = fbHttp('POST', $fb['page'] . '/feed', ['message' => $msg, 'access_token' => $fb['tok']] + $media);
    }
    if (!empty($r['error'])) return ['err' => 'Facebook: ' . ($r['error']['message'] ?? 'Fehler')];
    return ['id' => $r['post_id'] ?? ($r['id'] ?? '')];
}

// Geänderten Bericht auch auf Facebook ändern: Text direkt; geänderte Bilder → alter Beitrag weg, neu gepostet
function fbUpdate($p, $imgNeu) {
    $fb = json_decode((string)@file_get_contents(fbFile()), true);
    if (!is_array($fb) || empty($fb['tok']) || empty($p['fb'])) return ['err' => 'Facebook ist noch nicht verbunden'];
    if ($imgNeu) {
        fbHttp('POST', $p['fb'], ['method' => 'delete', 'access_token' => $fb['tok']]);
        return fbPublish($p);
    }
    $en = $p['tr']['en'] ?? ['t' => $p['t'], 'x' => $p['x']];
    $msg = trim($en['t'] . "\n\n" . $en['x']) . "\n\nhttps://www.wbu-boxing.com/#news/" . $p['id'];
    $r = fbHttp('POST', $p['fb'], ['message' => $msg, 'access_token' => $fb['tok']]);
    if (!empty($r['error'])) return ['err' => 'Facebook: ' . ($r['error']['message'] ?? 'Fehler')];
    return ['id' => $p['fb']];
}

// ===================== INSTAGRAM (über die verbundene Facebook-Seite) =====================
// Nur Berichte MIT Bild gehen auf Instagram (Instagram erlaubt keine reinen Text-Beiträge).
function igBild($f) {   // Seitenverhältnis auf 4:5 … 1,91:1 bringen (schwarz auffüllen), sonst lehnt Instagram ab
    $g = $f . '.ig.jpg'; if (file_exists($g) && filemtime($g) >= filemtime($f)) return $g;
    $im = @imagecreatefromjpeg($f); if (!$im) return $f;
    $w = imagesx($im); $h = imagesy($im); $r = $w / max(1, $h);
    if ($r >= 0.8 && $r <= 1.91) { imagedestroy($im); return $f; }
    if ($r < 0.8) { $nw = (int)ceil($h * 0.8); $nh = $h; } else { $nw = $w; $nh = (int)ceil($w / 1.91); }
    $c = imagecreatetruecolor($nw, $nh); imagefill($c, 0, 0, imagecolorallocate($c, 0, 0, 0));
    imagecopy($c, $im, (int)(($nw - $w) / 2), (int)(($nh - $h) / 2), 0, 0, $w, $h);
    imagejpeg($c, $g, 90); imagedestroy($c); imagedestroy($im); return $g;
}
function igKonto($fb, $neu = false) {   // Instagram-Business-Konto der Facebook-Seite suchen (wird gemerkt)
    if (!$neu && !empty($fb['ig'])) return $fb;
    $r = fbHttp('GET', $fb['page'], ['fields' => 'instagram_business_account{id,username}', 'access_token' => $fb['tok']]);
    $fb['ig'] = $r['instagram_business_account']['id'] ?? ''; $fb['igName'] = $r['instagram_business_account']['username'] ?? '';
    $fb['igErr'] = !empty($r['error']) ? ($r['error']['message'] ?? 'Fehler') : ($fb['ig'] ? '' : 'Mit der Facebook-Seite ist kein Instagram-Business-Konto verknüpft');
    @file_put_contents(fbFile(), json_encode($fb)); return $fb;
}
function igWarte($id, $tok) { for ($k = 0; $k < 15; $k++) { $s = fbHttp('GET', $id, ['fields' => 'status_code', 'access_token' => $tok]); $c = $s['status_code'] ?? ''; if ($c === 'FINISHED') return true; if ($c === 'ERROR' || $c === 'EXPIRED') return false; sleep(2); } return false; }
function igPublish($p) {
    $n = count($p['img'] ?? []); if ($n === 0) return ['err' => ''];   // ohne Bild: nicht auf Instagram
    $fb = json_decode((string)@file_get_contents(fbFile()), true);
    if (!is_array($fb) || empty($fb['tok'])) return ['err' => 'Facebook/Instagram ist noch nicht verbunden'];
    $fb = igKonto($fb); if (empty($fb['ig'])) return ['err' => 'Instagram: ' . ($fb['igErr'] ?: 'nicht verknüpft')];
    $en = $p['tr']['en'] ?? ['t' => $p['t'], 'x' => $p['x']];
    $cap = mb_substr(trim($en['t'] . "\n\n" . $en['x']), 0, 2100) . "\n\nwww.wbu-boxing.com";
    $url = function ($i) use ($p) { return newsImgUrl($p['id'], $i) . '&ig=1'; };
    $ig = $fb['ig']; $tk = $fb['tok'];
    if ($n === 1) $c = fbHttp('POST', "$ig/media", ['image_url' => $url(0), 'caption' => $cap, 'access_token' => $tk]);
    else {
        $kids = [];
        for ($i = 0; $i < min($n, 10); $i++) {
            $k = fbHttp('POST', "$ig/media", ['image_url' => $url($i), 'is_carousel_item' => 'true', 'access_token' => $tk]);
            if (empty($k['id'])) return ['err' => 'Instagram: ' . ($k['error']['message'] ?? 'Bild abgelehnt')];
            $kids[] = $k['id'];
        }
        foreach ($kids as $k) igWarte($k, $tk);
        $c = fbHttp('POST', "$ig/media", ['media_type' => 'CAROUSEL', 'children' => implode(',', $kids), 'caption' => $cap, 'access_token' => $tk]);
    }
    if (empty($c['id'])) return ['err' => 'Instagram: ' . ($c['error']['message'] ?? 'Fehler')];
    igWarte($c['id'], $tk);
    $r = fbHttp('POST', "$ig/media_publish", ['creation_id' => $c['id'], 'access_token' => $tk]);
    if (empty($r['id'])) return ['err' => 'Instagram: ' . ($r['error']['message'] ?? 'Fehler')];
    return ['id' => $r['id']];
}

function newsSecret() { global $DIR; $f = "$DIR/news.key"; if (!file_exists($f)) file_put_contents($f, bin2hex(random_bytes(32))); return trim((string)file_get_contents($f)); }
function newsOkSig($em) { return hash_hmac('sha256', 'news-ok|' . mb_strtolower($em), newsSecret()); }
/** Facebook-Beiträge der Seite als Berichte übernehmen (Bilder werden auf den eigenen Server kopiert) */
function fbImport($n) {
    $fb = json_decode((string)@file_get_contents(fbFile()), true);
    if (!is_array($fb) || empty($fb['tok'])) fail('Facebook ist noch nicht verbunden');
    $r = fbHttp('GET', $fb['page'] . '/posts', ['access_token' => $fb['tok'], 'limit' => $n,
        'fields' => 'id,message,created_time,full_picture,attachments{media,subattachments{media}}']);
    if (!empty($r['error'])) fail('Facebook: ' . ($r['error']['message'] ?? 'Fehler'));
    $neu = 0;
    foreach (array_reverse((array)($r['data'] ?? [])) as $po) {
        $msg = trim((string)($po['message'] ?? ''));
        $urls = [];
        foreach ((array)($po['attachments']['data'] ?? []) as $at) {
            foreach ((array)($at['subattachments']['data'] ?? []) as $sa) if (!empty($sa['media']['image']['src'])) $urls[] = $sa['media']['image']['src'];
            if (!$urls && !empty($at['media']['image']['src'])) $urls[] = $at['media']['image']['src'];
        }
        if (!$urls && !empty($po['full_picture'])) $urls[] = $po['full_picture'];
        if ($msg === '' && !$urls) continue;
        $exists = withNews(function (&$all) use ($po) { foreach ($all as $q) if (($q['fb'] ?? '') === $po['id']) return true; return false; });
        if ($exists) continue;
        $bilder = [];
        foreach (array_slice($urls, 0, 20) as $u) {
            $c = curl_init($u); curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 40]);
            $d = curl_exec($c); curl_close($c);
            if (is_string($d) && strlen($d) > 500) {
                if (strncmp($d, "\xFF\xD8", 2) !== 0 && function_exists('imagecreatefromstring') && ($im = @imagecreatefromstring($d))) { ob_start(); imagejpeg($im, null, 85); $d = ob_get_clean(); imagedestroy($im); }
                if (strncmp($d, "\xFF\xD8", 2) === 0) $bilder[] = $d;
            }
        }
        $zeilen = preg_split('/\R/u', $msg, 2);
        $titel = mb_substr(trim($zeilen[0] ?? ''), 0, 120);
        if ($titel === '') $titel = 'Bericht vom ' . date('d.m.Y', strtotime((string)($po['created_time'] ?? 'now')) ?: time());
        $text = trim($zeilen[1] ?? '');
        if (mb_strlen($zeilen[0] ?? '') > 120) { $titel = mb_substr($zeilen[0], 0, 117) . ' …'; $text = $msg; }
        $ts = strtotime((string)($po['created_time'] ?? '')) ?: time();
        withNews(function (&$all) use ($po, $titel, $text, $bilder, $ts) {
            $id = bin2hex(random_bytes(6)); $dir = newsDir(); $img = [];
            foreach ($bilder as $k => $d) { file_put_contents("$dir/$id-$k.jpg", $d); $img[] = 1; }
            $all[] = ['id' => $id, 'ts' => $ts, 'd' => date('Y-m-d', $ts), 'em' => '__facebook__', 'by' => 'WBU', 'img' => $img, 'fb' => $po['id'], 't' => $titel, 'x' => $text, 'upd' => time()];
        }, true);
        $neu++;
    }
    return $neu;
}


// ---- Einmalig (20.11.2026): YouTube-Livestream für die Galas in Dillingen am 20. und 21.11. eintragen ----
function migYtDillingen() {
    global $DIR; $mark = "$DIR/mig_yt_dillingen.done"; if (file_exists($mark)) return;
    $yt = 'https://www.youtube.com/live/ji3uDNzOr6Y'; $tage = ['2026-11-20', '2026-11-21']; $log = [];
    $passt = function ($e) use ($tage) { $t = mb_strtolower(($e['ort'] ?? '') . ' ' . ($e['name'] ?? ''));
        return in_array(substr((string)($e['date'] ?? ''), 0, 10), $tage, true) && mb_strpos($t, 'dillingen') !== false; };
    $ids = [];
    foreach (glob("$DIR/ws_*.json") as $f) { $h = fopen($f, 'c+'); if (!$h) continue; flock($h, LOCK_EX); $w = json_decode((string)stream_get_contents($h), true);
        if (is_array($w) && !empty($w['ev']) && $passt($w['ev'])) { $w['ev']['yt'] = $yt; $w['ev']['ytAdm'] = 1; $w['mt'] = round(microtime(true) * 1000); $ids[] = $w['ev']['id'];
            ftruncate($h, 0); rewind($h); fwrite($h, json_encode($w, JSON_UNESCAPED_UNICODE)); fflush($h); $log[] = 'ws ' . $w['ev']['id'] . ' ' . ($w['ev']['date'] ?? '') . ' ' . ($w['ev']['ort'] ?? ''); }
        flock($h, LOCK_UN); fclose($h); }
    foreach (glob("$DIR/lv_*.json") as $f) { $h = fopen($f, 'c+'); if (!$h) continue; flock($h, LOCK_EX); $l = json_decode((string)stream_get_contents($h), true);
        if (is_array($l) && is_array($l['snap'] ?? null) && (in_array($l['snap']['eid'] ?? '', $ids, true) || $passt($l['snap']))) { $l['snap']['yt'] = $yt; $l['updated'] = time();
            ftruncate($h, 0); rewind($h); fwrite($h, json_encode($l, JSON_UNESCAPED_UNICODE)); fflush($h); $log[] = 'lv ' . basename($f); }
        flock($h, LOCK_UN); fclose($h); }
    @file_put_contents($mark, date('c') . "\n" . implode("\n", $log));
}
migYtDillingen();
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

case 'join':     // Punktrichter: nur mit der PIN vom Supervisor – kommt direkt in die richtige Veranstaltung (keine Liste)
    $pin = preg_replace('/\D/', '', (string)($in['pin'] ?? ''));
    if (strlen($pin) < 4) fail('Bitte die PIN vom Supervisor eingeben (4 Ziffern)');
    $best = null;
    foreach (glob("$DIR/ev_*.json") as $f) { $o = json_decode((string)@file_get_contents($f), true);
        if (is_array($o) && time() - ($o['created'] ?? 0) <= 48 * 3600 && ($o['pin'] ?? '') === $pin && (!$best || $o['created'] > $best['created'])) $best = $o; }
    if (!$best) fail('Keine Veranstaltung mit dieser PIN gefunden – bitte die PIN beim Supervisor erfragen');
    out(['ok' => true, 'id' => $best['id'], 'name' => $best['name'], 'ort' => $best['ort'], 'date' => $best['date']]);

case 'auth':
    // Passwort prüfen, wenn eine bestehende Veranstaltung weitergeführt wird
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches Supervisor-Passwort', 403);
    out(['ok' => true]);

case 'create':
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches Supervisor-Passwort', 403);
    $id = bin2hex(random_bytes(8));
    $key = bin2hex(random_bytes(12));
    $pin = preg_replace('/\D/', '', (string)($in['pin'] ?? ''));
    if (strlen($pin) < 4) fail('Bitte eine PIN mit 4 Ziffern für die Punktrichter festlegen');
    foreach (glob("$DIR/ev_*.json") as $f) { $o = json_decode((string)@file_get_contents($f), true);   // PIN darf gerade nicht doppelt vergeben sein
        if (is_array($o) && time() - ($o['created'] ?? 0) <= 48 * 3600 && ($o['pin'] ?? '') === mb_substr($pin, 0, 8)) fail('Diese PIN ist gerade schon bei einer anderen Veranstaltung vergeben – bitte eine andere PIN wählen'); }
    $ev = ['id' => $id, 'key' => $key, 'name' => txt($in['name'] ?? ''), 'ort' => txt($in['ort'] ?? ''),
           'date' => txt($in['date'] ?? '', 20), 'sup' => txt($in['sup'] ?? ''), 'pin' => mb_substr($pin, 0, 8),
           'created' => time(), 'cards' => new stdClass(), 'msgs' => [], 'seen' => new stdClass(),
           'lid' => preg_match('/^[a-f0-9]{16}$/', (string)($in['lid'] ?? '')) ? $in['lid'] : '', 'cur' => null];
    if (file_put_contents(evfile($id), json_encode($ev, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
    out(['ok' => true, 'id' => $id, 'key' => $key]);

case 'push':
    $item = $in['item'] ?? null;
    if (!is_array($item) || empty($item['id'])) fail('Leere Sendung');
    withEvent($in['ev'] ?? '', function (&$ev) use ($in, $item) {
        $isSup = ($in['key'] ?? '') !== '' && hash_equals($ev['key'], (string)$in['key']);
        if (!$isSup && !pinOk($ev, $in['pin'] ?? '')) fail('Falsche PIN', 403);
        $item['srv'] = round(microtime(true) * 1000);
        if (($item['t'] ?? '') === 'cur') {            // Supervisor: aktueller Kampf (Namen für die Punktrichter)
            if (!$isSup) fail('Nicht berechtigt', 403);
            $ev['cur'] = ['no' => (int)($item['no'] ?? 0), 'kl' => txt($item['kl'] ?? ''), 'red' => txt($item['red'] ?? ''), 'blue' => txt($item['blue'] ?? ''),
                          'rc' => txt($item['rc'] ?? ''), 'bc' => txt($item['bc'] ?? '')];
            return;
        }
        if (($item['t'] ?? '') === 'res') {            // Supervisor: Ergebnis zurück an WBU Sports
            if (!$isSup) fail('Nicht berechtigt', 403);
            if (empty($ev['lid'])) return;
            $mid = txt($item['mid'] ?? '', 40); $res = is_array($item['res'] ?? null) ? $item['res'] : null;
            withLive($ev['lid'], function (&$l) use ($mid, $res) {
                $r = (array)$l['results'];
                if ($res === null) unset($r[$mid]);
                else $r[$mid] = ['k' => txt($res['k'] ?? '', 8), 'w' => in_array($res['w'] ?? null, ['R', 'B'], true) ? $res['w'] : null,
                                 'r' => isset($res['r']) ? (int)$res['r'] : null, 't' => txt($res['t'] ?? '', 10), 'ts' => (int)($res['ts'] ?? 0), 'by' => txt($res['by'] ?? '')];
                $l['results'] = (object)$r;
            }, true);
            return;
        }
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
        $live = !empty($ev['lid']) ? liveRows($ev['lid']) : null;
        if (!empty($ev['lid'])) supTouch($ev['lid']);
        return ['cards' => array_values((array)$ev['cards']), 'msgs' => $ev['msgs'], 'judges' => $active, 'live' => $live];
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
        return ['msgs' => $msgs, 'name' => $ev['name'], 'sup' => $ev['sup'], 'cur' => $ev['cur'] ?? null];
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
    if (!orgPassOk($in['pass'] ?? '')) fail('Falsches Passwort', 403);
    // kein zweites Turnier mit gleichem Namen und Datum
    foreach (glob("$DIR/tu_*.json") as $f) { $o = json_decode((string)@file_get_contents($f), true);
        if (is_array($o) && mb_strtolower(trim($o['name'] ?? '')) === mb_strtolower(trim((string)($m['name'] ?? ''))) && ($o['date'] ?? '') === ($m['date'] ?? ''))
            fail('Dieses Turnier ist schon veröffentlicht (gleicher Name und Datum). Unter „Auf dem Server veröffentlicht“ kannst du das alte löschen.', 409); }
    $own = clubByToken($in['tok'] ?? '');
    $t = ['id' => bin2hex(random_bytes(8)), 'owner' => $own ? $own['email'] : '', 'key' => bin2hex(random_bytes(12)), 'created' => time(), 'regs' => [], 'nextNo' => 1];
    tMeta($t, $m);
    if (file_put_contents(tufile($t['id']), json_encode($t, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
    neueVeranstaltungMail($in['eid'] ?? ('t' . $t['id']), 'Turnier (Online-Anmeldung)', $t['name'] ?? '', $t['date'] ?? '', $t['ort'] ?? '', 'Anmeldung online: ja', '', $in['tok'] ?? '');
    out(['ok' => true, 'tid' => $t['id'], 'key' => $t['key']]);


case 't_doc':   // Veranstalter lädt Ausschreibung / Ablaufplan / Formulare hoch (oder löscht sie)
    $kind = (string)($in['kind'] ?? '');
    if (!isset(DOC_KINDS[$kind])) fail('Unbekannte Unterlage');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in, $kind) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $docs = (array)($t['docs'] ?? []);
        foreach (glob(docdir() . "/t_{$t['id']}_{$kind}.*") as $old) @unlink($old);
        if (empty($in['data'])) { unset($docs[$kind]); }
        else {
            [$data, $ext] = decodeFile($in['data'], 15000000);
            file_put_contents(docdir() . "/t_{$t['id']}_{$kind}.$ext", $data);
            $docs[$kind] = ['name' => txt($in['name'] ?? DOC_KINDS[$kind], 120), 'ext' => $ext, 'size' => strlen($data), 'at' => time()];
        }
        $t['docs'] = (object)$docs;
        return ['docs' => $t['docs']];
    }, true);
    out(['ok' => true] + $r);

case 't_docget':   // Plakat, Ausschreibung und Ablaufplan öffentlich; Formulare mit Login
    $tid = (string)($_GET['tid'] ?? $in['tid'] ?? ''); $kind = (string)($_GET['kind'] ?? $in['kind'] ?? '');
    if (!in_array($kind, ['plakat', 'aus', 'ablauf'], true)) needLogin((string)($_GET['tok'] ?? $in['tok'] ?? ''));
    if (!isset(DOC_KINDS[$kind])) fail('Unbekannte Unterlage');
    $t = json_decode((string)@file_get_contents(tufile($tid)), true);
    $d = $t['docs'][$kind] ?? null;
    if (!$d) fail('Nicht vorhanden', 404);
    sendFile(docdir() . "/t_{$tid}_{$kind}.{$d['ext']}", $d['ext'], $d['name']);

case 't_regdoc':   // Veranstalter: hochgeladene Erklärung eines Sportlers ansehen
    $tid = (string)($_GET['tid'] ?? ''); $rid = (string)($_GET['rid'] ?? ''); $kind = (string)($_GET['kind'] ?? '');
    $t = json_decode((string)@file_get_contents(tufile($tid)), true);
    if (!is_array($t) || !tKeyOk($t, (string)($_GET['key'] ?? ''))) fail('Nicht berechtigt', 403);
    foreach ($t['regs'] as $x) if ($x['id'] === $rid && $kind === 'foto' && !empty($x['foto']))
        sendFile(docdir() . "/r_{$tid}_{$rid}_foto.{$x['foto']}", $x['foto'], 'foto.' . $x['foto']);
    foreach ($t['regs'] as $x) if ($x['id'] === $rid && !empty($x['docs'][$kind]))
        sendFile(docdir() . "/r_{$tid}_{$rid}_{$kind}.{$x['docs'][$kind]['ext']}", $x['docs'][$kind]['ext'], $x['docs'][$kind]['name']);
    fail('Nicht vorhanden', 404);


case 't_public':   // nur mit Login: Teilnehmer, Kategorien, Clubs (ohne Kontaktdaten)
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in) {
        $club = clubByToken($in['tok'] ?? '');
        $full = $club !== null;
        $list = []; $pids = []; $clubs = [];
        foreach ($t['regs'] as $x) {
            if (!regIn($t, $x)) continue;   // nur bezahlte Sportler sind im System
            $pids[mb_strtolower($x['vorname'] . '|' . $x['name'] . '|' . $x['geb'])] = 1; $clubs[mb_strtolower($x['verein'])] = 1;
            if (!$full) continue;   // ohne Login nur die Gesamtzahlen
            $e = ['id' => $x['id'], 'no' => $x['no'], 'nr' => $x['nr'], 'sp' => $x['sp'], 'sex' => $x['sex'], 'klasse' => $x['klasse'],
                  'verein' => $x['verein'], 'land' => $x['land'], 'trainer' => $x['trainer'], 'betreuer' => $x['betreuer'] ?? '',
                  'foto' => !empty($x['foto']), 'pid' => substr(hash('sha256', mb_strtolower($x['vorname'] . '|' . $x['name'] . '|' . $x['geb'])), 0, 12)];
            $e['vorname'] = $x['vorname']; $e['name'] = $x['name']; $e['kg'] = $x['kg']; $e['cm'] = $x['cm'] ?? ''; $e['geb'] = $x['geb'];
            $e['own'] = ($x['club'] ?? '') === $club['email'];
            if ($e['own']) $e['bezahlt'] = regPaid($t, $x);
            $list[] = $e;
        }
        $starts = 0; foreach ($t['regs'] as $x) if (regIn($t, $x)) $starts++;
        if ($full && $club['rolle'] === 'veranstalter') $res['konten'] = kontenZahl();
        return ($res ?? []) + ['regs' => $list, 'full' => $full, 'count' => ['persons' => count($pids), 'starts' => $starts, 'clubs' => count($clubs)]];
    });
    out(['ok' => true] + $r);

case 't_foto':     // mit Login: Foto eines Sportlers
    needLogin((string)($_GET['tok'] ?? ''));
    $tid = (string)($_GET['tid'] ?? ''); $rid = (string)($_GET['rid'] ?? '');
    $t = json_decode((string)@file_get_contents(tufile($tid)), true);
    if (is_array($t)) foreach ($t['regs'] as $x) if ($x['id'] === $rid && !empty($x['foto']) && empty($x['storno']))
        sendFile(docdir() . "/r_{$tid}_{$rid}_foto.{$x['foto']}", $x['foto'], 'foto.' . $x['foto']);
    fail('Kein Foto', 404);



case 'cron':   // vom Cronjob (über update.php): nach Anmeldeschluss Zahlungserinnerung mit Nachfrist verschicken
    if (!is_array($CFG) || empty($CFG['update_key']) || !hash_equals($CFG['update_key'], (string)($_GET['key'] ?? ''))) fail('Nicht berechtigt', 403);
    $sent = 0;
    foreach (glob("$DIR/tu_*.json") as $f) {
        $id = substr(basename($f, '.json'), 3);
        $t0 = json_decode((string)@file_get_contents($f), true);
        $base = is_array($t0) ? ($t0['schluss'] ?: $t0['date']) : '';
        if (!$base || time() <= strtotime($base . ' 23:59:59') || (empty($t0['orders']) && empty($t0['regs']))) continue;
        $sent += withTurnier($id, function (&$t) {
            $n = 0; $grace = max(1, (int)($t['grace'] ?? 3));
            // Unterlagen (Attest, Haftungsausschluss, Einverständnis) fehlen: Erinnerung mit Nachfrist, danach raus – wie beim Startgeld
            $by = [];
            foreach ($t['regs'] as $i => $x) {
                if (!empty($x['docReminded']) || !regAlive($t, $x) || !docsMiss($x) || !filter_var($x['club'] ?? '', FILTER_VALIDATE_EMAIL)) continue;
                $by[$x['club']][] = $i;
            }
            foreach ($by as $mail => $is) {
                $due = strtotime(date('Y-m-d', time() + $grace * 86400) . ' 23:59:59'); $lines = [];
                foreach ($is as $i) {
                    $x = &$t['regs'][$i]; $x['docDue'] = $due; $x['docReminded'] = time();
                    $lines[] = "- {$x['vorname']} {$x['name']} (Kategorie {$x['nr']}): fehlt " . implode(', ', array_map(function ($k) { return DOC_KINDS[$k]; }, docsMiss($x)));
                    unset($x);
                }
                wbuMail($mail, "Letzte Erinnerung: Unterlagen bitte innerhalb von $grace Tagen hochladen – {$t['name']}",
                    "Hallo,\n\nder Anmeldeschluss für {$t['name']} ist vorbei. Für diese Sportler fehlen noch Pflicht-Unterlagen:\n\n" . implode("\n", $lines) .
                    "\n\nBitte lade sie innerhalb von $grace Tagen hoch – bis spätestens " . date('d.m.Y', $due) . ":\nwww.wbu-boxing.com/anmeldung/ → einloggen → Turnier → „Meine Anmeldungen & Bezahlung“ → Unterlagen.\n" .
                    "Das sportärztliche Attest muss aus dem Jahr " . substr($t['date'], 0, 4) . " sein.\n\nFehlt danach noch etwas, wird der Sportler komplett aus dem Turnier entfernt.\n\nVielen Dank!");
                $n++;
            }
            foreach (($t['orders'] ?? []) as $k => $o) {
                $st = ostat($o);
                if (!empty($o['reminded']) || $st === 'paid' || $st === 'storno') continue;
                $total = orderTotal($t, $o['id']);
                if ($total <= 0) continue;
                $o = &$t['orders'][$k];
                if (empty($o['closed'])) { $o['closed'] = time(); $o['total'] = $total; }
                $o['due'] = max($o['due'] ?? 0, strtotime(date('Y-m-d', time() + $grace * 86400) . ' 23:59:59'));
                $o['reminded'] = time();
                $amt = (float)($o['paidAmt'] ?? 0); $rest = round($total - $amt, 2);
                $names = []; foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $o['id'] && empty($x['storno'])) $names[] = "- {$x['vorname']} {$x['name']} (Kategorie {$x['nr']})";
                wbuMail($o['club'], "Letzte Erinnerung: Startgeld bitte innerhalb von $grace Tagen überweisen – {$t['name']}",
                    "Hallo,\n\nder Anmeldeschluss für {$t['name']} ist vorbei. Für deine Anmeldung {$o['code']} ist das Startgeld noch nicht vollständig bei uns eingegangen" .
                    ($amt > 0 ? " (eingegangen: " . euro($amt) . " von " . euro($total) . ")" : '') . ".\n\n" .
                    "Bitte überweise innerhalb von $grace Tagen – bis spätestens " . date('d.m.Y', $o['due']) . ":\n\n" . bankText($t, $o, $rest) . "\n\n" .
                    "Ist der Betrag bis dahin nicht vollständig eingegangen, werden diese Sportler komplett aus dem Turnier entfernt:\n\n" . implode("\n", $names) . "\n\nVielen Dank!");
                unset($o); $n++;
            }
            return $n;
        }, true);
    }
    out(['ok' => true, 'sent' => $sent]);

case 'c_register':   // Club / Trainer / Einzelsportler legt ein Konto an
    $email = mb_strtolower(trim((string)($in['email'] ?? '')));
    $pw = (string)($in['pw'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Bitte eine gültige E-Mail-Adresse angeben');
    if (mb_strlen($pw) < 6) fail('Das Passwort muss mindestens 6 Zeichen haben');
    $club = txt($in['club'] ?? '', 100); $trainer = txt($in['trainer'] ?? '', 100);
    if ($trainer === '') fail('Bitte deinen Namen angeben');
    if ($club === '') $club = '–';
    $r = withClubs(function (&$c) use ($email, $pw, $club, $trainer, $in) {
        if (isset($c[$email])) fail('Für diese E-Mail gibt es schon ein Konto – bitte einloggen');
        $rolle = in_array($in['rolle'] ?? '', ['club', 'trainer', 'einzel', 'veranstalter', 'sup', 'ref', 'sonst'], true) ? $in['rolle'] : 'club';
        $c[$email] = ['club' => $club, 'trainer' => $trainer, 'tel' => txt($in['tel'] ?? '', 40), 'rolle' => $rolle, 'pw' => password_hash($pw, PASSWORD_DEFAULT), 'created' => time(), 'tok' => []];
        $tok = newToken($c[$email]);
        return ['tok' => $tok, 'me' => clubPublic($email, $c[$email])];
    }, true);
    out(['ok' => true] + $r);

case 'c_login':
    $email = mb_strtolower(trim((string)($in['email'] ?? '')));
    $r = withClubs(function (&$c) use ($email, $in) {
        if (!isset($c[$email]) || !password_verify((string)($in['pw'] ?? ''), $c[$email]['pw'])) { sleep(1); fail('E-Mail oder Passwort falsch', 403); }
        $tok = newToken($c[$email]);
        return ['tok' => $tok, 'me' => clubPublic($email, $c[$email])];
    }, true);
    out(['ok' => true] + $r);


case 'c_forgot':   // Passwort vergessen: Code per E-Mail (Antwort immer gleich, damit niemand E-Mails ausprobieren kann)
    $email = mb_strtolower(trim((string)($in['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Bitte eine gültige E-Mail-Adresse angeben');
    $send = withClubs(function (&$c) use ($email) {
        if (!isset($c[$email])) return null;
        if (time() - ($c[$email]['resetAt'] ?? 0) < 60) fail('Bitte eine Minute warten, dann erneut versuchen');
        $code = (string)random_int(100000, 999999);
        $c[$email]['reset'] = hash('sha256', $code); $c[$email]['resetAt'] = time(); $c[$email]['resetTry'] = 0;
        return $code;
    }, true);
    if ($send !== null) {
        $host = preg_replace('/[^a-z0-9.\-]/i', '', $_SERVER['HTTP_HOST'] ?? 'wbu-boxing.com');
        $host = preg_replace('/^www\./', '', $host) ?: 'wbu-boxing.com';
        $subj = '=?UTF-8?B?' . base64_encode('WBU – Code zum Zurücksetzen deines Passworts') . '?=';
        $body = "Hallo,\n\ndein Code zum Zurücksetzen des Passworts für die WBU-Turnieranmeldung lautet:\n\n    $send\n\n"
              . "Der Code ist 30 Minuten gültig. Wenn du das nicht angefordert hast, kannst du diese E-Mail ignorieren.\n\nWorld Boxing Union";
        $hdr = "From: WBU Turniere <noreply@$host>\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
        if (!@mail($email, $subj, $body, $hdr)) fail('Die E-Mail konnte nicht gesendet werden – bitte später erneut versuchen', 500);
    }
    out(['ok' => true]);

case 'c_reset':    // Code + neues Passwort -> eingeloggt
    $email = mb_strtolower(trim((string)($in['email'] ?? '')));
    $pw = (string)($in['pw'] ?? '');
    if (mb_strlen($pw) < 6) fail('Das Passwort muss mindestens 6 Zeichen haben');
    $r = withClubs(function (&$c) use ($email, $pw, $in) {
        $a = &$c[$email];
        if (!isset($c[$email]) || empty($a['reset']) || time() - ($a['resetAt'] ?? 0) > 1800) fail('Der Code ist abgelaufen – bitte neu anfordern', 403);
        if (($a['resetTry'] ?? 0) >= 5) { $a['reset'] = ''; fail('Zu viele Versuche – bitte neuen Code anfordern', 403); }
        if (!hash_equals($a['reset'], hash('sha256', preg_replace('/\D/', '', (string)($in['code'] ?? ''))))) { $a['resetTry'] = ($a['resetTry'] ?? 0) + 1; return ['err' => 'Der Code stimmt nicht']; }
        $a['pw'] = password_hash($pw, PASSWORD_DEFAULT); $a['reset'] = ''; $a['tok'] = [];
        $tok = newToken($a);
        return ['tok' => $tok, 'me' => clubPublic($email, $a)];
    }, true);
    if (isset($r['err'])) fail($r['err'], 403);
    out(['ok' => true] + $r);

case 'n_list':     // öffentlich: neueste Berichte
    $all = file_exists(newsFile()) ? withNews(function (&$n) { return $n; }) : [];
    usort($all, function ($x, $y) { return $y['ts'] - $x['ts']; });
    out(['ok' => true, 'news' => array_map('newsPublic', array_slice($all, 0, 60))]);

case 'n_img':      // öffentlich: Bild eines Berichts
    $id = preg_replace('/[^a-f0-9]/', '', (string)($_GET['id'] ?? ($in['id'] ?? ''))); $i = (int)($_GET['i'] ?? ($in['i'] ?? 0));
    $f = newsDir() . "/$id-$i.jpg";
    if ($id === '' || !file_exists($f)) { http_response_code(404); header('Content-Type: text/plain'); exit('nicht gefunden'); }
    if (!empty($_GET['ig'])) $f = igBild($f);
    header('Content-Type: image/jpeg'); header('Cache-Control: public, max-age=31536000'); header_remove('Access-Control-Allow-Origin');
    readfile($f); exit;

case 'n_me':       // eingeloggt: darf ich schreiben?
    $me = needLogin($in['tok'] ?? '');
    $fb = json_decode((string)@file_get_contents(fbFile()), true);
    out(['ok' => true, 'me' => $me, 'status' => newsStatus($me), 'super' => isSuper($me), 'fb' => is_array($fb) && !empty($fb['page']) ? ($fb['name'] ?? 'Facebook') : '', 'ig' => is_array($fb) ? ($fb['igName'] ?? '') : '']);

case 'ig_check':   // Superadmin: Instagram-Konto der verbundenen Facebook-Seite suchen
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $fb = json_decode((string)@file_get_contents(fbFile()), true); if (!is_array($fb) || empty($fb['tok'])) fail('Facebook nicht verbunden');
    $fb = igKonto($fb, true);
    out(['ok' => true, 'ig' => $fb['ig'] ?? '', 'name' => $fb['igName'] ?? '', 'err' => $fb['igErr'] ?? '']);

case 'n_req':      // Schreibrechte anfragen
    $me = needLogin($in['tok'] ?? '');
    $first = withClubs(function (&$c) use ($me) { if (!isset($c[$me['email']]) || ($c[$me['email']]['news'] ?? '') === 'ok') return false; $was = $c[$me['email']]['news'] ?? ''; $c[$me['email']]['news'] = 'req'; return $was !== 'req'; }, true);
    if ($first) {
        $link = 'https://www.wbu-boxing.com/scorecard/api.php?a=n_ok&e=' . rawurlencode($me['email']) . '&k=' . newsOkSig($me['email']);
        wbuMail('info@wbu-boxing.com', 'WBU News – Anfrage auf Schreibrechte: ' . trim(($me['trainer'] ?? '') . ' ' . ($me['club'] ?? '')),
            "Neue Anfrage auf Schreibrechte für die WBU News:\n\nName: " . ($me['trainer'] ?? '') . "\nVerein: " . ($me['club'] ?? '') . "\nE-Mail: " . $me['email'] . "\n\n"
            . "FREIGEBEN – einfach diesen Link antippen:\n$link\n\nWenn du die Person nicht kennst, ignoriere diese E-Mail einfach.");
    }
    out(['ok' => true, 'status' => 'req']);

case 'n_ok':       // Freigabe per Link aus der E-Mail (nur mit gültiger Unterschrift)
    header('Content-Type: text/html; charset=utf-8');
    $em = mb_strtolower(trim((string)($_GET['e'] ?? ''))); $k = (string)($_GET['k'] ?? '');
    $okSig = $em !== '' && hash_equals(newsOkSig($em), $k);
    $done = $okSig ? withClubs(function (&$c) use ($em) { if (!isset($c[$em])) return false; $c[$em]['news'] = 'ok'; return $c[$em]; }, true) : false;
    if ($done) wbuMail($em, 'WBU News – du bist freigeschaltet', "Hallo " . ($done['trainer'] ?? '') . ",\n\ndu kannst ab sofort Berichte für die WBU News schreiben: auf www.wbu-boxing.com oben auf das Schloss tippen und mit deinem WBU-Konto anmelden.");
    echo '<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:Arial,sans-serif;background:#eceef1;color:#000;padding:40px;text-align:center"><h2>'
       . ($done ? '✅ Freigegeben' : '❌ Link ungültig oder Konto nicht gefunden') . '</h2><p>' . htmlspecialchars($em) . '</p><p><a href="https://www.wbu-boxing.com/">Zur WBU-Startseite</a></p></body>';
    exit;

case 'n_fbimport': // Superadmin: letzte Facebook-Beiträge als Berichte übernehmen
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    out(['ok' => true, 'neu' => fbImport(max(1, min(50, (int)($in['n'] ?? 10))))]);

case 'n_mine':     // eigene Berichte (Superadmin: alle)
    $me = needLogin($in['tok'] ?? ''); $sup = isSuper($me);
    if (newsStatus($me) !== 'ok') fail('Keine Schreibrechte', 403);
    $all = file_exists(newsFile()) ? withNews(function (&$n) { return $n; }) : [];
    $all = array_values(array_filter($all, function ($p) use ($me, $sup) { return $sup || ($p['em'] ?? '') === $me['email']; }));
    usort($all, function ($x, $y) { return $y['ts'] - $x['ts']; });
    out(['ok' => true, 'news' => array_map('newsPublic', $all)]);

case 'n_save':     // Bericht anlegen oder ändern (Bilder kommen fertig verkleinert als JPEG)
    $me = needLogin($in['tok'] ?? '');
    if (newsStatus($me) !== 'ok') fail('Keine Schreibrechte – bitte bei der WBU freischalten lassen', 403);
    $t = txt($in['t'] ?? '', 160); $x = mb_substr(trim((string)($in['x'] ?? '')), 0, 20000);
    if ($t === '') fail('Bitte eine Überschrift eintragen');
    $id = preg_replace('/[^a-f0-9]/', '', (string)($in['id'] ?? ''));
    $keep = array_map('intval', (array)($in['keep'] ?? []));   // beim Ändern: welche alten Bilder bleiben (Reihenfolge)
    $neu = array_slice((array)($in['img'] ?? []), 0, 30);
    $bilder = [];
    foreach ($neu as $b64) {
        $d = base64_decode(preg_replace('/^data:[^,]*,/', '', (string)$b64), true);
        if ($d === false || strncmp($d, "\xFF\xD8", 2) !== 0) fail('Bild fehlerhaft (nur JPEG)');
        if (strlen($d) > 4000000) fail('Ein Bild ist zu groß');
        $bilder[] = $d;
    }
    $bearb = $id !== ''; $imgNeu = $bearb && ($bilder || $keep !== range(0, max(0, count($keep) - 1)) || !empty($in['imgchg']));
    $sup = isSuper($me); $tr = isset($in['tr']) && is_array($in['tr']) ? newsTr($in['tr']) : null;
    $p = withNews(function (&$n) use ($id, $t, $x, $keep, $bilder, $me, $sup, $tr) {
        $i = $id === '' ? -1 : array_search($id, array_column($n, 'id'));
        if ($id !== '' && $i === false) fail('Bericht nicht gefunden', 404);
        if ($i >= 0 && !$sup && ($n[$i]['em'] ?? '') !== $me['email']) fail('Nur eigene Berichte bearbeiten', 403);
        $p = $i >= 0 ? $n[$i] : ['id' => bin2hex(random_bytes(6)), 'ts' => time(), 'd' => date('Y-m-d'), 'em' => $me['email'], 'by' => trim(($me['trainer'] ?? '') ?: ($me['club'] ?? '')), 'img' => [], 'fb' => ''];
        $dir = newsDir(); $alt = $p['img']; $tmp = [];
        foreach ($keep as $k) if (isset($alt[$k]) && file_exists("$dir/{$p['id']}-$k.jpg")) $tmp[] = file_get_contents("$dir/{$p['id']}-$k.jpg");
        foreach ($alt as $k => $_) @unlink("$dir/{$p['id']}-$k.jpg");
        $all = array_merge($tmp, $bilder); $p['img'] = [];
        foreach ($all as $k => $d) { file_put_contents("$dir/{$p['id']}-$k.jpg", $d); $p['img'][] = 1; }
        $p['t'] = $t; $p['x'] = $x; $p['upd'] = time(); if ($tr !== null) $p['tr'] = $tr;
        if ($i >= 0) $n[$i] = $p; else $n[] = $p;
        return $p;
    }, true);
    if ($tr === null) {   // nicht von der WBU mitgeliefert → automatisch in alle Sprachen übersetzen (Facebook bekommt dann Englisch)
        $auto = newsAutoTr($t, $x);
        if (is_array($auto)) { $p['tr'] = $auto; $pid = $p['id']; withNews(function (&$n) use ($pid, $auto) { foreach ($n as &$q) if ($q['id'] === $pid) $q['tr'] = $auto; }, true); }
    }
    $fbErr = '';
    if ($bearb && !empty($p['fb']) && empty($in['nofb'])) {   // schon auf Facebook → dort mit ändern
        $altAnz = (int)($in['altn'] ?? -1); if ($altAnz >= 0 && count($keep) !== $altAnz) $imgNeu = true;
        $r = fbUpdate($p, $imgNeu);
        if (!empty($r['id'])) { if ($r['id'] !== $p['fb']) { $nid = $r['id']; $pid = $p['id']; withNews(function (&$n) use ($pid, $nid) { foreach ($n as &$q) if ($q['id'] === $pid) $q['fb'] = $nid; }, true); $p['fb'] = $nid; } }
        else $fbErr = $r['err'] ?? 'Facebook-Fehler';
    }
    if (!empty($in['fb']) && empty($p['fb'])) {
        $r = fbPublish($p);
        if (!empty($r['id'])) withNews(function (&$n) use ($p, $r) { foreach ($n as &$q) if ($q['id'] === $p['id']) $q['fb'] = $r['id']; }, true);
        else $fbErr = $r['err'] ?? 'Facebook-Fehler';
        $p['fb'] = $r['id'] ?? '';
    }
    $igErr = '';
    if (!empty($p['fb']) && empty($p['ig']) && count($p['img'] ?? []) > 0 && empty($in['noig'])) {   // mit Bild → auch Instagram
        $r = igPublish($p);
        if (!empty($r['id'])) { $p['ig'] = $r['id']; withNews(function (&$n) use ($p) { foreach ($n as &$q) if ($q['id'] === $p['id']) $q['ig'] = $p['ig']; }, true); }
        else $igErr = $r['err'] ?? '';
    }
    out(['ok' => true, 'post' => newsPublic($p), 'fbErr' => $fbErr, 'igErr' => $igErr, 'ig' => !empty($p['ig'])]);

case 'fb_texts':   // Superadmin: Texte älterer Facebook-Beiträge lesen (nur lesen, nichts übernehmen)
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $fb = json_decode((string)@file_get_contents(fbFile()), true); if (!is_array($fb) || empty($fb['tok'])) fail('Facebook nicht verbunden');
    $out = []; $after = (string)($in['after'] ?? '');
    $q = ['fields' => 'id,message,created_time', 'limit' => 100, 'access_token' => $fb['tok']]; if ($after !== '') $q['after'] = $after;
    $r = fbHttp('GET', $fb['page'] . '/posts', $q);
    if (!empty($r['error'])) fail('Facebook: ' . ($r['error']['message'] ?? 'Fehler'));
    foreach ((array)($r['data'] ?? []) as $po) if (!empty($po['message'])) $out[] = ['d' => substr((string)$po['created_time'], 0, 10), 'm' => (string)$po['message']];
    out(['ok' => true, 'posts' => $out, 'after' => $r['paging']['cursors']['after'] ?? '', 'more' => !empty($r['paging']['next'])]);

case 'wp_despam':   // Superadmin: versteckte Spam-Links aus allen WordPress-Seiten und -Beiträgen löschen (dry=1: nur anzeigen)
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $wpl = dirname(__DIR__) . '/wp-load.php'; if (!file_exists($wpl)) fail('WordPress nicht gefunden');
    define('WP_USE_THEMES', false); require_once $wpl;
    $re = '#<(p|div|span|section)\b[^>]*style="[^"]*(?:height:\s*[0-2]px|display:\s*none|visibility:\s*hidden|font-size:\s*0|left:\s*-\d{3,})[^"]*"[^>]*>.*?</\1>#is';
    $rep = [];
    foreach (get_posts(['post_type' => ['page', 'post'], 'post_status' => 'any', 'numberposts' => -1]) as $po) {
        $c = $po->post_content; $n = 0;
        $neu = preg_replace_callback($re, function ($m) use (&$n) { if (stripos($m[0], '<a ') === false) return $m[0]; $n++; return ''; }, $c);
        if ($n) { $rep[] = ['id' => $po->ID, 'slug' => $po->post_name, 'raus' => $n];
            if (empty($in['dry'])) wp_update_post(['ID' => $po->ID, 'post_content' => $neu]); }
    }
    out(['ok' => true, 'dry' => !empty($in['dry']), 'seiten' => $rep]);

case 'wl_nonce':    // Text zum Unterschreiben (kostenlos, keine Zahlung)
    $w = preg_replace('/[^1-9A-HJ-NP-Za-km-z]/', '', (string)($in['wallet'] ?? ''));
    $pk = b58dec($w); if (!$pk || strlen($pk) !== 32) fail('Invalid wallet address');
    $n = bin2hex(random_bytes(12)); global $DIR; @mkdir("$DIR/wlnonce", 0700);
    foreach (glob("$DIR/wlnonce/*") ?: [] as $f) if (filemtime($f) < time() - 900) @unlink($f);
    $msg = "WBU Coin – whitelist sign-in\nWallet: $w\nNonce: $n\nThis signature is free and does not send any coins.";
    file_put_contents("$DIR/wlnonce/$n", $w);
    out(['ok' => true, 'msg' => $msg]);

case 'wl_auth':     // Unterschrift prüfen → Anmelde-Schlüssel (30 Tage)
    $w = (string)($in['wallet'] ?? ''); $msg = (string)($in['msg'] ?? ''); $sig = base64_decode((string)($in['sig'] ?? ''));
    if (!preg_match('/\nNonce: ([0-9a-f]{24})\n/', $msg, $m)) fail('Invalid request');
    global $DIR; $nf = "$DIR/wlnonce/{$m[1]}";
    if (!file_exists($nf) || trim(file_get_contents($nf)) !== $w || filemtime($nf) < time() - 900) fail('Please connect your wallet again');
    @unlink($nf); $pk = b58dec($w);
    if (!$pk || strlen($pk) !== 32 || strlen($sig) !== 64 || strpos($msg, "Wallet: $w\n") === false || !sodium_crypto_sign_verify_detached($sig, $msg, $pk)) fail('Invalid signature', 403);
    out(['ok' => true, 'tok' => wlTok($w)]);

case 'wl_me':
    $w = wlAuth($in['tok'] ?? '');
    $r = withWl(function (&$d) use ($w) { foreach ($d as $k => $x) if ($x['wallet'] === $w) { if (strpos($x['ref'] ?? '', 'WBU') !== 0) { $d[$k]['refOld'] = $x['ref']; $d[$k]['ref'] = wlNewRef($d); } return [$d[$k], wlAccount($d, $d[$k])]; } return null; }, true);
    out(['ok' => true, 'me' => $r ? array_merge(wlPublic($r[0]), ['p' => wlDec($r[0]['enc']), 'acc' => $r[1]]) : null, 'wallet' => $w]);

case 'wl_save':
    $w = wlAuth($in['tok'] ?? ''); $p = (array)($in['p'] ?? []);
    $pd = []; foreach (['name' => 80, 'dob' => 10, 'street' => 120, 'zip' => 20, 'city' => 80, 'country' => 60, 'email' => 120, 'phone' => 40] as $k => $mx) { $pd[$k] = txt($p[$k] ?? '', $mx); if ($pd[$k] === '') fail('Please fill in all required fields'); }
    if (!filter_var($pd['email'], FILTER_VALIDATE_EMAIL)) fail('Invalid e-mail address');
    if (wlTrash($pd['email'])) fail('Please use your real e-mail address – temporary e-mail addresses are not accepted');
    if (!preg_match('/^(19|20)\d\d-\d\d-\d\d$/', $pd['dob']) || strtotime($pd['dob']) === false || strtotime($pd['dob']) > time()) fail('Invalid date of birth');
    if (strlen(preg_replace('/\D/', '', $pd['phone'])) < 6) fail('Invalid phone number');
    $idh = wlIdHashes($pd);
    $fighter = txt($in['fighter'] ?? '', 30); if (mb_strlen($fighter) < 3) fail('Fighter name: at least 3 characters');
    $kl = array_values(array_unique(array_filter((array)($in['klassen'] ?? []), fn($k) => in_array($k, WL_KL, true)))); if (!$kl) fail('Please choose at least one weight class');
    if (empty($in['terms'])) fail('Please accept the participation terms');
    $lang = in_array($in['lang'] ?? '', ['en','de','es','fr','ru'], true) ? $in['lang'] : 'en';
    $refIn = preg_replace('/[^A-Z0-9]/', '', strtoupper((string)($in['refBy'] ?? '')));
    $res = withWl(function (&$d) use ($w, $pd, $fighter, $kl, $lang, $refIn, $idh) {
        foreach ($d as $x) if ($x['wallet'] !== $w && mb_strtolower($x['fighter']) === mb_strtolower($fighter) && array_intersect($x['klassen'], $kl)) fail('This fighter name already exists in this weight class');
        foreach ($d as $k => $x) { if ($x['wallet'] === $w) continue;
            if (empty($x['idh'])) { $o = wlDec($x['enc'] ?? ''); if ($o) { $d[$k]['idh'] = wlIdHashes(array_merge(['dob' => ''], $o)); $x = $d[$k]; } }
            $h = $x['idh'] ?? []; if (($h['em'] ?? '') === $idh['em']) fail('This e-mail address is already registered');
            if (($h['ph'] ?? '') === $idh['ph']) fail('This phone number is already registered');
            if (($h['pe'] ?? '') === $idh['pe']) fail('This person is already registered'); }
        $i = null; foreach ($d as $k => $x) if ($x['wallet'] === $w) $i = $k;
        if ($i === null) {
            $ref = wlNewRef($d);
            $r = ['id' => bin2hex(random_bytes(6)), 'wallet' => $w, 'ref' => $ref, 'refBy' => '', 'refs' => 0, 'created' => time(), 'mailOk' => false, 'bonus' => []];
            if ($refIn) foreach ($d as $k => $x) if (($x['ref'] ?? '') === $refIn || ($x['refOld'] ?? '') === $refIn) {
                $r['refBy'] = $x['ref']; $d[$k]['refs'] = ($x['refs'] ?? 0) + 1;
                // Geworbener: 10 Freispiele sofort · Werbender: 20 Freispiele, sobald der Geworbene für 5 $ gespielt hat
                $r['bonus'][] = ['t' => 'welcome', 'n' => 10, 'st' => 'ok', 'd' => time()];
                $d[$k]['bonus'] = $x['bonus'] ?? []; $d[$k]['bonus'][] = ['t' => 'ref', 'n' => 20, 'st' => 'wait', 'who' => $fighter, 'd' => time()];
                break; }
            $d[] = $r; $i = count($d) - 1; $neu = true;
        } else $neu = false;
        $alt = wlDec($d[$i]['enc'] ?? ''); $mailNeu = ($alt['email'] ?? '') !== $pd['email'];
        $d[$i]['fighter'] = $fighter; $d[$i]['klassen'] = $kl; $d[$i]['sport'] = 'pro'; $d[$i]['lang'] = $lang; $d[$i]['upd'] = time(); $d[$i]['enc'] = wlEnc($pd); $d[$i]['idh'] = $idh;
        if ($mailNeu) $d[$i]['mailOk'] = false;
        return [$d[$i], $neu || $mailNeu];
    }, true);
    if ($res[1]) wlConfirmMail($res[0], $pd);
    $acc = withWl(function ($d) use ($w) { foreach ($d as $x) if ($x['wallet'] === $w) return wlAccount($d, $x); return null; });
    out(['ok' => true, 'me' => array_merge(wlPublic($res[0]), ['p' => $pd, 'acc' => $acc]), 'mail' => $res[1]]);

case 'wl_ok':       // Link aus der Bestätigungs-Mail
    $id = preg_replace('/[^a-f0-9]/', '', (string)($_GET['id'] ?? '')); $sg = (string)($_GET['s'] ?? '');
    $ok = $id && hash_equals(substr(hash_hmac('sha256', 'ok|' . $id, wlSecret()), 0, 24), $sg) && withWl(function (&$d) use ($id) { foreach ($d as $k => $x) if ($x['id'] === $id) { $d[$k]['mailOk'] = true; return true; } return false; }, true);
    header('Location: https://www.wbu-boxing.com/coin/?wl=' . ($ok ? 'ok' : 'err') . '#whitelist'); exit;

case 'wl_stats':
    out(withWl(function ($d) { $pk = []; $n = 0; foreach ($d as $x) { if (!empty($x['blocked'])) continue; $n++; foreach ($x['klassen'] as $k) $pk[$k] = ($pk[$k] ?? 0) + 1; } return ['ok' => true, 'total' => $n, 'klassen' => $pk]; }));

case 'wl_admin':    // Superadmin: alle Anmeldungen (entschlüsselt)
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    out(['ok' => true, 'list' => withWl(function ($d) { return array_map(fn($x) => array_merge(wlPublic($x), ['p' => wlDec($x['enc'] ?? ''), 'refBy' => $x['refBy'] ?? '']), array_reverse($d)); })]);

case 'wl_block':
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $id = preg_replace('/[^a-f0-9]/', '', (string)($in['id'] ?? '')); $b = !empty($in['b']);
    withWl(function (&$d) use ($id, $b) { foreach ($d as $k => $x) if ($x['id'] === $id) $d[$k]['blocked'] = $b; }, true);
    out(['ok' => true]);

case 'wl_mail':     // Superadmin: Rundmail an alle bestätigten Anmeldungen
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $subj = txt($in['subj'] ?? '', 150); $body = mb_substr(trim((string)($in['text'] ?? '')), 0, 20000); if ($subj === '' || $body === '') fail('Betreff und Text angeben');
    $n = 0; foreach (withWl(fn($d) => $d) as $x) { if (empty($x['mailOk']) || !empty($x['blocked'])) continue; $pd = wlDec($x['enc'] ?? ''); if (wlMail($pd['email'] ?? '', $x['lang'] ?? 'en', $subj, $body)) $n++; }
    out(['ok' => true, 'sent' => $n]);

case 'n_tr':       // Superadmin: Übersetzungen eines Berichts setzen (Bilder und Facebook bleiben unberührt)
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $id = preg_replace('/[^a-f0-9]/', '', (string)($in['id'] ?? '')); $tr = newsTr((array)($in['tr'] ?? []));
    $p = withNews(function (&$n) use ($id, $tr) { foreach ($n as &$q) if ($q['id'] === $id) { $q['tr'] = $tr; return $q; } fail('Bericht nicht gefunden', 404); }, true);
    out(['ok' => true, 'post' => newsPublic($p)]);

case 'n_del':
    $me = needLogin($in['tok'] ?? ''); $sup = isSuper($me);
    $id = preg_replace('/[^a-f0-9]/', '', (string)($in['id'] ?? ''));
    withNews(function (&$n) use ($id, $me, $sup) {
        foreach ($n as $k => $p) if ($p['id'] === $id) {
            if (!$sup && ($p['em'] ?? '') !== $me['email']) fail('Nur eigene Berichte löschen', 403);
            foreach ($p['img'] as $i => $_) @unlink(newsDir() . "/$id-$i.jpg");
            array_splice($n, $k, 1); return;
        }
        fail('Bericht nicht gefunden', 404);
    }, true);
    out(['ok' => true]);

case 'n_users':    // Superadmin: Anfragen und Freigaben
case 'n_grant':
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    $em = mb_strtolower(trim((string)($in['email'] ?? '')));
    $r = withClubs(function (&$c) use ($a, $em, $in) {
        if ($a === 'n_grant') { if (!isset($c[$em])) fail('Konto nicht gefunden', 404); if (!empty($in['on'])) $c[$em]['news'] = 'ok'; else unset($c[$em]['news']); }
        $L = [];
        foreach ($c as $e => $x) if (!empty($x['news'])) $L[] = ['email' => $e, 'name' => trim(($x['trainer'] ?? '') . ' · ' . ($x['club'] ?? ''), ' ·'), 'status' => $x['news']];
        return $L;
    }, $a === 'n_grant');
    out(['ok' => true, 'users' => $r]);

case 'fb_connect': // Superadmin: Facebook verbinden (App-ID, App-Geheimcode, Zugangsschlüssel aus dem Graph API Explorer)
case 'fb_pick':
case 'fb_off':
    $me = needLogin($in['tok'] ?? ''); if (!isSuper($me)) fail('Nur für die WBU', 403);
    if ($a === 'fb_off') { @unlink(fbFile()); out(['ok' => true]); }
    if ($a === 'fb_pick') {
        $pend = json_decode((string)@file_get_contents(fbFile() . '.pending'), true) ?: [];
        foreach ($pend as $pg) if ((string)$pg['id'] === (string)($in['page'] ?? '')) {
            $neu = ['page' => $pg['id'], 'name' => $pg['name'], 'tok' => $pg['access_token'], 'at' => time()];
            file_put_contents(fbFile(), json_encode($neu)); @unlink(fbFile() . '.pending');
            $neu = igKonto($neu, true);
            out(['ok' => true, 'name' => $pg['name'], 'ig' => $neu['igName'] ?? '', 'igErr' => $neu['igErr'] ?? '']);
        }
        fail('Seite nicht gefunden – bitte neu verbinden');
    }
    $app = preg_replace('/\D/', '', (string)($in['app'] ?? '')); $sec = trim((string)($in['secret'] ?? '')); $tok = trim((string)($in['token'] ?? ''));
    if ($app === '' || $sec === '' || $tok === '') fail('Bitte App-ID, App-Geheimcode und Zugangsschlüssel eintragen');
    $l = fbHttp('GET', 'oauth/access_token', ['grant_type' => 'fb_exchange_token', 'client_id' => $app, 'client_secret' => $sec, 'fb_exchange_token' => $tok]);
    if (empty($l['access_token'])) fail('Facebook: ' . ($l['error']['message'] ?? 'Schlüssel wurde nicht angenommen'));
    $pg = fbHttp('GET', 'me/accounts', ['access_token' => $l['access_token'], 'fields' => 'id,name,access_token', 'limit' => 100]);
    $pages = array_values(array_filter((array)($pg['data'] ?? []), function ($x) { return !empty($x['access_token']); }));
    if (!$pages) fail('Facebook: keine Seite gefunden – beim Zugangsschlüssel die Seite „Official WBU“ mit auswählen');
    file_put_contents(fbFile() . '.pending', json_encode($pages));
    out(['ok' => true, 'pages' => array_map(function ($x) { return ['id' => $x['id'], 'name' => $x['name']]; }, $pages)]);

case 'c_me':
    $me = clubByToken($in['tok'] ?? '');
    if (!$me) fail('Bitte neu einloggen', 403);
    out(['ok' => true, 'me' => $me + ['super' => isSuper($me)]]);

case 't_admin':      // WBU Sports: alle veröffentlichten Turniere (auch geschlossene) – nur für Veranstalter
case 't_admin_del':  // … und ein Turnier löschen (nur mit WBU-Passwort)
    $me = needLogin($in['tok'] ?? '');
    if ($me['rolle'] !== 'veranstalter') fail('Nur für Veranstalter', 403);
    if ($a === 't_admin_del') {
        if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
        $f = tufile($in['tid'] ?? ''); if (!file_exists($f)) fail('Nicht gefunden', 404);
        rename($f, $f . '.geloescht-' . date('Ymd-His'));
        out(['ok' => true]);
    }
    $list = [];
    foreach (glob("$DIR/tu_*.json") as $f) {
        $t = json_decode(@file_get_contents($f), true); if (!is_array($t)) continue;
        $p = tPublic($t); $p['created'] = $t['created'] ?? 0; $p['open'] = !empty($t['open']); $p['owner'] = $t['owner'] ?? ''; $list[] = $p;
    }
    usort($list, function ($x, $y) { return strcmp($x['date'], $y['date']) ?: $x['created'] - $y['created']; });
    out(['ok' => true, 'turniere' => $list]);

case 'c_setrole':   // eigenes Konto: Rolle ändern (z. B. Verein -> Veranstalter)
    $rolle = (string)($in['rolle'] ?? '');
    if (!in_array($rolle, ['club', 'trainer', 'einzel', 'veranstalter', 'sup', 'ref', 'sonst'], true)) fail('Unbekannte Rolle');
    $me = needLogin($in['tok'] ?? '');
    if (empty($me['email']) || strpos($me['email'], '@') === false) fail('Nicht möglich', 403);
    withClubs(function (&$c) use ($me, $rolle) { $c[$me['email']]['rolle'] = $rolle; }, true);
    out(['ok' => true, 'me' => clubByToken($in['tok'] ?? '')]);

case 'c_logo_set':  // eigenes Konto: ein Logo (Verein/Veranstalter) für Urkunden hochladen – ersetzt das alte
    $me = needLogin($in['tok'] ?? '');
    if (empty($me['email']) || strpos($me['email'], '@') === false) fail('Nur mit eigenem Konto möglich', 403);
    [$data, $ext] = decodeFile($in['data'] ?? '', 3000000);
    if ($ext !== 'jpg' && $ext !== 'png') fail('Das Logo muss ein Bild sein (JPG oder PNG)');
    $id = substr(hash('sha256', 'logo|' . $me['email']), 0, 14);
    foreach (['jpg', 'png'] as $e) @unlink(docdir() . "/logo_$id.$e");
    file_put_contents(docdir() . "/logo_$id.$ext", $data);
    withClubs(function (&$c) use ($me, $ext) { $c[$me['email']]['logo'] = $ext; $c[$me['email']]['logoAt'] = time(); }, true);
    out(['ok' => true, 'id' => $id]);

case 'c_logos':     // eingeloggt: alle hochgeladenen Logos (eigenes zuerst) – zum Auswählen für die Urkunde
    $me = needLogin($in['tok'] ?? '');
    $list = withClubs(function (&$c) use ($me) { $L = [];
        foreach ($c as $em => $x) if (!empty($x['logo'])) {
            $id = substr(hash('sha256', 'logo|' . $em), 0, 14);
            $L[] = ['id' => $id, 'name' => trim((string)($x['club'] ?? '')) ?: (string)($x['trainer'] ?? ''), 'own' => $em === ($me['email'] ?? ''), 'v' => (int)($x['logoAt'] ?? 0)];
        }
        usort($L, fn($a, $b) => $b['own'] <=> $a['own'] ?: strcasecmp($a['name'], $b['name']));
        return $L; });
    out(['ok' => true, 'logos' => $list]);

case 'c_logo':      // Logo-Bild (öffentlich lesbar, wie auf einer Urkunde)
    $id = preg_replace('/[^a-f0-9]/', '', (string)($_GET['id'] ?? ''));
    foreach (['png', 'jpg'] as $e) if ($id !== '' && file_exists(docdir() . "/logo_$id.$e")) sendFile(docdir() . "/logo_$id.$e", $e, "logo.$e");
    fail('Kein Logo', 404);

case 't_info':      // öffentlich (ohne Login): Turnierseite zum Informieren – Plakat, Ausschreibung, Eckdaten
    $t = json_decode((string)@file_get_contents(tufile($in['tid'] ?? ($_GET['tid'] ?? ''))), true);
    if (!is_array($t)) fail('Turnier nicht gefunden', 404);
    $p = tPublic($t); unset($p['iban'], $p['bic'], $p['inhaber']);
    $p['docs'] = array_intersect_key((array)($t['docs'] ?? []), ['plakat' => 1, 'aus' => 1, 'ablauf' => 1, 'haft' => 1]);
    out(['ok' => true, 't' => $p]);

case 't_list':
    needLogin($in['tok'] ?? '');
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
    needLogin($in['tok'] ?? '');
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
            'bem' => txt($r['bem'] ?? '', 500), 'betreuer' => txt($r['betreuer'] ?? '', 200),
            'cm' => txt($r['cm'] ?? '', 5)];
    if ($reg['vorname'] === '' || $reg['name'] === '' || $reg['geb'] === '') fail('Bitte Vorname, Name und Geburtsdatum angeben');
    if (!filter_var($reg['email'], FILTER_VALIDATE_EMAIL)) fail('Bitte eine gültige E-Mail-Adresse angeben');
    if ($reg['nr'] < 100 || $reg['nr'] > 1000 || $reg['klasse'] === '') fail('Bitte eine Klasse wählen');
    $files = is_array($r['files'] ?? null) ? $r['files'] : [];
    $club = clubByToken($in['tok'] ?? '');
    if (!$club) fail('Bitte zuerst einloggen', 401);
    if (!in_array($club['rolle'], ['club', 'trainer', 'einzel', 'veranstalter'], true) || $club['email'] === '__veranstalter__') fail('Sportler anmelden können nur Clubs, Trainer, Einzelsportler und Veranstalter', 403);
    $reg['club'] = $club['email'];
    if ($reg['verein'] === '') $reg['verein'] = $club['club'];
    $res = withTurnier($in['tid'] ?? '', function (&$t) use ($reg, $files) {
        if (!tOffen($t)) fail('Die Anmeldung für dieses Turnier ist geschlossen', 403);
        if (!in_array($reg['sp'], $t['sports'], true)) fail('Diese Sportart wird bei diesem Turnier nicht angeboten');
        foreach ($t['regs'] as $x) {
            if (regAlive($t, $x) && $x['nr'] === $reg['nr'] && $x['geb'] === $reg['geb']
                && mb_strtolower($x['name'] . $x['vorname']) === mb_strtolower($reg['name'] . $reg['vorname'])) fail('Dieser Sportler ist in dieser Klasse bereits angemeldet');
        }
        if (count($t['regs']) >= 3000) fail('Teilnehmerzahl erreicht', 403);
        $reg['id'] = bin2hex(random_bytes(6)); $reg['no'] = $t['nextNo']++; $reg['at'] = time(); $reg['paid'] = false;
        // Unterschriebene Erklärungen: Pflicht je nach Alter – erst damit ist der Sportler freigegeben
        // Pflicht-Unterlagen: können gleich oder später (unter „Meine Anmeldungen“) hochgeladen werden – wie beim Startgeld
        $need = needDocs($t, $reg); $reg['docs'] = []; $reg['need'] = $need;
        if (in_array('attest', $need, true) && !empty($files['attest']['data'])) $reg['attestDate'] = attestOk($t, $files['attest']['datum'] ?? '');
        foreach ($need as $k) if (!empty($files[$k]['data'])) saveRegDoc($t, $reg, $k, $files[$k]);
        if (!empty($files['foto']['data'])) {      // Foto des Sportlers (freiwillig)
            [$data, $ext] = decodeFile($files['foto']['data'], 6000000);
            if ($ext !== 'jpg' && $ext !== 'png') fail('Das Foto muss ein Bild (JPG/PNG) sein');
            file_put_contents(docdir() . "/r_{$t['id']}_{$reg['id']}_foto.$ext", $data);
            $reg['foto'] = $ext;
            if ($k = kopfOk($files['foto']['kopf'] ?? null)) $reg['kopf'] = $k;
        }
        $reg['frei'] = !docsMiss($reg);
        // Warenkorb des Vereins für dieses Turnier (ein Zahlungscode für alle Sportler darin)
        if (!empty($t['fee'])) {
            $t['orders'] = $t['orders'] ?? [];
            $oid = null;
            foreach ($t['orders'] as $o) if ($o['club'] === $reg['club'] && ostat($o) === 'cart') $oid = $o['id'];
            if (!$oid) {
                $oid = bin2hex(random_bytes(5));
                $t['orders'][$oid] = ['id' => $oid, 'code' => newCode($t), 'club' => $reg['club'], 'verein' => $reg['verein'], 'created' => time(), 'due' => dueTs($t, time()), 'closed' => null];
            }
            $reg['oid'] = $oid; $reg['fee'] = $t['fee'];
        } else $reg['fee'] = 0;
        $t['regs'][] = $reg;
        recalcFees($t);
        return ['no' => $reg['no'], 'name' => $t['name'], 'reg' => $reg, 'tid' => $t['id']];
    }, true);
    $rg = $res['reg']; $tid0 = $res['tid']; unset($res['reg'], $res['tid']);
    withKaempfer(function (&$k) use ($rg, $tid0) { kPut($k, kFromReg($rg), 't:' . $tid0); });
    out(['ok' => true] + $res);


case 't_import':   // Veranstalter: in WBU Sports eingetragene / vorab gemeldete Sportler online eintragen
    $list = $in['list'] ?? [];
    if (!is_array($list)) fail('Liste fehlt');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in, $list) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $ids = []; $neu = [];
        foreach (array_slice($list, 0, 500) as $x) {
            $full = txt($x['name'] ?? '', 120); $vn = txt($x['vn'] ?? '', 60); $nn = txt($x['nn'] ?? '', 60);
            if ($vn === '' && $nn === '') { $p = strrpos($full, ' '); $vn = $p === false ? $full : substr($full, 0, $p); $nn = $p === false ? '' : substr($full, $p + 1); }
            $reg = ['vorname' => $vn, 'name' => $nn, 'geb' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $x['geb'] ?? '') ? $x['geb'] : '',
                    'sex' => in_array($x['sex'] ?? '', ['m', 'w'], true) ? $x['sex'] : ((int)($x['nr'] ?? 0) === 1000 ? 'x' : 'm'),
                    'verein' => txt($x['verein'] ?? '', 100), 'land' => '', 'trainer' => txt($x['trainer'] ?? '', 100), 'email' => '', 'tel' => '',
                    'sp' => txt($x['sp'] ?? '', 4), 'nr' => (int)($x['nr'] ?? 0), 'kg' => txt($x['kg'] ?? '', 8), 'klasse' => txt($x['klasse'] ?? '', 80),
                    'bem' => 'vom Veranstalter eingetragen', 'betreuer' => '', 'cm' => '',
                    'id' => bin2hex(random_bytes(6)), 'no' => $t['nextNo']++, 'at' => time(), 'paid' => false, 'docs' => [], 'need' => [], 'frei' => true,
                    'club' => 'veranstalter', 'fee' => $t['fee']];
            $t['regs'][] = $reg;
            $ids[(string)($x['pid'] ?? '')] = $reg['id'];
            $neu[] = $reg;
        }
        return ['ids' => $ids, 'neu' => $neu, 'tid' => $t['id']];
    }, true);
    $neu = $r['neu']; $tid0 = $r['tid']; unset($r['neu'], $r['tid']);
    if ($neu) withKaempfer(function (&$k) use ($neu, $tid0) { foreach ($neu as $rg) kPut($k, kFromReg($rg), 't:' . $tid0); });
    out(['ok' => true] + $r);


case 't_my':        // Verein: eigene Anmeldungen, Warenkorb, Zahlungen
    $club = needLogin($in['tok'] ?? '');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($club) {
        $os = [];
        foreach (($t['orders'] ?? []) as $o) if ($o['club'] === $club['email']) $os[] = orderView($t, $o);
        usort($os, function ($a, $b) { return $b['created'] - $a['created']; });
        $mine = [];
        foreach ($t['regs'] as $x) if (($x['club'] ?? '') === $club['email'] && regAlive($t, $x))
            $mine[] = ['id' => $x['id'], 'vorname' => $x['vorname'], 'name' => $x['name'], 'nr' => $x['nr'], 'need' => $x['need'] ?? [], 'docs' => array_keys((array)($x['docs'] ?? [])),
                       'miss' => docsMiss($x), 'docDue' => $x['docDue'] ?? null, 'attestDate' => $x['attestDate'] ?? null];
        $staff = []; foreach (($t['staff'] ?? []) as $x) if ($x['club'] === $club['email']) $staff[] = ['id' => $x['id'], 'name' => $x['name'], 'rolle' => $x['rolle'], 'foto' => !empty($x['foto']), 'kopf' => $x['kopf'] ?? null];
        return ['staff' => $staff, 'staffMax' => staffMax(myAthletes($t, $club['email'])), 'rechnungAb' => invoiceFrom($t), 'regs' => $mine, 'year' => substr($t['date'] ?: date('Y-m-d'), 0, 4), 'orders' => $os, 'bank' => ['inhaber' => $t['inhaber'], 'iban' => $t['iban'], 'bic' => $t['bic']], 'schluss' => $t['schluss'] ?: $t['date']];
    });
    out(['ok' => true] + $r);

case 't_staff_add':  // Verein/Trainer: Trainer oder Betreuer fürs Turnier anmelden (für die Akkreditierung, kostenlos)
    $club = needLogin($in['tok'] ?? '');
    if (empty($club['email']) || strpos($club['email'], '@') === false) fail('Nur mit eigenem Konto möglich', 403);
    $name = txt($in['name'] ?? '', 80); $rolle = ($in['rolle'] ?? '') === 'trainer' ? 'trainer' : 'betreuer';
    if (mb_strlen($name) < 3) fail('Bitte Vor- und Nachnamen angeben');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($club, $name, $rolle, $in) {
        $mine = array_values(array_filter($t['staff'] ?? [], fn($x) => $x['club'] === $club['email']));
        $n = myAthletes($t, $club['email']); $max = staffMax($n)[$rolle];
        if ($n === 0) fail('Bitte zuerst Sportler anmelden – dann sind 1 Trainer und 2 Betreuer frei (ab 6 Sportlern bis zu 4 Betreuer).');
        $has = count(array_filter($mine, fn($x) => $x['rolle'] === $rolle));
        if ($has >= $max) fail($rolle === 'trainer' ? 'Es ist schon ein Trainer angemeldet – pro Team ist 1 Trainer frei.'
            : "Es sind schon $max Betreuer angemeldet – laut Ausschreibung sind 2 Betreuer pro angefangene 5 Sportler frei, höchstens 4 pro Team. Weitere zahlen Eintritt.");
        foreach ($mine as $x) if (mb_strtolower($x['name']) === mb_strtolower($name)) fail('Diese Person ist schon angemeldet');
        $s = ['id' => bin2hex(random_bytes(6)), 'club' => $club['email'], 'verein' => $club['club'] ?: $club['trainer'], 'name' => $name, 'rolle' => $rolle, 'at' => time()];
        if (!empty($in['foto'])) { [$data, $ext] = decodeFile($in['foto'], 6000000); if ($ext !== 'jpg' && $ext !== 'png') fail('Das Foto muss ein Bild sein (JPG/PNG)');
            file_put_contents(docdir() . "/s_{$t['id']}_{$s['id']}.$ext", $data); $s['foto'] = $ext; if ($k = kopfOk($in['kopf'] ?? null)) $s['kopf'] = $k; }
        $t['staff'][] = $s; return ['id' => $s['id']];
    }, true);
    out(['ok' => true] + $r);

case 't_staff_del':
    $club = needLogin($in['tok'] ?? '');
    withTurnier($in['tid'] ?? '', function (&$t) use ($club, $in) {
        $keep = [];
        foreach (($t['staff'] ?? []) as $x) { if ($x['id'] === ($in['id'] ?? '') && $x['club'] === $club['email']) { if (!empty($x['foto'])) @unlink(docdir() . "/s_{$t['id']}_{$x['id']}.{$x['foto']}"); continue; } $keep[] = $x; }
        $t['staff'] = $keep;
    }, true);
    out(['ok' => true]);

case 't_staffdoc':   // Foto eines Trainers/Betreuers: eigener Verein (tok) oder Veranstalter (key)
    $tid = (string)($_GET['tid'] ?? ''); $sid = (string)($_GET['sid'] ?? '');
    $t = json_decode((string)@file_get_contents(tufile($tid)), true);
    if (!is_array($t)) fail('Nicht gefunden', 404);
    $me = clubByToken((string)($_GET['tok'] ?? ''));
    foreach (($t['staff'] ?? []) as $x) if ($x['id'] === $sid && !empty($x['foto']) && (tKeyOk($t, (string)($_GET['key'] ?? '')) || ($me && $me['email'] === $x['club'])))
        sendFile(docdir() . "/s_{$tid}_{$sid}.{$x['foto']}", $x['foto'], 'foto.' . $x['foto']);
    fail('Kein Foto', 404);

case 't_akk':        // Veranstalter: alle Personen für Akkreditierungskarten (Sportler im System + Trainer/Betreuer)
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $L = [];
        foreach ($t['regs'] as $x) if (regIn($t, $x))
            $L[] = ['k' => 'r', 'id' => $x['id'], 'name' => trim($x['vorname'] . ' ' . $x['name']), 'verein' => $x['verein'], 'rolle' => 'sportler', 'klasse' => $x['klasse'], 'nr' => $x['nr'],
                    'foto' => !empty($x['foto']), 'kopf' => $x['kopf'] ?? null, 'sig' => akkSig($t['id'], 'r', $x['id'])];
        foreach (($t['staff'] ?? []) as $x)
            $L[] = ['k' => 's', 'id' => $x['id'], 'name' => $x['name'], 'verein' => $x['verein'], 'rolle' => $x['rolle'], 'klasse' => '', 'nr' => 0,
                    'foto' => !empty($x['foto']), 'kopf' => $x['kopf'] ?? null, 'sig' => akkSig($t['id'], 's', $x['id'])];
        return ['list' => $L, 'name' => $t['name'], 'date' => $t['date'], 'ort' => $t['ort'] ?? ''];
    });
    out(['ok' => true] + $r);

case 't_kopf':       // Veranstalter: Kopf-Ausschnitt eines Fotos festlegen
    $k = kopfOk($in['kopf'] ?? null); if (!$k) fail('Ausschnitt fehlerhaft');
    withTurnier($in['tid'] ?? '', function (&$t) use ($in, $k) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $list = ($in['kind'] ?? '') === 's' ? 'staff' : 'regs';
        foreach (($t[$list] ?? []) as $i => $x) if ($x['id'] === ($in['id'] ?? '')) { $t[$list][$i]['kopf'] = $k; return; }
        fail('Nicht gefunden', 404);
    }, true);
    out(['ok' => true]);

case 't_akkcheck':   // öffentlich: QR-Code einer Akkreditierungskarte prüfen (Einlass)
    $c = explode('.', (string)($in['c'] ?? ($_GET['c'] ?? '')));
    if (count($c) !== 4) out(['ok' => true, 'valid' => false]);
    [$tid, $kind, $id, $sig] = $c;
    $t = json_decode((string)@file_get_contents(tufile($tid)), true);
    if (!is_array($t) || !hash_equals(akkSig($tid, $kind, $id), $sig)) out(['ok' => true, 'valid' => false]);
    $p = null;
    if ($kind === 'r') { foreach ($t['regs'] as $x) if ($x['id'] === $id && regIn($t, $x)) $p = ['name' => trim($x['vorname'] . ' ' . $x['name']), 'verein' => $x['verein'], 'rolle' => 'sportler', 'klasse' => $x['klasse']]; }
    else foreach (($t['staff'] ?? []) as $x) if ($x['id'] === $id) $p = ['name' => $x['name'], 'verein' => $x['verein'], 'rolle' => $x['rolle'], 'klasse' => ''];
    out(['ok' => true, 'valid' => (bool)$p, 'p' => $p, 'turnier' => $t['name'], 'date' => $t['date']]);

case 't_mydoc':     // Verein: fehlende Unterlage eines eigenen Sportlers nachreichen
    $club = needLogin($in['tok'] ?? '');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($club, $in) {
        $k = (string)($in['kind'] ?? '');
        foreach ($t['regs'] as &$x) if ($x['id'] === ($in['rid'] ?? '') && ($x['club'] ?? '') === $club['email']) {
            if (!regAlive($t, $x)) fail('Dieser Sportler ist nicht mehr angemeldet (Frist abgelaufen)');
            if (!in_array($k, (array)($x['need'] ?? []), true)) fail('Diese Unterlage wird für diesen Sportler nicht gebraucht');
            if (empty($in['data'])) fail('Bitte eine Datei wählen');
            if ($k === 'attest') $x['attestDate'] = attestOk($t, $in['datum'] ?? '');
            saveRegDoc($t, $x, $k, ['data' => $in['data'], 'name' => $in['name'] ?? $k]);
            return ['miss' => docsMiss($x)];
        }
        fail('Nicht gefunden', 404);
    }, true);
    out(['ok' => true] + $r);

case 't_invoice':   // Rechnung herunterladen: Verein (eigene, bezahlte Bestellung) oder Veranstalter (Schlüssel)
    $GLOBALS['INV_LANG'] = in_array($_GET['lang'] ?? ($in['lang'] ?? ''), ['en', 'es', 'fr', 'ru'], true) ? ($_GET['lang'] ?? $in['lang']) : 'de';
    $in2 = $in + $_GET;
    $club = clubByToken($in2['tok'] ?? '');
    $res = withTurnier($in2['tid'] ?? '', function (&$t) use ($in2, $club) {
        $o = &$t['orders'][$in2['oid'] ?? ''];
        if (empty($o)) fail('Nicht gefunden', 404);
        $own = $club && (($o['club'] ?? '') === $club['email'] || $club['rolle'] === 'veranstalter');
        if (!$own && !tKeyOk($t, $in2['key'] ?? '')) fail('Nicht berechtigt', 403);
        if (ostat($o) !== 'paid') fail('Die Rechnung gibt es, sobald die Zahlung eingegangen ist.');
        if (time() < invoiceFrom($t)) fail('Die Rechnung wird am ' . date('d.m.Y', invoiceFrom($t)) . ' erstellt (Tag nach der Veranstaltung).');
        if (empty($o['inv'])) {
            $ts = invoiceFrom($t);
            $items = [];
            foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $o['id'] && empty($x['storno']))
                $items[] = ['text' => 'Startgeld ' . trim(explode(' – ', $t['name'])[0]) . ': ' . $x['vorname'] . ' ' . $x['name'] . ' (Kat. ' . $x['nr'] . ')', 'fee' => (float)$x['fee']];
            $cl = json_decode((string)@file_get_contents(clubsFile()), true) ?: [];
            $t['invSeq'] = (int)($t['invSeq'] ?? 0) + 1;
            $o['inv'] = ['no' => invPrefix($t) . '-' . sprintf('%04d', $t['invSeq']), 'date' => $ts, 'paid' => ((int)($o['paid'] ?? 0) > 1e9 ? (int)$o['paid'] : time()), 'items' => $items, 'name' => $cl[$o['club']]['trainer'] ?? ''];
        }
        return ['inv' => $o['inv'], 'o' => $o, 't' => $t];
    }, true);
    $pdf = invoicePdf($res['t'], $res['o'], $res['inv']);
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="WBU-Rechnung-' . $res['inv']['no'] . '.pdf"');
    header('Content-Length: ' . strlen($pdf));
    echo $pdf; exit;

case 't_checkout':  // Verein: Anmeldung abschließen -> Summe steht fest, jetzt überweisen
case 't_cartdel':   // Verein: Sportler aus dem Warenkorb nehmen
    $club = needLogin($in['tok'] ?? '');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($club, $in, $a) {
        if ($a === 't_cartdel') {
            foreach ($t['regs'] as &$x) if ($x['id'] === ($in['rid'] ?? '') && ($x['club'] ?? '') === $club['email']) {
                $o = $t['orders'][$x['oid'] ?? ''] ?? null;
                if (!$o || ostat($o) !== 'cart') fail('Nur Sportler einer noch nicht abgeschlossenen Anmeldung können entfernt werden');
                $x['storno'] = true; unset($x);
                recalcFees($t);
                return ['ok' => 1];
            }
            fail('Nicht gefunden', 404);
        }
        if (!isset($t['orders'][$in['oid'] ?? ''])) fail('Anmeldung nicht gefunden', 404);
        $o = &$t['orders'][$in['oid']];
        if ($o['club'] !== $club['email'] || ostat($o) !== 'cart') fail('Diese Anmeldung kann nicht abgeschlossen werden');
        if (orderTotal($t, $o['id']) <= 0) fail('Die Anmeldung ist leer');
        $o['closed'] = time(); $o['total'] = orderTotal($t, $o['id']);
        $names = []; foreach ($t['regs'] as $x) if (($x['oid'] ?? '') === $o['id'] && empty($x['storno'])) $names[] = "- {$x['vorname']} {$x['name']} (Kategorie {$x['nr']}): " . euro($x['fee']);
        wbuMail($o['club'], "Deine Anmeldung {$o['code']} – bitte jetzt überweisen – {$t['name']}",
            "Hallo,\n\nvielen Dank für deine Anmeldung zu {$t['name']}:\n\n" . implode("\n", $names) . "\n\nBitte überweise jetzt genau diesen Betrag:\n\n" .
            bankText($t, $o, $o['total']) . "\n\nBitte nur den Code {$o['code']} als Verwendungszweck angeben. Deine Sportler stehen schon in der Teilnehmerliste. " .
            "Wer bis zum Anmeldeschluss nicht vollständig bezahlt hat, bekommt noch eine Erinnerung mit kurzer Nachfrist – danach werden die Sportler entfernt.");
        return ['order' => orderView($t, $o)];
    }, true);
    out(['ok' => true] + $r);

case 't_pay':       // Veranstalter: Zahlungen aus dem Kontoauszug zuordnen (Betrag muss genau passen)
case 't_opaid':     // Veranstalter: Zahlung von Hand bestätigen / zurücknehmen
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in, $a) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $res = [];
        if ($a === 't_opaid') {
            if (!isset($t['orders'][$in['oid'] ?? ''])) fail('Nicht gefunden', 404);
            $o = &$t['orders'][$in['oid']];
            if (!empty($in['paid'])) { $o['paid'] = time(); $o['paidAmt'] = orderTotal($t, $o['id']); $o['manual'] = true; payMail($t, $o); }
            else { $o['paid'] = null; $o['paidAmt'] = round(array_sum($o['tx'] ?? []), 2) ?: null; $o['manual'] = false; }
            return ['res' => []];
        }
        // Buchungen je Code sammeln: jede Buchung hat eine eigene Kennung, doppelt eingelesene Auszüge zählen nicht doppelt
        foreach ((array)($in['items'] ?? []) as $it) {
            $code = strtoupper(preg_replace('/[^A-Z0-9]/i', '', (string)($it['code'] ?? '')));
            $amt = round((float)($it['amount'] ?? 0), 2);
            $ref = substr(preg_replace('/[^a-z0-9]/i', '', (string)($it['ref'] ?? '')), 0, 64) ?: md5($code . $amt);
            $found = null;
            foreach ($t['orders'] as $k => $o) if (str_replace('-', '', $o['code']) === $code) $found = $k;
            if ($found === null) { $res[] = ['code' => $it['code'], 'st' => 'unbekannt', 'amount' => $amt]; continue; }
            $o = &$t['orders'][$found];
            if ($amt > 0) { $o['tx'] = $o['tx'] ?? []; $o['tx'][$ref] = $amt; }
            unset($o);
        }
        $done = [];
        foreach ((array)($in['items'] ?? []) as $it) {
            $code = strtoupper(preg_replace('/[^A-Z0-9]/i', '', (string)($it['code'] ?? '')));
            foreach ($t['orders'] as $k => $o) if (str_replace('-', '', $o['code']) === $code && !isset($done[$k])) {
                $done[$k] = 1;
                $o = &$t['orders'][$k];
                $total = orderTotal($t, $o['id']);
                $sum = round(array_sum($o['tx'] ?? []), 2);
                if (empty($o['manual'])) {
                    $o['paidAmt'] = $sum;
                    if (empty($o['closed'])) $o['closed'] = time();
                    $o['paid'] = ($sum + 0.004 >= $total && $total > 0) ? ($o['paid'] ?: time()) : null;
                }
                payMail($t, $o);
                $res[] = ['code' => $o['code'], 'verein' => $o['verein'], 'st' => !empty($o['paid']) ? ($sum > $total + 0.004 ? 'zu viel' : 'bezahlt') : 'zu wenig', 'total' => $total, 'amount' => $sum];
                unset($o);
            }
        }
        return ['res' => $res];
    }, true);
    out(['ok' => true] + $r);

case 't_regs':
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $regs = [];
        foreach ($t['regs'] as $x) { $x['paid'] = regPaid($t, $x); $x['alive'] = regAlive($t, $x); $x['ostat'] = !empty($x['oid']) && isset($t['orders'][$x['oid']]) ? ostat($t['orders'][$x['oid']]) : ($x['paid'] ? 'paid' : ''); $regs[] = $x; }
        $os = []; foreach (($t['orders'] ?? []) as $o) $os[] = orderView($t, $o);
        return ['regs' => $regs, 'orders' => $os, 'turnier' => tPublic($t), 'konten' => kontenZahl()];
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


case 'l_create':
    // Veranstalter-Passwort – oder das Konto des WBU-Präsidenten (Superadmin) ohne Passwort
    if (!orgPassOk($in['pass'] ?? '') && !isSuper(clubByToken($in['tok'] ?? ''))) fail('Falsches Passwort', 403);
    $l = ['id' => bin2hex(random_bytes(8)), 'key' => bin2hex(random_bytes(12)), 'created' => time(), 'updated' => time(), 'snap' => null, 'results' => new stdClass()];
    if (file_put_contents(lvfile($l['id']), json_encode($l, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
    out(['ok' => true, 'lid' => $l['id'], 'key' => $l['key']]);

case 'l_push':
    $snap = $in['snap'] ?? null;
    if (!is_array($snap)) fail('Leerer Stand');
    $js = json_encode($snap, JSON_UNESCAPED_UNICODE);
    if (strlen($js) > 1500000) fail('Stand zu groß');
    withLive($in['lid'] ?? '', function (&$l) use ($in, $snap) {
        if (!tKeyOk($l, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        if (!empty($l['fc']) && (int)($snap['fcv'] ?? 0) < (int)$l['fc']['v'] && !empty($l['snap']['rows'])) { $snap['rows'] = $l['snap']['rows']; $snap['fcv'] = $l['fc']['v']; }
        if (trim((string)($snap['yt'] ?? '')) === '' && !empty($l['snap']['yt'])) $snap['yt'] = $l['snap']['yt'];
        $l['snap'] = $snap; $l['updated'] = time();
    }, true);
    $sn = $snap; $lid = (string)$in['lid'];
    if (trim((string)($sn['name'] ?? '')) !== '') {
        $nk = count($sn['rows'] ?? []);
        neueVeranstaltungMail($sn['eid'] ?? ('l' . $lid), ($sn['type'] ?? '') === 'turnier' ? 'Turnier' : 'Gala', txt($sn['name']), txt($sn['date'] ?? '', 20), txt($sn['ort'] ?? ''),
            (($sn['type'] ?? '') === 'turnier' ? 'Kämpfe in der Kampfliste: ' : 'Kämpfe auf der Fight Card: ') . $nk, 'https://www.wbu-boxing.com/live/?l=' . $lid, $in['tok'] ?? '');
    }
    if (is_array($in['k'] ?? null) && $in['k']) withKaempfer(function (&$k) use ($in, $lid) { foreach (array_slice($in['k'], 0, 600) as $x) if (is_array($x)) kPut($k, $x, 'l:' . $lid); });
    out(['ok' => true]);

case 'l_pull':
    $r = withLive($in['lid'] ?? '', function (&$l) use ($in) {
        if (!tKeyOk($l, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        return ['results' => $l['results'], 'fc' => $l['fc'] ?? null];
    });
    out(['ok' => true] + $r);

// ---- Gala: Fight Card vom Supervisor ändern (Scorecard oder WBU-Sports-Konto) ----
case 'l_fc':
case 'l_grant':
    $lid = (string)($in['lid'] ?? '');
    $okPass = hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')));
    $okEv = false;   // Supervisor im Browser: seine Scorecard-Veranstaltung (mit WBU-Passwort angelegt) gehört zu dieser Gala
    if (!$okPass && !empty($in['ev'])) { $e = json_decode((string)@file_get_contents(evfile((string)$in['ev'])), true); $okEv = is_array($e) && tKeyOk($e, $in['key'] ?? '') && ($e['lid'] ?? '') === $lid; }
    $acc = clubByToken($in['tok'] ?? '');
    $r = withLive($lid, function (&$l) use ($in, $a, $okPass, $okEv, $acc) {
        $g = (array)($l['grants'] ?? []);
        $okAcc = $acc && isset($g[$acc['email']]);
        if (!$okPass && !$okEv && !$okAcc) fail('Nicht berechtigt – bitte als Supervisor mit dem WBU-Passwort anmelden', 403);
        if ($acc && ($okPass || $okEv)) { $g[$acc['email']] = time(); $l['grants'] = $g; }   // Konto für diese Veranstaltung freischalten
        $l['sup'] = time();   // Supervisor ist verbunden -> Live-Monitor auf der Startseite
        if ($a === 'l_grant') return [];
        if (($l['snap']['type'] ?? '') !== 'gala') fail('Nur bei Galas möglich');
        $fs = [];
        foreach (array_slice((array)($in['fights'] ?? []), 0, 80) as $f) {
            if (!is_array($f)) continue;
            $x = ['id' => preg_replace('/[^A-Za-z0-9_-]/', '', (string)($f['id'] ?? '')) ?: bin2hex(random_bytes(5))];
            foreach (['red', 'blue', 'rl', 'rg', 'rw', 'rv', 'bl', 'bg', 'bw', 'bv', 'cls', 'title', 'kind', 'dur'] as $k) $x[$k] = txt($f[$k] ?? '', 120);
            $x['rounds'] = max(1, min(12, (int)($f['rounds'] ?? 6)));
            $fs[] = $x;
        }
        $v = (int)round(microtime(true) * 1000);
        $by = txt($in['by'] ?? ($acc['trainer'] ?? 'Supervisor'));
        $l['fc'] = ['v' => $v, 'by' => $by, 'fights' => $fs];
        // Stand für Punktrichter, WBU Live und WBU Time sofort anpassen (auch wenn der Veranstalter gerade nicht online ist)
        $old = []; foreach (($l['snap']['rows'] ?? []) as $row) $old[$row['mid'] ?? ''] = $row;
        $rows = [];
        foreach ($fs as $i => $f) {
            $o = $old[$f['id']] ?? [];
            $rows[] = ['mid' => $f['id'], 'no' => $i + 1, 'rd' => $f['title'], 'kl' => implode(' · ', array_filter([$f['cls'], $f['kind']])), 'a' => $f['red'], 'ac' => '',
                       'b' => $f['blue'], 'bc' => '', 'done' => !empty($o['done']), 'ai' => fcInfo($f, 'r', $l['snap']['date'] ?? ''), 'bi' => fcInfo($f, 'b', $l['snap']['date'] ?? ''),
                       'rounds' => $f['rounds'], 'dur' => $f['dur'], 'kind' => $f['kind'], 'res' => $o['res'] ?? '', 'f' => $f];
        }
        foreach ($old as $mid => $o) if (!empty($o['done']) && !in_array($mid, array_column($fs, 'id'), true)) $rows[] = $o;   // gewertete Kämpfe bleiben
        $l['snap']['rows'] = $rows; $l['snap']['fcv'] = $v; $l['snap']['fcBy'] = $by; $l['updated'] = time();
        return ['v' => $v];
    }, $a === 'l_fc' || ($acc && ($okPass || $okEv)));
    out(['ok' => true] + $r);

// ---- Resultate: Supervisor schließt die Veranstaltung ab -> Daten + PDF an den Server, E-Mail ans Büro, öffentliche Tabelle ----
case 'r_submit':
    $okPass = hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')));
    if (!$okPass && !empty($in['ev'])) { $e = json_decode((string)@file_get_contents(evfile((string)$in['ev'])), true); $okPass = is_array($e) && tKeyOk($e, $in['key'] ?? ''); }
    if (!$okPass) fail('Falsches WBU-Passwort', 403);
    $d = is_array($in['data'] ?? null) ? $in['data'] : fail('Keine Ergebnisse');
    $lid = preg_match('/^[a-f0-9]{16}$/', (string)($d['lid'] ?? '')) ? $d['lid'] : '';
    $T = function ($k, $n = 120) use ($d) { return txt($d[$k] ?? '', $n); };
    $grp = $lid ?: substr(sha1(mb_strtolower($T('name') . '|' . $T('date') . '|' . $T('ort'))), 0, 16);
    $fs = [];
    foreach (array_slice((array)($d['fights'] ?? []), 0, 150) as $f) {
        if (!is_array($f)) continue;
        $x = ['no' => (int)($f['no'] ?? 0)];
        foreach (['title', 'red', 'blue', 'ri', 'bi', 'dur', 'k', 'kn', 'w', 't', 'ref', 'art'] as $k) $x[$k] = txt($f[$k] ?? '', 160);
        $x['rounds'] = (int)($f['rounds'] ?? 0); $x['r'] = (int)($f['r'] ?? 0);
        $x['judges'] = [];
        foreach (array_slice((array)($f['judges'] ?? []), 0, 5) as $j) if (is_array($j)) $x['judges'][] = ['n' => txt($j['n'] ?? '', 80), 'r' => (int)($j['r'] ?? 0), 'b' => (int)($j['b'] ?? 0)];
        $fs[] = $x;
    }
    $ring = max(1, (int)($d['ring'] ?? 1));
    $rec = ['grp' => $grp, 'lid' => $lid, 'type' => $T('type', 10) === 'turnier' ? 'turnier' : 'gala', 'name' => $T('name'), 'promoter' => $T('promoter'), 'ort' => $T('ort'),
            'date' => $T('date', 20), 'sup' => $T('sup'), 'arzt' => $T('arzt'), 'ring' => $ring, 'fights' => $fs, 'at' => time()];
    $f = "$DIR/res_" . substr(sha1($grp . '|' . $ring . '|' . mb_strtolower($rec['sup'])), 0, 20) . '.json';
    $again = file_exists($f);
    $old = $again ? json_decode((string)@file_get_contents($f), true) : null;
    if (is_array($old) && !empty($old['hidden'])) $rec['hidden'] = 1;
    if (file_put_contents($f, json_encode($rec, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler', 500);
    // E-Mail mit PDF ans Büro
    $title = ($rec['name'] ?: 'Veranstaltung') . ' · ' . $rec['ort'] . ' · ' . $rec['date'];
    $lines = [];
    foreach ($fs as $x) $lines[] = "Kampf {$x['no']}: {$x['red']} vs. {$x['blue']}" . ($x['title'] ? " ({$x['title']})" : '') . ' – ' . ($x['kn'] ?: 'ohne Ergebnis') .
        ($x['w'] ? ' – Sieger ' . ($x['w'] === 'R' ? $x['red'] : $x['blue']) : '') . ($x['r'] ? " – Runde {$x['r']}" . ($x['t'] ? " / {$x['t']}" : '') : '');
    $body = ($again ? "KORRIGIERTER Bericht\n\n" : '') . "Veranstaltung: $title\nArt: " . ($rec['type'] === 'turnier' ? 'Turnier' : 'Gala') . ($rec['promoter'] ? "\nPromoter: {$rec['promoter']}" : '') .
            "\nSupervisor: {$rec['sup']}\nRingarzt: {$rec['arzt']}" . ($ring > 1 ? "\nRing: $ring" : '') . "\n\n" . implode("\n", $lines) .
            "\n\nDie Ergebnisse stehen auf der Resultate-Seite: https://www.wbu-boxing.com/live/?resultate=1\n\nWorld Boxing Union";
    $pdf = base64_decode(preg_replace('/^data:[^,]*,/', '', (string)($in['pdf'] ?? '')), true);
    $host = preg_replace('/^www\./', '', preg_replace('/[^a-z0-9.\-]/i', '', $_SERVER['HTTP_HOST'] ?? '')) ?: 'wbu-boxing.com';
    $bnd = 'wbu' . bin2hex(random_bytes(8));
    $hdr = "From: WBU Scorecard <noreply@$host>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"$bnd\"";
    $msg = "--$bnd\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($body)) . "\r\n";
    if ($pdf && strlen($pdf) < 8000000 && substr($pdf, 0, 4) === '%PDF') {
        $fn = 'WBU-Bericht-' . preg_replace('/[^A-Za-z0-9-]+/', '_', $rec['date'] . '-' . $rec['ort']) . '.pdf';
        $msg .= "--$bnd\r\nContent-Type: application/pdf; name=\"$fn\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"$fn\"\r\n\r\n" . chunk_split(base64_encode($pdf)) . "\r\n";
    }
    $msg .= "--$bnd--";
    $sent = @mail('info@wbu-boxing.com', '=?UTF-8?B?' . base64_encode(($again ? 'Korrektur: ' : '') . 'Ergebnisse ' . $title) . '?=', $msg, $hdr);
    out(['ok' => true, 'mail' => (bool)$sent]);

case 'r_import':   // Ergebnisse einer früheren Veranstaltung (z. B. aus der Draw-Liste) – nur mit WBU-Passwort (der einmalige Import-Schlüssel ist verbraucht)
    $okI = hash_equals('0000000000000000000000000000000000000000000000000000000000000000', hash('sha256', (string)($in['imp'] ?? '')));
    if (!$okI && !hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Nicht berechtigt', 403);
    $d = is_array($in['data'] ?? null) ? $in['data'] : fail('Keine Daten');
    $T = function ($k, $n = 120) use ($d) { return txt($d[$k] ?? '', $n); };
    $grp = substr(sha1(mb_strtolower($T('name') . '|' . $T('date') . '|' . $T('ort'))), 0, 16);
    $fs = [];
    foreach (array_slice((array)($d['fights'] ?? []), 0, 400) as $f) { if (!is_array($f)) continue;
        $x = ['no' => (int)($f['no'] ?? 0)]; foreach (['title', 'red', 'blue', 'ri', 'bi', 'dur', 'k', 'kn', 'w', 't', 'ref', 'art'] as $k) $x[$k] = txt($f[$k] ?? '', 160);
        $x['rounds'] = (int)($f['rounds'] ?? 0); $x['r'] = (int)($f['r'] ?? 0); $x['judges'] = []; $fs[] = $x; }
    $pe = function ($e) { return is_array($e) && trim((string)($e['n'] ?? '')) !== '' ? ['n' => txt($e['n'], 120), 'c' => txt($e['c'] ?? '', 120)] : null; };
    $pl = [];
    foreach (array_slice((array)($d['places'] ?? []), 0, 200) as $p) if (is_array($p)) $pl[] = ['kl' => txt($p['kl'] ?? '', 160), 'first' => $pe($p['first'] ?? null), 'second' => $pe($p['second'] ?? null), 'third' => array_values(array_filter(array_map($pe, (array)($p['third'] ?? []))))];
    $rec = ['grp' => $grp, 'lid' => '', 'type' => $T('type', 10) === 'gala' ? 'gala' : 'turnier', 'name' => $T('name'), 'promoter' => $T('promoter'), 'ort' => $T('ort'), 'date' => $T('date', 20),
            'sup' => $T('sup'), 'arzt' => $T('arzt'), 'ring' => 1, 'fights' => $fs, 'places' => $pl, 'at' => time(), 'import' => 1];
    if (file_put_contents("$DIR/res_" . substr(sha1($grp . '|import'), 0, 20) . '.json', json_encode($rec, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler', 500);
    out(['ok' => true, 'kaempfe' => count($fs), 'kategorien' => count($pl)]);

case 'r_list':
    $G = [];
    foreach (glob("$DIR/res_*.json") as $f) {
        $r = json_decode((string)@file_get_contents($f), true);
        if (!is_array($r) || (!empty($r['hidden']) && empty($in['all']))) continue;
        $g = &$G[$r['grp']];
        if (!$g) $g = ['id' => $r['grp'], 'type' => $r['type'], 'name' => $r['name'], 'promoter' => $r['promoter'], 'ort' => $r['ort'], 'date' => $r['date'], 'arzt' => $r['arzt'], 'sups' => [], 'fights' => [], 'at' => 0, 'hidden' => !empty($r['hidden']), 'lid' => $r['lid']];
        if (!empty($r['places'])) $g['places0'] = $r['places'];
        if ($r['sup'] !== '' && !in_array($r['sup'], $g['sups'], true)) $g['sups'][] = $r['sup'];
        foreach ($r['fights'] as $x) { $x['ring'] = $r['ring']; $g['fights'][] = $x; }
        $g['at'] = max($g['at'], $r['at']);
        unset($g);
    }
    foreach ($G as &$g) {
        usort($g['fights'], function ($a, $b) { return [$a['ring'], $a['no']] <=> [$b['ring'], $b['no']]; });
        if ($g['type'] === 'turnier' && $g['lid']) { $l = json_decode((string)@file_get_contents(lvfile($g['lid'])), true); $g['places'] = $l['snap']['places'] ?? []; }
        if (empty($g['places']) && !empty($g['places0'])) $g['places'] = $g['places0'];
        unset($g['places0']);
        $t = strtotime(preg_replace('/^(\d{2})\.(\d{2})\.(\d{4})$/', '$3-$2-$1', (string)$g['date'])) ?: $g['at']; $g['ts'] = $t;
        unset($g['lid']);
    }
    unset($g);
    $L = array_values($G);
    usort($L, function ($a, $b) { return $b['ts'] <=> $a['ts']; });
    out(['ok' => true, 'list' => $L]);

case 'r_hide':
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
    $n = 0;
    foreach (glob("$DIR/res_*.json") as $f) {
        $r = json_decode((string)@file_get_contents($f), true);
        if (!is_array($r) || $r['grp'] !== ($in['id'] ?? '')) continue;
        if (!empty($in['hide'])) $r['hidden'] = 1; else unset($r['hidden']);
        file_put_contents($f, json_encode($r, JSON_UNESCAPED_UNICODE)); $n++;
    }
    out(['ok' => true, 'n' => $n]);

// ---- WBU-Sports-Konto: Galas, für die dieses Konto als Supervisor freigeschaltet ist ----
case 'l_mine':
    $acc = needLogin($in['tok'] ?? '');
    $list = [];
    foreach (glob("$DIR/lv_*.json") as $f) {
        $l = json_decode(@file_get_contents($f), true);
        if (!is_array($l) || empty($l['snap']) || ($l['snap']['type'] ?? '') !== 'gala' || !isset(((array)($l['grants'] ?? []))[$acc['email']])) continue;
        $d = strtotime((string)($l['snap']['date'] ?? '')) ?: 0;
        if ($d && $d < strtotime('today') - 86400) continue;   // nach der Veranstaltung endet die Freigabe
        $list[] = ['id' => $l['id'], 'name' => $l['snap']['name'] ?? '', 'ort' => $l['snap']['ort'] ?? '', 'date' => $l['snap']['date'] ?? '', 'kampfe' => count($l['snap']['rows'] ?? [])];
    }
    out(['ok' => true, 'list' => $list]);

case 'l_result':
    // Ergebnis von der Android-App (Supervisor per Bluetooth): mit WBU-Passwort
    // … oder vom Bedienplatz (zweiter PC am Ring) mit dem Schlüssel aus dem Bedienplatz-Link
    $byKey = !empty($in['key']) && !empty($in['lid']) && tKeyOk(json_decode((string)@file_get_contents(lvfile($in['lid'])), true) ?: [], $in['key']);
    if (!$byKey && !hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
    $mid = txt($in['mid'] ?? '', 40); $res = is_array($in['res'] ?? null) ? $in['res'] : null;
    if ($mid === '' || !$res) fail('Ergebnis fehlt');
    withLive($in['lid'] ?? '', function (&$l) use ($mid, $res) {
        $r = (array)$l['results'];
        $r[$mid] = ['k' => txt($res['k'] ?? '', 8), 'w' => in_array($res['w'] ?? null, ['R', 'B'], true) ? $res['w'] : null,
                    'r' => isset($res['r']) ? (int)$res['r'] : null, 't' => txt($res['t'] ?? '', 10), 'ts' => (int)($res['ts'] ?? 0), 'by' => txt($res['by'] ?? '')];
        $l['results'] = (object)$r;
    }, true);
    out(['ok' => true]);

case 'l_clock':     // Zeitnahme: Uhr eines Rings speichern (Veranstalter-Schlüssel)
    $st = $in['st'] ?? null; $rg = (string)(int)($in['ring'] ?? 1);
    if (!is_array($st)) fail('Kein Uhrzeit-Stand');
    $d = (int)round(microtime(true) * 1000) - (int)($in['now'] ?? 0);   // Uhr des Geräts -> Serverzeit
    if (!empty($st['t0'])) $st['t0'] += $d;
    if (!empty($st['med']['t0'])) $st['med']['t0'] += $d;
    withLive($in['lid'] ?? '', function (&$l) use ($in, $st, $rg) {
        if (!tKeyOk($l, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $c = (array)($l['clock'] ?? []); $c[$rg] = $st; $l['clock'] = $c;
    }, true);
    out(['ok' => true]);

case 'l_clockget':  // WBU Time: öffentlich lesen (Fernseher)
    $rg = (string)(int)($in['ring'] ?? ($_GET['ring'] ?? 1));
    $r = withLive($in['lid'] ?? ($_GET['lid'] ?? ''), function (&$l) use ($rg) { return ['st' => ((array)($l['clock'] ?? []))[$rg] ?? null, 'name' => $l['snap']['name'] ?? '']; });
    out(['ok' => true, 'srv' => (int)round(microtime(true) * 1000)] + $r);

case 'l_get':
    // Öffentlich (WBU Live, Live-Monitor, Fernseher): ohne Geburtsdatum und genaues Gewicht – nur Alter und Gewichtsklasse.
    // Vollständig nur für Berechtigte (WBU-Passwort, Supervisor-Veranstaltung, freigeschaltetes Konto) – die brauchen es zum Bearbeiten der Fight Card.
    $lidG = (string)($in['lid'] ?? '');
    $full = hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')));
    if (!$full && !empty($in['ev'])) { $e = json_decode((string)@file_get_contents(evfile((string)$in['ev'])), true); $full = is_array($e) && tKeyOk($e, $in['key'] ?? '') && ($e['lid'] ?? '') === $lidG; }
    $accG = $full ? null : clubByToken($in['tok'] ?? '');
    $r = withLive($lidG, function (&$l) use ($full, $accG) {
        $ok = $full || ($accG && isset(((array)($l['grants'] ?? []))[$accG['email']]));
        return ['snap' => $ok ? $l['snap'] : liveOeffentlich($l['snap']), 'updated' => $l['updated'], '_sup' => $ok];
    });
    if (!empty($r['_sup'])) supTouch($lidG);
    unset($r['_sup']);
    out(['ok' => true] + $r);

case 'l_plakat':   // Veranstalter lädt das Plakat seiner Gala / seines Turniers hoch (oder löscht es) – erscheint automatisch rechts bei „WBU Shows“
    $lid = (string)($in['lid'] ?? '');
    $r = withLive($lid, function (&$l) use ($in, $DIR) {
        if (!tKeyOk($l, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $f = "$DIR/plakat_{$l['id']}.jpg";
        if (empty($in['data'])) { @unlink($f); unset($l['plakat']); return ['plakat' => 0]; }
        [$data, $ext] = decodeFile($in['data'], 10000000);
        if (!in_array($ext, ['jpg', 'png'], true)) fail('Bitte ein Foto (JPG oder PNG) hochladen');
        $im = @imagecreatefromstring($data); if (!$im) fail('Bild konnte nicht gelesen werden');
        $w = imagesx($im); $h = imagesy($im); $nw = min(900, $w); $nh = (int)round($h * $nw / $w);
        $o = imagecreatetruecolor($nw, $nh); imagecopyresampled($o, $im, 0, 0, 0, 0, $nw, $nh, $w, $h);
        imagejpeg($o, $f, 86); imagedestroy($o); imagedestroy($im);
        $l['plakat'] = time(); return ['plakat' => $l['plakat']];
    }, true);
    out(['ok' => true] + $r);

case 'l_plakatimg':  // öffentlich: Plakat einer Gala
    $id = preg_replace('/[^a-f0-9]/', '', (string)($_GET['id'] ?? ''));
    $f = "$DIR/plakat_$id.jpg";
    if ($id === '' || !file_exists($f)) { http_response_code(404); header('Content-Type: text/plain'); exit('nicht gefunden'); }
    header('Content-Type: image/jpeg'); header('Cache-Control: public, max-age=86400'); header_remove('Access-Control-Allow-Origin');
    readfile($f); exit;

case 'shows':      // öffentlich: kommende Galas und Turniere aus WBU Sports für Startseite (Plakat + Countdown)
    $list = []; $heute = date('Y-m-d');
    foreach (glob("$DIR/lv_*.json") as $f) {
        $l = json_decode((string)@file_get_contents($f), true);
        if (!is_array($l) || empty($l['snap']) || !in_array($l['snap']['type'] ?? '', ['gala', 'turnier'], true)) continue;
        $sn = $l['snap']; $d = substr((string)($sn['date'] ?? ''), 0, 10);
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) || $d < $heute) continue;
        $t = preg_match('/^\d{1,2}:\d{2}$/', (string)($sn['time'] ?? '')) ? str_pad($sn['time'], 5, '0', STR_PAD_LEFT) : '19:00';
        $list[] = ['d' => $d, 'n' => (string)($sn['name'] ?? ''), 'ort' => (string)($sn['ort'] ?? ''), 'st' => [$d . 'T' . $t],
                   'img' => !empty($l['plakat']) ? '/scorecard/api.php?a=l_plakatimg&id=' . $l['id'] . '&v=' . $l['plakat'] : '', 'lid' => $l['id']];
    }
    out(['ok' => true, 'shows' => $list]);

case 'yt_live':   // öffentlich: YouTube-Livestreams der Veranstaltungen (Veranstaltungstag) – läuft der Stream gerade?
    $heute = date('Y-m-d'); $gestern = date('Y-m-d', time() - 86400); $out = []; $cf = "$DIR/ytlive.json";
    $cache = json_decode((string)@file_get_contents($cf), true) ?: []; $neu = 0;
    foreach (glob("$DIR/lv_*.json") as $f) { $l = json_decode((string)@file_get_contents($f), true); $sn = is_array($l) ? ($l['snap'] ?? null) : null;
        if (!is_array($sn)) continue; $yt = trim((string)($sn['yt'] ?? '')); $d = substr((string)($sn['date'] ?? ''), 0, 10);
        if ($yt === '' || ($d !== $heute && $d !== $gestern)) continue;
        $c = $cache[$yt] ?? null;
        if ((!$c || time() - (int)$c['at'] > 90) && $neu < 3) { $neu++; $c = ['at' => time(), 'live' => ytIstLive($yt)]; $cache[$yt] = $c; }
        $out[] = ['lid' => $l['id'], 'name' => $sn['name'] ?? '', 'ort' => $sn['ort'] ?? '', 'date' => $d, 'yt' => $yt, 'live' => $c ? $c['live'] : null]; }
    if ($neu) @file_put_contents($cf, json_encode($cache, JSON_UNESCAPED_UNICODE));
    header('Cache-Control: no-store');
    out(['ok' => true, 'yt' => $out]);

case 'l_list':
    $list = [];
    foreach (glob("$DIR/lv_*.json") as $f) {
        $l = json_decode(@file_get_contents($f), true);
        if (!is_array($l) || empty($l['snap'])) continue;
        $sn = $l['snap'];
        // sichtbar: kürzlich bearbeitet ODER Veranstaltungstag ist heute/noch nicht vorbei (Galas/Turniere früh angelegt)
        $evDay = strtotime((string)($sn['date'] ?? '')) ?: 0;
        if (time() - ($l['updated'] ?? 0) > 3 * 86400 && !($evDay && $evDay >= strtotime('today') - 86400)) continue;
        $open = 0; foreach (($sn['rows'] ?? []) as $x) if (empty($x['done'])) $open++;
        $list[] = ['id' => $l['id'], 'name' => $sn['name'] ?? '', 'ort' => $sn['ort'] ?? '', 'date' => $sn['date'] ?? '', 'arzt' => $sn['arzt'] ?? '',
                   'type' => $sn['type'] ?? '', 'offen' => $open, 'updated' => $l['updated'], 'sup' => (int)($l['sup'] ?? 0), 'rings' => $sn['rings'] ?? 1, 'ringName' => $sn['ringName'] ?? 'Ring'];
    }
    usort($list, function ($x, $y) { return $y['updated'] - $x['updated']; });
    out(['ok' => true, 'live' => $list]);

case 'k_list':     // Kämpfer-Datenbank lesen (geschlossen)
    $tg = kAllowed($in) ? '' : kTrainerGym($in);
    if (!kAllowed($in) && $tg === '') fail('Die Kämpfer-Datenbank sehen nur Veranstalter, Supervisoren, Trainer (eigenes Gym) und die WBU – bitte einloggen', 403);
    $L = withKaempfer(function (&$k) use ($tg) { $o = []; kAusResultaten($k);
        foreach ($k as $id => $x) { if ($tg !== '' && kNorm($x['gym'] ?? '') !== $tg) continue; $P = kProfil($id, $x); $bil = [];
            foreach ($P['rec'] as $a => $v) $bil[] = $a . ' ' . $v['sum']['w'] . '-' . $v['sum']['l'] . '-' . $v['sum']['d'];
            $o[] = ['bil' => implode(' · ', $bil), 'sperre' => $P['sperre'], 'titel' => count($P['titel']), 'id' => $id, 'name' => $x['name'], 'vn' => $x['vn'] ?? '', 'nn' => $x['nn'] ?? '', 'geb' => $x['geb'] ?? '', 'sex' => $x['sex'] ?? '',
            'gym' => $x['gym'] ?? '', 'land' => $x['land'] ?? '', 'kg' => $x['kg'] ?? '', 'sp' => $x['sp'] ?? '', 'klasse' => $x['klasse'] ?? '', 'trainer' => $x['trainer'] ?? '', 'n' => $x['n'] ?? 0, 'at' => $x['at'] ?? 0]; }
        return $o; });
    usort($L, function ($a, $b) { return strcasecmp($a['gym'] ?: 'zzz', $b['gym'] ?: 'zzz') ?: strcasecmp($a['name'], $b['name']); });
    header('Cache-Control: no-store');
    out(['ok' => true, 'list' => $L]);

case 'k_save':     // Kämpfer von Hand eintragen oder korrigieren (Veranstalter / WBU)
    if (!kAllowed($in)) fail('Nicht berechtigt', 403);
    $x = $in['x'] ?? null; if (!is_array($x)) fail('Angaben fehlen');
    withKaempfer(function (&$k) use ($x) {
        $id = (string)($x['id'] ?? '');
        if ($id !== '' && isset($k[$id])) { $name = txt($x['name'] ?? '', 120); if (mb_strlen($name) >= 3) $k[$id]['name'] = $name;
            foreach (['gym' => 100, 'land' => 60, 'kg' => 8, 'trainer' => 100] as $f => $m) if (isset($x[$f])) $k[$id][$f] = txt($x[$f], $m);
            if (isset($x['geb'])) $k[$id]['geb'] = preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$x['geb']) ? $x['geb'] : '';
            $k[$id]['at'] = time(); }
        else kPut($k, $x, 'hand');
    });
    out(['ok' => true]);

case 'k_import':   // Liste einspielen (z. B. Starterliste eines früheren Turniers) – nur Name, Gym, Land
    if (!kAllowed($in)) fail('Nicht berechtigt', 403);
    $list = $in['list'] ?? []; if (!is_array($list) || !$list) fail('Die Liste ist leer');
    $src = 'import:' . preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($in['label'] ?? 'liste'));
    $n = withKaempfer(function (&$k) use ($list, $src) { $vor = count($k);
        foreach (array_slice($list, 0, 3000) as $x) if (is_array($x)) kPut($k, ['vn' => $x['vn'] ?? '', 'nn' => $x['nn'] ?? '', 'name' => $x['name'] ?? '', 'gym' => $x['gym'] ?? '', 'land' => $x['land'] ?? ''], $src);
        return [count($k) - $vor, count($k)]; });
    out(['ok' => true, 'neu' => $n[0], 'gesamt' => $n[1]]);

case 'k_suggest':  // Namensvorschläge beim Eintippen – gegen Doppel-Einträge
    $q = kNorm($in['q'] ?? ''); if (mb_strlen($q) < 3) out(['ok' => true, 'list' => [], 'andere' => 0]);
    $tok = array_values(array_filter(explode(' ', $q)));
    $hit = function ($name) use ($tok) { $w = explode(' ', kNorm($name)); foreach ($tok as $t) { $ok = false; foreach ($w as $x) if (mb_strpos($x, $t) === 0) { $ok = true; break; } if (!$ok) return false; } return true; };
    $voll = function ($name) use ($q) { return kNorm($name) === $q; };
    if (kAllowed($in)) {   // Veranstalter / Supervisor / WBU: ganze Datenbank
        $L = withKaempfer(function (&$k) use ($hit) { $o = [];
            foreach ($k as $id => $x) if ($hit($x['name'])) $o[] = ['id' => $id, 'name' => $x['name'], 'vn' => $x['vn'] ?? '', 'nn' => $x['nn'] ?? '', 'gym' => $x['gym'] ?? '', 'land' => $x['land'] ?? '', 'geb' => $x['geb'] ?? '', 'sex' => $x['sex'] ?? '', 'trainer' => $x['trainer'] ?? ''];
            return $o; });
        usort($L, function ($a, $b) { return strcasecmp($a['name'], $b['name']); });
        out(['ok' => true, 'list' => array_slice($L, 0, 10), 'andere' => 0]);
    }
    $me = needLogin($in['tok'] ?? '');   // Verein / Trainer: nur die eigenen, früher gemeldeten Sportler – fremde Daten bleiben geschlossen
    $own = []; $seen = [];
    foreach (glob("$DIR/tu_*.json") as $f) { $t = json_decode((string)@file_get_contents($f), true); if (!is_array($t)) continue;
        foreach (($t['regs'] ?? []) as $r) { if (($r['club'] ?? '') !== $me['email'] || !empty($r['storno'])) continue;
            $n = trim(($r['vorname'] ?? '') . ' ' . ($r['name'] ?? '')); $key = kNorm($n) . '|' . ($r['geb'] ?? '');
            if (isset($seen[$key]) || !$hit($n)) continue; $seen[$key] = 1;
            $own[] = ['id' => '', 'name' => $n, 'vn' => $r['vorname'] ?? '', 'nn' => $r['name'] ?? '', 'gym' => $r['verein'] ?? '', 'land' => $r['land'] ?? '', 'geb' => $r['geb'] ?? '', 'sex' => $r['sex'] ?? '', 'trainer' => $r['trainer'] ?? ''];
        } }
    $andere = withKaempfer(function (&$k) use ($voll, $own) { $n = 0; foreach ($k as $x) if ($voll($x['name'])) { $mine = false; foreach ($own as $o) if (kNorm($o['name']) === kNorm($x['name']) && ($o['geb'] === ($x['geb'] ?? '') || ($x['geb'] ?? '') === '')) $mine = true; if (!$mine) $n++; } return $n; });
    out(['ok' => true, 'list' => array_slice($own, 0, 10), 'andere' => $andere]);

case 'k_del':      // Eintrag löschen (nur WBU-Passwort)
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Löschen nur mit dem WBU-Passwort', 403);
    withKaempfer(function (&$k) use ($in) { unset($k[(string)($in['id'] ?? '')]); });
    out(['ok' => true]);

// ===================== WBU Sports: Veranstaltungen auf dem Server (für alle Geräte, Supervisor-Zugang) =====================
case 'tts_info':  // Ringsprecher: ist eine Google-Stimme eingerichtet? Welche Stimme / welches Tempo?
    $tc = ttsCfg(); out(['ok' => true, 'google' => ttsKey() !== '', 'voice' => $tc['voice'], 'rate' => $tc['rate'], 'pitch' => $tc['pitch'], 'nrate' => $tc['nrate'], 'npitch' => $tc['npitch'], 'vowel' => $tc['vowel'], 'voices' => TTS_VOICES]);

case 'tts_key':   // Ringsprecher: Google-Schlüssel speichern (nur WBU-Passwort / WBU-Konto)
    if (!kIsSuper($in)) fail('Nur mit dem WBU-Supervisor-Passwort', 403);
    $k = trim((string)($in['key'] ?? ''));
    if ($k !== '' && !preg_match('/^[A-Za-z0-9_\-]{20,80}$/', $k)) fail('Der Schlüssel sieht nicht richtig aus');
    if (!empty($in['delKey'])) @unlink("$DIR/tts_key.txt"); elseif ($k !== '') file_put_contents("$DIR/tts_key.txt", $k, LOCK_EX);
    if (isset($in['voice']) || isset($in['rate']) || isset($in['pitch'])) { $tc = ttsCfg();
        if (isset($in['vowel'])) $tc['vowel'] = !empty($in['vowel']);
        if (isset($in['nrate'])) $tc['nrate'] = max(0.6, min(1.1, round((float)$in['nrate'], 2)));
        if (isset($in['npitch'])) $tc['npitch'] = max(0.8, min(1.1, round((float)$in['npitch'], 2)));
        if (isset($in['pitch'])) $tc['pitch'] = max(0.8, min(1.1, round((float)$in['pitch'], 2)));
        if (isset($in['voice']) && in_array($in['voice'], TTS_VOICES, true)) $tc['voice'] = $in['voice'];
        if (isset($in['rate'])) $tc['rate'] = max(0.6, min(1.3, round((float)$in['rate'], 2)));
        file_put_contents("$DIR/tts_cfg.json", json_encode($tc), LOCK_EX); }
    out(['ok' => true, 'google' => ttsKey() !== '']);

case 'tts':       // Ringsprecher: Text -> MP3 (Google Chirp 3 HD, kostenlos bis 1 Mio. Zeichen/Monat), mit Zwischenspeicher
    $txt = trim(mb_substr((string)($in['text'] ?? ''), 0, 400));
    $lang = (string)($in['lang'] ?? 'de');
    $VO = ['de' => 'de-DE', 'en' => 'en-US', 'es' => 'es-ES', 'fr' => 'fr-FR', 'ru' => 'ru-RU'];
    if ($txt === '' || !isset($VO[$lang])) fail('Kein Text');
    $key = ttsKey(); if ($key === '') fail('Keine Google-Stimme eingerichtet', 409);
    $tc = ttsCfg(); $vn = (isset($in['voice']) && in_array($in['voice'], TTS_VOICES, true)) ? $in['voice'] : $tc['voice'];
    $rate = isset($in['rate']) ? max(0.6, min(1.3, round((float)$in['rate'], 2))) : $tc['rate'];
    $voice = $VO[$lang] . '-Chirp3-HD-' . $vn;
    // Tonlage: wird beim Abspielen tiefer gestellt (langsamer abgespielt) – Google spricht dafür entsprechend schneller
    $pitch = isset($in['pitch']) ? max(0.8, min(1.1, round((float)$in['pitch'], 2))) : $tc['pitch'];
    $sr = max(0.5, min(2.0, round($rate / $pitch, 3)));
    @mkdir("$DIR/tts", 0755, true);
    $f = "$DIR/tts/" . sha1($voice . '|' . $sr . '|' . $txt) . '.mp3';
    if (!is_file($f)) {
        // Schutz: nur angemeldete Veranstalter/Supervisor dürfen neue Ansagen erzeugen
        if (!kIsSuper($in) && !clubByToken($in['tok'] ?? '')) fail('Bitte anmelden', 401);
        $req = json_encode(['input' => ['text' => $txt], 'voice' => ['languageCode' => $VO[$lang], 'name' => $voice],
            'audioConfig' => ['audioEncoding' => 'MP3', 'speakingRate' => $sr]], JSON_UNESCAPED_UNICODE);
        $c = curl_init('https://texttospeech.googleapis.com/v1/text:synthesize?key=' . urlencode($key));
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => $req, CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json']]);
        $r = json_decode((string)curl_exec($c), true); $code = curl_getinfo($c, CURLINFO_HTTP_CODE); curl_close($c);
        if ($code !== 200 || empty($r['audioContent'])) fail('Google-Stimme: ' . ($r['error']['message'] ?? ('Fehler ' . $code)), 502);
        file_put_contents($f, base64_decode($r['audioContent']), LOCK_EX);
    }
    out(['ok' => true, 'mp3' => base64_encode((string)file_get_contents($f)), 'pitch' => $pitch]);

case 'ws_save':   // ganze Veranstaltung speichern – Veranstalter (Konto), Supervisor (WBU-Passwort) oder WBU
case 'ws_list':
case 'ws_get':
case 'ws_del':
case 'ws_lock':
    $sup = hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')));
    $acc = clubByToken($in['tok'] ?? ''); $su = $acc && isSuper($acc);
    if (!$sup && !$acc) fail('Bitte einloggen', 401);
    $mail = $acc ? strtolower($acc['email']) : '';
    $wsf = function ($id) use ($DIR) { if (!preg_match('/^[A-Za-z0-9_-]{3,40}$/', (string)$id)) fail('Ungültige Veranstaltung'); return "$DIR/ws_$id.json"; };
    $mayAll = $sup || $su;
    if ($a === 'ws_list') { $o = [];
        foreach (glob("$DIR/ws_*.json") as $f) { $w = json_decode((string)@file_get_contents($f), true); if (!is_array($w) || empty($w['ev'])) continue;
            if (!$mayAll && ($w['owner'] ?? '') !== $mail) continue; $e = $w['ev'];
            $o[] = ['id' => $e['id'], 'type' => $e['type'] ?? '', 'name' => $e['name'] ?? '', 'ort' => $e['ort'] ?? '', 'date' => $e['date'] ?? '', 'mt' => $w['mt'] ?? 0, 'by' => $w['by'] ?? '',
                'n' => ($e['type'] ?? '') === 'gala' ? count($e['fights'] ?? []) : count($e['cats'] ?? []), 'lock' => $w['lock'] ?? null]; }
        usort($o, function ($x, $y) { return strcmp((string)$y['date'], (string)$x['date']); });
        out(['ok' => true, 'list' => $o, 'sup' => $mayAll]); }
    $f = $wsf($in['id'] ?? ($in['ev']['id'] ?? ''));
    $fh = fopen($f, 'c+'); flock($fh, LOCK_EX); $w = json_decode((string)stream_get_contents($fh), true) ?: [];
    $isOwner = ($w['owner'] ?? '') !== '' && ($w['owner'] ?? '') === $mail;
    if (!empty($w['ev']) && !$mayAll && !$isOwner) { flock($fh, LOCK_UN); fclose($fh); fail('Diese Veranstaltung gehört einem anderen Veranstalter', 403); }
    $res = ['ok' => true];
    if ($a === 'ws_get') { if (empty($w['ev'])) { flock($fh, LOCK_UN); fclose($fh); fail('Veranstaltung nicht gefunden', 404); } $res += ['ev' => $w['ev'], 'mt' => $w['mt'] ?? 0, 'lock' => $w['lock'] ?? null]; }
    elseif ($a === 'ws_save') { $ev = $in['ev'] ?? null; if (!is_array($ev) || empty($ev['id'])) { flock($fh, LOCK_UN); fclose($fh); fail('Leere Veranstaltung'); }
        if (strlen(json_encode($ev)) > 4000000) { flock($fh, LOCK_UN); fclose($fh); fail('Veranstaltung zu groß'); }
        if (empty($w['owner']) && $mail && !$sup) $w['owner'] = $mail;
        if (!empty($w['ev']['ytAdm']) && trim((string)($ev['yt'] ?? '')) === '' && !empty($w['ev']['yt'])) { $ev['yt'] = $w['ev']['yt']; $ev['ytAdm'] = 1; }
        $w['ev'] = $ev; $w['mt'] = round(microtime(true) * 1000); $w['by'] = txt($in['name'] ?? ($acc['trainer'] ?? 'Supervisor'), 60); $res['mt'] = $w['mt']; }
    elseif ($a === 'ws_del') { if (!$su && !$isOwner) { flock($fh, LOCK_UN); fclose($fh); fail('Löschen nur der Veranstalter oder die WBU', 403); } $w = ['deleted' => time()]; }
    elseif ($a === 'ws_lock') { $L = $w['lock'] ?? null; $dev = txt($in['dev'] ?? '', 40);
        if (!$L || ($L['dev'] ?? '') === $dev || time() - (int)($L['at'] ?? 0) > 90 || !empty($in['take'])) $w['lock'] = $L = ['dev' => $dev, 'name' => txt($in['name'] ?? '', 60), 'at' => time(), 'since' => ($L && ($L['dev'] ?? '') === $dev) ? ($L['since'] ?? time()) : time()];
        $res['lock'] = $L; }
    ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($w, JSON_UNESCAPED_UNICODE)); fflush($fh); flock($fh, LOCK_UN); fclose($fh);
    out($res);

case 'k_profil':   // Sportlerprofil: Bilanz je Sportart, Kämpfe, Titel, Sperre, Gewichte, Änderungen
    $tg = kAllowed($in) ? '' : kTrainerGym($in); $su = kIsSuper($in);
    if (!kAllowed($in) && $tg === '') fail('Nicht berechtigt', 403);
    $id = (string)($in['id'] ?? '');
    $r = withKaempfer(function (&$k) use ($id, $tg, $su, $in) { if (!isset($k[$id])) fail('Kämpfer nicht gefunden', 404); $x = $k[$id];
        if ($tg !== '' && kNorm($x['gym'] ?? '') !== $tg) fail('Nur Kämpfer aus deinem Gym', 403);
        $me = clubByToken($in['tok'] ?? ''); $trainerHier = $me && $me['rolle'] === 'trainer' && kNorm($me['club'] ?? '') === kNorm($x['gym'] ?? '');
        return kProfil($id, $x) + ['name' => $x['name'], 'gym' => $x['gym'] ?? '', 'kgh' => $x['kgh'] ?? [], 'log' => array_slice($x['log'] ?? [], -30),
            'darf' => $su ? 'super' : ($trainerHier ? 'trainer' : ''), 'arten' => K_ARTEN]; });
    out(['ok' => true] + $r);

case 'k_bilanz':   // Bilanz von anderswo nachtragen: Trainer (gleiches Gym) nur nach oben, WBU auch nach unten
    $su = kIsSuper($in); $me = clubByToken($in['tok'] ?? '');
    $art = (string)($in['art'] ?? ''); if (!in_array($art, K_ARTEN, true)) fail('Unbekannte Sportart');
    $neu = []; foreach (kLeer() as $f => $_) $neu[$f] = max(0, min(999, (int)($in['v'][$f] ?? 0)));
    if ($neu['wko'] > $neu['w'] || $neu['lko'] > $neu['l']) fail('„davon K.O.“ kann nicht größer sein als Siege bzw. Niederlagen');
    withKaempfer(function (&$k) use ($in, $art, $neu, $su, $me) { $id = (string)($in['id'] ?? ''); if (!isset($k[$id])) fail('Kämpfer nicht gefunden', 404);
        $x = &$k[$id]; $alt = array_merge(kLeer(), array_map('intval', (array)($x['rec'][$art] ?? [])));
        if (!$su) { if (!$me || $me['rolle'] !== 'trainer' || kNorm($me['club'] ?? '') !== kNorm($x['gym'] ?? '')) fail('Die Bilanz ändert nur der Trainer aus dem gleichen Gym (Rolle „Trainer“) oder die WBU', 403);
            foreach ($neu as $f => $v) if ($v < $alt[$f]) fail('Die Bilanz kann nur ergänzt werden – Zahlen dürfen nicht kleiner werden. Fehler bitte an die WBU melden.'); }
        $x['rec'][$art] = $neu;
        $x['log'][] = ['at' => time(), 'by' => $su ? 'WBU' : ($me['trainer'] . ' (' . $me['club'] . ')'), 'was' => "Bilanz $art (extern): " . implode('-', [$alt['w'], $alt['l'], $alt['d']]) . ' → ' . implode('-', [$neu['w'], $neu['l'], $neu['d']])];
        $x['log'] = array_slice($x['log'], -60); });
    out(['ok' => true]);

case 'k_titel':    // Titel eintragen: WBU-Titel nur WBU; Trainer nur Titel anderer Verbände (Vermerk „extern“) – löschen nur WBU
    $su = kIsSuper($in); $me = clubByToken($in['tok'] ?? '');
    withKaempfer(function (&$k) use ($in, $su, $me) { $id = (string)($in['id'] ?? ''); if (!isset($k[$id])) fail('Kämpfer nicht gefunden', 404); $x = &$k[$id];
        $trainer = $me && $me['rolle'] === 'trainer' && kNorm($me['club'] ?? '') === kNorm($x['gym'] ?? '');
        if (!$su && !$trainer) fail('Titel trägt nur der Trainer aus dem gleichen Gym oder die WBU ein', 403);
        if (isset($in['del'])) { if (!$su) fail('Titel löschen nur die WBU', 403); $t = $x['titel'][(int)$in['del']] ?? null; array_splice($x['titel'], (int)$in['del'], 1);
            $x['log'][] = ['at' => time(), 'by' => 'WBU', 'was' => 'Titel gelöscht: ' . ($t['t'] ?? '')]; return; }
        $t = txt($in['t'] ?? '', 160); if (mb_strlen($t) < 3) fail('Bitte den Titel eintragen');
        $ext = $su ? (int)!empty($in['ext']) : 1;
        if (!$su && preg_match('/\bwbu\b|world boxing union/i', $t)) fail('WBU-Titel trägt nur die WBU ein');
        $x['titel'][] = ['t' => $t, 'j' => txt($in['j'] ?? '', 4), 'ext' => $ext, 'by' => $su ? 'WBU' : $me['trainer']];
        $x['log'][] = ['at' => time(), 'by' => $su ? 'WBU' : $me['trainer'], 'was' => 'Titel eingetragen: ' . $t . ($ext ? ' (extern)' : '')]; });
    out(['ok' => true]);

case 'k_sperre':   // nur WBU: Sperre von Hand eintragen (z. B. K.O. bei einem anderen Verband) oder alle Sperren aufheben (ärztliche Freigabe)
    if (!kIsSuper($in)) fail('Sperren ändert nur die WBU', 403);
    withKaempfer(function (&$k) use ($in) { $id = (string)($in['id'] ?? ''); if (!isset($k[$id])) fail('Kämpfer nicht gefunden', 404); $x = &$k[$id];
        if (!empty($in['frei'])) { $x['frei'] = time(); $x['log'][] = ['at' => time(), 'by' => 'WBU', 'was' => 'Sperre aufgehoben' . (($g = txt($in['grund'] ?? '', 120)) ? ": $g" : '')]; return; }
        $bis = (string)($in['bis'] ?? ''); if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $bis)) fail('Bitte ein Datum wählen');
        $x['sperren'][] = ['bis' => $bis, 'grund' => txt($in['grund'] ?? '', 160) ?: 'von der WBU eingetragen', 'at' => time()];
        $x['log'][] = ['at' => time(), 'by' => 'WBU', 'was' => 'Sperre bis ' . date('d.m.Y', kTs($bis)) . ' eingetragen']; });
    out(['ok' => true]);

default:
    fail('Unbekannte Aktion');
}
