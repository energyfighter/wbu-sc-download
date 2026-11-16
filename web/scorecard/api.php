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


// ===================== Live =====================
function lvfile($id) {
    global $DIR;
    if (!is_string($id) || !preg_match('/^[a-f0-9]{16}$/', $id)) fail('Live-Veranstaltung unbekannt', 404);
    return "$DIR/lv_$id.json";
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
function liveRows($lid) {
    $f = @file_get_contents(lvfile($lid));
    $l = json_decode((string)$f, true);
    return is_array($l) ? ($l['snap'] ?? null) : null;
}


// ---- Unterlagen (Ausschreibung, Formulare, unterschriebene Erklärungen) ----
const DOC_KINDS = ['aus' => 'Ausschreibung', 'ablauf' => 'Ablaufplan', 'haft' => 'Haftungsausschluss / Teilnahmeerklärung', 'eltern' => 'Einverständniserklärung der Eltern',
                   'attest' => 'Sportärztliches Attest / Medical Check'];
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
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
    // kein zweites Turnier mit gleichem Namen und Datum
    foreach (glob("$DIR/tu_*.json") as $f) { $o = json_decode((string)@file_get_contents($f), true);
        if (is_array($o) && mb_strtolower(trim($o['name'] ?? '')) === mb_strtolower(trim((string)($m['name'] ?? ''))) && ($o['date'] ?? '') === ($m['date'] ?? ''))
            fail('Dieses Turnier ist schon veröffentlicht (gleicher Name und Datum). Unter „Auf dem Server veröffentlicht“ kannst du das alte löschen.', 409); }
    $own = clubByToken($in['tok'] ?? '');
    $t = ['id' => bin2hex(random_bytes(8)), 'owner' => $own ? $own['email'] : '', 'key' => bin2hex(random_bytes(12)), 'created' => time(), 'regs' => [], 'nextNo' => 1];
    tMeta($t, $m);
    if (file_put_contents(tufile($t['id']), json_encode($t, JSON_UNESCAPED_UNICODE)) === false) fail('Speicherfehler – Schreibrechte für den Ordner „daten“ prüfen', 500);
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

case 't_docget':   // mit Login: Ausschreibung / Formulare herunterladen
    needLogin((string)($_GET['tok'] ?? $in['tok'] ?? ''));
    $tid = (string)($_GET['tid'] ?? $in['tid'] ?? ''); $kind = (string)($_GET['kind'] ?? $in['kind'] ?? '');
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

case 'c_me':
    $me = clubByToken($in['tok'] ?? '');
    if (!$me) fail('Bitte neu einloggen', 403);
    out(['ok' => true, 'me' => $me]);

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
        return ['no' => $reg['no'], 'name' => $t['name']];
    }, true);
    out(['ok' => true] + $res);


case 't_import':   // Veranstalter: in WBU Sports eingetragene / vorab gemeldete Sportler online eintragen
    $list = $in['list'] ?? [];
    if (!is_array($list)) fail('Liste fehlt');
    $r = withTurnier($in['tid'] ?? '', function (&$t) use ($in, $list) {
        if (!tKeyOk($t, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        $ids = [];
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
        }
        return ['ids' => $ids];
    }, true);
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
        return ['regs' => $mine, 'year' => substr($t['date'] ?: date('Y-m-d'), 0, 4), 'orders' => $os, 'bank' => ['inhaber' => $t['inhaber'], 'iban' => $t['iban'], 'bic' => $t['bic']], 'schluss' => $t['schluss'] ?: $t['date']];
    });
    out(['ok' => true] + $r);

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
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
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
        $l['snap'] = $snap; $l['updated'] = time();
    }, true);
    out(['ok' => true]);

case 'l_pull':
    $r = withLive($in['lid'] ?? '', function (&$l) use ($in) {
        if (!tKeyOk($l, $in['key'] ?? '')) fail('Nicht berechtigt', 403);
        return ['results' => $l['results']];
    });
    out(['ok' => true] + $r);

case 'l_result':
    // Ergebnis von der Android-App (Supervisor per Bluetooth): mit WBU-Passwort
    if (!hash_equals(SUP_PASS_SHA256, hash('sha256', (string)($in['pass'] ?? '')))) fail('Falsches WBU-Passwort', 403);
    $mid = txt($in['mid'] ?? '', 40); $res = is_array($in['res'] ?? null) ? $in['res'] : null;
    if ($mid === '' || !$res) fail('Ergebnis fehlt');
    withLive($in['lid'] ?? '', function (&$l) use ($mid, $res) {
        $r = (array)$l['results'];
        $r[$mid] = ['k' => txt($res['k'] ?? '', 8), 'w' => in_array($res['w'] ?? null, ['R', 'B'], true) ? $res['w'] : null,
                    'r' => isset($res['r']) ? (int)$res['r'] : null, 't' => txt($res['t'] ?? '', 10), 'ts' => (int)($res['ts'] ?? 0), 'by' => txt($res['by'] ?? '')];
        $l['results'] = (object)$r;
    }, true);
    out(['ok' => true]);

case 'l_get':
    $r = withLive($in['lid'] ?? '', function (&$l) { return ['snap' => $l['snap'], 'updated' => $l['updated']]; });
    out(['ok' => true] + $r);

case 'l_list':
    $list = [];
    foreach (glob("$DIR/lv_*.json") as $f) {
        $l = json_decode(@file_get_contents($f), true);
        if (!is_array($l) || empty($l['snap'])) continue;
        if (time() - ($l['updated'] ?? 0) > 3 * 86400) continue;
        $sn = $l['snap'];
        $open = 0; foreach (($sn['rows'] ?? []) as $x) if (empty($x['done'])) $open++;
        $list[] = ['id' => $l['id'], 'name' => $sn['name'] ?? '', 'ort' => $sn['ort'] ?? '', 'date' => $sn['date'] ?? '',
                   'type' => $sn['type'] ?? '', 'offen' => $open, 'updated' => $l['updated'], 'rings' => $sn['rings'] ?? 1];
    }
    usort($list, function ($x, $y) { return $y['updated'] - $x['updated']; });
    out(['ok' => true, 'live' => $list]);

default:
    fail('Unbekannte Aktion');
}
