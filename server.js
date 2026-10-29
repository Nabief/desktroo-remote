// Desktroo Remote — © 2026 Mdm-services.fr. Tous droits réservés.
// Logiciel propriétaire, distribué avec l'abonnement Desktroo (https://desktroo.fr).
//
// Serveur d'assistance à distance auto-hébergé, installé depuis Desktroo Apps.
// Ce programme :
//   - lance et surveille le serveur RustDesk officiel, non modifié (hbbs : identifiants, hbbr : relais ; AGPL-3.0,
//     https://github.com/rustdesk/rustdesk-server) ; ses données (clé, base des postes) sont dans /data ;
//   - port 8080 : le panneau, derrière la session Desktroo (en-têtes posés par son nginx, acceptés seulement avec le
//     secret de cette installation) ;
//   - port 8081 (ouvert par Desktroo sur le port 21114 du NAS) : l'API que les clients RustDesk appellent d'eux-mêmes
//     (présence et fiche du poste). Seuls les postes déjà enregistrés auprès de ce serveur, avec sa clé, sont retenus.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = 8080;
const API_PORT = 8081;
const DATA = process.env.DATA_DIR || '/data';
const SECRET = process.env.DESKTROO_APP_SECRET || '';
const HOST = String(process.env.RD_PUBLIC_HOST || '').trim().toLowerCase();
const BIN = process.env.RD_BIN_DIR || '/usr/local/bin';
const PUB = path.join(__dirname, 'public');
const DEVICES = path.join(DATA, 'devices.json');
const KEY_FILE = path.join(DATA, 'id_ed25519.pub');
const DB_FILE = path.join(DATA, 'db_v2.sqlite3');
const VERSION = process.env.APP_VERSION || 'dev';
const RD_SERVER_VERSION = process.env.RD_SERVER_VERSION || '';
const PORTS = { nat: 21115, id: 21116, relay: 21117, api: 21114 };
const ONLINE_MS = 60_000;          // un client allumé se signale toutes les 15 s
const MAX_DEVICES = 5000;
const MAX_BODY = 16 * 1024;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^\d{1,3}(?:\.\d{1,3}){3}$/;
const ID_RE = /^[A-Za-z0-9_-]{6,32}$/;
fs.mkdirSync(DATA, { recursive: true });

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ── Serveur RustDesk : lancement et surveillance ───────────────────────────
const LOG_KEEP = 400;
const procs = {};
function supervise(name, args) {
  const p = { name, args, child: null, pid: 0, since: 0, restarts: 0, lastExit: null, lines: [], delay: 1000, stopping: false };
  procs[name] = p;
  const push = (chunk) => {
    for (const line of String(chunk).replace(/\x1b\[[0-9;]*m/g, '').split('\n')) {
      if (!line.trim()) continue;
      p.lines.push(line.slice(0, 500));
      if (p.lines.length > LOG_KEEP) p.lines.splice(0, p.lines.length - LOG_KEEP);
    }
  };
  const start = () => {
    if (p.stopping) return;
    // Le secret de Desktroo n'a rien à faire dans le serveur RustDesk : il n'en reçoit pas une copie.
    const env = { PATH: process.env.PATH, TZ: process.env.TZ || '', HOME: '/tmp' };
    let child;
    try { child = spawn(path.join(BIN, name), args, { cwd: DATA, env, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { push('[desktroo] lancement impossible : ' + e.message); return later(); }
    p.child = child; p.pid = child.pid || 0; p.since = Date.now();
    child.stdout.on('data', push); child.stderr.on('data', push);
    child.on('error', (e) => push('[desktroo] ' + e.message));
    child.on('exit', (code, sig) => {
      p.child = null; p.pid = 0; p.lastExit = { code, sig, at: Date.now() };
      if (p.stopping) return;
      push(`[desktroo] ${name} s'est arrêté (${sig || code}) : redémarrage dans ${Math.round(p.delay / 1000)} s`);
      later();
    });
    setTimeout(() => { if (p.child === child) p.delay = 1000; }, 60_000);   // stable une minute : délai remis à zéro
  };
  const later = () => {
    p.restarts++;
    setTimeout(start, p.delay);
    p.delay = Math.min(p.delay * 2, 60_000);
  };
  start();
  return p;
}
function procState(p) {
  return { running: !!p.child, pid: p.pid, since: p.since, restarts: p.restarts, lastExit: p.lastExit };
}

// ── Clé publique et chaîne de configuration des clients ────────────────────
function readKey() {
  try { const k = fs.readFileSync(KEY_FILE, 'utf8').trim(); return /^[A-Za-z0-9+/=]{40,60}$/.test(k) ? k : ''; } catch (_) { return ''; }
}
function apiUrl() { return HOST ? `http://${HOST}:${PORTS.api}` : ''; }
// Format lu par le client RustDesk (custom_server.rs) : JSON {host, key, api, relay}, base64 « URL », renversé.
// Il s'importe par « rustdesk --config <chaîne> » ou dans le nom du programme : rustdesk-licensed-<chaîne>.exe.
function configString(key) {
  if (!HOST || !key) return '';
  const json = JSON.stringify({ host: HOST, key, api: apiUrl(), relay: `${HOST}:${PORTS.relay}` });
  return Buffer.from(json, 'utf8').toString('base64url').split('').reverse().join('');
}

// ── Postes : base de hbbs (enregistrés) + présence et fiches envoyées par les clients ──
let DatabaseSync = null;
try { ({ DatabaseSync } = require('node:sqlite')); } catch (_) { log('node:sqlite indisponible : liste des postes réduite aux signaux de présence'); }
let peersCache = { at: 0, map: null };
function hbbsPeers() {
  if (!DatabaseSync || !fs.existsSync(DB_FILE)) return null;
  if (peersCache.map && Date.now() - peersCache.at < 5000) return peersCache.map;
  let db;
  try {
    db = new DatabaseSync(DB_FILE, { readOnly: true });
    const map = new Map();
    for (const r of db.prepare('SELECT id, uuid, created_at, info FROM peer LIMIT 20000').all()) {
      let ip = '';
      try { ip = String(JSON.parse(r.info || '{}').ip || ''); } catch (_) {}
      map.set(String(r.id), { uuid: r.uuid ? Buffer.from(r.uuid) : null, created: String(r.created_at || ''), ip: ip.replace(/^::ffff:/, '') });
    }
    peersCache = { at: Date.now(), map };
    return map;
  } catch (e) {
    log('base des postes illisible :', e.message);
    return peersCache.map;
  } finally { try { db && db.close(); } catch (_) {} }
}

function readJsonFile(p, dflt) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return dflt; } }
function writeJsonFile(p, obj) {
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
  fs.renameSync(tmp, p);
}
// { id: { hostname, os, cpu, memory, username, version, firstSeen, lastSeen, lastIp, conns, label, note, hidden, sysinfoAt } }
let devices = readJsonFile(DEVICES, {});
if (!devices || typeof devices !== 'object' || Array.isArray(devices)) devices = {};
let dirty = false, lastSave = 0;
function save(force) {
  if (!dirty) return;
  if (!force && Date.now() - lastSave < 30_000) return;   // la présence change toutes les 15 s : écriture groupée
  try { writeJsonFile(DEVICES, devices); dirty = false; lastSave = Date.now(); } catch (e) { log('enregistrement des postes impossible :', e.message); }
}
setInterval(() => save(false), 10_000).unref();

const clip = (v, n) => String(v == null ? '' : v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, n);

// Le poste existe-t-il dans la base de hbbs, avec le même identifiant matériel ? null si la base est illisible.
function checkPeer(id, uuidB64) {
  const peers = hbbsPeers();
  if (!peers) return null;
  const p = peers.get(id);
  if (!p) return false;
  if (p.uuid && p.uuid.length) {   // le client envoie toujours l'identifiant matériel donné à l'enregistrement
    if (typeof uuidB64 !== 'string' || !/^[A-Za-z0-9+/=]{4,200}$/.test(uuidB64)) return false;
    if (!Buffer.from(uuidB64, 'base64').equals(p.uuid)) return false;
  }
  return true;
}
function deviceFor(id, ip) {
  let d = devices[id];
  if (!d) {
    if (Object.keys(devices).length >= MAX_DEVICES) return null;
    d = devices[id] = { firstSeen: Date.now() };
  }
  d.lastSeen = Date.now();
  if (ip) d.lastIp = ip;
  if (d.hidden) delete d.hidden;      // un poste retiré de la liste qui se reconnecte y revient
  dirty = true;
  return d;
}

function deviceList() {
  const peers = hbbsPeers() || new Map();
  const ids = new Set([...peers.keys(), ...Object.keys(devices)]);
  const now = Date.now();
  const out = [];
  for (const id of ids) {
    const d = devices[id] || {}, p = peers.get(id) || {};
    if (d.hidden) continue;
    out.push({
      id, label: d.label || '', note: d.note || '', hostname: d.hostname || '', os: d.os || '', username: d.username || '',
      cpu: d.cpu || '', memory: d.memory || '', version: d.version || '',
      ip: d.lastIp || p.ip || '', registered: p.created || '', lastSeen: d.lastSeen || 0,
      online: !!d.lastSeen && now - d.lastSeen < ONLINE_MS, inSession: !!(d.conns && d.conns.length && now - d.lastSeen < ONLINE_MS),
      reporting: !!d.lastSeen,
    });
  }
  out.sort((a, b) => (b.online - a.online) || (b.lastSeen - a.lastSeen) || a.id.localeCompare(b.id));
  return out;
}

// ── HTTP commun ────────────────────────────────────────────────────────────
const HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};
const PANEL_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
  + "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'";
function send(res, code, body, type, extra) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(code, Object.assign({ 'Content-Type': type || 'text/plain; charset=utf-8', 'Content-Length': b.length,
    'Cache-Control': 'no-store' }, HEADERS, extra || {}));
  res.end(b);
}
const json = (res, code, obj, extra) => send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8', extra);
function fail(code, status) { const e = new Error(code); e.code = code; e.status = status || 400; return e; }
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const parts = []; let n = 0, over = false;
    req.on('data', (c) => {
      if (over) return;                       // la suite est lue et jetée : la réponse 413 part proprement
      n += c.length;
      if (n > max) { over = true; parts.length = 0; reject(fail('too_large', 413)); } else parts.push(c);
    });
    req.on('end', () => { if (!over) resolve(Buffer.concat(parts).toString('utf8')); });
    req.on('error', reject);
  });
}
async function readJson(req, max) {
  const t = await readBody(req, max || MAX_BODY);
  if (!t) return {};
  let o; try { o = JSON.parse(t); } catch (_) { throw fail('bad_request'); }
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw fail('bad_request');
  return o;
}
function safeEq(a, b) {
  const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

// ── API des clients RustDesk (port 21114 du NAS) ───────────────────────────
// Protocole du client (src/hbbs_http/sync.rs) : POST /api/heartbeat toutes les 15 s (3 s en session),
// POST /api/sysinfo (réponse « SYSINFO_UPDATED » ou « ID_NOT_FOUND »), POST /api/sysinfo_ver (version des fiches).
const SYSINFO_VER = '1';
const rate = new Map();   // ip -> {n, t}
function limited(ip) {
  const now = Date.now();
  let r = rate.get(ip);
  if (!r || now - r.t > 60_000) { r = { n: 0, t: now }; rate.set(ip, r); }
  r.n++;
  return r.n > 120;   // un poste en session envoie ~20 signaux par minute ; plusieurs postes derrière une même box restent sous la limite
}
setInterval(() => { const now = Date.now(); for (const [k, r] of rate) if (now - r.t > 60_000) rate.delete(k); }, 60_000).unref();
const rejectLogged = new Set();
function logRejectOnce(id, why) {
  const k = id + why;
  if (rejectLogged.has(k) || rejectLogged.size > 1000) return;
  rejectLogged.add(k);
  log('signal refusé pour le poste', id, ':', why);
}

async function apiRoute(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname.replace(/\/+$/, '');
  const ip = String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  if (req.method === 'GET' && (p === '' || p === '/healthz')) return send(res, 200, 'Desktroo Remote');
  if (req.method !== 'POST') return json(res, 404, { error: 'Not found' });
  if (limited(ip)) return json(res, 429, { error: 'Too many requests' });

  if (p === '/api/sysinfo_ver') return send(res, 200, SYSINFO_VER);
  if (p === '/api/heartbeat' || p === '/api/sysinfo') {
    const b = await readJson(req);
    const id = String(b.id || '');
    if (!ID_RE.test(id)) return json(res, 400, { error: 'Bad id' });
    const known = checkPeer(id, b.uuid);
    if (known === false) {
      logRejectOnce(id, 'inconnu de ce serveur ou identifiant matériel différent');
      return p === '/api/sysinfo' ? send(res, 200, 'ID_NOT_FOUND') : json(res, 200, {});
    }
    const d = deviceFor(id, ip);
    if (!d) return p === '/api/sysinfo' ? send(res, 200, 'ID_NOT_FOUND') : json(res, 200, {});
    if (p === '/api/heartbeat') {
      d.conns = Array.isArray(b.conns) ? b.conns.slice(0, 20).map(Number).filter(Number.isFinite) : [];
      const out = {};
      if (!d.sysinfoAt) out.sysinfo = 1;   // fiche inconnue (nouveau poste, données remises à zéro) : la demander
      if (Number.isFinite(Number(b.modified_at))) out.modified_at = Number(b.modified_at);
      return json(res, 200, out);
    }
    d.hostname = clip(b.hostname, 80); d.os = clip(b.os, 160); d.cpu = clip(b.cpu, 160); d.memory = clip(b.memory, 20);
    d.username = clip(b.username, 80); d.version = clip(b.version, 20); d.sysinfoAt = Date.now();
    save(true);
    return send(res, 200, 'SYSINFO_UPDATED');
  }
  // Fonctions de RustDesk Server Pro (comptes, carnet d'adresses…) : absentes, le client s'en passe.
  return json(res, 404, { error: 'Not supported by this server' });
}

// ── Client Windows préconfiguré et script de déploiement ───────────────────
let latestCache = { at: 0, version: '' };
async function latestClientVersion() {
  if (latestCache.version && Date.now() - latestCache.at < 6 * 3600_000) return latestCache.version;
  const r = await fetch('https://github.com/rustdesk/rustdesk/releases/latest', { redirect: 'manual', signal: AbortSignal.timeout(15000) });
  const m = /\/tag\/v?(\d+\.\d+\.\d+)$/.exec(r.headers.get('location') || '');
  if (!m) throw fail('github_unreachable', 502);
  latestCache = { at: Date.now(), version: m[1] };
  return m[1];
}

async function streamClient(res, cfg) {
  const v = await latestClientVersion();
  const r = await fetch(`https://github.com/rustdesk/rustdesk/releases/download/${v}/rustdesk-${v}-x86_64.exe`, { signal: AbortSignal.timeout(120000) });
  if (!r.ok || !r.body) throw fail('github_unreachable', 502);
  const headers = Object.assign({
    'Content-Type': 'application/vnd.microsoft.portable-executable',
    'Content-Disposition': `attachment; filename="rustdesk-licensed-${cfg}.exe"`,
    'Cache-Control': 'no-store', 'X-RustDesk-Version': v,
  }, HEADERS);
  if (r.headers.get('content-length')) headers['Content-Length'] = r.headers.get('content-length');
  res.writeHead(200, headers);
  const reader = r.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!res.write(Buffer.from(value))) await new Promise((ok) => res.once('drain', ok));
  }
  res.end();
}

const psq = (s) => "'" + String(s).replace(/'/g, "''") + "'";
function windowsScript(cfg, withPassword) {
  return [
    '# Desktroo Remote : installe RustDesk et le relie au serveur ' + HOST + '.',
    '# A lancer en administrateur :  powershell -ExecutionPolicy Bypass -File .\\desktroo-remote.ps1',
    '# Genere par Desktroo Remote (Mdm-services.fr). RustDesk est un logiciel libre (AGPL-3.0) de Purslane Ltd.',
    '$ErrorActionPreference = \'Stop\'',
    '$cfg = ' + psq(cfg),
    '$setPassword = $' + (withPassword ? 'true' : 'false'),
    '',
    'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {',
    '  Write-Host "Relancez ce script en administrateur (clic droit > Executer en tant qu\'administrateur)." -ForegroundColor Red; exit 1 }',
    '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12',
    '$exe = Join-Path $env:ProgramFiles \'RustDesk\\rustdesk.exe\'',
    '',
    'if (-not (Test-Path $exe)) {',
    '  Write-Host \'Recherche de la derniere version de RustDesk...\'',
    '  $rel = Invoke-RestMethod -UseBasicParsing \'https://api.github.com/repos/rustdesk/rustdesk/releases/latest\'',
    '  $asset = $rel.assets | Where-Object { $_.name -match \'^rustdesk-[\\d.]+-x86_64\\.exe$\' } | Select-Object -First 1',
    '  if (-not $asset) { throw \'Programme d\'\'installation introuvable sur GitHub.\' }',
    '  $tmp = Join-Path $env:TEMP $asset.name',
    '  Write-Host (\'Telechargement de \' + $asset.name + \'...\')',
    '  Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile $tmp',
    '  $sig = Get-AuthenticodeSignature $tmp',
    '  if ($sig.Status -ne \'Valid\') { Remove-Item $tmp -Force; throw (\'Signature du programme invalide (\' + $sig.Status + \') : installation annulee.\') }',
    '  Write-Host \'Installation...\'',
    '  Start-Process -FilePath $tmp -ArgumentList \'--silent-install\'',
    '  $t = 0; while (-not (Test-Path $exe) -and $t -lt 180) { Start-Sleep -Seconds 3; $t += 3 }',
    '  if (-not (Test-Path $exe)) { throw \'RustDesk ne s\'\'est pas installe dans le delai prevu.\' }',
    '  Start-Sleep -Seconds 10',
    '}',
    '',
    'Write-Host \'Reglage du serveur...\'',
    '& $exe --config $cfg | Out-Null',
    'Start-Sleep -Seconds 2',
    '$pw = \'\'',
    'if ($setPassword) {',
    '  $chars = \'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\'.ToCharArray()',
    '  $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 14; $rng.GetBytes($bytes)',
    '  $pw = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })',
    '  & $exe --password $pw | Out-Null',
    '}',
    '$id = (& $exe --get-id | Out-String).Trim()',
    'Write-Host \'\'',
    'Write-Host \'RustDesk est pret.\' -ForegroundColor Green',
    'Write-Host (\'  ID du poste : \' + $id)',
    'if ($pw) { Write-Host (\'  Mot de passe : \' + $pw) -ForegroundColor Yellow; Write-Host \'  Notez-le maintenant : il ne sera plus affiche.\' }',
    '',
  ].join('\r\n');
}

// ── Panneau (port 8080, derrière Desktroo) ─────────────────────────────────
function identity(req) {
  if (!SECRET) return null;   // sans secret, personne n'est accepté : l'app n'a de sens que dans Desktroo
  if (!safeEq(req.headers['x-desktroo-secret'], SECRET)) return null;
  let u = '';
  try { u = decodeURIComponent(String(req.headers['x-desktroo-user'] || '')); } catch (_) { return null; }
  return /^[A-Za-z0-9._@-]{1,64}$/.test(u) ? u : null;
}

const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'], '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/icon.svg': ['icon.svg', 'image/svg+xml'],
};

function state() {
  const key = readKey();
  const cfg = configString(key);
  const list = deviceList();
  return {
    version: VERSION, serverVersion: RD_SERVER_VERSION,
    host: HOST, hostOk: HOST_RE.test(HOST), key, config: cfg, api: apiUrl(), ports: PORTS,
    filename: cfg ? `rustdesk-licensed-${cfg}.exe` : '',
    procs: { hbbs: procState(procs.hbbs), hbbr: procState(procs.hbbr) },
    sqlite: !!DatabaseSync,
    counts: { total: list.length, online: list.filter((d) => d.online).length, reporting: list.filter((d) => d.reporting).length },
  };
}

async function panelRoute(req, res, url, user) {
  const p = url.pathname, m = req.method;
  if (p === '/api/state' && m === 'GET') return json(res, 200, state());
  if (p === '/api/devices' && m === 'GET') return json(res, 200, deviceList());
  const dm = /^\/api\/devices\/([A-Za-z0-9_-]{6,32})$/.exec(p);
  if (dm && m === 'PUT') {
    const b = await readJson(req);
    const d = devices[dm[1]] || (devices[dm[1]] = {});
    if ('label' in b) d.label = clip(b.label, 60);
    if ('note' in b) d.note = clip(b.note, 300);
    dirty = true; save(true);
    log('poste', dm[1], 'renommé ou annoté par', user);
    return json(res, 200, { ok: true });
  }
  if (dm && m === 'DELETE') {
    const d = devices[dm[1]] || (devices[dm[1]] = {});
    d.hidden = true; delete d.lastSeen; dirty = true; save(true);
    log('poste', dm[1], 'retiré de la liste par', user);
    return json(res, 200, { ok: true });
  }
  if (p === '/api/logs' && m === 'GET') {
    const name = url.searchParams.get('proc') === 'hbbr' ? 'hbbr' : 'hbbs';
    return json(res, 200, { lines: procs[name] ? procs[name].lines.slice(-300) : [] });
  }
  if (p === '/api/restart' && m === 'POST') {
    for (const pr of Object.values(procs)) if (pr.child) { pr.delay = 1000; pr.child.kill('SIGTERM'); }
    log('serveur RustDesk redémarré par', user);
    return json(res, 200, { ok: true });
  }
  if (p === '/deploy/windows.ps1' && m === 'GET') {
    const cfg = configString(readKey());
    if (!cfg) throw fail('not_ready', 409);
    const withPw = url.searchParams.get('password') === '1';
    log('script de déploiement Windows téléchargé par', user, withPw ? '(avec mot de passe)' : '');
    return send(res, 200, '﻿' + windowsScript(cfg, withPw), 'text/plain; charset=utf-8',
      { 'Content-Disposition': 'attachment; filename="desktroo-remote.ps1"' });
  }
  if (p === '/download/windows' && m === 'GET') {
    const cfg = configString(readKey());
    if (!cfg) throw fail('not_ready', 409);
    log('client Windows préconfiguré téléchargé par', user);
    return streamClient(res, cfg);
  }
  if (p === '/api/client-version' && m === 'GET') return json(res, 200, { version: await latestClientVersion() });
  if (m === 'GET' && FILES[p]) {
    const [file, type] = FILES[p];
    return send(res, 200, fs.readFileSync(path.join(PUB, file)), type, { 'Content-Security-Policy': PANEL_CSP });
  }
  return send(res, 404, 'Introuvable');
}

function onError(res, e) {
  const net = e && !e.status && (e.name === 'TimeoutError' || e.cause);
  const status = e && e.status ? e.status : (net ? 502 : 500);
  const code = e && e.code && /^[a-z_]+$/.test(e.code) ? e.code : (net ? 'github_unreachable' : 'server_error');
  if (status >= 500) log('erreur', e && e.message);
  if (!res.headersSent) json(res, status, { error: code }, status === 413 ? { Connection: 'close' } : undefined);
  else res.destroy();
}

// ── Démarrage ──────────────────────────────────────────────────────────────
const panel = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/healthz') return send(res, 200, 'ok');
  const user = identity(req);
  if (!user) return send(res, 403, 'Ouvrez Desktroo Remote depuis Desktroo.');
  try { await panelRoute(req, res, url, user); } catch (e) { onError(res, e); }
});
const api = http.createServer(async (req, res) => {
  try { await apiRoute(req, res); } catch (e) { onError(res, e); }
});
api.headersTimeout = 10_000; api.requestTimeout = 15_000;

if (HOST && !HOST_RE.test(HOST)) log('adresse publique invalide :', HOST);
supervise('hbbs', [...(HOST ? ['-r', `${HOST}:${PORTS.relay}`] : []), '-k', '_']);
supervise('hbbr', ['-k', '_']);
panel.listen(PORT, () => log('Desktroo Remote', VERSION, 'prêt sur le port', PORT, SECRET ? '' : '(secret absent : le panneau refusera tout)'));
api.listen(API_PORT, () => log('API des clients RustDesk sur le port', API_PORT));

function shutdown() {
  log('arrêt demandé');
  save(true);
  for (const p of Object.values(procs)) { p.stopping = true; if (p.child) p.child.kill('SIGTERM'); }
  api.close(); panel.close();
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
