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
const PORTS = { nat: 21115, id: 21116, relay: 21117, api: 21114, lan: 21120 };
const LAN_API_PORT = 8082;         // API complète (techniciens) : ouverte par Desktroo sur le port 21120, réseau local seulement
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
// Il s'importe par « rustdesk --config <chaîne> », dans le nom du programme (desktroo-remote--<chaîne>.exe) ou par le
// bouton « Importer » des réglages réseau.
// - Courte : les navigateurs raccourcissent les noms de fichier trop longs (un nom de 248 caractères est arrivé coupé à
//   187 : configuration illisible, le client part sur le serveur public). Seuls l'adresse et la clé y figurent : le
//   client en déduit l'API (port 21114) et hbbs lui donne le relais.
// - Sûre : le nom comme « --config » passent par un découpage sur « -- », et un « - » collé à « -licensed- » est
//   absorbé : la chaîne ne doit ni contenir « -- » ni commencer ou finir par « - ». Des espaces (sans effet sur le
//   JSON) changent l'encodage jusqu'à en obtenir une sûre.
const encodeConfig = (json) => Buffer.from(json, 'utf8').toString('base64url').split('').reverse().join('');
// « -qs- » ou « -qs.exe » dans le nom fait passer le client en mode « assistance rapide » (libs/portable) : à éviter aussi.
const safeConfig = (c) => !c.includes('--') && !c.startsWith('-') && !c.endsWith('-') && !/-qs(-|$)|_qs$|^qs-/i.test(c);
function configString(key) {
  if (!HOST || !key) return '';
  for (let n = 0; n < 64; n++) {
    const c = encodeConfig(`{"host":"${HOST}",${' '.repeat(n)}"key":"${key}"}`);
    if (safeConfig(c)) return c;
  }
  return '';
}
// Configuration des postes techniciens : la même, avec l'adresse de l'API où ils se connectent (HTTPS par NPMplus,
// ou le port 21120 du NAS sur le réseau local). Même précaution contre « -- ».
function techConfigString(key) {
  const api = settings.apiUrl || '';
  if (!HOST || !key || !api) return '';
  for (let n = 0; n < 64; n++) {
    const c = encodeConfig(`{"host":"${HOST}",${' '.repeat(n)}"key":"${key}","api":"${api}"}`);
    if (safeConfig(c)) return c;
  }
  return '';
}
// Adresse d'API acceptée : https://nom[:port] (proxy), ou http://adresse-locale:21120 (réseau local).
const API_URL_RE = /^(https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?|http:\/\/(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){1,3}:\d{2,5}|http:\/\/[a-z0-9-]{1,63}(?:\.local|\.lan|\.home)?:\d{2,5})$/;
function clientFilename(key) {
  const c = configString(key);
  return c ? `${brandSlug()}--${c}.exe` : '';   // le client découpe sur « -- » : le préfixe est ignoré
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
      id, label: d.label || '', group: d.group || '', note: d.note || '', hostname: d.hostname || '', os: d.os || '', username: d.username || '',
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
function readRaw(req, max) {
  return new Promise((resolve, reject) => {
    const parts = []; let n = 0, over = false;
    req.on('data', (c) => { if (over) return; n += c.length; if (n > max) { over = true; parts.length = 0; reject(fail('too_large', 413)); } else parts.push(c); });
    req.on('end', () => { if (!over) resolve(Buffer.concat(parts)); });
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

// ── Techniciens : comptes, jetons, double authentification ─────────────────
// Le client RustDesk se connecte par /api/login (flutter/lib/models/user_model.dart, common/widgets/login.dart) :
//   {username, password, id, uuid, type:'account', deviceInfo} → {type:'access_token', access_token, user}
//   avec code TOTP : → {type:'email_check', tfa_type:'tfa_check', secret, user}, puis
//   {type:'email_code', tfaCode, secret, username} → {type:'access_token', …}
// Ces routes ne sont servies que sur le port réservé au réseau local (8082 → 21120 du NAS) : un mot de passe ne
// peut pas arriver en clair d'Internet. Depuis l'extérieur, on passe par un proxy HTTPS (NPMplus) vers ce port.
const AUTH_FILE = path.join(DATA, 'auth.json');
const SETTINGS_FILE = path.join(DATA, 'settings.json');
const AB_DIR = path.join(DATA, 'ab');
const TECH_RE = /^[a-z0-9][a-z0-9._-]{1,31}$/;
const TOKEN_IDLE_MS = 90 * 86400_000;      // un jeton inutilisé 90 jours expire
const MAX_TOKENS_PER_TECH = 20;
const PW_MIN = 10;
let auth = readJsonFile(AUTH_FILE, {});
if (!auth || typeof auth !== 'object') auth = {};
auth.techs = auth.techs && typeof auth.techs === 'object' ? auth.techs : {};
auth.tokens = auth.tokens && typeof auth.tokens === 'object' ? auth.tokens : {};
let settings = readJsonFile(SETTINGS_FILE, {});
if (!settings || typeof settings !== 'object') settings = {};
function saveAuth() { writeJsonFile(AUTH_FILE, auth); }
function saveSettings() { writeJsonFile(SETTINGS_FILE, settings); }

// Messages renvoyés au client RustDesk (il les affiche tels quels), dans la langue du panneau.
const MSG = {
  bad_login: { fr: 'Identifiant ou mot de passe incorrect.', en: 'Wrong username or password.', es: 'Usuario o contraseña incorrectos.' },
  locked: { fr: 'Trop d’essais : réessayez dans quelques minutes.', en: 'Too many attempts: try again in a few minutes.', es: 'Demasiados intentos: inténtalo de nuevo en unos minutos.' },
  bad_code: { fr: 'Code incorrect ou expiré.', en: 'Wrong or expired code.', es: 'Código incorrecto o caducado.' },
  disabled: { fr: 'Ce compte est désactivé.', en: 'This account is disabled.', es: 'Esta cuenta está desactivada.' },
  use_lan: { fr: 'Connexion des techniciens : dans RustDesk, Paramètres › Réseau, réglez « Serveur API » sur {url}, puis reconnectez-vous.',
             en: 'Technician sign-in: in RustDesk, Settings › Network, set “API server” to {url}, then sign in again.',
             es: 'Inicio de sesión de técnicos: en RustDesk, Ajustes › Red, configura «Servidor API» con {url} y vuelve a iniciar sesión.' },
};
const msg = (k) => ((MSG[k] && (MSG[k][settings.lang] || MSG[k].fr)) || k)
  .replace('{url}', settings.apiUrl || ({ fr: 'l’adresse HTTPS donnée par Desktroo Remote (onglet Techniciens)', en: 'the HTTPS address given by Desktroo Remote (Technicians tab)', es: 'la dirección HTTPS que da Desktroo Remote (pestaña Técnicos)' })[settings.lang] || 'https://…');

function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex'); }
function setPassword(t, pw) { t.salt = crypto.randomBytes(16).toString('hex'); t.hash = hashPw(pw, t.salt); }
function checkPassword(t, pw) {
  if (!t || !t.salt || !t.hash) { hashPw(pw, 'leurre'); return false; }   // même durée qu'un vrai essai
  return safeEq(hashPw(pw, t.salt), t.hash);
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// TOTP (RFC 6238) : SHA-1, 6 chiffres, 30 s, une période d'écart tolérée, un code ne sert qu'une fois.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  let bits = '', out = [];
  for (const c of String(s).toUpperCase().replace(/[^A-Z2-7]/g, '')) bits += B32.indexOf(c).toString(2).padStart(5, '0');
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function b32encode(buf) {
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function totpAt(secret, counter) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(c).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
// Rend le compteur accepté (pour interdire sa réutilisation), ou -1.
function totpCheck(secret, code, lastCounter) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return -1;
  const now = Math.floor(Date.now() / 30_000);
  for (const c of [now, now - 1, now + 1]) if (c > (lastCounter || 0) && safeEq(totpAt(secret, c), code)) return c;
  return -1;
}

// Essais ratés : 5 par compte ou par adresse en 15 min, puis 15 min de blocage.
const fails = new Map();
function isLocked(k) { const f = fails.get(k); return !!(f && f.until > Date.now()); }
function addFail(k) {
  const now = Date.now();
  let f = fails.get(k);
  if (!f || now - f.first > 15 * 60_000) f = { n: 0, first: now, until: 0 };
  if (++f.n >= 5) f.until = now + 15 * 60_000;
  fails.set(k, f);
}
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (f.until < now && now - f.first > 15 * 60_000) fails.delete(k); }, 300_000).unref();

const challenges = new Map();   // secret de l'étape « code » -> {tech, exp, tries}
function userPayload(name) {
  const t = auth.techs[name] || {};
  return { name, display_name: t.display || name, email: '', note: '', status: 1, is_admin: false };
}
function issueToken(name, b, ip) {
  const token = 'dtr_' + crypto.randomBytes(32).toString('base64url');
  const di = b.deviceInfo && typeof b.deviceInfo === 'object' ? b.deviceInfo : {};
  auth.tokens[sha(token)] = { tech: name, created: Date.now(), lastUsed: Date.now(), ip,
    device: { id: clip(b.id, 32), os: clip(di.os, 40), name: clip(di.name, 80) } };
  const mine = Object.entries(auth.tokens).filter(([, v]) => v.tech === name).sort((a, z) => a[1].lastUsed - z[1].lastUsed);
  while (mine.length > MAX_TOKENS_PER_TECH) delete auth.tokens[mine.shift()[0]];
  auth.techs[name].lastLogin = Date.now();
  saveAuth();
  return token;
}
let tokenTouch = 0;
function techOf(req) {
  const m = /^Bearer\s+(dtr_[A-Za-z0-9_-]{20,80})$/.exec(String(req.headers.authorization || ''));
  if (!m) return null;
  const k = sha(m[1]), t = auth.tokens[k];
  if (!t) return null;
  const tech = auth.techs[t.tech];
  if (!tech || tech.disabled || Date.now() - t.lastUsed > TOKEN_IDLE_MS) { delete auth.tokens[k]; saveAuth(); return null; }
  t.lastUsed = Date.now();
  if (Date.now() - tokenTouch > 60_000) { tokenTouch = Date.now(); saveAuth(); }
  return { name: t.tech, key: k };
}
function revokeTokens(name) {
  let n = 0;
  for (const [k, v] of Object.entries(auth.tokens)) if (v.tech === name) { delete auth.tokens[k]; n++; }
  saveAuth();
  return n;
}

async function login(req, res, ip) {
  const b = await readJson(req);
  const type = String(b.type || 'account');
  if (type === 'email_code' || type === 'tfa_code') {          // 2e étape : code TOTP
    const ch = challenges.get(String(b.secret || ''));
    if (!ch || ch.exp < Date.now() || isLocked('u:' + ch.tech)) return json(res, 401, { error: msg(ch && isLocked('u:' + ch.tech) ? 'locked' : 'bad_code') });
    const t = auth.techs[ch.tech];
    const c = t && t.totp ? totpCheck(t.totp, b.tfaCode || b.verificationCode, t.totpLast) : -1;
    if (c < 0) {
      addFail('u:' + ch.tech); addFail('ip:' + ip);
      if (++ch.tries >= 3) challenges.delete(String(b.secret));
      log('code à usage unique refusé pour', ch.tech, 'depuis', ip);
      return json(res, 401, { error: msg('bad_code') });
    }
    challenges.delete(String(b.secret));
    t.totpLast = c;
    log('technicien connecté :', ch.tech, 'depuis', ip, '(avec code)');
    return json(res, 200, { type: 'access_token', access_token: issueToken(ch.tech, b, ip), user: userPayload(ch.tech) });
  }
  const name = String(b.username || '').trim().toLowerCase();
  if (isLocked('u:' + name) || isLocked('ip:' + ip)) return json(res, 429, { error: msg('locked') });
  const t = TECH_RE.test(name) ? auth.techs[name] : null;
  if (!checkPassword(t, String(b.password || '').slice(0, 256))) {
    addFail('u:' + name); addFail('ip:' + ip);
    log('connexion refusée pour', JSON.stringify(name.slice(0, 32)), 'depuis', ip);
    return json(res, 401, { error: msg('bad_login') });
  }
  if (t.disabled) return json(res, 403, { error: msg('disabled') });
  if (t.totp) {
    const secret = crypto.randomBytes(24).toString('base64url');
    challenges.set(secret, { tech: name, exp: Date.now() + 5 * 60_000, tries: 0 });
    if (challenges.size > 500) challenges.delete(challenges.keys().next().value);
    return json(res, 200, { type: 'email_check', tfa_type: 'tfa_check', secret, user: userPayload(name) });
  }
  log('technicien connecté :', name, 'depuis', ip);
  return json(res, 200, { type: 'access_token', access_token: issueToken(name, b, ip), user: userPayload(name) });
}

// Postes vus par les techniciens (onglet « Appareils accessibles » du client) : tous les postes connus du serveur,
// rangés par groupe (le client, le site…) choisi dans le panneau.
function accessiblePeers() {
  return deviceList().map((d) => ({
    id: d.id, status: 1, user: '', user_name: '', device_group_name: d.group || '', note: d.note || '',
    info: { device_name: d.label || d.hostname || d.id, os: d.os || '', username: d.username || '' },
  }));
}
function page(url, list) {
  const cur = Math.max(1, parseInt(url.searchParams.get('current') || '1', 10) || 1);
  const size = Math.min(500, Math.max(1, parseInt(url.searchParams.get('pageSize') || '100', 10) || 100));
  return { total: list.length, data: list.slice((cur - 1) * size, cur * size) };
}

// Carnet d'adresses personnel (format « ancien » du client : une chaîne JSON opaque par technicien).
const abFile = (name) => path.join(AB_DIR, name + '.json');

const ipOf = (req, full) => {
  const ip = String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  if (!full) return ip;
  // Port réservé au réseau local : derrière NPMplus, l'adresse du technicien est dans X-Forwarded-For.
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean).pop();
  return xff && /^[0-9a-fA-F.:]{3,45}$/.test(xff) ? xff.replace(/^::ffff:/, '') : ip;
};

// full = port réservé au réseau local (techniciens et postes) ; sinon port public (postes seulement).
async function apiRoute(req, res, full) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname.replace(/\/+$/, '');
  const m = req.method;
  const ip = ipOf(req, full);
  if (m === 'GET' && (p === '' || p === '/healthz')) return send(res, 200, 'Desktroo Remote');
  if (limited(ip)) return json(res, 429, { error: 'Too many requests' });

  if (full) {
    if (p === '/api/login-options') return json(res, 200, []);
    if (p === '/api/login' && m === 'POST') return login(req, res, ip);
    const tech = techOf(req);
    if (p === '/api/logout' && m === 'POST') {
      if (tech) { delete auth.tokens[tech.key]; saveAuth(); log('technicien déconnecté :', tech.name); }
      return json(res, 200, {});
    }
    if (/^\/api\/(currentUser|ab|ab\/.*|users|peers|device-group\/accessible)$/.test(p)) {
      if (!tech) return json(res, 401, { error: 'Unauthorized' });
      if (p === '/api/currentUser') return json(res, 200, userPayload(tech.name));
      if (p === '/api/users' && m === 'GET') {
        return json(res, 200, page(url, Object.keys(auth.techs).filter((n) => !auth.techs[n].disabled).sort().map(userPayload)));
      }
      if (p === '/api/peers' && m === 'GET') return json(res, 200, page(url, accessiblePeers()));
      if (p === '/api/device-group/accessible' && m === 'GET') {
        const groups = [...new Set(deviceList().map((d) => d.group).filter(Boolean))].sort().map((name) => ({ name }));
        return json(res, 200, page(url, groups));
      }
      if (p === '/api/ab' && m === 'GET') {
        const ab = readJsonFile(abFile(tech.name), null);
        return json(res, 200, { data: ab && typeof ab.data === 'string' ? ab.data : JSON.stringify({ tags: [], peers: [], tag_colors: '{}' }) });
      }
      if (p === '/api/ab' && m === 'POST') {
        const b = await readJson(req, 512 * 1024);
        if (typeof b.data !== 'string') throw fail('bad_request');
        try { JSON.parse(b.data); } catch (_) { throw fail('bad_request'); }
        fs.mkdirSync(AB_DIR, { recursive: true });
        writeJsonFile(abFile(tech.name), { data: b.data, at: Date.now() });
        return json(res, 200, {});
      }
      // /api/ab/settings, /api/ab/personal… (carnets partagés de RustDesk Server Pro) : 404 → le client passe au
      // carnet « ancien », servi ci-dessus.
      return json(res, 404, { error: 'Not found' });
    }
  } else if (p === '/api/login-options') {
    return json(res, 200, []);
  } else if (/^\/api\/(login|logout|currentUser|ab|users|peers|device-group)(\/|$)/.test(p)) {
    // Port public : pas de connexion des techniciens (le mot de passe circulerait en clair sur Internet).
    return json(res, 403, { error: msg('use_lan') });
  }

  if (m !== 'POST') return json(res, 404, { error: 'Not found' });
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

async function streamClient(res, filename) {
  const v = await latestClientVersion();
  const r = await fetch(`https://github.com/rustdesk/rustdesk/releases/download/${v}/rustdesk-${v}-x86_64.exe`, { signal: AbortSignal.timeout(120000) });
  if (!r.ok || !r.body) throw fail('github_unreachable', 502);
  const headers = Object.assign({
    'Content-Type': 'application/vnd.microsoft.portable-executable',
    'Content-Disposition': `attachment; filename="${filename}"`,
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

// Le même script en .cmd, lancé par un double-clic (Windows ouvre les .ps1 dans le Bloc-notes). Fichier « polyglotte » :
// cmd lit les lignes du début (« <# : » est pour lui une étiquette, ignorée), se relance en administrateur si besoin,
// puis fait exécuter le fichier entier par PowerShell, pour qui tout ce début est un commentaire <# … #>.
// Enregistré sans BOM (cmd ne le comprend pas) ; PowerShell le lit en UTF-8.
function windowsCmd(ps) {
  return [
    '<# : script',
    '@echo off',
    'title ' + cmdSafe(brandName()),
    'net session >nul 2>&1',
    'if errorlevel 1 (',
    '  echo Autorisation administrateur demandee...',
    '  powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
    '  exit /b',
    ')',
    'powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create([IO.File]::ReadAllText(\'%~f0\')))"',
    'echo.',
    'pause',
    'exit /b',
    '#>',
    ps,
  ].join('\r\n');
}

// ── Habillage Desktroo Remote du client installé ───────────────────────────
// Sans toucher aux programmes signés (rustdesk.exe, *.dll) : le client affiche « assets/logo_light.png » ou
// « logo_dark.png » en bandeau s'il les trouve (flutter/lib/common.dart, loadLogo), et « assets/icon.png » comme icône
// (loadIcon). Ces fichiers et les raccourcis sont réappliqués par une tâche planifiée (au démarrage, puis toutes les
// 6 h) : une mise à jour de RustDesk les remet d'origine. Le dossier de la tâche n'est modifiable que par SYSTEM et
// les administrateurs, puisqu'elle s'exécute en SYSTEM.
// Habillage personnalisable : nom (raccourcis, fichiers téléchargés) et images, réglés dans le panneau (onglet
// « Habillage ») et gardés dans /data/brand ; par défaut, ceux de Desktroo Remote (public/brand).
const BRAND_DIR = path.join(DATA, 'brand');
const BRAND_DEFAULT_NAME = 'Desktroo Remote';
const BRAND_SLOTS = {   // emplacement → contrôle de l'image envoyée
  logo_light: (w, h) => w >= 120 && w <= 2000 && h >= 30 && h <= 800 && w >= h,
  logo_dark: (w, h) => w >= 120 && w <= 2000 && h >= 30 && h <= 800 && w >= h,
  icon: (w, h) => w === h && w >= 64 && w <= 1024,
};
const BRAND_NAME_RE = /^[^\\/:*?"<>|\x00-\x1f]{1,40}$/;
let brandVersion = 0;
function pngSize(buf) {   // { w, h } d'un PNG valide, sinon null
  if (!Buffer.isBuffer(buf) || buf.length < 33 || buf.readUInt32BE(0) !== 0x89504e47 || buf.readUInt32BE(4) !== 0x0d0a1a0a
      || buf.toString('ascii', 12, 16) !== 'IHDR') return null;
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}
function brandCustom(slot) { try { return fs.readFileSync(path.join(BRAND_DIR, slot + '.png')); } catch (_) { return null; } }
const brandDefault = (rel) => fs.readFileSync(path.join(PUB, rel));
// Icône Windows faite d'une seule image PNG (format accepté depuis Windows Vista).
function pngToIco(png) {
  const { w, h } = pngSize(png);
  const head = Buffer.alloc(22);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(1, 4);
  head.writeUInt8(w >= 256 ? 0 : w, 6); head.writeUInt8(h >= 256 ? 0 : h, 7);
  head.writeUInt16LE(1, 10); head.writeUInt16LE(32, 12); head.writeUInt32LE(png.length, 14); head.writeUInt32LE(22, 18);
  return Buffer.concat([head, png]);
}
function brandName() { return (settings.brandName || '').trim() || BRAND_DEFAULT_NAME; }
// Nom de fichier tiré du nom de l'habillage (« Assistance Dupont » → « assistance-dupont »). Le client RustDesk lit
// sa configuration après « -- » et passe en « assistance rapide » si le nom contient « -qs- » : on s'en garde.
function brandSlug() {
  const s = brandName().normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  if (!s || /licensed|(^|-)qs(-|$)|_qs/.test(s)) return 'desktroo-remote';
  return s;
}
// Images effectivement envoyées aux postes : un bandeau manquant reprend l'autre, puis celui de Desktroo Remote.
function brandFiles() {
  const light = brandCustom('logo_light'), dark = brandCustom('logo_dark'), icon = brandCustom('icon');
  const files = {
    'logo_light.png': light || dark || brandDefault('brand/logo_light.png'),
    'logo_dark.png': dark || light || brandDefault('brand/logo_dark.png'),
    'icon.png': icon || brandDefault('brand/icon.png'),
    'desktroo-remote.ico': icon ? pngToIco(icon) : brandDefault('brand/desktroo-remote.ico'),
  };
  if (!icon) files['icon.svg'] = brandDefault('icon.svg');
  return files;
}
const cmdSafe = (s) => String(s).replace(/[&|<>^%!"()]/g, '').trim() || BRAND_DEFAULT_NAME;

let brandCache = null;
function brandingScript() {
  if (brandCache && brandCache.v === brandVersion) return brandCache.text;
  let files;
  try { files = Object.entries(brandFiles()).map(([n, b]) => [n, b.toString('base64')]); } catch (_) { return ''; }
  const name = brandName();
  const apply = String.raw`# Habillage de RustDesk (logo, icone, raccourcis), lance par la tache planifiee « Desktroo Remote - habillage ».
$ErrorActionPreference = 'SilentlyContinue'
$src = $PSScriptRoot
$name = ''
try { $name = ([IO.File]::ReadAllText((Join-Path $src 'name.txt'))).Trim() } catch { }
if (-not $name) { $name = 'Desktroo Remote' }
$dst = Join-Path $env:ProgramFiles 'RustDesk\data\flutter_assets\assets'
if (Test-Path $dst) {
  foreach ($f in 'logo_light.png','logo_dark.png','icon.png','icon.svg') {
    $a = Join-Path $src $f; $b = Join-Path $dst $f
    if (-not (Test-Path $a)) { continue }
    if (-not (Test-Path $b) -or (Get-FileHash $a).Hash -ne (Get-FileHash $b).Hash) { Copy-Item $a $b -Force }
  }
  Copy-Item (Join-Path $src 'logo_light.png') (Join-Path $dst 'logo.png') -Force
}
$ico = Join-Path $src 'desktroo-remote.ico'
$sh = New-Object -ComObject WScript.Shell
$places = @((Join-Path $env:PUBLIC 'Desktop'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'))
Get-ChildItem $places -Recurse -Filter *.lnk | ForEach-Object {
  $l = $sh.CreateShortcut($_.FullName)
  if ($l.TargetPath -notlike '*\RustDesk\rustdesk.exe') { return }
  if (-not $l.Arguments -and $_.BaseName -ne $name) {
    $n = $sh.CreateShortcut((Join-Path $_.DirectoryName ($name + '.lnk')))
    $n.TargetPath = $l.TargetPath; $n.WorkingDirectory = $l.WorkingDirectory; $n.IconLocation = "$ico,0"; $n.Description = $name; $n.Save()
    Remove-Item $_.FullName -Force
  } else { $l.IconLocation = "$ico,0"; $l.Save() }
}`;
  const text = [
    '',
    '# --- Habillage (logo, icone, raccourcis) ---',
    'Write-Host (\'Habillage \' + ' + psq(name) + ' + \'...\')',
    '$brand = Join-Path $env:ProgramData \'DesktrooRemote\'',
    'New-Item -ItemType Directory -Force $brand | Out-Null',
    '# Dossier reserve a SYSTEM et aux administrateurs : la tache qui l\'utilise tourne en SYSTEM.',
    'icacls $brand /inheritance:r /grant:r \'*S-1-5-18:(OI)(CI)F\' \'*S-1-5-32-544:(OI)(CI)F\' \'*S-1-5-32-545:(OI)(CI)RX\' | Out-Null',
    'Remove-Item (Join-Path $brand \'icon.svg\') -Force -ErrorAction SilentlyContinue',
    '[IO.File]::WriteAllText((Join-Path $brand \'name.txt\'), ' + psq(name) + ', (New-Object Text.UTF8Encoding $false))',
    ...files.map(([n, b64]) => `[IO.File]::WriteAllBytes((Join-Path $brand '${n}'), [Convert]::FromBase64String('${b64}'))`),
    '$apply = @\'',
    apply,
    '\'@',
    'Set-Content -Path (Join-Path $brand \'habillage.ps1\') -Value $apply -Encoding UTF8',
    '$act = New-ScheduledTaskAction -Execute \'powershell.exe\' -Argument (\'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "\' + (Join-Path $brand \'habillage.ps1\') + \'"\')',
    '$t1 = New-ScheduledTaskTrigger -AtStartup',
    '$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 3650)',
    'Register-ScheduledTask -TaskName \'Desktroo Remote - habillage\' -Action $act -Trigger @($t1, $t2) -User \'SYSTEM\' -RunLevel Highest -Force | Out-Null',
    '& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $brand \'habillage.ps1\')',
    '',
  ].join('\r\n');
  brandCache = { v: brandVersion, text };
  return text;
}
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
    brandingScript(),
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
    filename: clientFilename(key),
    apiUrl: settings.apiUrl || '', techConfig: techConfigString(key), lanPort: PORTS.lan,
    techs: Object.keys(auth.techs).length,
    procs: { hbbs: procState(procs.hbbs), hbbr: procState(procs.hbbr) },
    sqlite: !!DatabaseSync,
    counts: { total: list.length, online: list.filter((d) => d.online).length, reporting: list.filter((d) => d.reporting).length },
  };
}

async function panelRoute(req, res, url, user) {
  const p = url.pathname, m = req.method;
  if (p === '/api/state' && m === 'GET') {
    const l = url.searchParams.get('lang');   // langue du panneau : celle des messages envoyés au client RustDesk
    if (['fr', 'en', 'es'].includes(l) && settings.lang !== l) { settings.lang = l; saveSettings(); }
    return json(res, 200, state());
  }
  if (p === '/api/settings' && m === 'PUT') {
    const b = await readJson(req);
    const u = String(b.apiUrl || '').trim().replace(/\/+$/, '').toLowerCase();
    if (u && !API_URL_RE.test(u)) throw fail('bad_api_url');
    settings.apiUrl = u; saveSettings();
    log('adresse de l’API des techniciens :', u || '(aucune)', 'par', user);
    return json(res, 200, { ok: true });
  }
  // Habillage
  if (p === '/api/brand' && m === 'GET') {
    const custom = {};
    for (const s of Object.keys(BRAND_SLOTS)) custom[s] = !!brandCustom(s);
    return json(res, 200, { name: settings.brandName || '', defaultName: BRAND_DEFAULT_NAME, effectiveName: brandName(), slug: brandSlug(), custom, v: brandVersion });
  }
  if (p === '/api/brand' && m === 'PUT') {
    const b = await readJson(req);
    const n = String(b.name || '').trim();
    if (n && (!BRAND_NAME_RE.test(n) || /^[.\s]|[.\s]$/.test(n))) throw fail('bad_brand_name');
    settings.brandName = n; saveSettings(); brandVersion++;
    log('nom de l’habillage :', n || '(par défaut)', 'par', user);
    return json(res, 200, { ok: true });
  }
  const bm = /^\/(api\/brand\/img|brand\/img)\/(logo_light|logo_dark|icon)$/.exec(p);
  if (bm && bm[1] === 'brand/img' && m === 'GET') {   // aperçu : l'image envoyée aux postes pour cet emplacement
    const f = brandFiles()[bm[2] === 'icon' ? 'icon.png' : bm[2] + '.png'];
    return send(res, 200, f, 'image/png', { 'Cache-Control': 'no-store' });
  }
  if (bm && bm[1] === 'api/brand/img' && m === 'PUT') {
    const buf = await readRaw(req, 1024 * 1024);
    const sz = pngSize(buf);
    if (!sz) throw fail('bad_png');
    if (!BRAND_SLOTS[bm[2]](sz.w, sz.h)) throw fail(bm[2] === 'icon' ? 'bad_icon_size' : 'bad_logo_size');
    fs.mkdirSync(BRAND_DIR, { recursive: true });
    fs.writeFileSync(path.join(BRAND_DIR, bm[2] + '.png'), buf, { mode: 0o600 });
    brandVersion++;
    log('habillage :', bm[2], `(${sz.w}×${sz.h})`, 'envoyé par', user);
    return json(res, 200, { ok: true, w: sz.w, h: sz.h });
  }
  if (bm && bm[1] === 'api/brand/img' && m === 'DELETE') {
    try { fs.unlinkSync(path.join(BRAND_DIR, bm[2] + '.png')); } catch (_) {}
    brandVersion++;
    log('habillage :', bm[2], 'remis par défaut par', user);
    return json(res, 200, { ok: true });
  }
  if (p === '/api/techs' && m === 'GET') {
    const sessions = {};
    for (const t of Object.values(auth.tokens)) if (Date.now() - t.lastUsed <= TOKEN_IDLE_MS) sessions[t.tech] = (sessions[t.tech] || 0) + 1;
    return json(res, 200, Object.keys(auth.techs).sort().map((n) => {
      const t = auth.techs[n];
      return { name: n, display: t.display || '', totp: !!t.totp, disabled: !!t.disabled, created: t.created || 0,
               lastLogin: t.lastLogin || 0, sessions: sessions[n] || 0 };
    }));
  }
  if (p === '/api/techs' && m === 'POST') {
    const b = await readJson(req);
    const name = String(b.name || '').trim().toLowerCase();
    if (!TECH_RE.test(name)) throw fail('bad_name');
    if (auth.techs[name]) throw fail('name_taken', 409);
    if (String(b.password || '').length < PW_MIN || String(b.password).length > 256) throw fail('weak_password');
    const t = { display: clip(b.display, 60), created: Date.now(), createdBy: user };
    setPassword(t, b.password);
    auth.techs[name] = t; saveAuth();
    log('technicien', name, 'créé par', user);
    return json(res, 200, { ok: true });
  }
  const tm = /^\/api\/techs\/([a-z0-9][a-z0-9._-]{1,31})(\/totp|\/totp\/confirm|\/logout)?$/.exec(p);
  if (tm) {
    const name = tm[1], t = auth.techs[name], sub = tm[2] || '';
    if (!t) throw fail('not_found', 404);
    if (!sub && m === 'PUT') {
      const b = await readJson(req);
      if ('display' in b) t.display = clip(b.display, 60);
      if ('password' in b) {
        if (String(b.password || '').length < PW_MIN || String(b.password).length > 256) throw fail('weak_password');
        setPassword(t, b.password); revokeTokens(name);
      }
      if ('disabled' in b) { t.disabled = !!b.disabled; if (t.disabled) revokeTokens(name); }
      saveAuth();
      log('technicien', name, 'modifié par', user);
      return json(res, 200, { ok: true });
    }
    if (!sub && m === 'DELETE') {
      revokeTokens(name); delete auth.techs[name]; saveAuth();
      try { fs.unlinkSync(abFile(name)); } catch (_) {}
      log('technicien', name, 'supprimé par', user);
      return json(res, 200, { ok: true });
    }
    if (sub === '/logout' && m === 'POST') { const n = revokeTokens(name); log('sessions de', name, 'fermées par', user); return json(res, 200, { ok: true, closed: n }); }
    if (sub === '/totp' && m === 'POST') {       // nouveau secret, actif seulement après un premier code juste
      t.totpPending = b32encode(crypto.randomBytes(20)); saveAuth();
      const label = encodeURIComponent('Desktroo Remote:' + name);
      return json(res, 200, { secret: t.totpPending, uri: `otpauth://totp/${label}?secret=${t.totpPending}&issuer=Desktroo%20Remote&digits=6&period=30` });
    }
    if (sub === '/totp/confirm' && m === 'POST') {
      const b = await readJson(req);
      if (!t.totpPending) throw fail('bad_code');
      const c = totpCheck(t.totpPending, b.code, 0);
      if (c < 0) throw fail('bad_code');
      t.totp = t.totpPending; t.totpLast = c; delete t.totpPending; saveAuth();
      log('double authentification activée pour', name, 'par', user);
      return json(res, 200, { ok: true });
    }
    if (sub === '/totp' && m === 'DELETE') {
      delete t.totp; delete t.totpPending; delete t.totpLast; saveAuth();
      log('double authentification retirée pour', name, 'par', user);
      return json(res, 200, { ok: true });
    }
  }
  if (p === '/api/devices' && m === 'GET') return json(res, 200, deviceList());
  const dm = /^\/api\/devices\/([A-Za-z0-9_-]{6,32})$/.exec(p);
  if (dm && m === 'PUT') {
    const b = await readJson(req);
    const d = devices[dm[1]] || (devices[dm[1]] = {});
    if ('label' in b) d.label = clip(b.label, 60);
    if ('group' in b) d.group = clip(b.group, 40);
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
  const dm2 = /^\/deploy\/windows\.(ps1|cmd)$/.exec(p);
  if (dm2 && m === 'GET') {
    const tech = url.searchParams.get('tech') === '1';
    const cfg = tech ? techConfigString(readKey()) : configString(readKey());
    if (!cfg) throw fail(tech ? 'no_api_url' : 'not_ready', 409);
    const withPw = !tech && url.searchParams.get('password') === '1';
    log(tech ? 'script du poste technicien téléchargé par' : 'script de déploiement Windows téléchargé par', user, '(' + dm2[1] + ')', withPw ? '(avec mot de passe)' : '');
    const name = brandSlug() + (tech ? '-technicien' : '') + '.' + dm2[1];
    const body = dm2[1] === 'cmd' ? windowsCmd(windowsScript(cfg, withPw)) : '﻿' + windowsScript(cfg, withPw);
    return send(res, 200, body, 'application/octet-stream', { 'Content-Disposition': `attachment; filename="${name}"` });
  }
  if (p === '/download/windows' && m === 'GET') {
    const name = clientFilename(readKey());
    if (!name) throw fail('not_ready', 409);
    log('client Windows préconfiguré téléchargé par', user);
    return streamClient(res, name);
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
  try { await apiRoute(req, res, false); } catch (e) { onError(res, e); }
});
const lanApi = http.createServer(async (req, res) => {
  try { await apiRoute(req, res, true); } catch (e) { onError(res, e); }
});
for (const s of [api, lanApi]) { s.headersTimeout = 10_000; s.requestTimeout = 15_000; }

if (HOST && !HOST_RE.test(HOST)) log('adresse publique invalide :', HOST);
supervise('hbbs', [...(HOST ? ['-r', `${HOST}:${PORTS.relay}`] : []), '-k', '_']);
supervise('hbbr', ['-k', '_']);
panel.listen(PORT, () => log('Desktroo Remote', VERSION, 'prêt sur le port', PORT, SECRET ? '' : '(secret absent : le panneau refusera tout)'));
api.listen(API_PORT, () => log('API des postes sur le port', API_PORT));
lanApi.listen(LAN_API_PORT, () => log('API des techniciens (réseau local) sur le port', LAN_API_PORT));

function shutdown() {
  log('arrêt demandé');
  save(true);
  for (const p of Object.values(procs)) { p.stopping = true; if (p.child) p.child.kill('SIGTERM'); }
  api.close(); lanApi.close(); panel.close();
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
