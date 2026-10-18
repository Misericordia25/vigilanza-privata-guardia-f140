/* Vigilanza Privata: funzione server (Netlify Functions + Netlify Blobs)
   Endpoint: /.netlify/functions/sync   Azioni: status, setup, login, sync
   Variabile d'ambiente obbligatoria: APP_SECRET (almeno 16 caratteri, casuale) */
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const COLS = ['utenti', 'servizi', 'risposte', 'presenze', 'promemoria', 'log', 'impostazioni', 'chat', 'privacy'];
const RUOLI = ['admin', 'tecnico', 'lettura'];
const RET = 180, DAY = 864e5, OVR = 1e7, PAGE = 3.5e6, MAX_REC = 6e5, MAX_FIRMA = 4e5, TOKEN_GG = 30;
// "seq" = millisecondi*1000 + contatore: unico per record, ordina le modifiche e permette la paginazione
const sleep = ms => new Promise(r => setTimeout(r, ms));
let lastBytes = 0;
const J = (o, st = 200) => new Response((t => (lastBytes = t.length, t))(JSON.stringify(o)), { status: st, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const E = (err, st = 400) => J({ err }, st);
const hex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/i.test(s);
const okPw = p => !!p && hex(p.salt, 32) && hex(p.hash, 64);
const st = () => getStore({ name: 'vp', consistency: 'strong' });
/* ---------- Cifratura dei dati a riposo: AES-256-GCM con la chiave DATA_KEY (variabile d'ambiente, almeno 16 caratteri). Senza DATA_KEY i dati restano in chiaro ---------- */
const DK = () => { const k = process.env.DATA_KEY; return k && k.length >= 16 ? crypto.createHash('sha256').update('vp-enc:' + k).digest() : null };
const encOn = () => !!DK();
const enc = (key, obj) => {
  const k = DK(); if (!k) return obj; const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', k, iv); c.setAAD(Buffer.from(key));
  const ct = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]); return { enc: 1, iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') };
};
const dec = (key, o) => {
  if (!o || !o.enc) return o; const k = DK(); if (!k) throw new Error('Dati cifrati: manca DATA_KEY nelle variabili del server');
  try { const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.from(o.iv, 'base64')); d.setAAD(Buffer.from(key)); d.setAuthTag(Buffer.from(o.tag, 'base64')); return JSON.parse(Buffer.concat([d.update(Buffer.from(o.ct, 'base64')), d.final()]).toString()) }
  catch { throw new Error('DATA_KEY errata: impossibile leggere i dati cifrati') }
};
const encS = (key, str) => enc(key, { t: str }), decS = (key, raw) => { if (!raw) return raw; try { const o = JSON.parse(raw); if (o && o.enc) return dec(key, o).t } catch {} return raw };
const sealS = (key, str) => { const o = encS(key, str); return o.enc ? JSON.stringify(o) : str };
// password: oltre a PBKDF2 sul client, sul server l'impronta è protetta con un "pepper" derivato da DATA_KEY (inutile per chi copia solo il database)
const pepper = () => { const k = DK(); return k && crypto.createHmac('sha256', k).update('pw-pepper').digest() };
const hp = (h) => crypto.createHmac('sha256', pepper()).update(h.toLowerCase()).digest('hex');
const stPw = pw => pepper() ? { salt: pw.salt, hash: hp(pw.hash), p: 1 } : { salt: pw.salt, hash: pw.hash.toLowerCase() };
const okH = (cr, h) => !!cr && (cr.p ? !!pepper() && safeEq(hp(h), cr.hash) : safeEq(h, cr.hash));
const load = async (s, k) => dec(k, await s.get(k, { type: 'json' })) || { v: 1, recs: {} };

/* ---------- Sicurezza: password (PBKDF2-SHA256, 100000 iterazioni come il client) e token firmato ---------- */
const pbk = (pass, salt) => new Promise((ok, ko) => crypto.pbkdf2(pass, Buffer.from(salt, 'hex'), 100000, 32, 'sha256', (e, k) => e ? ko(e) : ok(k.toString('hex'))));
const safeEq = (a, b) => { const x = Buffer.from(String(a).toLowerCase()), y = Buffer.from(String(b).toLowerCase()); return x.length === y.length && crypto.timingSafeEqual(x, y) };
const mac = body => crypto.createHmac('sha256', process.env.APP_SECRET).update(body).digest('base64url');
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + mac(b) };
const verify = t => {
  if (typeof t !== 'string') return null; const [b, g] = t.split('.'); if (!b || !g || !safeEq(g, mac(b))) return null;
  try { const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.exp > Date.now() ? p : null } catch { return null }
};

/* ---------- Lettura/scrittura con ETag: nessuna modifica va persa se due dispositivi scrivono insieme ---------- */
async function mutate(s, key, fn) {
  for (let i = 0; i < 8; i++) {
    const cur = await s.getWithMetadata(key, { type: 'json' }), data = cur ? dec(key, cur.data) : { v: 1, recs: {} };
    if (!fn(data)) return data;
    const r = cur ? await s.setJSON(key, enc(key, data), { onlyIfMatch: cur.etag }) : await s.setJSON(key, enc(key, data), { onlyIfNew: true });
    if (r.modified) return data;
    await sleep(40 + Math.random() * 140);
  }
  throw new Error('Troppe scritture contemporanee: riprova tra poco');
}
async function auth(s, token) {
  const p = verify(token); if (!p) return null;
  const data = await load(s, 'c-utenti'), u = data.recs[p.u]?.r;
  return u && !u.deleted && u.attivo !== false ? { user: u, data } : null;
}

/* ---------- Permessi per ruolo ---------- */
// Restituisce null (non consentito), 'skip' (da ignorare) oppure { rec, pw }
// Servizi passati: si bloccano 6 ore dopo la fine. Il blocco vale per tutti; l'amministratore può solo cestinare/ripristinare (campi di servizio)
const PCH_GG = 7, dests = p => p.dest === 'tutti' ? 'tutti' : Array.isArray(p.dest) ? p.dest : [p.dest], inDest = (p, id) => { const d = dests(p); return d === 'tutti' || d.includes(id) };
const LOCK_H = 6, META = ['deleted', 'delAt', 'delCasc', 'escluso', 'updatedAt', 'updatedBy'];
const PRIV_GG = 365, privOk = (p, now) => !!p && !p.rev && p.scad > now; // conferma privacy: vale 365 giorni, finché nessuno toglie la spunta
// assegnazione alle squadre: un volontario è assegnato al servizio sv se ha dato disponibilità a un servizio del gruppo e l'amministratore l'ha comunicata (asC). Servizi senza gruppo (vecchi): basta la disponibilità
const assegn = (ctx, sv, uid) => !sv.gr ? ctx.ris[sv.id + '_' + uid]?.r?.esito === 'si' : Object.values(ctx.srv).some(e => e.r.gr === sv.gr && ctx.ris[e.r.id + '_' + uid]?.r?.esito === 'si' && ctx.ris[e.r.id + '_' + uid].r.asC === sv.id);
const lockedSv = (sv, now) => !!sv && !sv.deleted && now > fineServ(sv) + LOCK_H * 36e5;
const onlyMeta = (p, r) => !!p && [...new Set([...Object.keys(p), ...Object.keys(r)])].every(k => META.includes(k) || (k === 'firma' && p.firma === '@' && r.firma) || JSON.stringify(p[k]) === JSON.stringify(r[k]));
function clean(user, col, raw, prev, data, now, ctx) {
  if (!raw || typeof raw.id !== 'string' || !/^[\w.:@-]{1,200}$/.test(raw.id)) return null;
  const { pw, ...rec } = raw, ad = user.ruolo === 'admin', own = user.id;
  if (JSON.stringify(rec).length > MAX_REC) return null;
  const ua = Number(rec.updatedAt); rec.updatedAt = Math.min(ua > 0 ? ua : now, now + 6e5); rec.updatedBy = own;
  if (col === 'risposte' || col === 'presenze') { const sv = ctx?.srv[rec.servizioId]?.r; if (lockedSv(sv, now) && !(ad && (onlyMeta(prev, rec) || col === 'presenze' && prev?.auto && now < fineServ(sv) + 30 * DAY))) return null }
  if (col === 'servizi' && prev && lockedSv(prev, now) && !(ad && onlyMeta(prev, rec))) return null;
  if (col === 'log') {
    if (rec.utenteId !== own) return null;
    const ts = Number(rec.ts); rec.ts = ts > 0 && ts < now + DAY ? ts : now; return { rec };
  }
  if (col === 'utenti') {
    if (!ad) {
      if (rec.id !== own || !prev) return null;
      Object.assign(rec, { ruolo: prev.ruolo, attivo: prev.attivo, username: prev.username, creato: prev.creato, privacy: prev.privacy, privacyData: prev.privacyData }); delete rec.deleted;
    } else {
      rec.username = String(rec.username || '').trim().toLowerCase();
      if (!rec.deleted && (!rec.nome || !rec.cognome || !rec.username || !RUOLI.includes(rec.ruolo))) return null;
      if (Object.values(data.recs).some(e => e.r.id !== rec.id && !e.r.deleted && e.r.username === rec.username)) return null;
      if (rec.id === own) { rec.ruolo = 'admin'; rec.attivo = true; delete rec.deleted } // l'amministratore non può togliersi i permessi
    }
    if (pw && !okPw(pw)) return null;
    return { rec, pw: pw ? { salt: pw.salt, hash: pw.hash.toLowerCase() } : null };
  }
  if (col === 'chat' && rec.promId) { // chat di un promemoria: amministratore e destinatari; "a" = gestore | tutti | id utente
    const pm = ctx?.prom[rec.promId]?.r, tx = String(rec.testo || '').trim().slice(0, 500), a = String(rec.a || 'gestore');
    if (!ctx || ctx.cfg?.chat === false || !pm || pm.deleted || !tx || user.ruolo === 'lettura' || prev && prev.utenteId !== own && !ad) return null;
    if (!ad && (!inDest(pm, own) || a !== 'gestore' && a !== 'tutti')) return null;
    if (now > (pm.quando || 0) + PCH_GG * DAY) return null;
    const ts = Number(rec.ts); return { rec: { id: rec.id, promId: rec.promId, a, utenteId: own, nome: `${user.nome} ${user.cognome}`, testo: tx, ts: ts > 0 && ts < now + 6e5 ? ts : now, updatedAt: rec.updatedAt, updatedBy: own } };
  }
  if (col === 'chat') { // solo l'amministratore e chi ha accettato il servizio; chat attiva e non scaduta (48 h dopo la fine)
    const sv = ctx?.srv[rec.servizioId]?.r, tx = String(rec.testo || '').trim().slice(0, 500);
    if (!ctx || ctx.cfg?.chat === false || !sv || sv.deleted || !tx || user.ruolo === 'lettura' || prev && prev.utenteId !== own && !ad) return null;
    if (!ad && !assegn(ctx, sv, own)) return null;
    if (now > fineServ(sv) + 48 * 36e5) return null;
    const ts = Number(rec.ts); return { rec: { id: rec.id, servizioId: rec.servizioId, utenteId: own, nome: `${user.nome} ${user.cognome}`, testo: tx, ts: ts > 0 && ts < now + 6e5 ? ts : now, updatedAt: rec.updatedAt, updatedBy: own } };
  }
  if (col === 'risposte' || col === 'presenze') {
    if (!ad) {
      if (user.ruolo !== 'tecnico' || rec.utenteId !== own || rec.id !== rec.servizioId + '_' + own) return null;
      if (col === 'presenze' && prev?.verificatoDa) return null; // presenza già confermata dal coordinatore
      if (col === 'risposte' && prev?.asC !== undefined) return null; // squadre già comunicate: la risposta non si cambia più
      if (col === 'presenze' && rec.checkIn && !prev?.checkIn) { const sv = ctx?.srv[rec.servizioId]?.r; if (sv?.gr && !assegn(ctx, sv, own)) return null } // check-in solo per chi è stato assegnato
      delete rec.verificatoDa; delete rec.noteCoord;
      if (col === 'risposte') { delete rec.as; delete rec.asC; if (prev) { if (prev.as !== undefined) rec.as = prev.as } } // l'assegnazione la decide solo l'amministratore
    } else if (typeof rec.servizioId !== 'string' || typeof rec.utenteId !== 'string') return null;
    return { rec };
  }
  if (col === 'privacy') { // conferma privacy: la data e la scadenza le fissa il server; il volontario conferma o toglie la spunta, l'amministratore può solo toglierla
    if (!ctx?.ut[rec.id] || ctx.ut[rec.id].r.deleted || ctx.ut[rec.id].r.ruolo === 'admin' || !ad && rec.id !== own) return null;
    const base = { id: rec.id, utenteId: rec.id, updatedAt: rec.updatedAt, updatedBy: own };
    if (rec.rev) return prev && !prev.rev ? { rec: { ...prev, ...base, rev: now, revBy: own } } : null;
    if (ad) return null;
    const fo = ctx.cfg?.privFirma !== false, f = typeof rec.firma === 'string' && rec.firma.startsWith('data:image/') ? rec.firma : '';
    if (fo && !f) return null;
    return { rec: { ...base, ts: now, scad: now + PRIV_GG * DAY, ver: String(rec.ver || '').slice(0, 20), ...(f ? { firma: f } : {}) } };
  }
  if (col === 'promemoria') { rec.quando = Number(rec.quando) || Date.parse(String(rec.scadenza) + ':00Z') - 2 * 36e5; if (Array.isArray(rec.dest)) rec.dest = rec.dest.filter(x => typeof x === 'string').slice(0, 500) }
  return ad ? { rec } : null; // servizi, promemoria, impostazioni: solo amministratore
}
// Cosa può vedere ciascun ruolo
const fineServ = sv => { const t = Date.parse(sv.data + 'T' + (sv.oraFine || '23:59') + ':00Z') - 2 * 36e5; return sv.oraFine < sv.oraInizio ? t + DAY : t }; // fuso Italia approssimato (UTC+2)
function view(user, col, r, okS) {
  if (user.ruolo === 'admin') return r;
  if (col === 'chat' && r.promId) return user.ruolo !== 'lettura' && (r.utenteId === user.id || okS?.has('p:' + r.promId) && (r.a === 'tutti' || r.a === user.id)) ? r : null;
  if (col === 'chat') return user.ruolo === 'tecnico' && okS?.has(r.servizioId) ? r : null;
  const tec = user.ruolo === 'tecnico';
  if (col === 'utenti') { if (r.id === user.id) return r; if (tec) return null; const { cell, email, ...x } = r; return x }
  if (col === 'privacy') return r.id === user.id ? r : null;
  if (col === 'servizi') { const { posti, ...x } = r; return x } // i volontari non sanno quanti volontari servono
  if (col === 'risposte') { if (tec && r.utenteId !== user.id) return null; const { as, ...x } = r; return x } // la bozza di assegnazione è solo dell'amministratore
  if (col === 'presenze') return tec && r.utenteId !== user.id ? null : r;
  if (col === 'log') return r.utenteId === user.id ? r : null;
  if (col === 'promemoria') return inDest(r, user.id) ? r : null;
  if (col === 'impostazioni') { const { pinHash, pinSalt, ...x } = r; return x }
  return r;
}

/* ---------- Azioni ---------- */
async function setup(s, b) {
  const u = b.user;
  if (!u || typeof u.id !== 'string' || !/^[\w.:@-]{1,200}$/.test(u.id) || !okPw(u.pw)) return E('Dati di configurazione non validi');
  const un = String(u.username || '').trim().toLowerCase();
  if (!u.nome || !u.cognome || !un) return E('Compila nome, cognome e nome utente');
  const c = await s.setJSON('creds', enc('creds', { v: 1, recs: { [u.id]: stPw(u.pw) } }), { onlyIfNew: true });
  if (!c.modified) return E('Il cloud ha già degli utenti', 403); // il primo che arriva diventa amministratore
  const { pw, ...rest } = u, now = Date.now();
  const rec = { ...rest, username: un, ruolo: 'admin', attivo: true, updatedAt: Math.min(Number(u.updatedAt) || now, now), updatedBy: u.id }; delete rec.deleted;
  await s.setJSON('c-utenti', enc('c-utenti', { v: 1, recs: { [u.id]: { s: now * 1000, r: rec } } }));
  return J({ token: sign({ u: u.id, exp: now + TOKEN_GG * DAY }), user: rec });
}
async function login(s, b) {
  const un = String(b.username || '').trim().toLowerCase(), pw = String(b.password || '');
  const e = Object.values((await load(s, 'c-utenti')).recs).find(x => !x.r.deleted && x.r.username === un);
  const cr = e ? (await load(s, 'creds')).recs[e.r.id] : null;
  const h = await pbk(pw, cr?.salt || '0'.repeat(32)); // si calcola sempre: stesso tempo anche se l'utente non esiste
  if (!okH(cr, h)) { await sleep(500); return E('Nome utente o password errati', 401) }
  if (e.r.attivo === false) return E('Account sospeso: contatta il coordinatore', 403);
  if (encOn() && !cr.p) await mutate(s, 'creds', d => { d.recs[e.r.id] = stPw({ salt: cr.salt, hash: h }); return true }).catch(() => {}); // passa al pepper
  return J({ token: sign({ u: e.r.id, exp: Date.now() + TOKEN_GG * DAY }), user: e.r, salt: cr.salt });
}
const mStart = ms => { const d = new Date(ms); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1) };
const mNext = ms => { const d = new Date(ms); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) };
const mKey = ms => 'c-log-' + new Date(ms).toISOString().slice(0, 7);

/* ---------- Consumo del piano gratuito (stima in crediti Netlify: calcolo 10/GB-ora, richieste 2 ogni 10.000, banda 20/GB) ---------- */
const UL = 300, MEM = 1, SOGLIE = [100, 200, 250, 300];
let acc = { n: 0, ms: 0, by: 0 }, lastFl = 0;
const crd = a => a.n * 2e-4 + a.ms / 36e5 * MEM * 10 + a.by / 1e9 * 20;
async function flush(s, t0, force) {
  if (!force && acc.n < 10 && t0 - lastFl < 6e4) return; const a = acc; acc = { n: 0, ms: 0, by: 0 }; lastFl = t0;
  const m = new Date(t0).toISOString().slice(0, 7);
  await mutate(s, 'usage', d => {
    if (d.m !== m) { d.hist = { ...(d.hist || {}), ...(d.m ? { [d.m]: Math.round(d.cr * 100) / 100 } : {}) }; Object.assign(d, { m, n: 0, ms: 0, by: 0, cr: 0, av: [] }) }
    d.n += a.n; d.ms += a.ms; d.by += a.by; d.cr = crd(d);
    for (const g of SOGLIE) if (d.cr >= g && !d.av.some(x => x.s === g)) d.av.push({ s: g, ts: t0 });
    return true;
  });
}
async function getUsage(s) {
  const d = (await s.get('usage', { type: 'json' })) || {}, m = new Date().toISOString().slice(0, 7), cur = d.m === m;
  const n = (cur ? d.n || 0 : 0) + acc.n, cr = cur ? crd({ n: d.n || 0, ms: d.ms || 0, by: d.by || 0 }) + crd(acc) : crd(acc);
  const av = [...(cur ? d.av || [] : [])]; for (const g of SOGLIE) if (cr >= g && !av.some(x => x.s === g)) av.push({ s: g, ts: Date.now() });
  return { m, n, cr: Math.round(cr * 1000) / 1000, limit: UL, av, hist: d.hist || {}, enc: encOn() };
}

/* ---------- Conservazione: firme e posizioni GPS si cancellano dopo RET giorni (presenze e ore restano) ---------- */
const GPS = ['lat', 'lng', 'acc', 'ind'], hasDati = r => r.firma || [r.checkIn, r.checkOut].some(c => c && GPS.some(k => k in c));
function strip(r, t0) { delete r.firma; for (const c of [r.checkIn, r.checkOut]) if (c) for (const k of GPS) delete c[k]; r.datiRimossi = t0 }
const fk = (col, id) => col === 'privacy' ? 'pv-' + id : id; // chiave del blob della firma
let lastPurge = 0;
async function purge(s, t0, nextS) {
  if (t0 - lastPurge < 36e5) return 0; lastPurge = t0;
  const lim = t0 - RET * DAY, sv = (await load(s, 'c-servizi')).recs; let ids = [], tot = 0;
  await mutate(s, 'c-presenze', d => {
    ids = []; let n = 0;
    for (const e of Object.values(d.recs)) {
      const r = e.r, t = r.checkIn?.ts || r.checkOut?.ts || (sv[r.servizioId]?.r?.data ? Date.parse(sv[r.servizioId].r.data + 'T12:00:00Z') : 0);
      if (!t || t >= lim || !hasDati(r)) continue;
      if (r.firma) ids.push(r.id); strip(r, t0); r.updatedAt = t0; r.updatedBy = 'server'; e.s = nextS(); n++;
    }
    tot = n; return n > 0;
  });
  for (const id of ids) await s.delete('f-' + id).catch(() => {});
  // Cestino: dopo RET giorni gli elementi eliminati vengono cancellati in modo definitivo (gli utenti restano come nome anonimo per lo storico)
  const gone = r => r.deleted && !r.purged && (r.delAt || r.updatedAt || 0) < lim, dead = [];
  await mutate(s, 'c-utenti', d => { let n = 0; for (const e of Object.values(d.recs)) { const r = e.r; if (!gone(r)) continue; dead.push(r.id);
    e.r = { id: r.id, nome: r.nome, cognome: r.cognome, username: 'eliminato-' + r.id.slice(-6), ruolo: r.ruolo === 'admin' ? 'tecnico' : r.ruolo, attivo: false, deleted: true, purged: true, delMode: r.delMode, delAt: r.delAt, creato: r.creato, updatedAt: t0, updatedBy: 'server' }; e.s = nextS(); n++ } return n > 0 }).catch(() => {});
  if (dead.length) await mutate(s, 'creds', d => { for (const id of dead) delete d.recs[id]; return true }).catch(() => {});
  if (dead.length) { await mutate(s, 'c-privacy', d => { let n = 0; for (const id of dead) if (d.recs[id]) { delete d.recs[id]; n++ } return n > 0 }).catch(() => {}); for (const id of dead) await s.delete('f-pv-' + id).catch(() => {}) }
  for (const [col, keep] of [['servizi', ['id', 'data', 'oraInizio', 'oraFine', 'titolo']], ['promemoria', ['id', 'titolo', 'scadenza']], ['risposte', ['id', 'servizioId', 'utenteId', 'esito', 'ts']]])
    await mutate(s, 'c-' + col, d => { let n = 0; for (const e of Object.values(d.recs)) { const r = e.r; if (!gone(r)) continue; e.r = Object.fromEntries([...keep.filter(k => k in r).map(k => [k, r[k]]), ['deleted', true], ['purged', true], ['delAt', r.delAt], ['updatedAt', t0], ['updatedBy', 'server']]); e.s = nextS(); n++ } return n > 0 }).catch(() => {});
  const pr = (await load(s, 'c-promemoria')).recs;
  await mutate(s, 'c-chat', d => { let n = 0; for (const [k, e] of Object.entries(d.recs)) { const v = sv[e.r.servizioId]?.r, pm = pr[e.r.promId]?.r; if (e.r.promId ? !pm || pm.deleted || t0 > (pm.quando || 0) + PCH_GG * DAY : !v || v.deleted || t0 > fineServ(v) + 48 * 36e5) { delete d.recs[k]; n++ } } return n > 0 }).catch(() => {}); // la chat si azzera 48 h dopo la fine dell'evento
  return tot;
}

async function pushTo(s, ids, pl) {
  const key = vapidKey(); if (!key || !ids.length) return; const all = await getPush(s); let ch = false;
  for (const id of ids) for (const sub of all[id] || []) { const c = await sendPush(sub, JSON.stringify(pl), key).catch(() => 0); if (c === 404 || c === 410) { all[id] = all[id].filter(x => x.endpoint !== sub.endpoint); ch = true } }
  if (ch) await setPush(s, all);
}
const TIPO = { af: '🔴 Servizio Antincendio', ds: '🟠 Servizio Def safety' }, tp = sv => TIPO[sv?.tipo] || TIPO.af, dIt = d => String(d || '').split('-').reverse().join('/');
// Record derivato "squadra": per ogni servizio a cui il volontario è stato assegnato, i componenti della sola sua squadra (nome e telefono). Non è un dato salvato: si ricalcola a ogni sincronizzazione
function squadre(state, user, t0) {
  const srv = state['c-servizi'].recs, ris = Object.values(state['c-risposte'].recs).map(e => e.r).filter(r => !r.deleted && r.esito === 'si' && typeof r.asC === 'string' && r.asC !== '-'), ut = state['c-utenti'].recs, out = [];
  for (const sid of new Set(ris.filter(r => r.utenteId === user.id).map(r => r.asC))) {
    const sv = srv[sid]?.r; if (!sv || sv.deleted || t0 > fineServ(sv) + LOCK_H * 36e5) continue;
    out.push({ id: 'sq_' + sid, servizioId: sid, updatedAt: t0, m: ris.filter(r => r.asC === sid).map(r => ut[r.utenteId]?.r).filter(u => u && !u.deleted && u.attivo !== false).map(u => ({ id: u.id, n: u.nome + ' ' + u.cognome, c: u.cell || '' })) });
  }
  return out;
}
// Notifiche push per squadre, nuovi servizi e privacy
async function avvisi(s, state, evs) {
  if (!evs.length) return; const srv = state['c-servizi'].recs, us = Object.values(state['c-utenti'].recs).map(e => e.r).filter(u => !u.deleted && u.attivo !== false), adm = us.filter(u => u.ruolo === 'admin').map(u => u.id), vol = us.filter(u => u.ruolo === 'tecnico').map(u => u.id), nm = id => { const u = state['c-utenti'].recs[id]?.r; return u ? u.nome + ' ' + u.cognome : 'Volontario' };
  const nuovi = {}; for (const e of evs) if (e.k === 'sv') (nuovi[e.rec.gr || e.rec.id] ||= []).push(e.rec);
  for (const g of Object.values(nuovi)) { const a = g[0], tipi = g.map(x => x.tipo === 'ds' ? 'Def safety' : 'Antincendio');
    await pushTo(s, vol, g.length > 1 ? { t: '🔴🟠 Nuovo servizio: ' + a.titolo, b: `${dIt(a.data)} ore ${a.oraInizio}, ${a.luogo}. Puoi candidarti a una sola squadra: ${tipi.join(' oppure ')}.`, go: 'servizi', tg: 'ns-' + a.id } : { t: tp(a) + ': ' + a.titolo, b: `${dIt(a.data)} ore ${a.oraInizio}, ${a.luogo}. Apri l'app e candidati.`, go: 'servizi', tg: 'ns-' + a.id }) }
  for (const e of evs) {
    if (e.k === 'as') { const r = e.rec, sv = srv[r.asC]?.r || srv[r.servizioId]?.r; if (!sv) continue;
      await pushTo(s, [r.utenteId], r.asC !== '-' ? { t: tp(sv) + ': candidatura accettata', b: `${sv.titolo}, ${dIt(sv.data)} ore ${sv.oraInizio}. Apri Turno per vedere la tua squadra.`, go: 'turno', tg: 'as-' + r.id } : { t: 'Servizio: non sei stato selezionato', b: `${sv.titolo}, ${dIt(sv.data)}. Grazie per la disponibilità: questa volta non servi.`, go: 'servizi', tg: 'as-' + r.id }) }
    if (e.k === 'pv') { const id = e.rec.id; await pushTo(s, [id], { t: '🔒 Account sospeso', b: "La spunta della privacy è stata tolta. Se è un errore apri l'app, leggi l'informativa e riconferma.", tg: 'pv-' + id });
      await pushTo(s, adm.filter(x => x !== id), { t: '🔒 Privacy tolta: ' + nm(id), b: `${nm(id)}: tolta la spunta della privacy (${e.rec.revBy === id ? 'dal volontario' : "dall'amministratore"}). L'account è sospeso.`, go: 'volontari', tg: 'pv-' + id }) }
  }
}
async function doSync(s, user, udata, b) {
  const t0 = Date.now(), since = Number(b.since) || 0, by = {};
  for (const c of Array.isArray(b.changes) ? b.changes : []) if (c && COLS.includes(c.col) && c.rec) (by[c.col] ||= []).push(c.rec);
  const state = { 'c-utenti': udata }, rej = [], extra = [], firme = [], cred = [], evs = [];
  // senza una conferma privacy valida (mai data, scaduta o tolta) l'account è sospeso: si possono solo leggere/scrivere i dati della privacy
  let gate = user.ruolo !== 'admin' && !privOk((state['c-privacy'] = await load(s, 'c-privacy')).recs[user.id]?.r, t0);
  if (gate) for (const k of Object.keys(by)) if (k !== 'privacy' && k !== 'log') delete by[k];
  const ctx = by.chat?.length || by.risposte?.length || by.presenze?.length || by.servizi?.length || by.privacy?.length ? { ut: state['c-utenti'].recs, srv: (await load(s, 'c-servizi')).recs, ris: (await load(s, 'c-risposte')).recs, cfg: (await load(s, 'c-impostazioni')).recs.cfg?.r, prom: by.chat?.length ? (await load(s, 'c-promemoria')).recs : {} } : null;
  let ctr = 0; const nextS = () => t0 * 1000 + ctr++;
  const note = (azione, esito) => { if (extra.length < 30) extra.push({ id: 'sv_' + crypto.randomBytes(6).toString('hex'), ts: t0, utenteId: user.id, tipo: 'sync', azione, esito, updatedAt: t0, updatedBy: 'server' }) };

  // 1) scrittura delle modifiche ricevute (ultima modifica vince)
  const noFirma = by.presenze?.length ? (await load(s, 'c-impostazioni')).recs.cfg?.r?.firma === false : false;
  for (const col of COLS) {
    const items = by[col]; if (col === 'log' || !items?.length) continue;
    let acc, den, rj, fm, cu, ev;
    state['c-' + col] = await mutate(s, 'c-' + col, d => {
      acc = 0; den = []; rj = []; fm = []; cu = []; ev = [];
      for (const raw of items) {
        const prev = d.recs[raw?.id]?.r, c = clean(user, col, raw, prev, d, t0, ctx);
        if (!c) { den.push(raw?.id); continue }
        const { rec, pw } = c;
        if (col === 'presenze' && noFirma && typeof rec.firma === 'string' && rec.firma.startsWith('data:image/')) delete rec.firma;
        if (prev && (prev.updatedAt || 0) > rec.updatedAt) { rj.push({ col, ...d.recs[rec.id] }); continue }
        if (col === 'presenze') { const t = rec.checkIn?.ts || rec.checkOut?.ts; if (t && t < t0 - RET * DAY && hasDati(rec)) strip(rec, t0) }
        if ((col === 'presenze' || col === 'privacy') && typeof rec.firma === 'string' && rec.firma.startsWith('data:image/')) { // la firma sta in un blob a parte
          if (rec.firma.length > MAX_FIRMA) { den.push(rec.id); continue }
          fm.push([fk(col, rec.id), rec.firma]); rec.firma = '@';
        }
        if (col === 'risposte' && user.ruolo === 'admin' && rec.asC !== undefined && prev?.asC !== rec.asC) ev.push({ k: 'as', rec });
        if (col === 'servizi' && !prev && !rec.deleted) ev.push({ k: 'sv', rec });
        if (col === 'privacy' && rec.rev && !prev?.rev) ev.push({ k: 'pv', rec });
        d.recs[rec.id] = { s: nextS(), r: rec }; acc++;
        if (pw) cu.push([rec.id, pw]);
      }
      return acc > 0;
    });
    firme.push(...fm); cred.push(...cu); rej.push(...rj); evs.push(...(ev || []));
    for (const id of den) note(`Operazione non consentita: ${col} ${id}`, 'negato');
    for (const r of rj) note(`Modifica scartata: ${col} ${r.r.id} (sul server c'è una versione più recente)`, 'scartata');
  }
  if (by.promemoria?.length || by.servizi?.length || by.risposte?.length || by.presenze?.length || by.privacy?.length) await s.delete('rem-next').catch(() => {});
  if (cred.length) await mutate(s, 'creds', d => { for (const [id, p] of cred) d.recs[id] = stPw(p); return true });
  for (const [id, f] of firme) await s.set('f-' + id, sealS('f-' + id, f));
  if (gate) gate = !privOk(state['c-privacy'].recs[user.id]?.r, t0);
  await avvisi(s, state, evs).catch(() => {});
  const nrm = await purge(s, t0, nextS).catch(() => 0); if (nrm) delete state['c-presenze']; if (nrm) note(`Conservazione ${RET} giorni: rimosse firme e posizioni da ${nrm} presenze`, 'ok');
  const groups = {}, add = r => (groups[mKey(r.ts)] ||= []).push(r);
  for (const raw of by.log || []) { const c = clean(user, 'log', raw, null, null, t0); if (c) add(c.rec) }
  extra.forEach(add);
  for (const [k, arr] of Object.entries(groups)) state[k] = await mutate(s, k, d => { let n = 0; for (const r of arr) if (!d.recs[r.id]) { d.recs[r.id] = { s: nextS(), r }; n++ } return n > 0 });

  // 2) raccolta di ciò che è cambiato dall'ultima sincronizzazione (since<0: pagina successiva)
  const min = since === 0 ? -1 : since < 0 ? -since : since - OVR, cand = new Map();
  const put = (col, e) => { const k = col + '|' + e.r.id; if (!cand.has(k)) cand.set(k, { col, s: e.s, r: e.r }) };
  for (const col of COLS) {
    if (col === 'log') continue;
    const d = (state['c-' + col] ??= await load(s, 'c-' + col));
    for (const e of Object.values(d.recs)) if (e.s > min) put(col, e);
  }
  const ms0 = since === 0 ? t0 - 180 * DAY : Math.max(min / 1000, t0 - 180 * DAY);
  for (let m = mStart(user.ruolo === 'admin' ? ms0 : Math.max(ms0, t0 - 40 * DAY)); m <= t0; m = mNext(m)) {
    const k = mKey(m), d = state[k] ?? await load(s, k);
    for (const e of Object.values(d.recs)) if (e.s > min) put('log', e);
  }
  rej.forEach(e => put(e.col, e));
  let okS = null;
  if (user.ruolo === 'tecnico' && [...cand.values()].some(c => c.col === 'chat')) {
    okS = new Set(); for (const e of Object.values(state['c-risposte'].recs)) { const r = e.r; if (r.utenteId !== user.id || r.esito !== 'si' || r.deleted) continue; const sv = state['c-servizi'].recs[r.servizioId]?.r; if (sv?.gr) { if (typeof r.asC === 'string' && r.asC !== '-') okS.add(r.asC) } else okS.add(r.servizioId) }
    for (const e of Object.values((await load(s, 'c-promemoria')).recs)) if (!e.r.deleted && inDest(e.r, user.id)) okS.add('p:' + e.r.id);
  }
  let list = [...cand.values()].map(c => ({ ...c, v: view(user, c.col, c.r, okS) })).filter(c => c.v)
    .sort((a, b) => a.s - b.s || (a.col + a.r.id < b.col + b.r.id ? -1 : 1));

  if (gate) list = list.filter(c => ['utenti', 'impostazioni', 'privacy'].includes(c.col));
  else if (user.ruolo === 'tecnico') { let n = 0; for (const rec of squadre(state, user, t0)) list.push({ col: 'squadra', s: t0 * 1000 + n++, r: rec, v: rec }) }
  // 3) risposta a pagine (~3,5 MB): firme reinserite solo per i record inviati
  const recs = []; let size = 0, more = false, last = 0;
  for (let i = 0; i < list.length && !more; i += 8) {
    const ch = list.slice(i, i + 8);
    await Promise.all(ch.map(async c => {
      if ((c.col === 'presenze' || c.col === 'privacy') && c.v.firma === '@') { const k = 'f-' + fk(c.col, c.r.id), f = decS(k, await s.get(k, { type: 'text' })); c.v = { ...c.v }; if (f) c.v.firma = f; else delete c.v.firma }
    }));
    for (const c of ch) {
      const n = JSON.stringify(c.v).length;
      if (recs.length && size + n > PAGE) { more = true; break }
      recs.push({ col: c.col, rec: c.v }); size += n; last = c.s;
    }
  }
  return J({ recs, seq: gate ? since : more ? -last : t0 * 1000, more, gate, ...(user.ruolo === 'admin' ? { usage: await getUsage(s) } : {}) });
}

/* ---------- Azzeramento dati (prove): automatico a ogni deploy se RESET_ON_DEPLOY=true, oppure quando cambia RESET_KEY; manuale con l'azione reset ---------- */
const KEEP = ['usage', 'rk'];
async function wipe(s) { const { blobs } = await s.list(); await Promise.all(blobs.filter(x => !KEEP.includes(x.key)).map(x => s.delete(x.key))) }
let rkOk = false, raOk = false;
// Reimpostazione dell'amministratore (volontari e dati restano): a ogni deploy se RESET_ADMIN_ON_DEPLOY=true, oppure quando cambia RESET_ADMIN_KEY
async function autoAdmin(s, ctx) {
  if (raOk) return; const k = process.env.RESET_ADMIN_KEY || (process.env.RESET_ADMIN_ON_DEPLOY === 'true' ? (ctx?.deploy?.id || process.env.DEPLOY_ID) : '');
  if (k && (await s.get('ark', { type: 'text' })) !== k) {
    if (await s.get('creds', { type: 'json' })) {
      const now = Date.now(); await mutate(s, 'c-utenti', d => { let n = 0; for (const e of Object.values(d.recs)) if (e.r.ruolo === 'admin' && e.r.attivo !== false && !e.r.deleted) { e.r = { ...e.r, attivo: false, updatedAt: now, updatedBy: 'server' }; e.s = now * 1000 + n++ } return n > 0 });
      await s.setJSON('needadmin', { t: now });
    } await s.set('ark', k);
  } raOk = true;
}
async function adminSetup(s, b) {
  if (!(await s.get('needadmin', { type: 'json' }))) return E('Reimpostazione dell\'amministratore non attiva', 403);
  const u = b.user; if (!u || typeof u.id !== 'string' || !/^[\w.:@-]{1,200}$/.test(u.id) || !okPw(u.pw)) return E('Dati non validi');
  const un = String(u.username || '').trim().toLowerCase(); if (!u.nome || !u.cognome || !un) return E('Compila nome, cognome e nome utente');
  const { pw, ...rest } = u, now = Date.now(); let id = u.id, rec;
  await mutate(s, 'c-utenti', d => {
    const ex = Object.values(d.recs).find(e => !e.r.deleted && e.r.username === un);
    if (ex && !(ex.r.ruolo === 'admin' && ex.r.attivo === false)) { id = null; return false }
    if (ex) id = ex.r.id; rec = { ...(ex?.r || {}), ...rest, id, username: un, ruolo: 'admin', attivo: true, updatedAt: now, updatedBy: id }; delete rec.deleted;
    d.recs[id] = { s: now * 1000, r: rec }; return true;
  });
  if (!id) return E('Nome utente già usato da un altro utente', 409);
  await mutate(s, 'creds', d => { d.recs[id] = stPw(pw); return true });
  await s.delete('needadmin'); return J({ token: sign({ u: id, exp: now + TOKEN_GG * DAY }), user: rec });
}
async function autoReset(s, ctx) {
  if (rkOk) return; const k = process.env.RESET_KEY || (process.env.RESET_ON_DEPLOY === 'true' ? (ctx?.deploy?.id || process.env.DEPLOY_ID) : '');
  if (k && (await s.get('rk', { type: 'text' })) !== k) { await wipe(s); await s.set('rk', k) } rkOk = true;
}

// Migrazione una tantum: cifra i dati già presenti in chiaro quando DATA_KEY viene impostata (il marcatore evita di rifarla a ogni avvio)
let encMig = false;
async function migra(s) {
  if (encMig || !encOn()) return; const fp = crypto.createHash('sha256').update(DK()).digest('hex').slice(0, 12);
  if ((await s.get('encm', { type: 'text' })) !== fp) {
    const { blobs } = await s.list();
    for (const { key } of blobs) {
      if (key === 'creds' || key.startsWith('c-')) { const o = await s.get(key, { type: 'json' }); if (o && !o.enc) await mutate(s, key, () => true) }
      else if (key.startsWith('f-')) { const f = await s.get(key, { type: 'text' }); if (f && !f.startsWith('{"enc"')) await s.set(key, sealS(key, f)) }
    }
    await s.set('encm', fp);
  } encMig = true;
}


/* ---------- Notifiche push (Web Push, RFC 8030/8291/8292) senza librerie esterne. Chiave privata VAPID: variabile VAPID_PRIVATE_KEY ---------- */
const VAPID_PUB = 'BGYnD8gOFFydbHrAnqD2R_w2b7VUfxF0sl_rLtVheewbq_G4PVyYE19enHbWgYVu0DqKHo5o5kj-5RXPYo7mYkA', b64u = b => Buffer.from(b).toString('base64url');
const getPush = async s => { const o = await s.get('push', { type: 'json' }).catch(() => null); try { return o ? dec('push', o) : {} } catch { return {} } };
const setPush = (s, o) => s.setJSON('push', enc('push', o));
function vapidKey() {
  const d = process.env.VAPID_PRIVATE_KEY; if (!d) return null; const pub = Buffer.from(process.env.VAPID_PUBLIC_KEY || VAPID_PUB, 'base64url');
  return crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) }, format: 'jwk' });
}
const hk = (salt, ikm, info, n) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, n));
export function encPush(sub, payload) {
  const ua = Buffer.from(sub.keys.p256dh, 'base64url'), au = Buffer.from(sub.keys.auth, 'base64url'), e = crypto.createECDH('prime256v1'); e.generateKeys();
  const pub = e.getPublicKey(), ikm = hk(au, e.computeSecret(ua), Buffer.concat([Buffer.from('WebPush: info\0'), ua, pub]), 32), salt = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-128-gcm', hk(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16), hk(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12));
  const ct = Buffer.concat([c.update(Buffer.concat([Buffer.from(payload), Buffer.from([2])])), c.final(), c.getAuthTag()]), rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([pub.length]), pub, ct]);
}
async function sendPush(sub, payload, key) {
  const h = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' })), p = b64u(JSON.stringify({ aud: new URL(sub.endpoint).origin, exp: Math.floor(Date.now() / 1e3) + 12 * 3600, sub: process.env.VAPID_SUBJECT || 'mailto:admin@vigilanza.invalid' }));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + p), { key, dsaEncoding: 'ieee-p1363' });
  const r = await fetch(sub.endpoint, { method: 'POST', headers: { 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: '3600', urgency: 'high', authorization: `vapid t=${h}.${p}.${b64u(sig)}, k=${process.env.VAPID_PUBLIC_KEY || VAPID_PUB}` }, body: encPush(sub, payload), signal: AbortSignal.timeout(8000) });
  return r.status;
}
// Eseguita ogni minuto dalla funzione pianificata: se nulla è in scadenza esce subito (1 sola lettura)
const iniServ = sv => Date.parse(sv.data + 'T' + (sv.oraInizio || '00:00') + ':00Z') - 2 * 36e5;
export async function runPush(s = st(), now = Date.now()) {
  const nx = await s.get('rem-next', { type: 'json' }).catch(() => null); if (nx && nx.t > now) return 0;
  const key = vapidKey(), live = async c => Object.values((await load(s, c)).recs).map(e => e.r).filter(r => !r.deleted);
  const pr = (await live('c-promemoria')).filter(p => p.quando);
  const sent = await s.get('rem-sent', { type: 'json' }).catch(() => null) || {}, due = [], fut = [];
  const add = (t, k, it) => { if (t > now) fut.push(t); else if (now - t < 12 * 6e4 && !sent[k]) due.push({ k, ...it }) };
  for (const p of pr) for (const n of [0, 1]) add(p.quando + n * 3e5, `${p.id}:${p.quando}:${n}`, { dest: u => inDest(p, u), pl: { t: '🔔 ' + p.titolo, b: String(p.testo || 'Promemoria').slice(0, 140), prom: p.id, n } });
  // avvisi di turno: 30 min prima dell'inizio (check-in mancante) e 2 ore dopo la fine (check-out mancante), ripetuti dopo 5 minuti
  let pres = {};
  const sv = Object.fromEntries((await live('c-servizi')).filter(v => v.data && Math.abs(Date.parse(v.data) - now) < 4 * DAY).map(v => [v.id, v]));
  if (Object.keys(sv).length) {
    pres = Object.fromEntries((await live('c-presenze')).map(p => [p.servizioId + '_' + p.utenteId, p]));
    for (const r of await live('c-risposte')) { const v = sv[r.servizioId]?.gr ? sv[r.asC] : sv[r.servizioId]; if (!v || r.esito !== 'si') continue; const p = pres[v.id + '_' + r.utenteId], me = u => u === r.utenteId; // con le squadre vale il servizio a cui sei stato assegnato
      for (const n of [0, 1]) {
        if (!p?.checkIn) add(iniServ(v) - 18e5 + n * 3e5, `ci:${v.id}:${r.utenteId}:${n}`, { dest: me, pl: { t: '⏱ Servizio tra 30 minuti', b: `${v.titolo}, ore ${v.oraInizio}. Quando inizia premi Turno e fai il check-in.`, go: 'turno', tg: `ci-${v.id}-${n}` } });
        if (p?.checkIn && !p.checkOut) add(fineServ(v) + 18e5 + n * 3e5, `co:${v.id}:${r.utenteId}:${n}`, { dest: me, pl: { t: '⏹ Check-out mancante', b: `${v.titolo} è terminato. Premi Turno e fai il check-out.`, go: 'turno', tg: `co-${v.id}-${n}` } });
      } }
  }
  for (const pv of await live('c-privacy')) if (!pv.rev && pv.scad) for (const k of [15, 1]) add(pv.scad - k * DAY, `pv:${pv.id}:${pv.scad}:${k}`, { dest: u => u === pv.id, pl: { t: '🔒 Privacy in scadenza', b: `La tua conferma della privacy scade il ${dIt(new Date(pv.scad + 36e5).toISOString().slice(0, 10))}. Apri l'app e riconfermala.`, go: 'altro', tg: `pv-${pv.id}-${k}` } });
  const us = (await live('c-utenti')).filter(u => u.attivo !== false), adm = new Set(us.filter(u => u.ruolo === 'admin').map(u => u.id));
  // chiusura automatica: 2 ore dopo la fine chi non ha fatto il check-out viene chiuso all'ora di fine evento; avviso agli amministratori
  const chiusi = [];
  for (const p of Object.values(pres)) { const v = sv[p.servizioId]; if (!v || !p.checkIn || p.checkOut) continue; const t = fineServ(v) + 72e5; if (t > now) fut.push(t); else chiusi.push({ p, v }) }
  if (chiusi.length) {
    await mutate(s, 'c-presenze', d => { let n = 0; for (const { p, v } of chiusi) { const e = d.recs[p.id]; if (!e || e.r.checkOut || !e.r.checkIn) continue; const ts = Math.max(fineServ(v), e.r.checkIn.ts); e.r = { ...e.r, checkOut: { ts, ind: '' }, ore: Math.round((ts - e.r.checkIn.ts) / 9e5) / 4, stato: 'presente', auto: true, updatedAt: now, updatedBy: 'server' }; e.s = now * 1000 + n++ } return n > 0 });
    await s.delete('rem-next').catch(() => {});
    const nm = id => { const u = us.find(x => x.id === id); return u ? u.cognome + ' ' + u.nome : 'Volontario' };
    for (const { p, v } of chiusi) due.push({ k: `ac:${p.id}`, dest: u => adm.has(u), pl: { t: '⏹ Check-out chiuso in automatico', b: `${nm(p.utenteId)} non ha fatto il check-out: ${v.titolo}. Verifica o correggi l'orario.`, go: 'servizi', tg: `ac-${p.id}` } });
  }
  let tot = 0;
  if (due.length && key) {
    const all = await getPush(s); let ch = false;
    for (const it of due) {
      sent[it.k] = now;
      for (const u of us) if (it.dest(u.id)) for (const sub of all[u.id] || []) {
        const st_ = await sendPush(sub, JSON.stringify(it.pl), key).catch(() => 0);
        if (st_ === 404 || st_ === 410) { all[u.id] = all[u.id].filter(x => x.endpoint !== sub.endpoint); ch = true } else if (st_ >= 200 && st_ < 300) tot++;
      }
    }
    if (ch) await setPush(s, all);
  }
  for (const k of Object.keys(sent)) if (now - sent[k] > 2 * DAY) delete sent[k];
  if (due.length) await s.setJSON('rem-sent', sent);
  await s.setJSON('rem-next', { t: Math.min(now + 10 * 6e4, fut.length ? Math.min(...fut) : Infinity) });
  return tot;
}
export default async (req, ctx) => {
  if (req.method !== 'POST') return E('Metodo non consentito', 405);
  let b; try { b = await req.json() } catch { return E('Richiesta non valida') }
  try {
    const s = st(); await autoReset(s, ctx); await autoAdmin(s, ctx); await migra(s);
    if (b?.action === 'status') return J({ setup: !(await s.get('creds', { type: 'json' })), needAdmin: !!(await s.get('needadmin', { type: 'json' })) });
    if (!process.env.APP_SECRET || process.env.APP_SECRET.length < 16) return E('Server non configurato: imposta APP_SECRET (almeno 16 caratteri) nelle variabili d\'ambiente di Netlify', 500);
    const t = Date.now(), fin = async res => { acc.n++; acc.ms += Date.now() - t; acc.by += lastBytes; await flush(s, Date.now()).catch(() => {}); return res };
    if (b?.action === 'reset') {
      const a = await auth(s, b.token); if (!a || a.user.ruolo !== 'admin') return E('Solo l\'amministratore può azzerare i dati', 403);
      if (b.conferma !== 'AZZERA') return E('Conferma mancante');
      const cr = (await load(s, 'creds')).recs[a.user.id], h = await pbk(String(b.password || ''), cr?.salt || '0'.repeat(32));
      if (!okH(cr, h)) { await sleep(500); return E('Password errata', 401) }
      await wipe(s); return J({ ok: true });
    }
    if (b?.action === 'adminsetup') return await fin(await adminSetup(s, b));
    if (b?.action === 'setup') return await fin(await setup(s, b));
    if (b?.action === 'login') return await fin(await login(s, b));
    if (b?.action === 'pushsub') {
      const a = await auth(s, b.token); if (!a) return E('Sessione non valida o scaduta', 401);
      const sub = b.sub; if (!sub?.endpoint || !/^https:\/\//.test(sub.endpoint) || !sub.keys?.p256dh || !sub.keys?.auth || sub.endpoint.length > 600) return E('Sottoscrizione non valida');
      const all = await getPush(s), l = (all[a.user.id] || []).filter(x => x.endpoint !== sub.endpoint);
      if (!b.off) l.unshift({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
      all[a.user.id] = l.slice(0, 5); await setPush(s, all); return J({ ok: true });
    }
    if (b?.action === 'sync') {
      const a = await auth(s, b.token);
      return a ? await fin(await doSync(s, a.user, a.data, b)) : E('Sessione non valida o scaduta', 401);
    }
    return E('Azione sconosciuta');
  } catch (e) { console.error(e); return E('Errore del server: ' + (e.message || 'sconosciuto'), 500) }
};
