// Emisora Enlace 1.1 — app única para Windows (Electron) y móviles (PWA / navegador). ERS v1.1.
//
// Sin configuración de red: los equipos solo hacen conexiones SALIENTES hacia un servidor
// de encuentro (PeerJS) que tiene IP pública. Nadie abre puertos ni toca routers.
// El servidor de encuentro solo presenta a los equipos; la contraseña se verifica entre
// los dos equipos por un canal cifrado (DTLS) y el audio viaja directo (WebRTC + Opus).
import {
  $, $$, esc, randomHex, PROFILES, applyOpusProfile, setSenderBitrate, tuneReceiver,
  Meter, StatsMonitor, fmt, qualityAlerts, beep, copyText, toast, detectDevice, BITRATES, kbpsOf, isStereo,
} from './common.js';

// Dirección del audio, vista desde quien inicia el enlace (el locutor):
//   both   = ida y vuelta · send = el locutor solo envía · listen = el locutor solo escucha
const DIRECTIONS = ['both', 'send', 'listen'];
const dirFor = (direction, role) => {
  const d = DIRECTIONS.includes(direction) ? direction : 'both';
  const callerSends = d !== 'listen', callerRecvs = d !== 'send';
  return role === 'caller' ? { sends: callerSends, recvs: callerRecvs } : { sends: callerRecvs, recvs: callerSends };
};
import { detectNetwork, NAT_TEXT } from './red.js';

const Peer = window.Peer;

// ------------------------------------------------------------ Entorno
const desktop = window.emisoraDesktop || null;
const rt = desktop ? await desktop.getRuntime() : null;
const dev = detectDevice();
const isMobile = !desktop && (dev.platform === 'Android' || dev.platform === 'iOS');
const androidApp = window.EnlaceAndroid || null; // app nativa de Android (APK)
document.body.classList.toggle('is-android-app', !!androidApp);
document.body.classList.toggle('is-desktop', !!desktop);
document.body.classList.toggle('is-mobile', isMobile);
const canPickOutput = 'setSinkId' in HTMLMediaElement.prototype;

// ------------------------------------------------------------ Almacenamiento local
const NS = 'enlace';
const load = (k, d) => { try { const v = localStorage.getItem(`${NS}:${k}`); return v ? JSON.parse(v) : d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(`${NS}:${k}`, JSON.stringify(v)); } catch {} };
// En Windows los secretos se cifran con el almacén del sistema (DPAPI).
const protect = async s => (desktop && s ? desktop.protect(s) : s);
const unprotect = async s => (desktop && s ? desktop.unprotect(s) : s);

const settings = load('settings', { profile: 'lowlat', proc: isMobile, inputId: '', outputId: '', tempPw: false, name: '', acceptMode: 'auto', allowList: [] });
const saveSettings = () => save('settings', settings);

// Servidor de encuentro: viene preconfigurado. Se puede cambiar en Configuración (Windows)
// o con ?servidor=https://host:puerto/ruta (móviles), para usar el servidor propio.
const DEFAULT_SERVER = { host: '0.peerjs.com', port: 443, path: '/', secure: true, key: 'peerjs' };
const urlSrv = new URLSearchParams(location.search).get('servidor');
if (urlSrv) {
  try {
    const u = new URL(urlSrv);
    settings.server = { host: u.hostname, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80), path: u.pathname || '/', secure: u.protocol === 'https:', key: 'peerjs' };
    saveSettings();
  } catch {}
}
const SERVER = (rt && rt.peerServer) || settings.server || DEFAULT_SERVER;
const ICE = (rt && rt.iceServers && rt.iceServers.length ? rt.iceServers : null) || [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];

// ------------------------------------------------------------ Identidad (RF-01, RF-02)
const PREFIX = 'emisora-enlace-';
const pid = id => PREFIX + id;
const unpid = p => (String(p).startsWith(PREFIX) ? String(p).slice(PREFIX.length) : '');
const fmtId = id => (id ? String(id).replace(/(\d{3})(\d{3})(\d{3})/, '$1 $2 $3') : '');
const cleanId = s => String(s || '').replace(/\D/g, '');
function newId() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(100000000 + (a[0] % 900000000));
}
let myId = load('id', null);
if (!myId) { myId = newId(); save('id', myId); }
let myName = settings.name || (rt && rt.hostname) || (isMobile ? `${dev.platform} de locutor` : `Equipo ${dev.platform}`);

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const enc = s => new TextEncoder().encode(String(s));
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc(s)));
async function pbkdf2(pw, salt) {
  const key = await crypto.subtle.importKey('raw', enc(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc(salt), iterations: 150000 }, key, 256));
}
async function makeRec(pw) { const salt = randomHex(16); return { salt, hash: await pbkdf2(pw, salt) }; }
async function checkRec(pw, rec) { return !!rec && (await pbkdf2(String(pw || ''), rec.salt)) === rec.hash; }

let pwRec = load('pw', null);          // hash de la contraseña fija (nunca la contraseña)
let tempPassword = '', tempRec = null; // contraseña temporal: solo en memoria
let trusted = load('trusted', {});     // { idQueLlama: [hash de token, …] } conexiones guardadas por otros
let contacts = load('contacts', []);   // [{ id, name, token(cifrado) }] mis conexiones guardadas
let history = load('history', []);
const saveContacts = () => { save('contacts', contacts); renderContacts(); refreshPresence(); };
const activeRec = () => (settings.tempPw ? tempRec : pwRec);

// ------------------------------------------------------------ Historial local (RF-26)
function logEvent(tipo, text, extra = {}) {
  history.unshift({ t: new Date().toISOString(), tipo, text, ...extra });
  history = history.slice(0, 300);
  save('history', history);
  renderHistory();
}
function renderHistory() {
  const d = s => new Date(s).toLocaleString('es-CO', { dateStyle: 'short', timeStyle: 'short' });
  $('#hist-count').textContent = history.length ? `(${history.length})` : '';
  $('#history').innerHTML = history.slice(0, 100).map(h => `<tr><td class="small">${d(h.t)}</td><td>${esc(h.tipo)}</td><td>${esc(h.text)}</td><td>${h.durS != null ? `${Math.floor(h.durS / 60)} min ${h.durS % 60} s` : ''}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Sin registros</td></tr>';
}
$('#hist-csv').onclick = () => {
  const rows = [['fecha', 'tipo', 'detalle', 'equipo', 'duracion_s']].concat(history.map(h => [h.t, h.tipo, h.text, h.peer || '', h.durS ?? '']));
  const csv = '﻿' + rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(';')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = `historial-${myId}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
};

// ------------------------------------------------------------ Servidor de encuentro
let peer = null;
let takenTries = 0;
const unavailableWaiters = new Map(); // id -> callback cuando el servidor dice que el equipo no está en línea

function setSig(st) {
  const el = $('#sig-status');
  el.textContent = st === 'open' ? 'En línea' : st === 'connecting' ? 'Conectando…' : 'Sin conexión — reintentando';
  el.className = 'sig ' + (st === 'open' ? 'ok' : 'bad');
  $('#net-server').textContent = `${SERVER.host}${SERVER.port !== 443 ? ':' + SERVER.port : ''} · ${st === 'open' ? 'conectado' : 'sin conexión'}`;
}

function startPeer() {
  if (peer && !peer.destroyed) peer.destroy();
  setSig('connecting');
  peer = new Peer(pid(myId), { ...SERVER, config: { iceServers: ICE }, debug: 1 });
  peer.on('open', () => { takenTries = 0; setSig('open'); renderMe(); refreshPresence(); });
  peer.on('connection', onIncomingData);
  peer.on('call', onIncomingCall);
  peer.on('disconnected', () => setSig('closed'));
  peer.on('close', () => setSig('closed'));
  peer.on('error', err => {
    if (err.type === 'peer-unavailable') {
      const id = unpid((String(err.message).match(/peer (\S+)/) || [])[1] || '');
      const cb = unavailableWaiters.get(id);
      if (cb) { unavailableWaiters.delete(id); cb(); }
      return;
    }
    if (err.type === 'unavailable-id') {
      // El ID sigue registrado por una sesión anterior: se reintenta; si persiste, se asigna otro.
      takenTries++;
      peer.destroy();
      if (takenTries >= 4) {
        const old = myId;
        myId = newId(); save('id', myId); takenTries = 0;
        toast(`El ID ${fmtId(old)} estaba en uso: este equipo ahora es ${fmtId(myId)}`, 8000);
        logEvent('identidad', `Nuevo ID ${myId} (el anterior estaba ocupado)`);
      }
      return;
    }
    if (['network', 'server-error', 'socket-error', 'socket-closed', 'disconnected'].includes(err.type)) setSig('closed');
    else console.warn('PeerJS', err.type, err.message);
  });
}
// Vigilante: si se cae la conexión con el servidor de encuentro, se recupera sola.
// Los enlaces activos no se cortan: el audio viaja directo entre los equipos.
setInterval(() => {
  if (!peer || peer.destroyed) startPeer();
  else if (peer.disconnected) { setSig('connecting'); try { peer.reconnect(); } catch { startPeer(); } }
}, 4000);
startPeer();

// ------------------------------------------------------------ Este equipo
function renderMe() {
  $('#my-id').textContent = fmtId(myId);
  if (document.activeElement !== $('#my-name')) $('#my-name').value = myName;
  const pv = $('#pw-value');
  if (settings.tempPw && tempPassword) { pv.textContent = tempPassword; pv.className = 'mono pw-value temp'; }
  else if (pwRec) { pv.textContent = '••••••••'; pv.className = 'mono pw-value'; }
  else { pv.textContent = 'sin definir — nadie puede conectarse a este equipo'; pv.className = 'mono pw-value warn-text'; }
  $('#pw-change').textContent = pwRec && !settings.tempPw ? 'Cambiar' : 'Definir';
  $('#pw-temp').checked = !!settings.tempPw;
  $$('input[name=accept]').forEach(r => { r.checked = r.value === (settings.acceptMode || 'auto'); });
  if (document.activeElement !== $('#allow-list')) $('#allow-list').value = (settings.allowList || []).map(fmtId).join(', ');
}
$('#copy-id').onclick = () => copyText(fmtId(myId)).then(() => toast('ID copiado'));
$('#my-name').addEventListener('change', e => {
  const name = e.target.value.trim();
  if (!name) return;
  myName = settings.name = name.slice(0, 40);
  saveSettings();
});
$('#pw-change').onclick = () => { $('#pw-form').hidden = false; $('#pw-new').value = ''; $('#pw-new').focus(); };
$('#pw-cancel').onclick = () => { $('#pw-form').hidden = true; };
$('#pw-form').onsubmit = async e => {
  e.preventDefault();
  const pw = $('#pw-new').value;
  if (pw.length < 8) return toast('Mínimo 8 caracteres');
  pwRec = await makeRec(pw); save('pw', pwRec);
  trusted = {}; save('trusted', trusted); // las conexiones guardadas por otros vuelven a pedir la contraseña
  settings.tempPw = false; saveSettings();
  tempPassword = ''; tempRec = null;
  $('#pw-form').hidden = true;
  renderMe();
  logEvent('seguridad', 'Contraseña del equipo cambiada');
  toast('Contraseña guardada. Las conexiones guardadas en otros equipos la pedirán de nuevo.', 5000);
};
$('#pw-temp').onchange = async e => {
  settings.tempPw = e.target.checked; saveSettings();
  if (settings.tempPw) await setTempPassword();
  else { tempPassword = ''; tempRec = null; renderMe(); if (!pwRec) $('#pw-change').click(); }
};
async function setTempPassword() {
  const abc = 'abcdefghjkmnpqrstuvwxyz23456789';
  const r = new Uint8Array(8);
  crypto.getRandomValues(r);
  tempPassword = [...r].map(x => abc[x % abc.length]).join('');
  tempRec = await makeRec(tempPassword);
  trusted = {}; save('trusted', trusted);
  renderMe();
}
if (settings.tempPw && !isMobile) setTempPassword();
$('#save-accept').onclick = () => {
  settings.acceptMode = $('input[name=accept]:checked')?.value || 'auto';
  settings.allowList = $('#allow-list').value.split(/[,;\n]/).map(cleanId).filter(x => x.length === 9);
  saveSettings();
  renderMe();
  toast('Recepción guardada');
};
renderMe();

// ------------------------------------------------------------ Mi red (RF-33)
let net = null;
async function refreshNetwork() {
  const run = (refreshNetwork.run = (refreshNetwork.run || 0) + 1);
  $('#net-v4').textContent = 'Detectando…';
  let res = null;
  try { res = await detectNetwork(ICE); } catch {}
  if (run !== refreshNetwork.run) return; // llegó una detección más reciente
  net = res;
  const n = net || { publicV4: [], publicV6: [], local: [], nat: 'bloqueado' };
  $('#net-v4').textContent = n.publicV4.join(', ') || 'No detectada';
  $('#net-v6').textContent = n.publicV6.length ? n.publicV6.join(', ')
    : n.mdnsHidden ? 'Oculta por el navegador: pulsa «Permitir» en «Mi audio»'
    : (n.localV6Only || []).length ? `Solo IPv6 local (${n.localV6Only[0]}): el router no entrega IPv6 pública al equipo`
    : 'El equipo no tiene IPv6 pública (revisa el router/ONU)';
  $('#net-local').textContent = n.local.join(', ') || (n.mdnsHidden ? 'Oculta por el navegador' : '—');
  const [txt, cls] = NAT_TEXT[n.nat] || NAT_TEXT.desconocido;
  $('#net-nat').textContent = txt;
  $('#net-nat').className = cls;
  $('#net-v6').className = 'mono ' + (n.publicV6.length ? 'good' : '');
}
$('#net-refresh').onclick = refreshNetwork;
setTimeout(refreshNetwork, 600);
setInterval(refreshNetwork, 5 * 60e3);

// ------------------------------------------------------------ Conexiones guardadas y presencia (RF-04, RF-05)
const presence = new Map();
const PRES = { online: 'En línea', busy: 'En enlace', offline: 'Desconectado', noroute: 'En línea · sin ruta directa', checking: 'Comprobando…' };
function renderContacts() {
  $('#contacts-empty').hidden = contacts.length > 0;
  $('#contacts').innerHTML = contacts.map(c => {
    const st = presence.get(c.id) || 'checking';
    const dot = st === 'noroute' ? 'busy' : st;
    return `<li data-id="${esc(c.id)}">
      <span class="st-dot ${dot}" title="${PRES[st]}"></span>
      <div class="c-info"><b>${esc(c.name)}</b><span class="muted small mono">${fmtId(c.id)} · ${PRES[st]}${c.token ? '' : ' · pide contraseña'}</span></div>
      <div class="c-actions">
        <button class="btn sm primary" data-act="call" ${st === 'offline' ? 'disabled' : ''}>Conectar</button>
        <button class="chip" data-act="rename" title="Renombrar">✎</button>
        <button class="chip" data-act="del" title="Eliminar">✕</button>
      </div>
    </li>`;
  }).join('');
}
$('#contacts').onclick = e => {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const id = btn.closest('li').dataset.id;
  const c = contacts.find(x => x.id === id);
  if (btn.dataset.act === 'call') connectTo(id);
  if (btn.dataset.act === 'rename') {
    const n = prompt('Nombre de la conexión', c.name);
    if (n && n.trim()) { c.name = n.trim().slice(0, 40); saveContacts(); }
  }
  if (btn.dataset.act === 'del' && confirm(`¿Eliminar «${c.name}»? Se borrará también su acceso guardado.`)) {
    contacts = contacts.filter(x => x.id !== id);
    saveContacts();
  }
};

// Presencia: se pregunta a cada equipo guardado por un canal directo y breve.
function probe(id) {
  return new Promise(resolve => {
    if (!peer || peer.disconnected) return resolve(presence.get(id) || 'checking');
    let done = false;
    const conn = peer.connect(pid(id), { metadata: { app: 'enlace', type: 'ping', from: myId }, reliable: true });
    const finish = st => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (unavailableWaiters.get(id) === onUnavail) unavailableWaiters.delete(id);
      try { conn.close(); } catch {}
      resolve(st);
    };
    const onUnavail = () => finish('offline');
    unavailableWaiters.set(id, onUnavail);
    conn.on('data', d => { if (d && d.type === 'pong') finish(d.busy ? 'busy' : 'online'); });
    conn.on('error', () => {});
    const timer = setTimeout(() => finish('noroute'), 10000);
  });
}
let probing = false;
async function refreshPresence() {
  if (probing || !peer || peer.disconnected) return;
  probing = true;
  try {
    await Promise.all(contacts.map(async c => {
      if ([...cards.values()].some(k => k.peer.id === c.id)) { presence.set(c.id, 'busy'); return; }
      if (attempt && attempt.id === c.id) return;
      presence.set(c.id, await probe(c.id));
    }));
  } finally { probing = false; renderContacts(); }
}
setInterval(refreshPresence, 20000);
renderContacts();

// ------------------------------------------------------------ Conectar (RF-03)
$('#target-id').addEventListener('input', e => {
  const d = cleanId(e.target.value).slice(0, 9);
  e.target.value = d.replace(/(\d{3})(?=\d)/g, '$1 ');
});
$('#profile').value = settings.profile;
$('#bitrate').innerHTML = '<option value="0">Automático (según el perfil)</option>' + BITRATES.map(k => `<option value="${k}">${k} kbps${k >= 160 ? ' — solo con buena conexión' : ''}</option>`).join('');
$('#bitrate').value = String(settings.bitrate || 0);
function bitrateHint() {
  const k = kbpsOf(settings.profile, settings.bitrate);
  const voice = !isStereo(settings.profile);
  $('#bitrate-hint').textContent = voice && k > 64
    ? `Para voz, más de 64 kbps no mejora el sonido y consume más datos (${Math.round(k * 0.45)} MB por hora).`
    : k >= 160 ? `Pensado para música en vivo con fibra o Wi-Fi estable. Consumo ≈ ${Math.round(k * 0.45)} MB por hora en cada sentido.`
    : `Consumo ≈ ${Math.round(k * 0.45)} MB por hora en cada sentido.`;
}
bitrateHint();
$('#profile').onchange = e => { settings.profile = e.target.value; saveSettings(); bitrateHint(); };
$('#bitrate').onchange = e => { settings.bitrate = Number(e.target.value) || 0; saveSettings(); bitrateHint(); };
const DIR_HINT = {
  both: 'Los dos equipos se escuchan (con retorno del programa).',
  send: 'Solo tu audio llega al otro equipo; tú no recibes audio. Ahorra datos. Los mensajes de producción siguen funcionando.',
  listen: 'Solo escuchas al otro equipo; tu micrófono no se abre.',
};
function renderDirection() {
  const d = DIRECTIONS.includes(settings.direction) ? settings.direction : 'both';
  $$('input[name=direction]').forEach(r => { r.checked = r.value === d; });
  $('#direction-hint').textContent = DIR_HINT[d];
}
$$('input[name=direction]').forEach(r => { r.onchange = () => { settings.direction = r.value; saveSettings(); renderDirection(); }; });
renderDirection();
$('#connect-form').onsubmit = e => {
  e.preventDefault();
  const id = cleanId($('#target-id').value);
  if (id.length !== 9) return toast('El ID tiene 9 dígitos');
  connectTo(id);
};

let attempt = null;
function setConnectStatus(text) {
  $('#connect-status').hidden = !text;
  $('#connect-status-text').textContent = text || '';
}
$('#connect-cancel').onclick = () => { attempt?.cancel(); };

async function connectTo(id, password = null, opts = {}) {
  if (id === myId) return toast('Ese es el ID de este mismo equipo');
  if ([...cards.values()].some(c => c.peer.id === id)) return toast('Ya hay un enlace con ese equipo');
  if (!peer || peer.disconnected) return toast('Sin conexión con el servidor de encuentro. Revisa tu Internet.');
  unlockAudio();
  const saved = contacts.find(x => x.id === id);
  let token = null;
  if (password == null) {
    if (saved && saved.token) token = await unprotect(saved.token);
    else return openPasswordDialog(id, '', { name: saved ? saved.name : '' });
  }
  attempt?.cancel(true);
  const profile = settings.profile;
  const bitrate = settings.bitrate || 0;
  const direction = DIRECTIONS.includes(settings.direction) ? settings.direction : 'both';
  const conn = peer.connect(pid(id), {
    metadata: { app: 'enlace', type: 'link', from: myId, name: myName, platform: dev.platform, mobile: isMobile },
    reliable: true,
  });
  let finished = false;
  const end = (msg, after) => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    unavailableWaiters.delete(id);
    attempt = null;
    setConnectStatus('');
    if (msg) toast(msg, 7000);
    after && after();
  };
  attempt = { id, cancel: silent => { end(silent ? '' : 'Conexión cancelada'); try { conn.close(); } catch {} } };
  setConnectStatus(`Buscando el equipo ${fmtId(id)}…`);
  unavailableWaiters.set(id, () => end('El equipo no está en línea. Verifica que la aplicación esté abierta en el otro equipo.'));
  const timer = setTimeout(() => {
    try { conn.close(); } catch {}
    end('El equipo está en línea pero no se encontró una ruta de red hacia él (algún NAT estricto). La versión oficial resolverá este caso con un servidor TURN.');
  }, 15000);
  conn.on('open', () => {
    setConnectStatus(`Verificando contraseña con ${fmtId(id)}…`);
    conn.send({ type: 'auth', password: token ? undefined : password, token: token || undefined, remember: !!opts.remember, profile, bitrate, direction });
  });
  conn.on('error', () => {});
  conn.on('data', async m => {
    if (!m || finished) return;
    if (m.type === 'ringing') { clearTimeout(timer); setConnectStatus('Esperando que el otro equipo acepte…'); return; }
    if (m.type === 'auth-fail') {
      end('', () => {
        try { conn.close(); } catch {}
        if (m.code === 'bad-token') {
          if (saved) { saved.token = null; saveContacts(); }
          openPasswordDialog(id, m.message, { name: saved ? saved.name : '' });
        } else if (m.code === 'bad-credentials') {
          openPasswordDialog(id, m.message, { name: opts.name || (saved && saved.name) || '', remember: opts.remember });
        } else toast(m.message, 7000);
      });
      logEvent('intento', `Conexión a ${fmtId(id)} no autorizada: ${m.message}`, { peer: id });
      return;
    }
    if (m.type === 'rejected') { end(m.message || 'El otro equipo rechazó la conexión.'); try { conn.close(); } catch {} return; }
    if (m.type === 'auth-ok') {
      end('');
      if (m.rememberToken) {
        const t = await protect(m.rememberToken);
        const c = contacts.find(x => x.id === id);
        if (c) { c.token = t; if (opts.name) c.name = opts.name; }
        else contacts.unshift({ id, name: opts.name || m.name || fmtId(id), token: t });
        saveContacts();
      }
      const card = addCard({ id, name: m.name || (saved && saved.name) || fmtId(id), platform: m.platform }, profile, 'caller', conn, m.linkKey, bitrate, direction);
      card.start();
    }
  });
}

// Diálogo de contraseña
const dlg = $('#pw-dialog');
let dlgTarget = null;
function openPasswordDialog(id, message = '', prev = {}) {
  dlgTarget = id;
  $('#dlg-id').textContent = fmtId(id);
  $('#dlg-msg').textContent = message;
  $('#dlg-msg').hidden = !message;
  $('#dlg-pw').value = '';
  $('#dlg-name').value = prev.name || '';
  $('#dlg-remember').checked = prev.remember ?? true;
  $('#dlg-name-wrap').hidden = !$('#dlg-remember').checked;
  if (!dlg.open) dlg.showModal();
  setTimeout(() => $('#dlg-pw').focus(), 50);
}
$('#dlg-remember').onchange = e => { $('#dlg-name-wrap').hidden = !e.target.checked; };
dlg.addEventListener('close', () => {
  if (dlg.returnValue !== 'ok' || !dlgTarget) return;
  connectTo(dlgTarget, $('#dlg-pw').value, { remember: $('#dlg-remember').checked, name: $('#dlg-name').value.trim() });
});

// ------------------------------------------------------------ Recibir conexiones (RF-06, RF-07)
const fails = new Map();   // idQueLlama -> { count, until }
let recentFails = [];      // límite global contra fuerza bruta con muchos ID
let ringing = null;
const inDlg = $('#in-dialog');

function onIncomingData(conn) {
  const md = conn.metadata || {};
  if (md.app !== 'enlace') { conn.close(); return; }
  const from = cleanId(md.from);

  if (md.type === 'ping') {
    conn.on('open', () => {
      conn.send({ type: 'pong', busy: cards.size > 0, name: myName });
      setTimeout(() => { try { conn.close(); } catch {} }, 1500);
    });
    return;
  }
  if (md.type !== 'link') { conn.close(); return; }

  conn.on('data', async m => {
    if (!m) return;
    if (m.type === 'resume') { // reconexión del canal de control sin pedir contraseña (RF-22)
      const card = [...cards.values()].find(c => c.key === m.linkKey && c.peer.id === from);
      if (card) { card.attachData(conn); conn.send({ type: 'resume-ok' }); }
      else { conn.send({ type: 'resume-fail' }); setTimeout(() => conn.close(), 500); }
      return;
    }
    if (m.type !== 'auth') return;
    const fail = (code, message) => { conn.send({ type: 'auth-fail', code, message }); setTimeout(() => { try { conn.close(); } catch {} }, 800); };

    if (isMobile) return fail('mobile', 'Ese equipo es un teléfono: en esta versión los teléfonos solo inician conexiones.');
    const now = Date.now();
    recentFails = recentFails.filter(t => now - t < 60e3);
    const f = fails.get(from);
    if ((f && f.until > now) || recentFails.length >= 10) {
      return fail('locked', 'Demasiados intentos fallidos. Intenta de nuevo en 15 minutos.');
    }
    if (settings.allowList && settings.allowList.length && !settings.allowList.includes(from)) {
      logEvent('rechazo', `${md.name || ''} (${fmtId(from)}) no está en la lista de autorizados`, { peer: from });
      return fail('not-allowed', 'Conexión no permitida: este equipo no está en la lista de autorizados del destino.');
    }
    const rec = activeRec();
    if (!rec) return fail('no-password', 'Ese equipo todavía no tiene contraseña: nadie puede conectarse a él.');

    let ok = false;
    if (m.token) {
      ok = (trusted[from] || []).includes(await sha256(m.token));
      if (!ok) return fail('bad-token', 'La contraseña de ese equipo cambió. Escríbela de nuevo.');
    } else {
      ok = await checkRec(m.password, rec);
      if (!ok) {
        const cur = fails.get(from) || { count: 0, until: 0 };
        cur.count++;
        recentFails.push(now);
        if (cur.count >= 5) { cur.until = now + 15 * 60e3; cur.count = 0; }
        fails.set(from, cur);
        logEvent('intento-fallido', `Contraseña incorrecta desde ${md.name || ''} (${fmtId(from)})`, { peer: from });
        return fail('bad-credentials', cur.until > now ? 'ID o contraseña incorrectos. Se bloquearon los intentos por 15 minutos.' : 'ID o contraseña incorrectos.');
      }
    }
    fails.delete(from);

    const accept = async () => {
      let rememberToken;
      if (m.remember && !m.token) {
        rememberToken = randomHex(16);
        trusted[from] = [await sha256(rememberToken), ...(trusted[from] || [])].slice(0, 5);
        save('trusted', trusted);
      }
      const key = randomHex(16);
      const profile = PROFILES[m.profile] ? m.profile : 'lowlat';
      const bitrate = Number(m.bitrate) >= 16 && Number(m.bitrate) <= 256 ? Number(m.bitrate) : 0;
      const direction = DIRECTIONS.includes(m.direction) ? m.direction : 'both';
      addCard({ id: from, name: md.name || fmtId(from), platform: md.platform }, profile, 'callee', conn, key, bitrate, direction);
      conn.send({ type: 'auth-ok', linkKey: key, rememberToken, name: myName, platform: dev.platform });
      beep([880, 1320]);
      notify(`Enlace con ${md.name || fmtId(from)}`);
    };

    if ((settings.acceptMode || 'auto') === 'auto') return accept();
    if (ringing) return fail('busy', 'El equipo está atendiendo otra solicitud. Intenta en unos segundos.');
    conn.send({ type: 'ringing' });
    ringing = {
      conn,
      accept: () => { closeIncoming(); accept(); },
      reject: () => { closeIncoming(); conn.send({ type: 'rejected', message: 'El otro equipo rechazó la conexión.' }); logEvent('rechazo', `Rechazada la conexión de ${md.name || ''} (${fmtId(from)})`, { peer: from }); setTimeout(() => conn.close(), 800); },
      timer: setTimeout(() => ringing && ringing.conn === conn && ringing.reject(), 30000),
      bell: setInterval(() => beep([880, 1320, 880]), 1600),
    };
    beep([880, 1320, 880]);
    notify(`${md.name || fmtId(from)} quiere conectarse`);
    $('#in-name').textContent = md.name || 'Equipo';
    $('#in-id').textContent = `ID ${fmtId(from)} · ${md.platform || ''}`;
    inDlg.showModal();
    conn.on('close', () => { if (ringing && ringing.conn === conn) closeIncoming(); });
  });
}
function closeIncoming() {
  if (!ringing) return;
  clearTimeout(ringing.timer);
  clearInterval(ringing.bell);
  ringing = null;
  if (inDlg.open) inDlg.close();
}
$('#in-accept').onclick = () => { unlockAudio(); ringing?.accept(); };
$('#in-reject').onclick = () => ringing?.reject();

// El audio solo se acepta si llega con la clave de un enlace ya autorizado.
function onIncomingCall(call) {
  const key = call.metadata && call.metadata.linkKey;
  const from = unpid(call.peer);
  const card = [...cards.values()].find(c => c.key === key && c.peer.id === from);
  if (!card) { call.close(); return; }
  card.answer(call);
}

function notify(text) {
  if (!document.hidden || !('Notification' in window)) return;
  try { if (Notification.permission === 'granted') new Notification('Enlace Primera St 99.2', { body: text, icon: 'icons/icon-192.png' }); } catch {}
}

// ------------------------------------------------------------ Mi audio
let testCtx = null, testStream = null;
let devices = { inputs: [], outputs: [] };
const testMeter = new Meter($('#test-meter'));
async function refreshDevices() {
  const list = await navigator.mediaDevices.enumerateDevices();
  devices.inputs = list.filter(d => d.kind === 'audioinput' && d.deviceId && d.deviceId !== 'default');
  devices.outputs = list.filter(d => d.kind === 'audiooutput' && d.deviceId && d.deviceId !== 'default');
  $('#perm-banner').hidden = !!testStream;
  fillSelect($('#def-in'), devices.inputs, settings.inputId, 'Entrada');
  fillSelect($('#def-out'), devices.outputs, settings.outputId, 'Salida', !canPickOutput);
  cards.forEach(c => c.renderDevices());
}
function fillSelect(sel, list, value, kind, disabled) {
  if (disabled) { sel.innerHTML = '<option>Predeterminada del sistema</option>'; sel.disabled = true; return; }
  sel.innerHTML = '<option value="">Predeterminada del sistema</option>' +
    list.map((d, i) => `<option value="${esc(d.deviceId)}">${esc(d.label || `${kind} ${i + 1}`)}</option>`).join('');
  sel.value = list.some(d => d.deviceId === value) ? value : '';
}
navigator.mediaDevices?.addEventListener('devicechange', refreshDevices);
function micConstraints(deviceId, proc, stereo = false) {
  return {
    deviceId: deviceId ? { exact: deviceId } : undefined,
    echoCancellation: proc, noiseSuppression: proc, autoGainControl: proc,
    channelCount: { ideal: stereo ? 2 : 1 }, sampleRate: { ideal: 48000 },
  };
}
async function startTestMic() {
  try {
    testCtx = testCtx || new AudioContext();
    testCtx.resume();
    testStream?.getTracks().forEach(t => t.stop());
    testStream = await navigator.mediaDevices.getUserMedia({ audio: micConstraints(settings.inputId, settings.proc) });
    const an = testCtx.createAnalyser(); an.fftSize = 1024;
    testCtx.createMediaStreamSource(testStream).connect(an);
    testMeter.attach(an);
    await refreshDevices();
    refreshNetwork(); // con permiso de micrófono el navegador deja ver la IPv6 real del equipo
  } catch (e) {
    $('#perm-banner').hidden = false;
    toast('No se pudo usar el micrófono: ' + (e.name || e.message), 5000);
  }
}
$('#perm-btn').onclick = startTestMic;
$('#def-in').onchange = e => { settings.inputId = e.target.value; saveSettings(); startTestMic(); };
$('#def-out').onchange = e => { settings.outputId = e.target.value; saveSettings(); };
$('#proc').checked = !!settings.proc;
$('#proc').onchange = e => { settings.proc = e.target.checked; saveSettings(); if (testStream) startTestMic(); };
$('#tone-btn').onclick = async () => {
  testCtx = testCtx || new AudioContext();
  await testCtx.resume();
  try { if (testCtx.setSinkId) await testCtx.setSinkId(settings.outputId || ''); } catch {}
  const t = testCtx.currentTime;
  [523.25, 659.25, 783.99].forEach((f, i) => {
    const o = testCtx.createOscillator(), g = testCtx.createGain();
    o.frequency.value = f;
    g.gain.setValueAtTime(0.0001, t + i * 0.18);
    g.gain.exponentialRampToValueAtTime(0.3, t + i * 0.18 + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, t + i * 0.18 + 0.5);
    o.connect(g).connect(testCtx.destination);
    o.start(t + i * 0.18); o.stop(t + i * 0.18 + 0.55);
  });
};
(async () => {
  try {
    const st = await navigator.permissions?.query({ name: 'microphone' });
    if (st && st.state === 'granted' && !isMobile) startTestMic(); else { $('#perm-banner').hidden = false; refreshDevices(); }
  } catch { $('#perm-banner').hidden = false; refreshDevices(); }
})();
function unlockAudio() {
  testCtx?.resume();
  cards.forEach(c => { c.ctx.resume(); if (c.audioEl.srcObject && c.audioEl.paused) c.audioEl.play().catch(() => {}); });
  $('#audio-unlock').hidden = true;
}
document.addEventListener('pointerdown', unlockAudio, true);

// ------------------------------------------------------------ Enlaces
const cards = new Map(); // key -> LinkCard
function addCard(peerInfo, profile, role, conn, key, bitrate = 0, direction = 'both') {
  const c = new LinkCard(peerInfo, profile, role, conn, key, bitrate, direction);
  cards.set(key, c);
  $('#links').prepend(c.el);
  presence.set(peerInfo.id, 'busy');
  renderContacts();
  reportLive();
  return c;
}
// Vistas: «Inicio» y «En vivo». Cuando alguien se conecta se pasa sola a «En vivo».
function setView(v) {
  document.body.dataset.view = v;
  $$('.redbar .tab[data-view]').forEach(t => t.classList.toggle('active', t.dataset.view === v));
  window.scrollTo(0, 0);
}
$$('.redbar .tab[data-view]').forEach(t => { t.onclick = () => setView(t.dataset.view); });
let lastCount = 0;
function reportLive() {
  const n = cards.size;
  $('.live-tab').hidden = n === 0;
  $('#live-count').textContent = n;
  if (n > lastCount) { setView('live'); desktop?.focus?.(); }
  if (n === 0 && lastCount > 0) setView('home');
  lastCount = n;
  desktop?.setLiveCount(cards.size);
  try { androidApp?.setLive(cards.size); } catch {}
  if (isMobile) { if (cards.size) requestWakeLock(); else releaseWakeLock(); }
}

const RECOVER_MS = 45000;

class LinkCard {
  constructor(peerInfo, profile, role, conn, key, bitrate = 0, direction = 'both') {
    this.peer = peerInfo;
    this.profile = PROFILES[profile] ? profile : 'lowlat';
    this.kbps = kbpsOf(this.profile, bitrate);
    this.role = role;
    this.key = key;
    this.direction = DIRECTIONS.includes(direction) ? direction : 'both';
    Object.assign(this, dirFor(this.direction, role)); // this.sends, this.recvs
    this.startedAt = Date.now();
    this.activeAlerts = new Set();
    this.lastRouteKey = '';
    this.cfg = { inputId: settings.inputId, outputId: settings.outputId, proc: settings.proc };
    this.el = $('#tpl-link').content.firstElementChild.cloneNode(true);
    this.q = s => $(s, this.el);
    this.q('.l-name').textContent = peerInfo.name;
    this.q('.l-id').textContent = fmtId(peerInfo.id);
    this.q('.l-platform').textContent = peerInfo.platform || '';
    this.q('.l-profile').textContent = `${PROFILES[this.profile].short} · ${this.kbps} kbps${isStereo(this.profile) ? ' estéreo' : ''}`;
    const badge = this.q('.l-dir');
    badge.textContent = this.sends && this.recvs ? '⇄ Ida y vuelta' : this.sends ? '→ Solo envío (no recibo audio)' : '← Solo recepción';
    badge.classList.toggle('oneway', !(this.sends && this.recvs));
    // Se ocultan los controles del sentido que no se usa
    this.q('.m-send').closest('.meter-block').hidden = !this.sends;
    this.q('.m-recv').closest('.meter-block').hidden = !this.recvs;
    this.q('.in-wrap').hidden = !this.sends;
    this.q('.out-wrap').hidden = !this.recvs;

    // Grafo de envío: micrófono → ganancia → silencio → (vúmetro, WebRTC)
    this.ctx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
    this.inGain = this.ctx.createGain();
    this.muteGain = this.ctx.createGain();
    this.sendAnalyser = this.ctx.createAnalyser(); this.sendAnalyser.fftSize = 1024;
    this.recvAnalyser = this.ctx.createAnalyser(); this.recvAnalyser.fftSize = 1024;
    this.dest = this.ctx.createMediaStreamDestination();
    this.dest.channelCount = isStereo(this.profile) ? 2 : 1;
    this.inGain.connect(this.muteGain);
    this.muteGain.connect(this.sendAnalyser);
    this.muteGain.connect(this.dest);
    this.sendMeter = new Meter(this.q('.m-send')); this.sendMeter.attach(this.sendAnalyser);
    this.recvMeter = new Meter(this.q('.m-recv'));
    this.audioEl = this.q('.remote-audio');
    this.sendMuted = false;
    this.micReady = this.sends
      ? this.openMic().catch(e => this.setNotice('No se pudo abrir el micrófono: ' + (e.name || e.message)))
      : Promise.resolve(); // solo escucha: el micrófono no se abre
    if (!this.recvs) this.audioEl.muted = true;
    this.bindUi();
    this.renderDevices();
    this.attachData(conn);
    this.setState(role === 'caller' ? 'Conectando…' : 'Esperando audio…', 'warn');
    logEvent('enlace', `Enlace iniciado con ${peerInfo.name} (${fmtId(peerInfo.id)})${role === 'caller' ? '' : ' — entrante'} · ${{ both: 'ida y vuelta', send: 'solo envía el locutor', listen: 'solo escucha el locutor' }[this.direction]}`, { peer: peerInfo.id });
  }

  bindUi() {
    this.el.addEventListener('click', e => {
      const act = e.target.closest('[data-act]')?.dataset.act;
      if (!act) return;
      this.ctx.resume();
      if (act === 'hangup' && confirm(`¿Colgar el enlace con ${this.peer.name}?`)) {
        this.hangingUp = true; // evita que el cierre se tome como un corte de red
        this.send({ type: 'hangup' });
        setTimeout(() => this.end(''), 300);
      }
      if (act === 'mute-send') this.setSendMuted(!this.sendMuted);
      if (act === 'mute-recv') {
        this.audioEl.muted = !this.audioEl.muted;
        const b = this.q('[data-act="mute-recv"]');
        b.classList.toggle('on', this.audioEl.muted);
        b.textContent = this.audioEl.muted ? 'Retorno silenciado' : 'Silenciar retorno';
      }
    });
    this.q('.in-dev').onchange = e => { if (!this.sends) return; this.cfg.inputId = e.target.value; this.openMic().catch(err => toast('No se pudo abrir la entrada: ' + err.message)); };
    this.q('.out-dev').onchange = e => { this.cfg.outputId = e.target.value; this.applyOutput(); };
    this.q('.g-send').oninput = e => {
      const db = Number(e.target.value);
      this.inGain.gain.setTargetAtTime(10 ** (db / 20), this.ctx.currentTime, 0.02);
      this.q('.g-send-v').textContent = `${db > 0 ? '+' : ''}${db} dB`;
    };
    this.q('.g-recv').oninput = e => { this.audioEl.volume = Number(e.target.value) / 100; this.q('.g-recv-v').textContent = `${e.target.value} %`; };
    this.q('.chat-form').onsubmit = e => { e.preventDefault(); this.sendChat(this.q('.chat-input').value); this.q('.chat-input').value = ''; };
    $$('.chip', this.el).forEach(ch => { ch.onclick = () => this.sendChat(ch.textContent); });
  }

  renderDevices() {
    fillSelect(this.q('.in-dev'), devices.inputs, this.cfg.inputId, 'Entrada');
    fillSelect(this.q('.out-dev'), devices.outputs, this.cfg.outputId, 'Salida', !canPickOutput);
  }
  async openMic() {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: micConstraints(this.cfg.inputId, this.cfg.proc, isStereo(this.profile)) });
    if (this.destroyed) { stream.getTracks().forEach(t => t.stop()); return; }
    this.micStream?.getTracks().forEach(t => t.stop());
    this.src?.disconnect();
    this.micStream = stream;
    this.src = this.ctx.createMediaStreamSource(stream);
    this.src.connect(this.inGain);
    if (!devices.inputs.some(d => d.label)) refreshDevices();
  }
  async applyOutput() {
    if (!canPickOutput) return;
    try { await this.audioEl.setSinkId(this.cfg.outputId || ''); } catch (e) { toast('No se pudo usar esa salida: ' + e.message); }
  }
  setSendMuted(muted) {
    this.sendMuted = muted;
    this.muteGain.gain.setTargetAtTime(muted ? 0 : 1, this.ctx.currentTime, 0.01);
    const b = this.q('[data-act="mute-send"]');
    b.classList.toggle('on', muted);
    b.textContent = muted ? 'Envío silenciado' : 'Silenciar envío';
    this.send({ type: 'peer-state', muted });
  }
  setNotice(t) { const n = this.q('.notice'); n.textContent = t; n.hidden = !t; }
  setState(text, cls) { const s = this.q('.l-state'); s.textContent = text; s.className = 'state l-state ' + cls; }

  // ---------------------------------------------------------- Canal de control (cifrado, directo)
  attachData(conn) {
    if (this.conn && this.conn !== conn) { try { this.conn.close(); } catch {} }
    this.conn = conn;
    conn.on('data', m => this.onControl(m));
    conn.on('close', () => { if (this.conn === conn && !this.destroyed) this.onLost(); });
    if (this.recoverStart && this.isConnected()) this.recovered();
  }
  send(m) { try { if (this.conn && this.conn.open) this.conn.send(m); } catch {} }
  onControl(m) {
    if (!m) return;
    if (m.type === 'chat') this.addChat(this.peer.name, m.text, false);
    if (m.type === 'peer-state') this.q('.peer-muted').hidden = !m.muted;
    if (m.type === 'hangup') this.end(`${this.peer.name} colgó.`);
  }

  // ---------------------------------------------------------- Audio
  async start() {
    await this.micReady;
    this.ctx.resume();
    if (this.ctx.state !== 'running') $('#audio-unlock').hidden = false;
    this.dial();
    this.connectTimer = setTimeout(() => {
      if (!this.isConnected()) this.setNotice('El audio no logra conectarse en 12 s: algún NAT estricto bloquea la ruta directa. La versión oficial usará un servidor TURN propio. Se sigue intentando.');
    }, 12000);
  }
  sdp() { return s => applyOpusProfile(s, this.profile, true, this.kbps); }
  dial() {
    if (this.destroyed || !peer || peer.disconnected) return;
    const call = peer.call(pid(this.peer.id), this.dest.stream, { metadata: { app: 'enlace', linkKey: this.key }, sdpTransform: this.sdp() });
    if (call) this.attachMedia(call);
  }
  async answer(call) {
    await this.micReady;
    if (this.destroyed) { call.close(); return; }
    call.answer(this.dest.stream, { sdpTransform: this.sdp() });
    this.attachMedia(call);
  }
  attachMedia(call) {
    if (this.call && this.call !== call) { const old = this.call; this.call = null; try { old.close(); } catch {} }
    this.stats?.stop();
    this.call = call;
    call.on('stream', s => this.onRemoteTrack(s));
    call.on('close', () => { if (this.call === call && !this.destroyed) this.onLost(); });
    call.on('error', () => {});
    const pc = call.peerConnection;
    if (pc) {
      this.pc = pc;
      pc.addEventListener('connectionstatechange', () => { if (this.pc === pc) this.onConnState(); });
      this.stats = new StatsMonitor(pc, st => this.onStats(st));
    }
  }
  isConnected() { return !!(this.pc && this.pc.connectionState === 'connected' && this.conn && this.conn.open); }
  onRemoteTrack(stream) {
    if (!this.recvs) return; // enlace de un solo sentido: no se reproduce nada
    try { tuneReceiver(this.pc.getReceivers().find(r => r.track && r.track.kind === 'audio'), this.profile); } catch {}
    this.audioEl.srcObject = stream;
    this.applyOutput();
    this.audioEl.play().catch(() => { $('#audio-unlock').hidden = false; });
    this.recvSrc?.disconnect();
    this.recvSrc = this.ctx.createMediaStreamSource(stream);
    this.recvSrc.connect(this.recvAnalyser);
    this.recvMeter.attach(this.recvAnalyser);
  }
  onConnState() {
    const s = this.pc.connectionState;
    clearTimeout(this.discTimer);
    if (s === 'connected') {
      clearTimeout(this.connectTimer);
      if (this.sends) setSenderBitrate(this.pc.getSenders().find(x => x.track && x.track.kind === 'audio'), this.profile, this.kbps);
      else this.pc.getSenders().forEach(x => { if (x.track) x.replaceTrack(null).catch(() => {}); }); // no se transmite audio
      this.setNotice('');
      if (this.conn && this.conn.open) this.recovered();
      else this.setState('AL AIRE · enlazado', 'live');
    } else if (s === 'disconnected') {
      this.setState('Reconectando…', 'warn');
      this.discTimer = setTimeout(() => { if (this.pc && this.pc.connectionState !== 'connected') this.onLost(); }, 4000);
    } else if (s === 'failed') {
      this.onLost();
    }
  }

  // ---------------------------------------------------------- Reconexión (RF-22): sin pedir contraseña
  onLost() {
    if (this.destroyed || this.hangingUp) return;
    this.setState('Reconectando…', 'warn');
    if (!this.recoverStart) {
      this.recoverStart = Date.now();
      logEvent('reconexion', `Se perdió la conexión con ${this.peer.name}; reconectando`, { peer: this.peer.id });
    }
    clearTimeout(this.giveUp);
    this.giveUp = setTimeout(() => { if (!this.isConnected()) this.end('Se perdió la conexión con el otro equipo.'); }, RECOVER_MS);
    if (this.role === 'caller') this.recover();
  }
  recover() {
    clearTimeout(this.recTimer);
    if (this.destroyed || !this.recoverStart) return;
    if (!this.conn || !this.conn.open) {
      if (peer && !peer.disconnected) {
        const c = peer.connect(pid(this.peer.id), { metadata: { app: 'enlace', type: 'link', from: myId, name: myName, platform: dev.platform }, reliable: true });
        c.on('open', () => c.send({ type: 'resume', linkKey: this.key }));
        c.on('data', m => {
          if (m && m.type === 'resume-ok') { this.attachData(c); if (!this.pc || this.pc.connectionState !== 'connected') this.dial(); }
          if (m && m.type === 'resume-fail') this.end('El otro equipo cerró el enlace.');
        });
        c.on('error', () => {});
      }
    } else if (!this.pc || this.pc.connectionState !== 'connected') {
      this.dial();
    }
    this.recTimer = setTimeout(() => this.recover(), 8000);
  }
  recovered() {
    this.setState('AL AIRE · enlazado', 'live');
    this.setNotice('');
    if (this.recoverStart) {
      logEvent('reconexion', `Enlace con ${this.peer.name} recuperado en ${((Date.now() - this.recoverStart) / 1000).toFixed(1)} s`, { peer: this.peer.id });
      this.recoverStart = 0;
      clearTimeout(this.giveUp);
      clearTimeout(this.recTimer);
    }
  }

  onStats(st) {
    const set = (s, v) => { this.q(s).textContent = v; };
    set('.st-proto', st.protocol);
    this.q('.st-proto').className = 'st-proto ' + (st.protocol === 'IPv6' ? 'good' : '');
    set('.st-route', st.connected ? `${st.route} · ${st.transport}` : '—');
    set('.st-rtt', fmt.ms(st.rtt));
    set('.st-jitter', st.jitter == null ? '—' : `${fmt.ms(st.jitter)}${st.jitterBuffer != null ? ` / ${st.jitterBuffer.toFixed(0)} ms` : ''}`);
    set('.st-loss', fmt.pct(st.loss));
    set('.st-br', `${fmt.kbps(st.sendKbps)} / ${fmt.kbps(st.recvKbps)}`);
    set('.st-codec', st.codec === '—' ? '—' : `${st.codec} · ${this.kbps} kbps máx.${isStereo(this.profile) ? ' · estéreo' : ''}`);
    set('.st-cand', st.connected ? `${st.candidates} · ${st.localAddr} ⇄ ${st.remoteAddr}` : '—');
    const k = `${st.protocol}|${st.route}|${st.transport}`;
    if (st.connected && k !== this.lastRouteKey) {
      this.lastRouteKey = k;
      this.route = `${st.protocol} · ${st.route}`;
    }
    const alerts = qualityAlerts(st);
    if (this.kbps >= 128 && st.loss != null && st.loss > 2) alerts.push(`La red no sostiene ${this.kbps} kbps: baja el bitrate o usa el perfil Voz`);
    this.q('.alerts').innerHTML = alerts.map(a => `<div class="alert">⚠ ${esc(a)}</div>`).join('');
    alerts.forEach(a => { const key = a.split(' (')[0]; if (!this.activeAlerts.has(key)) logEvent('alerta', `${this.peer.name}: ${a}`, { peer: this.peer.id }); });
    this.activeAlerts = new Set(alerts.map(a => a.split(' (')[0]));
  }

  sendChat(text) {
    text = text.trim();
    if (!text) return;
    this.send({ type: 'chat', text });
    this.addChat('Tú', text, true);
  }
  addChat(from, text, mine) {
    const log = this.q('.chat-log');
    const d = document.createElement('div');
    d.className = 'msg' + (mine ? ' mine' : '');
    d.innerHTML = `<b>${esc(from)}</b> ${esc(text)} <time>${new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' })}</time>`;
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
    if (!mine) { beep([1200], 0.08); navigator.vibrate?.(150); this.el.classList.add('flash'); setTimeout(() => this.el.classList.remove('flash'), 1200); }
  }

  end(reason) {
    if (this.destroyed) return;
    this.destroyed = true;
    if (reason) toast(`${this.peer.name}: ${reason}`, 5000);
    logEvent('enlace', `Enlace con ${this.peer.name} finalizado${reason ? ': ' + reason : ''}${this.route ? ` (ruta ${this.route})` : ''}`, { peer: this.peer.id, durS: Math.round((Date.now() - this.startedAt) / 1000) });
    [this.connectTimer, this.discTimer, this.giveUp, this.recTimer].forEach(clearTimeout);
    this.stats?.stop();
    try { this.call?.close(); } catch {}
    try { this.conn?.close(); } catch {}
    this.micStream?.getTracks().forEach(t => t.stop());
    this.sendMeter.destroy(); this.recvMeter.destroy();
    this.ctx.close();
    this.el.remove();
    cards.delete(this.key);
    presence.delete(this.peer.id);
    reportLive();
    setTimeout(refreshPresence, 1500);
  }
}
renderHistory();

// ------------------------------------------------------------ Móviles: PWA, pantalla encendida, cambio de red
if ('serviceWorker' in navigator && !desktop && !androidApp) navigator.serviceWorker.register('sw.js').catch(() => {});
let installEvent = null;
const dismissed = () => load('installDismissed', false);
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  installEvent = e;
  if (!dismissed() && isMobile) { $('#install-card').hidden = false; $('#install-btn').hidden = false; }
});
if (dev.platform === 'iOS' && !dev.installed && dev.browser === 'Safari' && !dismissed()) {
  $('#install-text').innerHTML = '<b>Instala Enlace Primera</b>Toca <span class="ios-share">Compartir ⬆</span> y luego <b style="display:inline">Agregar a inicio</b>.';
  $('#install-card').hidden = false;
}
$('#install-btn').onclick = async () => { if (!installEvent) return; installEvent.prompt(); await installEvent.userChoice.catch(() => {}); installEvent = null; $('#install-card').hidden = true; };
$('#install-close').onclick = () => { $('#install-card').hidden = true; save('installDismissed', true); };

let wakeLock = null;
async function requestWakeLock() { try { if (!wakeLock) { wakeLock = await navigator.wakeLock?.request('screen'); wakeLock?.addEventListener('release', () => { wakeLock = null; }); } } catch {} }
function releaseWakeLock() { try { wakeLock?.release(); } catch {} wakeLock = null; }
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible') return;
  if (cards.size) { if (isMobile) requestWakeLock(); unlockAudio(); }
});
// Cambio de red (Wi-Fi ↔ 4G): se vuelve a detectar la IP pública y se recupera todo solo.
function onNetworkChange() {
  setTimeout(refreshNetwork, 1500);
  if (peer && peer.disconnected) { try { peer.reconnect(); } catch {} }
  cards.forEach(c => { if (!c.isConnected()) c.onLost(); });
}
window.addEventListener('online', onNetworkChange);
navigator.connection?.addEventListener?.('change', onNetworkChange);
if (desktop && 'Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {});
