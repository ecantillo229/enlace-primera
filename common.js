// Utilidades compartidas por la página del estudio y la del invitado.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------ Señalización
// WebSocket con reconexión automática (backoff exponencial hasta 5 s).
export class Signaling {
  constructor(url) {
    this.url = url || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
    this.retry = 0;
    this.stopped = false;
    this.onmessage = null;
    this.onopen = null;
    this.onstatus = null;
    queueMicrotask(() => this.connect());
  }
  connect() {
    if (this.stopped) return;
    this.onstatus?.('connecting');
    const ws = this.ws = new WebSocket(this.url);
    ws.onopen = () => { this.retry = 0; this.onstatus?.('open'); this.onopen?.(); };
    ws.onmessage = e => { let m; try { m = JSON.parse(e.data); } catch { return; } this.onmessage?.(m); };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.onstatus?.('closed');
      if (this.stopped) return;
      const delay = Math.min(5000, 400 * 2 ** this.retry++);
      setTimeout(() => this.connect(), delay);
    };
  }
  reconnectNow() { try { this.ws.close(); } catch {} }
  get open() { return this.ws && this.ws.readyState === 1; }
  send(m) { if (this.open) this.ws.send(JSON.stringify(m)); }
  stop() { this.stopped = true; try { this.ws.close(); } catch {} }
}

// ------------------------------------------------------------ Plataforma del dispositivo
export function detectDevice() {
  const ua = navigator.userAgent;
  const iOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const platform = iOS ? 'iOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Mac/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Otro';
  const browser = /EdgA?\//.test(ua) ? 'Edge' : /CriOS|Chrome\//.test(ua) ? 'Chrome' : /FxiOS|Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Otro';
  const installed = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  return { platform, browser, installed };
}

// ------------------------------------------------------------ Opus (RF-17)
// Ajusta los parámetros fmtp de Opus en el SDP según el perfil.
// Cada extremo indica en su SDP cómo quiere RECIBIR, por eso se aplica a la
// oferta (estudio) y a la respuesta (invitado).
export const PROFILES = {
  lowlat: { label: 'Baja latencia · Opus mono 64 kbps · 10 ms', short: 'Baja latencia', kbps: 64, stereo: 0, ptime: 10 },
  voice: { label: 'Voz · Opus mono 64 kbps · 20 ms', short: 'Voz', kbps: 64, stereo: 0, ptime: 20 },
  hq: { label: 'Alta calidad · Opus estéreo 128 kbps', short: 'Alta calidad', kbps: 128, stereo: 1, ptime: 20 },
  max: { label: 'Máxima calidad · Opus estéreo 192 kbps (música en vivo)', short: 'Máxima calidad', kbps: 192, stereo: 1, ptime: 20 },
};

// Bitrate elegido a mano (kbps) o el del perfil. Es un techo: WebRTC lo baja solo si la red no alcanza.
export const BITRATES = [32, 48, 64, 96, 128, 160, 192, 256];
export const kbpsOf = (profile, custom) => (custom >= 16 && custom <= 256 ? Number(custom) : (PROFILES[profile] || PROFILES.lowlat).kbps);
export const isStereo = profile => !!(PROFILES[profile] || PROFILES.lowlat).stereo;

export function applyOpusProfile(sdp, profile, fec, customKbps) {
  const p = PROFILES[profile] || PROFILES.lowlat;
  const rtpmap = sdp.match(/a=rtpmap:(\d+) opus\/48000\/2/i);
  if (!rtpmap) return sdp;
  const pt = rtpmap[1];
  const wanted = {
    minptime: 10,
    useinbandfec: fec ? 1 : 0,
    stereo: p.stereo,
    'sprop-stereo': p.stereo,
    maxaveragebitrate: kbpsOf(profile, customKbps) * 1000,
    maxplaybackrate: 48000,
  };
  const re = new RegExp(`a=fmtp:${pt} ([^\\r\\n]*)`);
  const build = kv => `a=fmtp:${pt} ` + Object.entries(kv).map(([k, v]) => `${k}=${v}`).join(';');
  let out;
  if (re.test(sdp)) {
    out = sdp.replace(re, (_, existing) => {
      const kv = {};
      existing.split(';').map(x => x.trim()).filter(Boolean).forEach(x => { const i = x.indexOf('='); kv[x.slice(0, i)] = x.slice(i + 1); });
      return build({ ...kv, ...wanted });
    });
  } else {
    out = sdp.replace(rtpmap[0], `${rtpmap[0]}\r\n${build(wanted)}`);
  }
  // Tamaño de trama (ptime): 10 ms en el perfil Baja latencia
  out = out.replace(/a=ptime:\d+\r\n/g, '').replace(/a=maxptime:\d+\r\n/g, '');
  out = out.replace(new RegExp(`(a=fmtp:${pt} [^\\r\\n]*\\r\\n)`), `$1a=ptime:${p.ptime}\r\n`);
  return out;
}

// Pide al receptor el búfer de fluctuación más pequeño posible (RNF-03)
export function tuneReceiver(receiver, profile) {
  if (!receiver) return;
  const target = profile === 'lowlat' ? 20 : 60;
  try { if ('jitterBufferTarget' in receiver) receiver.jitterBufferTarget = target; } catch {}
  try { if ('playoutDelayHint' in receiver) receiver.playoutDelayHint = target / 1000; } catch {}
}

export async function setSenderBitrate(sender, profile, customKbps) {
  if (!sender) return;
  try {
    const params = sender.getParameters();
    if (!params.encodings || !params.encodings.length) params.encodings = [{}];
    params.encodings[0].maxBitrate = kbpsOf(profile, customKbps) * 1000;
    params.encodings[0].priority = 'high';
    params.encodings[0].networkPriority = 'high'; // marca DSCP donde el SO lo permite
    await sender.setParameters(params);
  } catch (e) { console.warn('No se pudo fijar el bitrate', e); }
}

// ------------------------------------------------------------ Vúmetros (RF-15)
// <div class="meter"><div class="cover"></div><span class="db"></span></div>
const meters = new Set();
function meterLoop() { for (const m of meters) m.tick(); requestAnimationFrame(meterLoop); }
requestAnimationFrame(meterLoop);

export class Meter {
  constructor(el) {
    this.el = el;
    this.cover = el.querySelector('.cover');
    this.label = el.querySelector('.db');
    this.analyser = null;
    this.level = -60;
    this.clipUntil = 0;
    meters.add(this);
  }
  attach(analyser) { this.analyser = analyser; this.buf = new Float32Array(analyser.fftSize); }
  detach() { this.analyser = null; }
  destroy() { meters.delete(this); }
  tick() {
    let db = -Infinity;
    if (this.analyser) {
      this.analyser.getFloatTimeDomainData(this.buf);
      let peak = 0;
      for (let i = 0; i < this.buf.length; i++) { const a = Math.abs(this.buf[i]); if (a > peak) peak = a; }
      db = peak > 0 ? 20 * Math.log10(peak) : -Infinity;
    }
    const target = Math.max(-60, db);
    this.level = target > this.level ? target : Math.max(target, this.level - 0.9); // ataque rápido, caída lenta
    const now = performance.now();
    if (db > -3) this.clipUntil = now + 1200; // saturación sobre −3 dBFS
    this.cover.style.width = (100 - ((this.level + 60) / 60) * 100).toFixed(1) + '%';
    this.el.classList.toggle('clip', now < this.clipUntil);
    this.label.textContent = this.level <= -59.5 ? '−∞' : `${Math.round(this.level) || 0} dB`;
  }
}

// ------------------------------------------------------------ Estadísticas (RF-22)
export class StatsMonitor {
  constructor(pc, onUpdate) {
    this.pc = pc;
    this.onUpdate = onUpdate;
    this.prev = null;
    this.timer = setInterval(() => this.poll().catch(() => {}), 2000);
  }
  stop() { clearInterval(this.timer); }
  async poll() {
    if (this.pc.connectionState === 'closed') return;
    const r = await this.pc.getStats();
    let transport, inbound, outbound, pair;
    r.forEach(s => {
      if (s.type === 'transport') transport = s;
      else if (s.type === 'inbound-rtp' && s.kind === 'audio') inbound = s;
      else if (s.type === 'outbound-rtp' && s.kind === 'audio') outbound = s;
    });
    if (transport && transport.selectedCandidatePairId) pair = r.get(transport.selectedCandidatePairId);
    if (!pair) r.forEach(s => { if (!pair && s.type === 'candidate-pair' && s.state === 'succeeded' && s.nominated) pair = s; });
    const local = pair && r.get(pair.localCandidateId);
    const remote = pair && r.get(pair.remoteCandidateId);
    const codec = inbound && inbound.codecId ? r.get(inbound.codecId) : (outbound && outbound.codecId ? r.get(outbound.codecId) : null);

    const now = performance.now();
    const p = this.prev;
    const dt = p ? (now - p.t) / 1000 : 0;
    const ipOf = c => String((c && (c.address || c.ip)) || '').replace(/^\[|\]$/g, '');
    let addr = ipOf(local);
    if (addr.endsWith('.local')) addr = ipOf(remote);
    const relay = (local && local.candidateType === 'relay') || (remote && remote.candidateType === 'relay');

    const res = {
      connected: !!pair,
      protocol: addr ? (addr.includes(':') ? 'IPv6' : 'IPv4') : '—',
      route: pair ? (relay ? 'TURN (retransmitida)' : 'Directa (P2P)') : '—',
      candidates: local ? `${local.candidateType} → ${remote ? remote.candidateType : '?'}` : '—',
      transport: local && local.protocol ? local.protocol.toUpperCase() : '—',
      localAddr: ipOf(local) || '—',
      remoteAddr: ipOf(remote) || '—',
      rtt: pair && pair.currentRoundTripTime != null ? pair.currentRoundTripTime * 1000 : null,
      jitter: inbound && inbound.jitter != null ? inbound.jitter * 1000 : null,
      jitterBuffer: inbound && inbound.jitterBufferEmittedCount ? (inbound.jitterBufferDelay / inbound.jitterBufferEmittedCount) * 1000 : null,
      loss: null, sendKbps: null, recvKbps: null,
      codec: codec ? `${codec.mimeType.split('/')[1]} ${codec.clockRate / 1000} kHz` : '—',
    };
    if (p && dt > 0) {
      if (inbound && p.inbound) {
        const lost = (inbound.packetsLost || 0) - (p.inbound.packetsLost || 0);
        const recv = (inbound.packetsReceived || 0) - (p.inbound.packetsReceived || 0);
        res.loss = lost + recv > 0 ? Math.max(0, (lost / (lost + recv)) * 100) : 0;
        res.recvKbps = ((inbound.bytesReceived - p.inbound.bytesReceived) * 8) / dt / 1000;
      }
      if (outbound && p.outbound) res.sendKbps = ((outbound.bytesSent - p.outbound.bytesSent) * 8) / dt / 1000;
    }
    this.prev = { t: now, inbound: inbound && { ...inbound }, outbound: outbound && { ...outbound } };
    this.onUpdate(res);
  }
}

export const fmt = {
  ms: v => (v == null ? '—' : `${v.toFixed(0)} ms`),
  pct: v => (v == null ? '—' : `${v.toFixed(1)} %`),
  kbps: v => (v == null ? '—' : `${v.toFixed(0)} kbps`),
};

// Umbrales de RF-23
export function qualityAlerts(st) {
  const a = [];
  if (st.loss != null && st.loss > 5) a.push(`Pérdida de paquetes alta (${st.loss.toFixed(1)} %)`);
  if (st.jitter != null && st.jitter > 50) a.push(`Jitter alto (${st.jitter.toFixed(0)} ms)`);
  if (st.rtt != null && st.rtt > 300) a.push(`Latencia alta (${st.rtt.toFixed(0)} ms ida y vuelta)`);
  return a;
}

// ------------------------------------------------------------ Sonidos
let uiCtx;
export function beep(freqs = [880, 1320], dur = 0.12) {
  try {
    uiCtx = uiCtx || new AudioContext();
    uiCtx.resume();
    freqs.forEach((f, i) => {
      const o = uiCtx.createOscillator();
      const g = uiCtx.createGain();
      const t = uiCtx.currentTime + i * (dur + 0.04);
      o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.25, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      o.connect(g).connect(uiCtx.destination);
      o.start(t);
      o.stop(t + dur + 0.02);
    });
  } catch {}
}

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); ta.remove(); return ok;
  }
}

export function toast(msg, ms = 3000) {
  let box = $('#toasts');
  if (!box) { box = document.createElement('div'); box.id = 'toasts'; document.body.appendChild(box); }
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  box.appendChild(t);
  setTimeout(() => t.classList.add('out'), ms - 400);
  setTimeout(() => t.remove(), ms);
}
