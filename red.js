// Detección automática de la red del equipo (ERS v1.1, RF-33).
// Usa STUN (el mismo mecanismo de WebRTC): no requiere servicios externos adicionales
// ni que el usuario escriba su IP.

const isPrivateV4 = ip => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
const isGlobalV6 = ip => /^[23][0-9a-f]{0,3}:/i.test(ip);
const isLocalV6 = ip => /^(f[cd][0-9a-f]{0,2}:|fe[89ab][0-9a-f]?:)/i.test(ip);

/**
 * Devuelve { publicV4[], publicV6[], local[], mdnsHidden, nat, at }
 * nat: 'compatible' | 'estricto' | 'sin-nat' | 'bloqueado' | 'desconocido'
 */
export async function detectNetwork(iceServers, timeout = 5000) {
  const pc = new RTCPeerConnection({ iceServers });
  pc.createDataChannel('red');
  const list = [];
  const done = new Promise(resolve => {
    const t = setTimeout(resolve, timeout);
    pc.onicecandidate = e => {
      if (!e.candidate) { clearTimeout(t); resolve(); return; }
      const c = e.candidate;
      // Chromium entrega las IPv6 entre corchetes ([2803:…]): se normalizan
      const clean = a => (a ? String(a).replace(/^\[|\]$/g, '') : a);
      if (c.address) list.push({ type: c.type, address: clean(c.address), port: c.port, protocol: c.protocol, raddr: clean(c.relatedAddress), rport: c.relatedPort });
    };
  });
  await pc.setLocalDescription(await pc.createOffer());
  await done;
  pc.close();

  const udp = list.filter(c => c.protocol === 'udp');
  const host = udp.filter(c => c.type === 'host');
  const srflx = udp.filter(c => c.type === 'srflx');
  const local = [...new Set(host.map(c => c.address).filter(a => !a.endsWith('.local')))];
  const mdnsHidden = host.some(c => c.address.endsWith('.local'));

  const v4 = new Set(), v6 = new Set();
  for (const c of srflx) (c.address.includes(':') ? v6 : v4).add(c.address);
  for (const a of local) {
    if (!a.includes(':') && !isPrivateV4(a)) v4.add(a);
    if (a.includes(':') && isGlobalV6(a)) v6.add(a);
  }

  // Tipo de NAT: si el mismo puerto local se ve con puertos públicos distintos
  // desde dos servidores STUN, el NAT es estricto (simétrico) y hará falta TURN.
  let nat = 'desconocido';
  const s4 = srflx.filter(c => !c.address.includes(':'));
  if (local.some(a => !a.includes(':') && !isPrivateV4(a))) nat = 'sin-nat';
  else if (!s4.length) nat = v6.size ? 'sin-nat' : 'bloqueado';
  else {
    const byBase = new Map();
    for (const c of s4) {
      if (!c.rport) continue;
      const k = `${c.raddr}:${c.rport}`;
      if (!byBase.has(k)) byBase.set(k, new Set());
      byBase.get(k).add(`${c.address}:${c.port}`);
    }
    if (byBase.size) nat = [...byBase.values()].some(s => s.size > 1) ? 'estricto' : 'compatible';
  }
  const localV6Only = local.filter(a => a.includes(':') && isLocalV6(a));
  return { publicV4: [...v4], publicV6: [...v6], localV6Only, local, mdnsHidden, nat, at: new Date() };
}

export const NAT_TEXT = {
  'sin-nat': ['Sin NAT: IP pública directa', 'good'],
  compatible: ['Compatible con conexión directa', 'good'],
  estricto: ['NAT estricto: la conexión directa puede fallar (la versión oficial usará TURN)', 'warn'],
  bloqueado: ['Sin respuesta STUN: UDP bloqueado o sin Internet', 'bad'],
  desconocido: ['No determinado (permite el micrófono para un diagnóstico completo)', ''],
};
