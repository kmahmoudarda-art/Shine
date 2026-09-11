// Lightweight signed-token helper (no external deps) for Cloudflare Pages Functions.

function b64url(buf) {
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBuf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}
async function getKey(secret) {
  const enc = new TextEncoder().encode(secret);
  return crypto.subtle.importKey('raw', enc, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signToken(payload, secret) {
  const key = await getKey(secret);
  const payloadB64 = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return payloadB64 + '.' + b64url(sig);
}

export async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  try {
    const key = await getKey(secret);
    const valid = await crypto.subtle.verify('HMAC', key, b64urlToBuf(sigB64), new TextEncoder().encode(payloadB64));
    if (!valid) return null;
    return JSON.parse(new TextDecoder().decode(b64urlToBuf(payloadB64)));
  } catch (e) {
    return null;
  }
}

export function getBearer(request) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer (.+)$/);
  return m ? m[1] : null;
}

export function genPassword(len) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

export function uid() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
}
