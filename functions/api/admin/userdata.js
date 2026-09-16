import { verifyToken, getBearer } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload || !payload.a) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });

  const url = new URL(request.url);
  const username = (url.searchParams.get('username') || '').trim();
  if (!username) return Response.json({ ok: false, error: 'Missing username' }, { status: 400 });

  const accountsRaw = await env.SHINE_KV.get('accounts');
  const accounts = accountsRaw ? JSON.parse(accountsRaw) : { lsas: [] };
  const known = accounts.lsas.some(l => l.username.toLowerCase() === username.toLowerCase());
  if (!known) return Response.json({ ok: false, error: 'Unknown LSA account' }, { status: 404 });

  const raw = await env.SHINE_KV.get('userdata:' + username);
  const data = raw ? JSON.parse(raw) : { folders: [] };
  return Response.json({ ok: true, username, data });
}
