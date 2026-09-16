import { verifyToken, getBearer } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload || !payload.a) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });

  const accountsRaw = await env.SHINE_KV.get('accounts');
  const accounts = accountsRaw ? JSON.parse(accountsRaw) : { lsas: [] };

  const folders = [];
  for (const lsa of accounts.lsas) {
    const raw = await env.SHINE_KV.get('userdata:' + lsa.username);
    const data = raw ? JSON.parse(raw) : { folders: [] };
    for (const folder of data.folders) {
      folders.push({ ...folder, ownerUsername: lsa.username, ownerName: lsa.name || lsa.username });
    }
  }

  return Response.json({ ok: true, folders });
}
