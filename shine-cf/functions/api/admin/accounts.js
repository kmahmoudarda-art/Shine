import { verifyToken, getBearer, genPassword } from '../../_lib/auth.js';

async function loadAccounts(env) {
  const raw = await env.SHINE_KV.get('accounts');
  return raw ? JSON.parse(raw) : { admin: { username: 'admin', password: '' }, lsas: [] };
}

export async function onRequestGet({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload || !payload.a) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  const accounts = await loadAccounts(env);
  return Response.json({ ok: true, lsas: accounts.lsas });
}

export async function onRequestPost({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload || !payload.a) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });

  let body;
  try { body = await request.json(); } catch (e) { return Response.json({ ok: false, error: 'Bad request' }, { status: 400 }); }
  const { action, index, name } = body;
  const accounts = await loadAccounts(env);

  if (index === undefined || !accounts.lsas[index]) {
    return Response.json({ ok: false, error: 'Account not found' }, { status: 404 });
  }
  if (action === 'rename') {
    accounts.lsas[index].name = name || accounts.lsas[index].name;
  } else if (action === 'reset') {
    accounts.lsas[index].password = genPassword(6);
  } else {
    return Response.json({ ok: false, error: 'Unknown action' }, { status: 400 });
  }

  await env.SHINE_KV.put('accounts', JSON.stringify(accounts));
  return Response.json({ ok: true, lsas: accounts.lsas });
}
