import { verifyToken, getBearer } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  const raw = await env.SHINE_KV.get('userdata:' + payload.u);
  const data = raw ? JSON.parse(raw) : { folders: [] };
  return Response.json({ ok: true, data });
}

export async function onRequestPost({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });
  let body;
  try { body = await request.json(); } catch (e) { return Response.json({ ok: false, error: 'Bad request' }, { status: 400 }); }
  await env.SHINE_KV.put('userdata:' + payload.u, JSON.stringify(body));
  return Response.json({ ok: true });
}
