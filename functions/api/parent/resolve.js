import { checkRateLimit, clientIp } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const allowed = await checkRateLimit(env, 'parent:' + clientIp(request), 2);
  if (!allowed) return Response.json({ ok: false, error: 'Too many attempts. Please wait a moment and try again.' }, { status: 429 });

  let body;
  try { body = await request.json(); } catch (e) { return Response.json({ ok: false, error: 'Bad request' }, { status: 400 }); }
  const { token, password } = body;
  if (!token) return Response.json({ ok: false, error: 'Missing link' }, { status: 400 });

  const linkIndexRaw = await env.SHINE_KV.get('linkindex');
  const linkIndex = linkIndexRaw ? JSON.parse(linkIndexRaw) : {};
  const entry = linkIndex[token];
  if (!entry) return Response.json({ ok: false, error: 'Link not found' }, { status: 404 });

  const raw = await env.SHINE_KV.get('userdata:' + entry.username);
  const data = raw ? JSON.parse(raw) : { folders: [] };
  const folder = data.folders.find(f => f.id === entry.folderId);

  if (!folder || !folder.viewLink || folder.viewLink.token !== token || folder.viewLink.password !== password) {
    return Response.json({ ok: false, error: 'Incorrect password' }, { status: 401 });
  }

  const forms = folder.forms
    .slice()
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(f => ({ id: f.id, weekBeginning: f.weekBeginning, createdAt: f.createdAt, data: f.data }));

  return Response.json({ ok: true, studentName: folder.studentName, forms });
}
