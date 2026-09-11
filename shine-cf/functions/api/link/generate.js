import { verifyToken, getBearer, uid, genPassword } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const payload = await verifyToken(getBearer(request), env.SHINE_SECRET);
  if (!payload) return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401 });

  let body;
  try { body = await request.json(); } catch (e) { return Response.json({ ok: false, error: 'Bad request' }, { status: 400 }); }
  const { folderId, formId, regenerate } = body;

  const raw = await env.SHINE_KV.get('userdata:' + payload.u);
  const data = raw ? JSON.parse(raw) : { folders: [] };
  const folder = data.folders.find(f => f.id === folderId);
  if (!folder) return Response.json({ ok: false, error: 'Folder not found' }, { status: 404 });
  const form = folder.forms.find(f => f.id === formId);
  if (!form) return Response.json({ ok: false, error: 'Form not found' }, { status: 404 });

  const linkIndexRaw = await env.SHINE_KV.get('linkindex');
  const linkIndex = linkIndexRaw ? JSON.parse(linkIndexRaw) : {};

  if (form.viewLink && !regenerate) {
    return Response.json({ ok: true, token: form.viewLink.token, password: form.viewLink.password });
  }
  if (form.viewLink && regenerate) {
    delete linkIndex[form.viewLink.token];
  }

  const newToken = uid() + uid();
  const newPassword = genPassword(6);
  form.viewLink = { token: newToken, password: newPassword };
  linkIndex[newToken] = { username: payload.u, folderId, formId };

  await env.SHINE_KV.put('userdata:' + payload.u, JSON.stringify(data));
  await env.SHINE_KV.put('linkindex', JSON.stringify(linkIndex));

  return Response.json({ ok: true, token: newToken, password: newPassword });
}
