export async function onRequestPost({ request, env }) {
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
  const form = folder ? folder.forms.find(f => f.id === entry.formId) : null;

  if (!form || !form.viewLink || form.viewLink.token !== token || form.viewLink.password !== password) {
    return Response.json({ ok: false, error: 'Incorrect password' }, { status: 401 });
  }

  return Response.json({ ok: true, studentName: folder.studentName, weekBeginning: form.weekBeginning, data: form.data });
}
