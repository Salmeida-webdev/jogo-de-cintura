const SESSION_SECONDS = 12 * 60 * 60;
const MAX_CONTENT_BYTES = 1_000_000;
const ALLOWED_STATUSES = new Set(['rascunho', 'em revisão', 'aprovado', 'devolvido', 'publicado', 'agendado']);

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders },
  });
}
function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function fromBase64url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
}
async function issueToken(env) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS })));
  return `${payload}.${base64url(await hmac(env.SESSION_SECRET, payload))}`;
}
async function verifyToken(request, env) {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '');
  if (!token || !token.includes('.')) return false;
  const [payload, signature] = token.split('.');
  try {
    const expected = await hmac(env.SESSION_SECRET, payload);
    const received = fromBase64url(signature);
    if (expected.length !== received.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ received[i];
    return diff === 0 && JSON.parse(new TextDecoder().decode(fromBase64url(payload))).exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function sameSecret(candidate, expected) {
  const left = new TextEncoder().encode(String(candidate || ''));
  const right = new TextEncoder().encode(expected);
  let diff = left.length ^ right.length;
  const max = Math.max(left.length, right.length);
  for (let i = 0; i < max; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}
function originAllowed(request, env) {
  const origin = request.headers.get('origin');
  return !origin || origin === env.APP_ORIGIN;
}
async function publicPayload(env) {
  const row = await env.DB.prepare('SELECT payload FROM site_content WHERE singleton_id = 1').first();
  if (!row?.payload) return null;
  const content = JSON.parse(row.payload);
  const articles = (content.articles || []).filter(article => article.status === 'publicado');
  const authorIds = new Set(articles.map(article => article.authorId));
  const categories = new Set(articles.map(article => article.category));
  const tags = new Set(articles.flatMap(article => article.tags || []));
  return {
    authors: (content.authors || []).filter(author => authorIds.has(author.id)),
    categories: (content.categories || []).filter(category => categories.has(category)),
    tags: (content.tags || []).filter(tag => tags.has(tag)),
    articles,
  };
}
async function saveContent(env, payload) {
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO site_content (singleton_id, payload, updated_at) VALUES (1, ?, ?)
      ON CONFLICT(singleton_id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`).bind(payload, now),
    env.DB.prepare('INSERT INTO content_revisions (payload, created_at) VALUES (?, ?)').bind(payload, now),
    env.DB.prepare('DELETE FROM content_revisions WHERE revision_id NOT IN (SELECT revision_id FROM content_revisions ORDER BY revision_id DESC LIMIT 50)'),
    env.DB.prepare("DELETE FROM login_attempts WHERE created_at < datetime('now', '-2 days')"),
  ]);
}
function validateContent(content) {
  if (!content || typeof content !== 'object' || !Array.isArray(content.articles) || !Array.isArray(content.authors) || !Array.isArray(content.categories) || !Array.isArray(content.tags)) return 'Estrutura de conteúdo inválida.';
  if (content.articles.length > 500 || content.authors.length > 100 || content.categories.length > 100 || content.tags.length > 300) return 'O conteúdo excede os limites permitidos.';
  const ids = new Set();
  const slugs = new Set();
  for (const article of content.articles) {
    if (!article || typeof article.title !== 'string' || !article.title.trim() || article.title.length > 130) return 'Cada matéria precisa de um título válido.';
    if (typeof article.id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(article.id) || ids.has(article.id)) return 'Identificador de matéria inválido ou repetido.';
    if (typeof article.slug !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(article.slug) || slugs.has(article.slug)) return 'Slug de matéria inválido ou repetido.';
    if (!ALLOWED_STATUSES.has(article.status)) return 'Etapa editorial inválida.';
    if (!Array.isArray(article.body) || !Array.isArray(article.tags)) return 'Conteúdo ou tags da matéria estão inválidos.';
    ids.add(article.id); slugs.add(article.slug);
  }
  return null;
}
async function login(request, env) {
  if (!originAllowed(request, env)) return json({ error: 'Origem não autorizada.' }, 403);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = base64url(await hmac(env.SESSION_SECRET, ip));
  const attempts = await env.DB.prepare("SELECT COUNT(*) AS total FROM login_attempts WHERE ip_hash = ? AND created_at > datetime('now', '-15 minutes')").bind(ipHash).first('total');
  if (Number(attempts) >= 8) return json({ error: 'Muitas tentativas. Aguarde 15 minutos e tente novamente.' }, 429);
  let email = '';
  let password = '';
  try {
    const credentials = await request.json();
    email = String(credentials.email || '').trim().toLocaleLowerCase('pt-BR');
    password = String(credentials.password || '');
  } catch { return json({ error: 'Informe o e-mail e a senha.' }, 400); }
  if (!sameSecret(email, String(env.ADMIN_EMAIL || '').trim().toLocaleLowerCase('pt-BR')) || !sameSecret(password, env.ADMIN_PASSWORD)) {
    await env.DB.prepare('INSERT INTO login_attempts (ip_hash) VALUES (?)').bind(ipHash).run();
    return json({ error: 'E-mail ou senha incorretos. Confira os dados e tente novamente.' }, 401);
  }
  await env.DB.prepare('DELETE FROM login_attempts WHERE ip_hash = ?').bind(ipHash).run();
  return json({ token: await issueToken(env), expiresIn: SESSION_SECONDS });
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'allow': 'GET, POST, OPTIONS' } });
    if (url.pathname === '/api/health' && request.method === 'GET') return json({ status: 'ok', service: 'jogo-de-cintura-api' });
    if (url.pathname === '/api/login' && request.method === 'POST') return login(request, env);
    if (url.pathname === '/api/content' && request.method === 'GET') {
      const admin = request.headers.has('authorization');
      if (admin && !(await verifyToken(request, env))) return json({ error: 'Sessão expirada. Entre novamente.' }, 401);
      try {
        const content = admin ? await env.DB.prepare('SELECT payload FROM site_content WHERE singleton_id = 1').first('payload') : await publicPayload(env);
        return content ? json(admin ? JSON.parse(content) : content) : json({ error: 'O conteúdo ainda não foi inicializado.' }, 503);
      } catch { return json({ error: 'Não foi possível carregar o conteúdo.' }, 500); }
    }
    if (url.pathname === '/api/content' && request.method === 'POST') {
      if (!originAllowed(request, env)) return json({ error: 'Origem não autorizada.' }, 403);
      if (!(await verifyToken(request, env))) return json({ error: 'Sessão expirada. Entre novamente.' }, 401);
      const length = Number(request.headers.get('content-length') || 0);
      if (length > MAX_CONTENT_BYTES) return json({ error: 'O conteúdo excede o limite de envio.' }, 413);
      let content;
      try { content = await request.json(); } catch { return json({ error: 'O conteúdo enviado não é um JSON válido.' }, 400); }
      const error = validateContent(content);
      if (error) return json({ error }, 422);
      const payload = JSON.stringify({ ...content, role: 'editor' });
      if (new TextEncoder().encode(payload).length > MAX_CONTENT_BYTES) return json({ error: 'O conteúdo excede o limite de armazenamento.' }, 413);
      try { await saveContent(env, payload); return json({ saved: true, updatedAt: new Date().toISOString() }); }
      catch { return json({ error: 'Falha ao gravar o conteúdo no banco da redação.' }, 500); }
    }
    return json({ error: 'Rota não encontrada.' }, 404);
  },
};
